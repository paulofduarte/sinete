// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! TPM 2.0 commands for sinete's needs: create an ECDSA NIST P-256 signing key under a deterministic
//! primary, load it, sign a digest, and run an NV monotonic counter (the replay epoch). Each builder
//! marshals a command into a caller buffer via wire.zig; each parser reads the response parameters.
//! Pure (no device I/O, no allocator) so it is golden-vector unit-tested without a TPM; the backend
//! (src/) feeds these commands to the device and feeds responses back. v1 keys are presence-less:
//! empty-password owner auth, no policy.

const std = @import("std");
const wire = @import("wire.zig");

pub const Error = wire.Error || error{ TpmError, Unsupported };

// --- algorithm IDs, handles, command codes (TCG Part 2 + Part 3) ---
const alg_rsa: u16 = 0x0001;
const alg_sha256: u16 = 0x000B;
const alg_aes: u16 = 0x0006;
const alg_null: u16 = 0x0010;
const alg_ecdsa: u16 = 0x0018;
const alg_ecc: u16 = 0x0023;
const alg_cfb: u16 = 0x0043;
const ecc_nist_p256: u16 = 0x0003;

const rh_owner: u32 = 0x40000001;
const rh_null: u32 = 0x40000007;
const rs_pw: u32 = 0x40000009; // the password authorization session
const st_hashcheck: u16 = 0x8024;

const cc_create_primary: u32 = 0x00000131;
const cc_create: u32 = 0x00000153;
const cc_load: u32 = 0x00000157;
const cc_sign: u32 = 0x0000015D;
const cc_read_public: u32 = 0x00000173;
const cc_nv_define_space: u32 = 0x0000012A;
const cc_nv_write: u32 = 0x00000137;
const cc_nv_increment: u32 = 0x00000134;
const cc_nv_read: u32 = 0x0000014E;
const cc_nv_read_public: u32 = 0x00000169;
const cc_flush_context: u32 = 0x00000165;
const cc_start_auth_session: u32 = 0x00000176;
const cc_policy_secret: u32 = 0x00000151; // TPM_CC_PolicySecret (confirmed on swtpm via the digest)

pub const se_policy: u8 = 0x01; // TPM_SE_POLICY: a real policy session
pub const se_trial: u8 = 0x03; // TPM_SE_TRIAL: computes a policy digest without authorizing anything

// Object attributes (TPMA_OBJECT).
const attr_fixed_tpm: u32 = 1 << 1;
const attr_fixed_parent: u32 = 1 << 4;
const attr_sensitive_origin: u32 = 1 << 5;
const attr_user_with_auth: u32 = 1 << 6;
const attr_restricted: u32 = 1 << 16;
const attr_decrypt: u32 = 1 << 17;
const attr_sign: u32 = 1 << 18;

const primary_attrs: u32 = attr_fixed_tpm | attr_fixed_parent | attr_sensitive_origin |
    attr_user_with_auth | attr_restricted | attr_decrypt;
const sign_attrs: u32 = attr_fixed_tpm | attr_fixed_parent | attr_sensitive_origin |
    attr_user_with_auth | attr_sign;
// A signing key authorized only by a policy: userWithAuth cleared (no password), authPolicy set.
const policy_sign_attrs: u32 = attr_fixed_tpm | attr_fixed_parent | attr_sensitive_origin | attr_sign;

/// Write a password authorization area (a single TPMS_AUTH_COMMAND wrapped in a u32 size): password
/// session handle, empty nonce, no attributes, and the cleartext password in the HMAC field. An
/// empty `secret` is the empty-password auth used for the owner/null hierarchies and v1 keys.
fn putPasswordAuth(m: *wire.Marshal, secret: []const u8) wire.Error!void {
    try m.put32(@intCast(9 + secret.len)); // 4 handle + 2 nonce + 1 attrs + (2 + secret.len) hmac
    try m.put32(rs_pw);
    try m.put16(0); // nonce: empty TPM2B
    try m.put8(0); // sessionAttributes
    try m.put2b(secret); // hmac field carries the password
}

fn putEmptyAuth(m: *wire.Marshal) wire.Error!void {
    try putPasswordAuth(m, "");
}

/// Write an authorization area that uses a policy session: the session handle, a fresh caller nonce,
/// continueSession cleared (so the session auto-flushes after the command), and an EMPTY HMAC --
/// valid for a pure-PolicySecret session (unbound, unsalted), confirmed on swtpm.
fn putPolicyAuth(m: *wire.Marshal, session: u32, nonce_caller: []const u8) wire.Error!void {
    try m.put32(@intCast(4 + (2 + nonce_caller.len) + 1 + 2));
    try m.put32(session);
    try m.put2b(nonce_caller);
    try m.put8(0); // sessionAttributes: continueSession=0
    try m.put16(0); // hmac: empty
}

/// Marshal a TPMT_PUBLIC for an ECC NIST P-256 object into `m`. `is_primary` selects the restricted
/// decrypt storage parent (AES-128-CFB symmetric, NULL scheme); otherwise an ECDSA-SHA256 signing
/// key (NULL symmetric). `unique` (x and y points) is empty in a creation template.
fn putEccTemplate(m: *wire.Marshal, is_primary: bool) wire.Error!void {
    try m.put16(alg_ecc); // type
    try m.put16(alg_sha256); // nameAlg
    try m.put32(if (is_primary) primary_attrs else sign_attrs); // objectAttributes
    try m.put16(0); // authPolicy: empty TPM2B
    // TPMS_ECC_PARMS: symmetric, scheme, curveID, kdf
    if (is_primary) {
        try m.put16(alg_aes); // symmetric.algorithm
        try m.put16(128); // symmetric.keyBits
        try m.put16(alg_cfb); // symmetric.mode
        try m.put16(alg_null); // scheme: NULL
    } else {
        try m.put16(alg_null); // symmetric: NULL
        try m.put16(alg_null); // scheme: NULL -- a general signing key; the scheme is given at Sign
    }
    try m.put16(ecc_nist_p256); // curveID
    try m.put16(alg_null); // kdf: NULL
    // unique: TPMS_ECC_POINT { x: TPM2B, y: TPM2B } -- empty in a template
    try m.put16(0);
    try m.put16(0);
}

/// inSensitive for an empty-auth creation: TPM2B_SENSITIVE_CREATE wrapping empty userAuth + data.
fn putEmptySensitive(m: *wire.Marshal) wire.Error!void {
    try m.put16(4); // size of the wrapped structure
    try m.put16(0); // userAuth: empty TPM2B
    try m.put16(0); // data: empty TPM2B
}

// --- CreatePrimary: a deterministic ECC P-256 storage parent under the owner hierarchy ---

pub fn createPrimary(buf: []u8) wire.Error![]const u8 {
    var m = try wire.startCommand(buf, wire.st_sessions, cc_create_primary);
    try m.put32(rh_owner); // primaryHandle
    try putEmptyAuth(&m);
    try putEmptySensitive(&m); // inSensitive
    const at = try m.beginSized(); // inPublic: TPM2B_PUBLIC
    try putEccTemplate(&m, true);
    try m.endSized(at);
    try m.put16(0); // outsideInfo: empty TPM2B_DATA
    try m.put32(0); // creationPCR: empty TPML_PCR_SELECTION (count 0)
    wire.finishCommand(&m);
    return m.bytes();
}

/// A sessions response begins with the handle area (caller knows how many handles), then a u32
/// parameterSize, then the response parameters. Returns an Unmarshal positioned at the parameters.
fn paramsAfterHandles(resp: []const u8, handles: usize) Error!struct { handles: []const u8, u: wire.Unmarshal } {
    const r = try wire.parseResponse(resp);
    if (r.code != 0) return Error.TpmError;
    var u = wire.Unmarshal{ .data = r.params };
    const h = try u.getBytes(handles * 4);
    const psize = try u.get32(); // parameterSize: the parameter area length, excluding the auth area
    const params = try u.getBytes(psize); // bound the parser so it can't read into the trailing auth area
    return .{ .handles = h, .u = wire.Unmarshal{ .data = params } };
}

/// The object handle returned by CreatePrimary (the transient primary). Other returned fields
/// (public, name, creation data) are not needed for v1 password auth.
pub fn createPrimaryHandle(resp: []const u8) Error!u32 {
    const p = try paramsAfterHandles(resp, 1);
    return std.mem.readInt(u32, p.handles[0..4], .big);
}

// --- Create: an ECDSA P-256 signing child under the primary ---

pub fn create(buf: []u8, parent: u32) wire.Error![]const u8 {
    var m = try wire.startCommand(buf, wire.st_sessions, cc_create);
    try m.put32(parent); // parentHandle
    try putEmptyAuth(&m);
    try putEmptySensitive(&m);
    const at = try m.beginSized(); // inPublic
    try putEccTemplate(&m, false);
    try m.endSized(at);
    try m.put16(0); // outsideInfo
    try m.put32(0); // creationPCR
    wire.finishCommand(&m);
    return m.bytes();
}

/// The outPrivate and outPublic blobs from Create (the persisted key material), aliasing `resp`.
pub fn createKeyBlobs(resp: []const u8) Error!struct { private: []const u8, public: []const u8 } {
    var p = try paramsAfterHandles(resp, 0);
    const priv = try p.u.get2b(); // outPrivate: TPM2B_PRIVATE
    const pub_blob = try p.u.get2b(); // outPublic: TPM2B_PUBLIC
    return .{ .private = priv, .public = pub_blob };
}

// --- Load: bring a saved (private, public) pair into a usable handle under the primary ---

pub fn load(buf: []u8, parent: u32, private: []const u8, public: []const u8) wire.Error![]const u8 {
    var m = try wire.startCommand(buf, wire.st_sessions, cc_load);
    try m.put32(parent); // parentHandle
    try putEmptyAuth(&m);
    try m.put2b(private); // inPrivate: TPM2B_PRIVATE
    try m.put2b(public); // inPublic: TPM2B_PUBLIC
    wire.finishCommand(&m);
    return m.bytes();
}

pub fn loadHandle(resp: []const u8) Error!u32 {
    const p = try paramsAfterHandles(resp, 1);
    return std.mem.readInt(u32, p.handles[0..4], .big);
}

// --- Sign: ECDSA over a SHA-256 digest, with a NULL validation ticket ---

pub fn sign(buf: []u8, key: u32, digest: []const u8) wire.Error![]const u8 {
    var m = try wire.startCommand(buf, wire.st_sessions, cc_sign);
    try m.put32(key); // keyHandle
    try putEmptyAuth(&m);
    try m.put2b(digest); // digest: TPM2B_DIGEST (SHA-256, 32 bytes)
    // inScheme: TPMT_SIG_SCHEME = ECDSA + SHA256 (the key has a NULL scheme, so it is given here)
    try m.put16(alg_ecdsa);
    try m.put16(alg_sha256);
    // validation: TPMT_TK_HASHCHECK -- a NULL ticket (digest not produced by the TPM)
    try m.put16(st_hashcheck);
    try m.put32(rh_null);
    try m.put16(0); // empty digest
    wire.finishCommand(&m);
    return m.bytes();
}

/// Parse the TPMT_SIGNATURE from a Sign response into r and s octets (aliasing `resp`). Rejects a
/// non-ECDSA signature.
pub fn signResult(resp: []const u8) Error!struct { r: []const u8, s: []const u8 } {
    var p = try paramsAfterHandles(resp, 0);
    if (try p.u.get16() != alg_ecdsa) return Error.Unsupported; // sigAlg
    _ = try p.u.get16(); // hashAlg
    const r = try p.u.get2b(); // signatureR: TPM2B_ECC_PARAMETER
    const s = try p.u.get2b(); // signatureS
    return .{ .r = r, .s = s };
}

/// Extract the 65-byte uncompressed P-256 point (0x04 || X || Y) from a marshaled TPM2B_PUBLIC blob
/// (the `public` stored in a keyfile or returned by Create). The point's X and Y are the TPMS_ECC_POINT
/// `unique` field at the end of the TPMT_PUBLIC.
pub fn pointFromPublic(public: []const u8, out: *[65]u8) Error!void {
    var u = wire.Unmarshal{ .data = public };
    if (try u.get16() != alg_ecc) return Error.Unsupported; // type
    _ = try u.get16(); // nameAlg
    _ = try u.get32(); // objectAttributes
    _ = try u.get2b(); // authPolicy
    // TPMS_ECC_PARMS: symmetric (skip), scheme (skip), curveID, kdf
    const sym = try u.get16();
    if (sym != alg_null) {
        _ = try u.get16(); // keyBits
        _ = try u.get16(); // mode
    }
    const scheme = try u.get16();
    if (scheme != alg_null) _ = try u.get16(); // scheme hashAlg
    if (try u.get16() != ecc_nist_p256) return Error.Unsupported; // curveID: only P-256 maps to nistp256
    const kdf = try u.get16();
    if (kdf != alg_null) _ = try u.get16(); // kdf hashAlg
    const x = try u.get2b();
    const y = try u.get2b();
    if (x.len > 32 or y.len > 32 or x.len == 0 or y.len == 0) return Error.Unsupported;
    out.*[0] = 0x04;
    @memset(out.*[1..33], 0);
    @memset(out.*[33..65], 0);
    @memcpy(out.*[1 + (32 - x.len) ..][0..x.len], x); // right-align (TPM may drop leading zeros)
    @memcpy(out.*[33 + (32 - y.len) ..][0..y.len], y);
}

/// Flush a transient object (primary or loaded key) so it does not accumulate in the TPM. The
/// handle to flush is a parameter (FlushContext takes no handle area and no sessions). Necessary on
/// a raw TPM like swtpm; the kernel /dev/tpmrm0 resource manager would otherwise virtualize it.
pub fn flushContext(buf: []u8, handle: u32) wire.Error![]const u8 {
    var m = try wire.startCommand(buf, wire.st_no_sessions, cc_flush_context);
    try m.put32(handle);
    wire.finishCommand(&m);
    return m.bytes();
}

// --- Policy binding (Z5b): a data key authorized by a TPM policy, not a password ---
//
// The data key carries an authPolicy whose only assertion is PolicySecret against a "master" NV
// index that holds a high-entropy authValue S. Signing therefore requires a policy session that the
// agent satisfies by proving S after the presence gesture; a copied key file is useless without it.
// The policy digest is SHA256( SHA256(zeros(32) || TPM_CC_PolicySecret || masterName) ) -- the empty
// policyRef fold is applied (validated on swtpm).

/// Whether a TPMT_PUBLIC carries a non-empty authPolicy, used to tell a policy-bound data key from a
/// legacy empty-auth one so both coexist in a key directory.
pub fn hasAuthPolicy(public: []const u8) Error!bool {
    var u = wire.Unmarshal{ .data = public };
    _ = try u.get16(); // type
    _ = try u.get16(); // nameAlg
    _ = try u.get32(); // objectAttributes
    const policy = try u.get2b(); // authPolicy
    return policy.len > 0;
}

/// The PolicySecret authPolicy digest for a master whose Name is `master_name`.
pub fn policySecretDigest(master_name: []const u8) [32]u8 {
    const Sha256 = std.crypto.hash.sha2.Sha256;
    var cc: [4]u8 = undefined;
    std.mem.writeInt(u32, &cc, cc_policy_secret, .big);
    var h = Sha256.init(.{});
    h.update(&([_]u8{0} ** 32)); // initial (empty) policyDigest
    h.update(&cc);
    h.update(master_name);
    var d1: [32]u8 = undefined;
    h.final(&d1);
    var out: [32]u8 = undefined;
    Sha256.hash(&d1, &out, .{}); // fold in the empty policyRef
    return out;
}

/// A signing-key creation template with the given (non-empty) authPolicy and userWithAuth cleared.
fn putEccSignTemplate(m: *wire.Marshal, auth_policy: []const u8) wire.Error!void {
    try m.put16(alg_ecc);
    try m.put16(alg_sha256);
    try m.put32(policy_sign_attrs);
    try m.put2b(auth_policy);
    try m.put16(alg_null); // symmetric: NULL
    try m.put16(alg_null); // scheme: NULL (given at Sign)
    try m.put16(ecc_nist_p256);
    try m.put16(alg_null); // kdf
    try m.put16(0); // unique x
    try m.put16(0); // unique y
}

/// Create an ECDSA P-256 signing child bound to `auth_policy` (no password). Parsed by createKeyBlobs.
pub fn createPolicyKey(buf: []u8, parent: u32, auth_policy: []const u8) wire.Error![]const u8 {
    var m = try wire.startCommand(buf, wire.st_sessions, cc_create);
    try m.put32(parent);
    try putEmptyAuth(&m);
    try putEmptySensitive(&m);
    const at = try m.beginSized();
    try putEccSignTemplate(&m, auth_policy);
    try m.endSized(at);
    try m.put16(0); // outsideInfo
    try m.put32(0); // creationPCR
    wire.finishCommand(&m);
    return m.bytes();
}

/// StartAuthSession for a POLICY or TRIAL session (tpmKey=bind=NULL, no salt, SHA-256). `nonce_caller`
/// must be non-empty (use random bytes the size of the hash).
pub fn startAuthSession(buf: []u8, session_type: u8, nonce_caller: []const u8) wire.Error![]const u8 {
    var m = try wire.startCommand(buf, wire.st_no_sessions, cc_start_auth_session);
    try m.put32(rh_null); // tpmKey
    try m.put32(rh_null); // bind
    try m.put2b(nonce_caller);
    try m.put16(0); // encryptedSalt: empty
    try m.put8(session_type);
    try m.put16(alg_null); // symmetric TPMT_SYM_DEF NULL (nothing follows)
    try m.put16(alg_sha256); // authHash
    wire.finishCommand(&m);
    return m.bytes();
}

/// The session handle and nonceTPM from a StartAuthSession response (a no-sessions response: the
/// handle is the only handle, then nonceTPM, with no parameterSize field).
pub fn startAuthSessionResult(resp: []const u8) Error!struct { handle: u32, nonce_tpm: []const u8 } {
    const r = try wire.parseResponse(resp);
    if (r.code != 0) return Error.TpmError;
    var u = wire.Unmarshal{ .data = r.params };
    const handle = try u.get32();
    const nonce = try u.get2b();
    return .{ .handle = handle, .nonce_tpm = nonce };
}

/// PolicySecret: prove the secret of `auth_handle` (the master, by password) to extend `policy_session`
/// with the PolicySecret assertion. `expiration` 0 means no ticket (re-proven each window in v1).
pub fn policySecret(buf: []u8, auth_handle: u32, policy_session: u32, secret: []const u8, nonce_tpm: []const u8, expiration: i32) wire.Error![]const u8 {
    var m = try wire.startCommand(buf, wire.st_sessions, cc_policy_secret);
    try m.put32(auth_handle); // the master entity (Auth Index 1, USER role -> needs an auth area)
    try m.put32(policy_session); // the session being extended (no auth)
    try putPasswordAuth(&m, secret);
    try m.put2b(nonce_tpm); // nonceTPM binds any returned ticket
    try m.put16(0); // cpHashA: empty
    try m.put16(0); // policyRef: empty
    try m.put32(@bitCast(expiration)); // signed: negative -> a ticket with that timeout
    wire.finishCommand(&m);
    return m.bytes();
}

/// Sign as `sign`, but authorize the key with a satisfied policy session (empty HMAC) instead of a
/// password. Parsed by `signResult`.
pub fn signPolicy(buf: []u8, key: u32, digest: []const u8, session: u32, nonce_caller: []const u8) wire.Error![]const u8 {
    var m = try wire.startCommand(buf, wire.st_sessions, cc_sign);
    try m.put32(key);
    try putPolicyAuth(&m, session, nonce_caller);
    try m.put2b(digest);
    try m.put16(alg_ecdsa);
    try m.put16(alg_sha256);
    try m.put16(st_hashcheck);
    try m.put32(rh_null);
    try m.put16(0);
    wire.finishCommand(&m);
    return m.bytes();
}

// --- NV monotonic counter (the replay epoch) ---

// TPMA_NV for a counter: OWNERWRITE(b1) | NT=COUNTER(b4..7=0x1) | OWNERREAD(b17) | NO_DA(b25).
const nv_counter_attrs: u32 = (1 << 1) | (0x1 << 4) | (1 << 17) | (1 << 25);
const rc_nv_defined: u32 = 0x0000014C; // TPM_RC_NV_DEFINED: the index already exists

pub fn nvDefineCounter(buf: []u8, index: u32) wire.Error![]const u8 {
    var m = try wire.startCommand(buf, wire.st_sessions, cc_nv_define_space);
    try m.put32(rh_owner); // authHandle
    try putEmptyAuth(&m);
    try m.put16(0); // auth: the NV index's authValue (empty)
    const at = try m.beginSized(); // publicInfo: TPM2B_NV_PUBLIC wrapping TPMS_NV_PUBLIC
    try m.put32(index); // nvIndex
    try m.put16(alg_sha256); // nameAlg
    try m.put32(nv_counter_attrs); // attributes
    try m.put16(0); // authPolicy: empty
    try m.put16(8); // dataSize: a 64-bit counter
    try m.endSized(at);
    wire.finishCommand(&m);
    return m.bytes();
}

/// NV_DefineSpace returns success, or TPM_RC_NV_DEFINED if the index already exists (idempotent
/// ensure); any other code is an error.
pub const DefineResult = enum { ok, defined };
pub fn checkOrDefined(resp: []const u8) Error!DefineResult {
    const r = try wire.parseResponse(resp);
    if (r.code == 0) return .ok;
    if (r.code == rc_nv_defined) return .defined;
    return Error.TpmError;
}

pub fn nvIncrement(buf: []u8, index: u32) wire.Error![]const u8 {
    var m = try wire.startCommand(buf, wire.st_sessions, cc_nv_increment);
    try m.put32(rh_owner); // authHandle (authorizes via owner auth)
    try m.put32(index); // nvIndex (the target counter)
    try putEmptyAuth(&m);
    wire.finishCommand(&m);
    return m.bytes();
}

pub fn nvRead(buf: []u8, index: u32, size: u16, offset: u16) wire.Error![]const u8 {
    var m = try wire.startCommand(buf, wire.st_sessions, cc_nv_read);
    try m.put32(rh_owner); // authHandle
    try m.put32(index); // nvIndex
    try putEmptyAuth(&m);
    try m.put16(size);
    try m.put16(offset);
    wire.finishCommand(&m);
    return m.bytes();
}

/// Parse an NV_Read response carrying the 8-byte big-endian counter value.
pub fn nvReadU64(resp: []const u8) Error!u64 {
    var p = try paramsAfterHandles(resp, 0);
    const data = try p.u.get2b();
    if (data.len != 8) return Error.Unsupported;
    return std.mem.readInt(u64, data[0..8], .big);
}

/// Assert a command with no response parameters succeeded.
pub fn expectOk(resp: []const u8) Error!void {
    const r = try wire.parseResponse(resp);
    if (r.code != 0) return Error.TpmError;
}

// --- master NV index (Z5b): an ordinary NV index holding the PolicySecret authValue S ---

// TPMA_NV for the master: OWNERWRITE(b1) | AUTHWRITE(b2) | OWNERREAD(b17) | AUTHREAD(b18) | NO_DA(b25),
// NT = ordinary (0). WRITTEN is set by the TPM on first write (which stabilizes the Name).
const nv_master_attrs: u32 = (1 << 1) | (1 << 2) | (1 << 17) | (1 << 18) | (1 << 25);

/// Define the master NV index with a 32-byte authValue `secret` (owner-authorized). Idempotent via
/// checkOrDefined like the counter.
pub fn nvDefineMaster(buf: []u8, index: u32, secret: []const u8) wire.Error![]const u8 {
    var m = try wire.startCommand(buf, wire.st_sessions, cc_nv_define_space);
    try m.put32(rh_owner); // authHandle
    try putEmptyAuth(&m);
    try m.put2b(secret); // auth: the NV index's authValue = S
    const at = try m.beginSized(); // publicInfo
    try m.put32(index);
    try m.put16(alg_sha256);
    try m.put32(nv_master_attrs);
    try m.put16(0); // authPolicy: empty
    try m.put16(32); // dataSize
    try m.endSized(at);
    wire.finishCommand(&m);
    return m.bytes();
}

/// Write `data` to the master NV index, authorized by its own authValue `secret` (sets WRITTEN, so
/// the Name stabilizes). The data content is unused -- a single write is enough.
pub fn nvWrite(buf: []u8, index: u32, secret: []const u8, data: []const u8) wire.Error![]const u8 {
    var m = try wire.startCommand(buf, wire.st_sessions, cc_nv_write);
    try m.put32(index); // authHandle = the index itself (AUTHWRITE)
    try m.put32(index); // nvIndex
    try putPasswordAuth(&m, secret);
    try m.put2b(data);
    try m.put16(0); // offset
    wire.finishCommand(&m);
    return m.bytes();
}

pub fn nvReadPublic(buf: []u8, index: u32) wire.Error![]const u8 {
    var m = try wire.startCommand(buf, wire.st_no_sessions, cc_nv_read_public);
    try m.put32(index);
    wire.finishCommand(&m);
    return m.bytes();
}

/// The NV index's Name (nameAlg || hash) from an NV_ReadPublic response. The Name feeds the
/// PolicySecret digest. Aliases `resp`.
pub fn nvReadPublicName(resp: []const u8) Error![]const u8 {
    const r = try wire.parseResponse(resp);
    if (r.code != 0) return Error.TpmError;
    var u = wire.Unmarshal{ .data = r.params };
    _ = try u.get2b(); // nvPublic: TPM2B_NV_PUBLIC
    return u.get2b(); // nvName: TPM2B_NAME
}

const testing = std.testing;

test "ECC sign template marshals the expected TPMT_PUBLIC prefix" {
    var buf: [256]u8 = undefined;
    var m = wire.Marshal{ .buf = &buf };
    try putEccTemplate(&m, false);
    // type=ECC nameAlg=SHA256 attrs=sign_attrs authPolicy=empty sym=NULL scheme=NULL (a general
    // signing key) curve=P256 kdf=NULL unique x/y empty. Validated against swtpm.
    const want = [_]u8{
        0x00, 0x23, 0x00, 0x0B, // ECC, SHA256
        0x00, 0x04, 0x00, 0x72, // sign_attrs = 0x00040072
        0x00, 0x00, // authPolicy empty
        0x00, 0x10, // symmetric NULL
        0x00, 0x10, // scheme NULL
        0x00, 0x03, // P256
        0x00, 0x10, // kdf NULL
        0x00, 0x00, 0x00, 0x00, // unique x,y empty
    };
    try testing.expectEqualSlices(u8, &want, m.bytes());
}

test "primary template uses the restricted-decrypt attrs + AES symmetric" {
    var buf: [256]u8 = undefined;
    var m = wire.Marshal{ .buf = &buf };
    try putEccTemplate(&m, true);
    var u = wire.Unmarshal{ .data = m.bytes() };
    try testing.expectEqual(alg_ecc, try u.get16());
    try testing.expectEqual(alg_sha256, try u.get16());
    try testing.expectEqual(primary_attrs, try u.get32()); // 0x00030072
    try testing.expectEqual(@as(u16, 0), try u.get16()); // authPolicy
    try testing.expectEqual(alg_aes, try u.get16());
    try testing.expectEqual(@as(u16, 128), try u.get16());
    try testing.expectEqual(alg_cfb, try u.get16());
}

test "createPrimary command header + handle + auth" {
    var buf: [256]u8 = undefined;
    const cmd = try createPrimary(&buf);
    var u = wire.Unmarshal{ .data = cmd };
    try testing.expectEqual(wire.st_sessions, try u.get16());
    try testing.expectEqual(@as(u32, @intCast(cmd.len)), try u.get32()); // commandSize == len
    try testing.expectEqual(cc_create_primary, try u.get32());
    try testing.expectEqual(rh_owner, try u.get32());
    try testing.expectEqual(@as(u32, 9), try u.get32()); // authorizationSize
    try testing.expectEqual(rs_pw, try u.get32());
}

test "signResult parses r,s and rejects non-ECDSA" {
    // params: parameterSize(4)=12 then TPMT_SIGNATURE: ECDSA, SHA256, r(2b), s(2b)
    const params = [_]u8{ 0, 0, 0, 0x0C, 0x00, 0x18, 0x00, 0x0B, 0x00, 0x02, 0xAA, 0xBB, 0x00, 0x02, 0xCC, 0xDD };
    const resp = [_]u8{ 0x80, 0x02, 0, 0, 0, @intCast(10 + params.len), 0, 0, 0, 0 } ++ params;
    const sig = try signResult(&resp);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0xBB }, sig.r);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xCC, 0xDD }, sig.s);

    const bad = [_]u8{ 0x80, 0x02, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 2, 0x00, 0x16 }; // parameterSize=2; sigAlg != ECDSA
    try testing.expectError(Error.Unsupported, signResult(&bad));
}

test "paramsAfterHandles surfaces a TPM error code" {
    const resp = [_]u8{ 0x80, 0x01, 0, 0, 0, 10, 0, 0, 0x01, 0x01 }; // responseCode != 0
    try testing.expectError(Error.TpmError, createPrimaryHandle(&resp));
}

test "create targets the parent; createKeyBlobs extracts the blobs" {
    var buf: [256]u8 = undefined;
    const c = try create(&buf, 0x80000000);
    var u = wire.Unmarshal{ .data = c };
    try testing.expectEqual(wire.st_sessions, try u.get16());
    _ = try u.get32();
    try testing.expectEqual(cc_create, try u.get32());
    try testing.expectEqual(@as(u32, 0x80000000), try u.get32()); // parentHandle

    // response params: parameterSize(4)=9, outPrivate(2b "AA"), outPublic(2b "BBB")
    const params = [_]u8{ 0, 0, 0, 9, 0, 2, 'A', 'A', 0, 3, 'B', 'B', 'B' };
    const resp = [_]u8{ 0x80, 0x02, 0, 0, 0, @intCast(10 + params.len), 0, 0, 0, 0 } ++ params;
    const b = try createKeyBlobs(&resp);
    try testing.expectEqualStrings("AA", b.private);
    try testing.expectEqualStrings("BBB", b.public);
}

test "paramsAfterHandles bounds the parser to parameterSize, excluding the auth area" {
    // 9 parameter bytes (outPrivate "AA" + outPublic "BBB"), then a bogus auth area that must be ignored.
    const params = [_]u8{ 0, 0, 0, 9, 0, 2, 'A', 'A', 0, 3, 'B', 'B', 'B' };
    const auth = [_]u8{ 0xFF, 0xFF, 0xFF, 0xFF };
    const resp = [_]u8{ 0x80, 0x02, 0, 0, 0, @intCast(10 + params.len + auth.len), 0, 0, 0, 0 } ++ params ++ auth;
    const b = try createKeyBlobs(&resp);
    try testing.expectEqualStrings("AA", b.private);
    try testing.expectEqualStrings("BBB", b.public);
}

test "load carries inPrivate/inPublic; loadHandle reads the handle" {
    var buf: [128]u8 = undefined;
    const c = try load(&buf, 0x80000000, "pp", "uuu");
    var u = wire.Unmarshal{ .data = c };
    _ = try u.get16();
    _ = try u.get32();
    try testing.expectEqual(cc_load, try u.get32());

    // header(10) + objectHandle(4) + parameterSize(4)
    const resp = [_]u8{ 0x80, 0x02, 0, 0, 0, 18, 0, 0, 0, 0, 0x80, 0x00, 0x00, 0x02, 0, 0, 0, 0 };
    try testing.expectEqual(@as(u32, 0x80000002), try loadHandle(&resp));
}

test "sign command matches the swtpm-validated layout" {
    var buf: [128]u8 = undefined;
    const digest = [_]u8{0xAB} ** 32;
    const c = try sign(&buf, 0x80000001, &digest);
    // header(10) + keyHandle + auth(4+9) + digest(2+32) + inScheme(4) + validation(8) = 73
    const want_head = [_]u8{
        0x80, 0x02, 0, 0, 0, 73, 0x00, 0x00, 0x01, 0x5d, // ST_SESSIONS, size, TPM_CC_Sign (0x15d!)
        0x80, 0x00, 0x00, 0x01, // keyHandle
        0x00, 0x00, 0x00, 0x09, 0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, // auth
        0x00, 0x20, // digest size 32
    };
    try testing.expectEqualSlices(u8, &want_head, c[0..want_head.len]);
    const tail = c[want_head.len + 32 ..];
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x18, 0x00, 0x0b, 0x80, 0x24, 0x40, 0x00, 0x00, 0x07, 0x00, 0x00 }, tail);
}

test "flushContext targets the handle with no auth/sessions" {
    var buf: [32]u8 = undefined;
    const c = try flushContext(&buf, 0x80000001);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x80, 0x01, 0, 0, 0, 14, 0x00, 0x00, 0x01, 0x65, 0x80, 0x00, 0x00, 0x01 }, c);
}

test "NV commands build and parse" {
    var buf: [128]u8 = undefined;

    const def = try nvDefineCounter(&buf, 0x018E7E7E);
    var u = wire.Unmarshal{ .data = def };
    _ = try u.get16();
    _ = try u.get32();
    try testing.expectEqual(cc_nv_define_space, try u.get32());
    try testing.expectEqual(rh_owner, try u.get32());

    const inc = try nvIncrement(&buf, 0x018E7E7E);
    var ui = wire.Unmarshal{ .data = inc };
    _ = try ui.get16();
    _ = try ui.get32();
    try testing.expectEqual(cc_nv_increment, try ui.get32());
    try testing.expectEqual(rh_owner, try ui.get32());
    try testing.expectEqual(@as(u32, 0x018E7E7E), try ui.get32()); // nvIndex after authHandle

    const rd = try nvRead(&buf, 0x018E7E7E, 8, 0);
    var ur = wire.Unmarshal{ .data = rd };
    _ = try ur.get16();
    _ = try ur.get32();
    try testing.expectEqual(cc_nv_read, try ur.get32());

    // NV_Read response: parameterSize(4)=10, data(2b, 8 bytes = 0x0102030405060708)
    const params = [_]u8{ 0, 0, 0, 10, 0, 8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const resp = [_]u8{ 0x80, 0x02, 0, 0, 0, @intCast(10 + params.len), 0, 0, 0, 0 } ++ params;
    try testing.expectEqual(@as(u64, 0x0102030405060708), try nvReadU64(&resp));
}

test "checkOrDefined and expectOk classify response codes" {
    const ok = [_]u8{ 0x80, 0x01, 0, 0, 0, 10, 0, 0, 0, 0 };
    const defined = [_]u8{ 0x80, 0x01, 0, 0, 0, 10, 0, 0, 0x01, 0x4c }; // TPM_RC_NV_DEFINED
    const fail = [_]u8{ 0x80, 0x01, 0, 0, 0, 10, 0, 0, 0x01, 0x00 };
    try testing.expectEqual(DefineResult.ok, try checkOrDefined(&ok));
    try testing.expectEqual(DefineResult.defined, try checkOrDefined(&defined));
    try testing.expectError(Error.TpmError, checkOrDefined(&fail));
    try expectOk(&ok);
    try testing.expectError(Error.TpmError, expectOk(&fail));
}

test "pointFromPublic recovers the uncompressed point, right-aligning short coords" {
    var buf: [256]u8 = undefined;
    var m = wire.Marshal{ .buf = &buf };
    // a sign-template public with a 32-byte X and a 31-byte Y (TPM dropped one leading zero)
    try m.put16(alg_ecc);
    try m.put16(alg_sha256);
    try m.put32(sign_attrs);
    try m.put16(0);
    try m.put16(alg_null);
    try m.put16(alg_ecdsa);
    try m.put16(alg_sha256);
    try m.put16(ecc_nist_p256);
    try m.put16(alg_null);
    try m.put2b(&([_]u8{0x11} ** 32));
    try m.put2b(&([_]u8{0x22} ** 31));
    var point: [65]u8 = undefined;
    try pointFromPublic(m.bytes(), &point);
    try testing.expectEqual(@as(u8, 0x04), point[0]);
    try testing.expectEqual(@as(u8, 0x11), point[1]); // X starts immediately
    try testing.expectEqual(@as(u8, 0x00), point[33]); // Y padded with one leading zero
    try testing.expectEqual(@as(u8, 0x22), point[34]);
}

test "pointFromPublic rejects a non-P256 curve" {
    var buf: [256]u8 = undefined;
    var m = wire.Marshal{ .buf = &buf };
    try m.put16(alg_ecc);
    try m.put16(alg_sha256);
    try m.put32(sign_attrs);
    try m.put16(0);
    try m.put16(alg_null);
    try m.put16(alg_ecdsa);
    try m.put16(alg_sha256);
    try m.put16(0x0001); // TPM_ECC_NIST_P192, not P-256
    try m.put16(alg_null);
    try m.put2b(&([_]u8{0x11} ** 24));
    try m.put2b(&([_]u8{0x22} ** 24));
    var point: [65]u8 = undefined;
    try testing.expectError(Error.Unsupported, pointFromPublic(m.bytes(), &point));
}

// --- Z5b policy commands ---

test "policySecretDigest matches the swtpm-confirmed name -> digest" {
    // From the 5b spike: a master NV index Name and the policy digest the TPM computed for it.
    const name = [_]u8{ 0x00, 0x0b } ++ hexToBytes("dac66d4cb73148bc0f8850853b61f0292e5e591ebfa5911df9388738dd65d0f0");
    const want = hexToBytes("da520d948b3cc7f137f9217bc4cf998d1d05e02512972e76dd35d126d689cd51");
    try testing.expectEqualSlices(u8, &want, &policySecretDigest(&name));
}

fn hexToBytes(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "startAuthSession marshals a policy/trial session with no auth area" {
    var buf: [128]u8 = undefined;
    const c = try startAuthSession(&buf, se_policy, &[_]u8{0xAA} ** 32);
    var u = wire.Unmarshal{ .data = c };
    try testing.expectEqual(wire.st_no_sessions, try u.get16());
    _ = try u.get32(); // size
    try testing.expectEqual(cc_start_auth_session, try u.get32());
    try testing.expectEqual(rh_null, try u.get32()); // tpmKey
    try testing.expectEqual(rh_null, try u.get32()); // bind
    try testing.expectEqualSlices(u8, &[_]u8{0xAA} ** 32, try u.get2b()); // nonceCaller
    try testing.expectEqual(@as(u16, 0), try u.get16()); // salt empty
    try testing.expectEqual(@as(u8, se_policy), try u.get8());
    try testing.expectEqual(alg_null, try u.get16()); // symmetric
    try testing.expectEqual(alg_sha256, try u.get16()); // authHash

    // the response parser: header(10) + sessionHandle(4) + nonceTPM(2b), no parameterSize
    const resp = [_]u8{ 0x80, 0x01, 0, 0, 0, 18, 0, 0, 0, 0, 0x03, 0x00, 0x01, 0x00, 0x00, 0x02, 0xBB, 0xBB };
    const sr = try startAuthSessionResult(&resp);
    try testing.expectEqual(@as(u32, 0x03000100), sr.handle);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xBB, 0xBB }, sr.nonce_tpm);
}

test "policySecret carries both handles, the password auth, and a signed expiration" {
    var buf: [128]u8 = undefined;
    const c = try policySecret(&buf, 0x018E7E7F, 0x03000100, "secret", &[_]u8{0xCC} ** 32, -30);
    var u = wire.Unmarshal{ .data = c };
    _ = try u.get16();
    _ = try u.get32();
    try testing.expectEqual(cc_policy_secret, try u.get32());
    try testing.expectEqual(@as(u32, 0x018E7E7F), try u.get32()); // authHandle (master)
    try testing.expectEqual(@as(u32, 0x03000100), try u.get32()); // policySession
    try testing.expectEqual(@as(u32, 9 + 6), try u.get32()); // authorizationSize = 9 + len("secret")
    try testing.expectEqual(rs_pw, try u.get32());
    _ = try u.get16(); // nonce
    _ = try u.get8(); // attrs
    try testing.expectEqualStrings("secret", try u.get2b()); // password in the hmac field
    _ = try u.get2b(); // nonceTPM
    _ = try u.get16(); // cpHashA
    _ = try u.get16(); // policyRef
    try testing.expectEqual(@as(u32, @bitCast(@as(i32, -30))), try u.get32()); // expiration two's complement
}

test "signPolicy authorizes with the session handle and an empty HMAC" {
    var buf: [128]u8 = undefined;
    const c = try signPolicy(&buf, 0x80000002, &([_]u8{0xAB} ** 32), 0x03000100, &[_]u8{0xDD} ** 32);
    var u = wire.Unmarshal{ .data = c };
    _ = try u.get16();
    _ = try u.get32();
    try testing.expectEqual(cc_sign, try u.get32());
    try testing.expectEqual(@as(u32, 0x80000002), try u.get32()); // keyHandle
    _ = try u.get32(); // authorizationSize
    try testing.expectEqual(@as(u32, 0x03000100), try u.get32()); // the policy session, not rs_pw
    _ = try u.get2b(); // nonceCaller
    try testing.expectEqual(@as(u8, 0), try u.get8()); // continueSession=0
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x00 }, c[u.pos .. u.pos + 2]); // empty HMAC TPM2B
}

test "putEccSignTemplate clears userWithAuth and sets a 32-byte authPolicy; hasAuthPolicy detects it" {
    var buf: [256]u8 = undefined;
    var m = wire.Marshal{ .buf = &buf };
    const policy = [_]u8{0xEE} ** 32;
    try putEccSignTemplate(&m, &policy);
    var u = wire.Unmarshal{ .data = m.bytes() };
    try testing.expectEqual(alg_ecc, try u.get16());
    try testing.expectEqual(alg_sha256, try u.get16());
    try testing.expectEqual(@as(u32, 0x00040032), try u.get32()); // policy_sign_attrs (no user_with_auth)
    try testing.expectEqualSlices(u8, &policy, try u.get2b());
    try testing.expect(try hasAuthPolicy(m.bytes()));

    // a legacy empty-auth template has no policy
    var b2: [256]u8 = undefined;
    var m2 = wire.Marshal{ .buf = &b2 };
    try putEccTemplate(&m2, false);
    try testing.expect(!try hasAuthPolicy(m2.bytes()));
}

test "nvDefineMaster + nvWrite + nvReadPublicName" {
    var buf: [128]u8 = undefined;
    const d = try nvDefineMaster(&buf, 0x018E7E7F, &([_]u8{0x5A} ** 32));
    var ud = wire.Unmarshal{ .data = d };
    _ = try ud.get16();
    _ = try ud.get32();
    try testing.expectEqual(cc_nv_define_space, try ud.get32());
    try testing.expectEqual(rh_owner, try ud.get32());

    var buf2: [128]u8 = undefined;
    const w = try nvWrite(&buf2, 0x018E7E7F, "secret", "data");
    var uw = wire.Unmarshal{ .data = w };
    _ = try uw.get16();
    _ = try uw.get32();
    try testing.expectEqual(cc_nv_write, try uw.get32());
    try testing.expectEqual(@as(u32, 0x018E7E7F), try uw.get32()); // authHandle = index
    try testing.expectEqual(@as(u32, 0x018E7E7F), try uw.get32()); // nvIndex

    // NV_ReadPublic response: nvPublic(2b) then nvName(2b) -> return the Name
    const resp = [_]u8{ 0x80, 0x01, 0, 0, 0, 10 + 4 + 5, 0, 0, 0, 0 } ++
        [_]u8{ 0x00, 0x02, 0xAA, 0xBB } ++ // nvPublic 2b
        [_]u8{ 0x00, 0x03, 0x00, 0x0b, 0x99 }; // nvName 2b
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x0b, 0x99 }, try nvReadPublicName(&resp));
}
