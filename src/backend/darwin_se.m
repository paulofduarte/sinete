// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

// Secure Enclave key access via Apple's Security.framework, for the Cryptoprocessor seam. The Zig
// core never sees a SecKey; it passes a 65-byte public point (the key_id) and receives a DER
// signature. Keys are presence-less (no biometric ACL) -- the agent gates presence in software via
// the Touch ID Authorizer -- so SecKeyCreateSignature here never prompts.
//
// Keys live in sinete's keychain access group (the signed bundle's application-identifier,
// LDT534J26W.me.paulofduarte.sinete); the entitlement wall makes them usable only by that signed
// identity. We filter to labels prefixed "sinete-" and exclude the reserved master key, matching
// the Go implementation so this reads the same keys.
//
// Compiled without ARC: Objective-C literals/dictionaries autorelease within @autoreleasepool, and
// every CoreFoundation object (SecKeyRef, CFDataRef, the match-array) is CFRelease'd by hand.

#import <Foundation/Foundation.h>
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <string.h>
#include <stdint.h>

#define SINETE_LABEL_PREFIX "sinete-"
#define SINETE_MASTER_LABEL "sinete-_master"
#define SINETE_APP_TAG      "me.paulofduarte.sinete"

typedef struct {
    uint8_t pub[65];     // uncompressed P-256 point: 0x04 || X(32) || Y(32)
    char    label[128];  // kSecAttrLabel, surfaced as the SSH key comment
} sinete_se_key;

// Base query for sinete's Secure Enclave EC keys. kSecUseDataProtectionKeychain is mandatory on
// macOS: access-group SE keys live in the data-protection keychain and are otherwise not found.
static NSMutableDictionary *sinete_base_query(void) {
    NSMutableDictionary *q = [NSMutableDictionary dictionary];
    q[(__bridge id)kSecClass] = (__bridge id)kSecClassKey;
    q[(__bridge id)kSecAttrKeyType] = (__bridge id)kSecAttrKeyTypeECSECPrimeRandom;
    q[(__bridge id)kSecAttrTokenID] = (__bridge id)kSecAttrTokenIDSecureEnclave;
    q[(__bridge id)kSecUseDataProtectionKeychain] = @YES;
    return q;
}

// Copy the 65-byte uncompressed public point of a private SecKeyRef into out. Returns 1 on success.
static int sinete_copy_point(SecKeyRef priv, uint8_t out[65]) {
    SecKeyRef pub = SecKeyCopyPublicKey(priv);
    if (!pub) return 0;
    CFErrorRef e = NULL;
    CFDataRef d = SecKeyCopyExternalRepresentation(pub, &e);
    CFRelease(pub);
    if (!d) { if (e) CFRelease(e); return 0; }
    int ok = 0;
    if (CFDataGetLength(d) == 65) {
        memcpy(out, CFDataGetBytePtr(d), 65);
        ok = 1;
    }
    CFRelease(d);
    return ok;
}

// Find the sinete SE private key whose public point equals pub[65]. Returns a retained SecKeyRef
// (the caller CFRelease's it) or NULL.
static SecKeyRef sinete_find_key(const uint8_t pub[65]) {
    NSMutableDictionary *q = sinete_base_query();
    q[(__bridge id)kSecReturnRef] = @YES;
    q[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitAll;

    CFTypeRef result = NULL;
    if (SecItemCopyMatching((__bridge CFDictionaryRef)q, &result) != errSecSuccess) return NULL;
    NSArray *items = (__bridge NSArray *)result;
    SecKeyRef found = NULL;
    for (id obj in items) {
        SecKeyRef priv = (__bridge SecKeyRef)obj;
        uint8_t point[65];
        if (sinete_copy_point(priv, point) && memcmp(point, pub, 65) == 0) {
            found = (SecKeyRef)CFRetain(priv);
            break;
        }
    }
    CFRelease(result);
    return found;
}

// List sinete's presence-less SE keys into out (up to max). Returns the count (>= 0) or a negative
// OSStatus. errSecItemNotFound maps to 0.
int32_t sinete_se_enumerate(sinete_se_key *out, int32_t max) {
    @autoreleasepool {
        NSMutableDictionary *q = sinete_base_query();
        q[(__bridge id)kSecReturnRef] = @YES;
        q[(__bridge id)kSecReturnAttributes] = @YES;
        q[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitAll;

        CFTypeRef result = NULL;
        OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &result);
        if (st == errSecItemNotFound) return 0;
        if (st != errSecSuccess) return (int32_t)st;

        NSArray *items = (__bridge NSArray *)result;
        int32_t n = 0;
        for (NSDictionary *item in items) {
            if (n >= max) break;
            NSString *label = item[(__bridge id)kSecAttrLabel];
            const char *lbl = label ? [label UTF8String] : NULL;
            if (!lbl) continue;
            if (strncmp(lbl, SINETE_LABEL_PREFIX, strlen(SINETE_LABEL_PREFIX)) != 0) continue;
            if (strcmp(lbl, SINETE_MASTER_LABEL) == 0) continue;
            SecKeyRef priv = (__bridge SecKeyRef)item[(__bridge id)kSecValueRef];
            if (!priv) continue;
            uint8_t point[65];
            if (!sinete_copy_point(priv, point)) continue;
            memcpy(out[n].pub, point, 65);
            strncpy(out[n].label, lbl, sizeof(out[n].label) - 1);
            out[n].label[sizeof(out[n].label) - 1] = '\0';
            n++;
        }
        CFRelease(result);
        return n;
    }
}

// Sign the raw message data with the key matching pub[65]. The Secure Enclave hashes it (SHA-256)
// and writes the ASN.1 DER ECDSA-Sig-Value into der_out. Returns the DER length or a negative
// OSStatus.
int32_t sinete_se_sign(const uint8_t pub[65], const uint8_t *data, size_t len,
                       uint8_t *der_out, size_t cap) {
    @autoreleasepool {
        SecKeyRef priv = sinete_find_key(pub);
        if (!priv) return (int32_t)errSecItemNotFound;

        NSData *msg = [NSData dataWithBytes:data length:len];
        CFErrorRef e = NULL;
        CFDataRef sig = SecKeyCreateSignature(
            priv, kSecKeyAlgorithmECDSASignatureMessageX962SHA256, (__bridge CFDataRef)msg, &e);
        CFRelease(priv);
        if (!sig) {
            OSStatus code = errSecParam;
            if (e) { code = (OSStatus)CFErrorGetCode(e); CFRelease(e); }
            return (int32_t)code;
        }
        CFIndex slen = CFDataGetLength(sig);
        if (slen < 0 || (size_t)slen > cap) { CFRelease(sig); return (int32_t)errSecParam; }
        memcpy(der_out, CFDataGetBytePtr(sig), (size_t)slen);
        CFRelease(sig);
        return (int32_t)slen;
    }
}

// Generate a new presence-less P-256 Secure Enclave key labelled `label`, writing its public point
// to pub_out[65]. Returns 0 or a negative OSStatus.
int32_t sinete_se_generate(const char *label, uint8_t pub_out[65]) {
    @autoreleasepool {
        CFErrorRef e = NULL;
        SecAccessControlRef ac = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecAccessControlPrivateKeyUsage, &e); // no presence flag => presence-less
        if (!ac) {
            OSStatus code = errSecParam;
            if (e) { code = (OSStatus)CFErrorGetCode(e); CFRelease(e); }
            return (int32_t)code;
        }

        NSDictionary *privAttrs = @{
            (__bridge id)kSecAttrIsPermanent: @YES,
            (__bridge id)kSecAttrApplicationTag: [@(SINETE_APP_TAG) dataUsingEncoding:NSUTF8StringEncoding],
            (__bridge id)kSecAttrLabel: @(label),
            (__bridge id)kSecAttrAccessControl: (__bridge id)ac,
        };
        NSDictionary *attrs = @{
            (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
            (__bridge id)kSecAttrKeySizeInBits: @256,
            (__bridge id)kSecAttrTokenID: (__bridge id)kSecAttrTokenIDSecureEnclave,
            (__bridge id)kSecUseDataProtectionKeychain: @YES,
            (__bridge id)kSecPrivateKeyAttrs: privAttrs,
        };

        SecKeyRef priv = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attrs, &e);
        CFRelease(ac);
        if (!priv) {
            OSStatus code = errSecParam;
            if (e) { code = (OSStatus)CFErrorGetCode(e); CFRelease(e); }
            return (int32_t)code;
        }
        int ok = sinete_copy_point(priv, pub_out);
        CFRelease(priv);
        return ok ? 0 : (int32_t)errSecParam;
    }
}

// Delete the sinete SE key whose public point equals pub[65]. Returns 0 or a negative OSStatus.
int32_t sinete_se_remove(const uint8_t pub[65]) {
    @autoreleasepool {
        SecKeyRef priv = sinete_find_key(pub);
        if (!priv) return (int32_t)errSecItemNotFound;
        NSDictionary *q = @{
            (__bridge id)kSecClass: (__bridge id)kSecClassKey,
            (__bridge id)kSecValueRef: (__bridge id)priv,
            (__bridge id)kSecUseDataProtectionKeychain: @YES,
        };
        OSStatus st = SecItemDelete((__bridge CFDictionaryRef)q);
        CFRelease(priv);
        return (int32_t)st;
    }
}
