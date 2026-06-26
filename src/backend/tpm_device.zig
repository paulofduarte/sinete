// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//! The TPM 2.0 device transport: write a marshaled command and read the full response, raw, over
//! either the kernel resource manager (/dev/tpmrm0, the production path) or a swtpm unix socket
//! (the test path) -- both speak raw TPM framing, verified against swtpm. Linux-only, impure (real
//! I/O), so it lives in src/ and is exercised by the swtpm integration test rather than unit tests.
//! A connected socket and the character device are both driven as a std.Io.File handle.

const std = @import("std");
const net = std.Io.net;
const File = std.Io.File;

pub const Error = error{ TpmClosed, TpmResponseTooBig, TpmResponseTooSmall, TpmBufferTooSmall };

pub const Device = struct {
    io: std.Io,
    file: File,

    /// Open the TPM. `is_socket` selects a swtpm unix socket (connect) over the character device
    /// (open read-write). Selected by the caller from the SINETE_TPM env / the default path.
    pub fn open(io: std.Io, path: []const u8, is_socket: bool) !Device {
        if (is_socket) {
            const ua = try net.UnixAddress.init(path);
            const stream = try ua.connect(io);
            return .{ .io = io, .file = .{ .handle = stream.socket.handle, .flags = .{ .nonblocking = false } } };
        }
        const file = try std.Io.Dir.cwd().openFile(io, path, .{ .mode = .read_write });
        return .{ .io = io, .file = file };
    }

    pub fn close(self: *Device) void {
        self.file.close(self.io);
    }

    /// Send a marshaled command and read the full response into `buf` (the 10-byte header carries
    /// the response size). Returns the response slice. A TPM response is bounded, so a few-KB buf
    /// suffices.
    pub fn transact(self: *Device, cmd: []const u8, buf: []u8) ![]const u8 {
        if (buf.len < 10) return Error.TpmBufferTooSmall; // must hold at least the 10-byte header
        try self.file.writeStreamingAll(self.io, cmd);
        var got: usize = 0;
        // Cap the header read at 10 bytes: never consume past the size field before it is known,
        // so a stream transport can't fold the start of a following response into this header.
        while (got < 10) got += try self.readSome(buf[got..10]);
        const size = std.mem.readInt(u32, buf[2..6], .big);
        if (size < 10) return Error.TpmResponseTooSmall; // must cover at least the header just read
        if (size > buf.len) return Error.TpmResponseTooBig;
        while (got < size) got += try self.readSome(buf[got..size]);
        return buf[0..size];
    }

    fn readSome(self: *Device, dst: []u8) !usize {
        const n = try self.file.readStreaming(self.io, &.{dst});
        if (n == 0) return Error.TpmClosed;
        return n;
    }
};
