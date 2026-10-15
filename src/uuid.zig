const std = @import("std");
const fsys = @import("fsys.zig");

const hex_digits = "0123456789abcdef";

/// UUIDGen mints RFC 9562 UUIDv7 identifiers with a 48-bit millisecond
/// timestamp (`now()*1000`), version 7, a 12-bit monotonic counter in `rand_a`
/// (§6.2 method 1), variant `10`, and 62 random bits.
pub const UUIDGen = struct {
    io: ?std.Io = null,
    now_fn: ?*const fn (?*anyopaque) i64 = null,
    now_ctx: ?*anyopaque = null,
    rand_fn: ?*const fn (?*anyopaque, []u8) void = null,
    rand_ctx: ?*anyopaque = null,
    last_ms: i64 = -1,
    seq: u16 = 0,

    pub fn initHost(io: std.Io) UUIDGen {
        return .{
            .io = io,
            .last_ms = -1,
            .seq = 0,
        };
    }

    pub fn initCustom(
        now_ctx: ?*anyopaque,
        now_fn: *const fn (?*anyopaque) i64,
        rand_ctx: ?*anyopaque,
        rand_fn: *const fn (?*anyopaque, []u8) void,
    ) UUIDGen {
        return .{
            .now_fn = now_fn,
            .now_ctx = now_ctx,
            .rand_fn = rand_fn,
            .rand_ctx = rand_ctx,
            .last_ms = -1,
            .seq = 0,
        };
    }

    pub fn nowSeconds(self: *const UUIDGen) i64 {
        if (self.now_fn) |f| {
            return f(self.now_ctx);
        }
        if (self.io) |io_val| {
            const ts = std.Io.Clock.real.now(io_val);
            return @intCast(@divTrunc(ts.nanoseconds, std.time.ns_per_s));
        }
        return -1;
    }

    /// NowMs returns the current Unix timestamp in milliseconds (`Now()*1000`),
    /// or refuses with `clock_unset` when `Now() <= 0`.
    pub fn nowMs(self: *const UUIDGen) !i64 {
        const sec = self.nowSeconds();
        if (sec <= 0) {
            return fsys.refuse("clock_unset", "");
        }
        return sec * 1000;
    }

    pub fn fillRand(self: *const UUIDGen, buf: []u8) void {
        if (self.rand_fn) |f| {
            f(self.rand_ctx, buf);
            return;
        }
        if (self.io) |io_val| {
            io_val.random(buf);
            return;
        }
        @memset(buf, 0);
    }

    /// NewBytes mints a 16-byte RFC 9562 UUIDv7.
    pub fn newBytes(self: *UUIDGen) ![16]u8 {
        const ms = try self.nowMs();
        if (ms > self.last_ms) {
            self.last_ms = ms;
            self.seq = 0;
        } else {
            self.seq += 1;
            if (self.seq > 0x0fff) {
                self.seq = 0;
                self.last_ms += 1;
            }
        }
        var rnd: [8]u8 = undefined;
        self.fillRand(&rnd);

        var u: [16]u8 = undefined;
        const ts: u64 = @intCast(self.last_ms);
        u[0] = @truncate(ts >> 40);
        u[1] = @truncate(ts >> 32);
        u[2] = @truncate(ts >> 24);
        u[3] = @truncate(ts >> 16);
        u[4] = @truncate(ts >> 8);
        u[5] = @truncate(ts);
        u[6] = 0x70 | @as(u8, @truncate((self.seq >> 8) & 0x0f));
        u[7] = @truncate(self.seq & 0xff);
        @memcpy(u[8..16], &rnd);
        u[8] = 0x80 | (u[8] & 0x3f);
        return u;
    }

    /// New mints a canonical 36-character lowercase UUIDv7 string.
    pub fn new(self: *UUIDGen) ![36]u8 {
        const u = try self.newBytes();
        return formatUUID(u);
    }

    /// NewAlloc mints a heap-allocated 36-character lowercase UUIDv7 string.
    pub fn newAlloc(self: *UUIDGen, allocator: std.mem.Allocator) ![]u8 {
        const buf = try self.new();
        return allocator.dupe(u8, &buf);
    }
};

/// FormatUUID formats 16 bytes as canonical 8-4-4-4-12 lowercase hex.
pub fn formatUUID(u: [16]u8) [36]u8 {
    var out: [36]u8 = undefined;
    var j: usize = 0;
    for (u, 0..) |v, i| {
        if (i == 4 or i == 6 or i == 8 or i == 10) {
            out[j] = '-';
            j += 1;
        }
        out[j] = hex_digits[v >> 4];
        out[j + 1] = hex_digits[v & 0x0f];
        j += 2;
    }
    return out;
}

fn lowerHexVal(c: u8) ?u8 {
    if (c >= '0' and c <= '9') return c - '0';
    if (c >= 'a' and c <= 'f') return c - 'a' + 10;
    return null;
}

/// ParseUUID parses a canonical 36-character lowercase UUID string into 16 bytes.
pub fn parseUUID(s: []const u8) ?[16]u8 {
    if (s.len != 36 or s[8] != '-' or s[13] != '-' or s[18] != '-' or s[23] != '-') {
        return null;
    }
    var u: [16]u8 = undefined;
    var byte_idx: usize = 0;
    var i: usize = 0;
    while (i < 36) {
        if (i == 8 or i == 13 or i == 18 or i == 23) {
            i += 1;
            continue;
        }
        const hi = lowerHexVal(s[i]) orelse return null;
        const lo = lowerHexVal(s[i + 1]) orelse return null;
        u[byte_idx] = (hi << 4) | lo;
        byte_idx += 1;
        i += 2;
    }
    return u;
}

/// IsUUIDv7 reports whether s is a well-formed RFC 9562 UUIDv7 string
/// (version nibble 7, variant bits 10).
pub fn isUUIDv7(s: []const u8) bool {
    const u = parseUUID(s) orelse return false;
    return (u[6] >> 4) == 7 and (u[8] >> 6) == 2;
}

test "UUIDv7 monotonic within a tick, RFC 9562 layout, and clock_unset" {
    const State = struct {
        now: i64 = 1760000000,
        seed: u8 = 1,

        fn getNow(ptr: ?*anyopaque) i64 {
            const st: *@This() = @ptrCast(@alignCast(ptr.?));
            return st.now;
        }

        fn fillRand(ptr: ?*anyopaque, buf: []u8) void {
            const st: *@This() = @ptrCast(@alignCast(ptr.?));
            for (buf) |*b| {
                b.* = st.seed;
                st.seed = st.seed *% 31 +% 17;
            }
        }
    };

    var st = State{};
    var gen = UUIDGen.initCustom(&st, State.getNow, &st, State.fillRand);

    var prev_bytes: [16]u8 = undefined;
    var prev_str: [36]u8 = undefined;
    var i: usize = 0;
    while (i < 1000) : (i += 1) {
        const id = try gen.new();
        try std.testing.expect(isUUIDv7(&id));
        const b = parseUUID(&id).?;
        if (i > 0) {
            try std.testing.expect(std.mem.order(u8, &prev_bytes, &b) == .lt);
            try std.testing.expect(std.mem.order(u8, &prev_str, &id) == .lt);
        }
        prev_bytes = b;
        prev_str = id;
    }

    // Clock unset refusal (`now() < 0`)
    st.now = -4;
    try std.testing.expectError(error.Refuse, gen.new());
    try std.testing.expectEqualStrings("clock_unset", fsys.last_refuse.code());

    // Invalid UUIDv7 strings
    try std.testing.expect(!isUUIDv7(""));
    try std.testing.expect(!isUUIDv7("019639c2-7f00-4abc-9def-0123456789ab")); // v4
    try std.testing.expect(!isUUIDv7("019639c2-7f00-7abc-cdef-0123456789ab")); // bad variant
    try std.testing.expect(!isUUIDv7("019639C2-7f00-7abc-9def-0123456789ab")); // uppercase
    try std.testing.expect(!isUUIDv7("019639c2_7f00-7abc-9def-0123456789ab")); // missing hyphen
}
