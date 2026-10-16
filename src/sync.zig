const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

const fsys = @import("fsys.zig");
const FS = fsys.FS;
const uuid = @import("uuid.zig");
const store = @import("store.zig");
const json = @import("json.zig");
const ed25519 = @import("ed25519.zig");
const sign = @import("sign.zig");
const merge = @import("merge.zig");

pub const ProtoVersion = "FLINT-SYNC/1";

/// The protocol-visible spec revision this client implements. Must equal
/// the repo-root `SPECREV` file — `tools/tests/test_specrev.py` enforces
/// the match. Bump rules and the downstream-pinning convention live in
/// `docs/spec-versioning.md`.
pub const SpecRev: u32 = 1;

pub const AuthDomain = "FLINT-SYNC-AUTH/1\x00";
pub const DefaultReadLimit: usize = 256;
pub const MaxBatchChanges: usize = 256;
pub const MaxWireLineBytes: usize = 4 * 1024 * 1024;
pub const MaxStreams: usize = 256;
pub const MaxWorkspaces: usize = 256;
/// Receive bound for one raw Change line. The documented per-line bound is
/// 4 MiB (#60): a producer-valid Change can exceed 1 MiB, so clamping below
/// `MaxWireLineBytes` rejects streams real flintd accepts.
pub const MaxChangeBytes: usize = MaxWireLineBytes;

/// Detail attached to `stale_head` refusals so a divergent push still points
/// at the recovery journey instead of failing bare.
pub const stale_head_recovery_hint =
    "remote head advanced; pull to catch up (diverged: fork <stream> <aside>, pull --reset, merge <aside>, push)";

/// Default per-reply deadline for remote verbs (#51): a peer that connects and
/// then goes silent must not block `clone`/`pull`/`push` forever.
pub const default_read_timeout_ms: u64 = 30_000;

/// Options `defaultTcpDial` reads from its `dial_ctx`; other injected dialers
/// ignore `dial_ctx` handling and are unaffected.
pub const TcpDialOptions = struct {
    read_timeout_ms: u64 = default_read_timeout_ms,
};

/// Refuses `store_too_large file` when `extra` appended bytes would push the
/// stream log at `log_path` past `MaxFileReadBytes` — the bound `verify` and
/// every log reader enforce, so an oversized pull/clone would brick the local
/// store (#59).
fn checkLogAppendBound(allocator: Allocator, fs: FS, log_path: []const u8, extra: usize) !void {
    var existing: usize = 0;
    if (fs.exists(allocator, log_path)) {
        const b = try fs.readFile(allocator, log_path, store.MaxFileReadBytes);
        defer allocator.free(b);
        existing = b.len;
    }
    if (existing + extra > store.MaxFileReadBytes) {
        return fsys.refuse("store_too_large", "file");
    }
}

fn readStreamRawLines(allocator: Allocator, fs: FS, root: []const u8, stream_id: []const u8) ![][]u8 {
    const p = try store.streamLogPath(allocator, root, stream_id);
    defer allocator.free(p);
    if (!fs.exists(allocator, p)) {
        return try allocator.alloc([]u8, 0);
    }
    const b = try fs.readFile(allocator, p, store.MaxFileReadBytes);
    defer allocator.free(b);

    const lines = try store.readJSONLLines(allocator, b);
    defer allocator.free(lines);

    if (lines.len > store.MaxChanges) {
        return fsys.refuse("store_too_large", "changes");
    }

    var out: std.ArrayList([]u8) = .empty;
    errdefer {
        for (out.items) |l| allocator.free(l);
        out.deinit(allocator);
    }
    for (lines) |l| {
        const duped = try allocator.dupe(u8, l);
        errdefer allocator.free(duped);
        try out.append(allocator, duped);
    }
    return out.toOwnedSlice(allocator);
}

fn freeRawLines(allocator: Allocator, lines: [][]u8) void {
    for (lines) |l| allocator.free(l);
    allocator.free(lines);
}

fn forkOriginEql(a: ?store.ForkOrigin, b: ?store.ForkOrigin) bool {
    if (a == null and b == null) return true;
    if (a == null or b == null) return false;
    return std.mem.eql(u8, a.?.stream, b.?.stream) and std.mem.eql(u8, a.?.change, b.?.change);
}

fn isLowerHex(s: []const u8, exact_len: usize) bool {
    if (s.len != exact_len) return false;
    for (s) |b| {
        switch (b) {
            '0'...'9', 'a'...'f' => {},
            else => return false,
        }
    }
    return true;
}

/// Abstract line-oriented request/response transport for `FLINT-SYNC/1`.
pub const Transport = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        requestLine: *const fn (ptr: *anyopaque, allocator: Allocator, req_line: []const u8) anyerror![]u8,
        close: *const fn (ptr: *anyopaque, allocator: Allocator) void,
    };

    pub fn requestLine(self: Transport, allocator: Allocator, req_line: []const u8) ![]u8 {
        return self.vtable.requestLine(self.ptr, allocator, req_line);
    }

    pub fn close(self: Transport, allocator: Allocator) void {
        self.vtable.close(self.ptr, allocator);
    }
};

pub const DialFn = *const fn (
    dial_ctx: ?*anyopaque,
    allocator: Allocator,
    io: Io,
    remote_url: []const u8,
) anyerror!Transport;

/// Parses `tcp://<host>:<port>` into host and port.
pub fn parseTcpRemoteUrl(remote_url: []const u8) !struct { host: []const u8, port: u16 } {
    const prefix = "tcp://";
    if (!std.mem.startsWith(u8, remote_url, prefix)) {
        return fsys.refuse("remote_malformed", "");
    }
    const rest = remote_url[prefix.len..];
    if (rest.len == 0) return fsys.refuse("remote_malformed", "");

    if (rest[0] == '[') {
        const bracket_end = std.mem.indexOfScalar(u8, rest, ']') orelse return fsys.refuse("remote_malformed", "");
        if (bracket_end <= 1 or bracket_end + 2 > rest.len or rest[bracket_end + 1] != ':') {
            return fsys.refuse("remote_malformed", "");
        }
        const host = rest[1..bracket_end];
        const port_str = rest[bracket_end + 2 ..];
        const port = std.fmt.parseInt(u16, port_str, 10) catch return fsys.refuse("remote_malformed", "");
        if (port == 0) return fsys.refuse("remote_malformed", "");
        return .{ .host = host, .port = port };
    }

    const colon = std.mem.lastIndexOfScalar(u8, rest, ':') orelse return fsys.refuse("remote_malformed", "");
    if (colon == 0 or colon + 1 >= rest.len) return fsys.refuse("remote_malformed", "");
    const host = rest[0..colon];
    if (std.mem.indexOfScalar(u8, host, '/') != null) return fsys.refuse("remote_malformed", "");
    const port_str = rest[colon + 1 ..];
    const port = std.fmt.parseInt(u16, port_str, 10) catch return fsys.refuse("remote_malformed", "");
    if (port == 0) return fsys.refuse("remote_malformed", "");
    return .{ .host = host, .port = port };
}

const TcpTransport = struct {
    io: Io,
    stream: Io.net.Stream,
    read_buf: [8192]u8 = undefined,
    write_buf: [8192]u8 = undefined,
    writer: Io.net.Stream.Writer = undefined,
    buf_len: usize = 0,
    buf_pos: usize = 0,
    read_timeout_ms: u64 = default_read_timeout_ms,

    fn init(allocator: Allocator, io: Io, stream: Io.net.Stream) !*TcpTransport {
        const self = try allocator.create(TcpTransport);
        self.* = .{
            .io = io,
            .stream = stream,
        };
        self.writer = self.stream.writer(io, &self.write_buf);
        return self;
    }

    /// One socket fill under `io.operateTimeout` so a silent peer surfaces as
    /// `error.Timeout` instead of blocking the verb forever.
    fn fillReadBuf(self: *TcpTransport, timeout: Io.Timeout) !usize {
        var bufs = [_][]u8{self.read_buf[0..]};
        const res = try (try self.io.operateTimeout(.{ .net_read = .{
            .socket_handle = self.stream.socket.handle,
            .data = &bufs,
        } }, timeout)).net_read;
        self.buf_len = res.data_len;
        self.buf_pos = 0;
        return res.data_len;
    }

    fn nextByte(self: *TcpTransport, timeout: Io.Timeout) !?u8 {
        if (self.buf_pos >= self.buf_len) {
            if (try self.fillReadBuf(timeout) == 0) return null;
        }
        const b = self.read_buf[self.buf_pos];
        self.buf_pos += 1;
        return b;
    }

    fn transport(self: *TcpTransport) Transport {
        return .{
            .ptr = self,
            .vtable = &.{
                .requestLine = requestLineImpl,
                .close = closeImpl,
            },
        };
    }

    fn requestLineImpl(ptr: *anyopaque, allocator: Allocator, req_line: []const u8) anyerror![]u8 {
        const self: *TcpTransport = @ptrCast(@alignCast(ptr));
        const w = &self.writer.interface;
        try w.writeAll(req_line);
        if (req_line.len == 0 or req_line[req_line.len - 1] != '\n') {
            try w.writeByte('\n');
        }
        try w.flush();

        // Absolute deadline over the whole reply line — a drip-feeding peer
        // cannot reset it per byte.
        var timeout: Io.Timeout = .none;
        if (self.read_timeout_ms != 0) {
            const dl = std.Io.Clock.now(.awake, self.io)
                .addDuration(std.Io.Duration.fromMilliseconds(@intCast(self.read_timeout_ms)));
            timeout = .{ .deadline = dl.withClock(.awake) };
        }

        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);

        while (true) {
            const b = try self.nextByte(timeout) orelse break;
            if (b == '\n') break;
            if (out.items.len >= MaxWireLineBytes) return fsys.refuse("change_too_large", "");
            try out.append(allocator, b);
        }

        if (out.items.len == 0) return error.EndOfStream;
        if (out.items[out.items.len - 1] == '\r') {
            _ = out.pop();
        }
        return out.toOwnedSlice(allocator);
    }

    fn closeImpl(ptr: *anyopaque, allocator: Allocator) void {
        const self: *TcpTransport = @ptrCast(@alignCast(ptr));
        self.stream.close(self.io);
        allocator.destroy(self);
    }
};

pub fn defaultTcpDial(
    dial_ctx: ?*anyopaque,
    allocator: Allocator,
    io: Io,
    remote_url: []const u8,
) anyerror!Transport {
    const opts: TcpDialOptions = if (dial_ctx) |ctx|
        @as(*const TcpDialOptions, @ptrCast(@alignCast(ctx))).*
    else
        .{};
    const parsed = try parseTcpRemoteUrl(remote_url);
    const stream = blk: {
        if (Io.net.IpAddress.parse(parsed.host, parsed.port)) |ip_addr| {
            break :blk try ip_addr.connect(io, .{ .mode = .stream, .protocol = .tcp });
        } else |_| {
            if (std.ascii.eqlIgnoreCase(parsed.host, "localhost")) {
                const lo = Io.net.IpAddress{ .ip4 = Io.net.Ip4Address.loopback(parsed.port) };
                break :blk try lo.connect(io, .{ .mode = .stream, .protocol = .tcp });
            }
            const hn = Io.net.HostName.init(parsed.host) catch return fsys.refuse("remote_malformed", "");
            break :blk try hn.connect(io, parsed.port, .{ .mode = .stream, .protocol = .tcp });
        }
    };
    errdefer stream.close(io);
    const tcp = try TcpTransport.init(allocator, io, stream);
    tcp.read_timeout_ms = opts.read_timeout_ms;
    return tcp.transport();
}

/// Parses `--read-timeout=<sec>`; 0 disables protection so it refuses `usage`
/// (mirroring `flintd --read-timeout=0`).
fn parseReadTimeoutSeconds(value: []const u8) !u64 {
    const secs = std.fmt.parseInt(u64, value, 10) catch return fsys.refuse("usage", "");
    if (secs == 0 or secs > 86400) return fsys.refuse("usage", "");
    return secs * 1000;
}

/// Dials the remote; when the dialer is `defaultTcpDial` the `TcpDialOptions`
/// carry the `--read-timeout` deadline through `dial_ctx`. Injected dialers
/// keep their own ctx and see no change.
fn dialRemote(
    dial_fn: DialFn,
    dial_ctx: ?*anyopaque,
    read_timeout_ms: u64,
    allocator: Allocator,
    io: Io,
    remote_url: []const u8,
) anyerror!Transport {
    var opts = TcpDialOptions{
        .read_timeout_ms = if (read_timeout_ms != 0) read_timeout_ms else default_read_timeout_ms,
    };
    const ctx: ?*anyopaque = if (dial_fn == defaultTcpDial) @ptrCast(&opts) else dial_ctx;
    return dial_fn(ctx, allocator, io, remote_url);
}

/// Computes `HMAC-SHA256(key, "FLINT-SYNC-AUTH/1\x00" || nonce_bytes)` as 64 lowercase hex chars.
pub fn computeAuthHmac(key_bytes: *const [32]u8, nonce_hex: []const u8) ![64]u8 {
    if (!isLowerHex(nonce_hex, 32)) return fsys.refuse("auth_failed", "");
    var nonce_bytes: [16]u8 = undefined;
    _ = std.fmt.hexToBytes(&nonce_bytes, nonce_hex) catch return fsys.refuse("auth_failed", "");
    defer @memset(&nonce_bytes, 0);

    var msg: [AuthDomain.len + 16]u8 = undefined;
    @memcpy(msg[0..AuthDomain.len], AuthDomain);
    @memcpy(msg[AuthDomain.len..], &nonce_bytes);
    defer @memset(&msg, 0);

    var mac: [32]u8 = undefined;
    HmacSha256.create(&mac, &msg, key_bytes);
    defer @memset(&mac, 0);

    return std.fmt.bytesToHex(mac, .lower);
}

/// Loads a 32-byte shared auth secret from `--auth-key=<file>` or `FLINT_AUTH_KEY`.
pub fn loadAuthKey(
    allocator: Allocator,
    fs: FS,
    auth_key_flag: []const u8,
    env_auth_key: ?[]const u8,
) !?[32]u8 {
    const spec = if (auth_key_flag.len > 0)
        auth_key_flag
    else if (env_auth_key) |e|
        e
    else
        return null;
    if (spec.len == 0) return null;

    if (fs.exists(allocator, spec)) {
        const raw = fs.readFile(allocator, spec, 256) catch return fsys.refuse("secret_not_found", "");
        defer {
            @memset(raw, 0);
            allocator.free(raw);
        }
        const trimmed = if (raw.len > 0 and raw[raw.len - 1] == '\n') raw[0 .. raw.len - 1] else raw;
        if (!isLowerHex(trimmed, 64)) return fsys.refuse("secret_malformed", "");
        var key: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&key, trimmed) catch return fsys.refuse("secret_malformed", "");
        return key;
    }

    if (isLowerHex(spec, 64)) {
        var key: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&key, spec) catch return fsys.refuse("secret_malformed", "");
        return key;
    }

    return fsys.refuse("secret_not_found", "");
}

/// Resolves the remote URL in precedence order:
/// 1. `--remote` flag (or positional `<remote>` on `clone`)
/// 2. `FLINT_REMOTE` environment variable
/// 3. `ws/<ws_name>/REMOTE.json` (when `ws_name` is non-null and `REMOTE.json` exists)
/// 4. Refuse `remote_missing`
pub fn resolveRemoteUrl(
    allocator: Allocator,
    fs: FS,
    root: []const u8,
    remote_flag: []const u8,
    env_remote: ?[]const u8,
    ws_name: ?[]const u8,
) ![]u8 {
    if (remote_flag.len > 0) {
        _ = try parseTcpRemoteUrl(remote_flag);
        return allocator.dupe(u8, remote_flag);
    }
    if (env_remote) |e| {
        if (e.len > 0) {
            _ = try parseTcpRemoteUrl(e);
            return allocator.dupe(u8, e);
        }
    }
    if (ws_name) |wn| {
        if (try store.loadWorkspaceRemote(allocator, fs, root, wn)) |rc| {
            defer rc.deinit(allocator);
            _ = try parseTcpRemoteUrl(rc.remote);
            return allocator.dupe(u8, rc.remote);
        }
    }
    return fsys.refuse("remote_missing", "");
}

pub const ReadPage = struct {
    head: ?[]u8,
    changes: [][]u8,
    more: bool,

    pub fn deinit(self: *ReadPage, allocator: Allocator) void {
        if (self.head) |h| allocator.free(h);
        for (self.changes) |c| allocator.free(c);
        allocator.free(self.changes);
    }
};

pub const SyncClient = struct {
    allocator: Allocator,
    transport: Transport,
    seq: u64 = 0,
    in_list_hint: bool = false,
    /// Spec revision announced by the server in its `hello` reply
    /// (`spec_rev` field), when present. Absent on older servers; see
    /// `docs/spec-versioning.md`.
    server_spec_rev: ?u32 = null,

    pub fn init(allocator: Allocator, transport: Transport) SyncClient {
        return .{
            .allocator = allocator,
            .transport = transport,
            .seq = 0,
        };
    }

    pub fn deinit(self: *SyncClient) void {
        self.transport.close(self.allocator);
    }

    fn nextSeq(self: *SyncClient) u64 {
        self.seq += 1;
        return self.seq;
    }

    fn sendAndParse(self: *SyncClient, req_line: []const u8) !std.json.Parsed(std.json.Value) {
        const resp_line = try self.transport.requestLine(self.allocator, req_line);
        defer self.allocator.free(resp_line);
        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, resp_line, .{
            .allocate = .alloc_always,
        }) catch return fsys.refuse("change_malformed", "");
        return parsed;
    }

    fn checkResponseOk(self: *SyncClient, parsed: std.json.Value, expected_seq: u64) !std.json.ObjectMap {
        const obj = switch (parsed) {
            .object => |o| o,
            else => return fsys.refuse("change_malformed", ""),
        };
        const seq_val = obj.get("seq") orelse return fsys.refuse("change_malformed", "");
        const got_seq: u64 = switch (seq_val) {
            .integer => |i| if (i >= 0) @intCast(i) else return fsys.refuse("change_malformed", ""),
            else => return fsys.refuse("change_malformed", ""),
        };
        if (got_seq != expected_seq) return fsys.refuse("change_malformed", "");

        const ok_val = obj.get("ok") orelse return fsys.refuse("change_malformed", "");
        const is_ok = switch (ok_val) {
            .bool => |b| b,
            else => return fsys.refuse("change_malformed", ""),
        };
        if (!is_ok) {
            const refuse_name = if (obj.get("refuse")) |rv| switch (rv) {
                .string => |s| s,
                else => "wire_error",
            } else "wire_error";
            if (!self.in_list_hint) {
                if (std.mem.eql(u8, refuse_name, "stream_missing") or
                    std.mem.eql(u8, refuse_name, "stream_exists"))
                {
                    const detail: []const u8 = if (obj.get("detail")) |dv| switch (dv) {
                        .string => |s| s,
                        else => "",
                    } else "";
                    return self.refuseWithRemoteStreams(refuse_name, detail);
                }
                if (std.mem.eql(u8, refuse_name, "stale_head")) {
                    return fsys.refuse(refuse_name, stale_head_recovery_hint);
                }
            }
            return fsys.refuse(refuse_name, "");
        }
        return obj;
    }

    /// Re-refuses `stream_missing`/`stream_exists` naming the streams the
    /// remote actually has (via `list`), so a bare refusal still tells the
    /// user what to clone/pull or which name collided. Falls back to the
    /// unadorned detail when `list` fails or the buffer fills.
    fn refuseWithRemoteStreams(self: *SyncClient, code: []const u8, detail: []const u8) error{Refuse} {
        self.in_list_hint = true;
        defer self.in_list_hint = false;
        const streams = self.list() catch return fsys.refuse(code, detail);
        defer {
            for (streams) |s| s.deinit(self.allocator);
            self.allocator.free(streams);
        }

        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(self.allocator);
        buf.appendSlice(self.allocator, detail) catch return fsys.refuse(code, detail);
        if (detail.len > 0) buf.appendSlice(self.allocator, " ") catch {};
        buf.appendSlice(self.allocator, "(available streams:") catch return fsys.refuse(code, detail);
        for (streams) |s| {
            buf.append(self.allocator, ' ') catch break;
            buf.appendSlice(self.allocator, s.name) catch break;
        }
        buf.append(self.allocator, ')') catch {};
        return fsys.refuse(code, buf.items);
    }

    pub fn list(self: *SyncClient) ![]store.Stream {
        const seq = self.nextSeq();
        var req: std.ArrayList(u8) = .empty;
        defer req.deinit(self.allocator);
        try req.print(self.allocator, "{{\"op\":\"list\",\"seq\":{d}}}", .{seq});

        var parsed = try self.sendAndParse(req.items);
        defer parsed.deinit();
        const obj = try self.checkResponseOk(parsed.value, seq);

        const streams_val = obj.get("streams") orelse return fsys.refuse("change_malformed", "");
        const streams_arr = switch (streams_val) {
            .array => |a| a,
            else => return fsys.refuse("change_malformed", ""),
        };

        var out: std.ArrayList(store.Stream) = .empty;
        errdefer {
            for (out.items) |s| s.deinit(self.allocator);
            out.deinit(self.allocator);
        }
        for (streams_arr.items) |item| {
            try out.append(self.allocator, try parseStreamValue(self.allocator, item));
        }
        return out.toOwnedSlice(self.allocator);
    }

    /// Records the server's announced `spec_rev` from a successful `hello`
    /// reply, when present. Older servers omit the field; a non-integer or
    /// out-of-range value is tolerated as unannounced rather than refused.
    fn captureSpecRev(self: *SyncClient, obj: std.json.ObjectMap) void {
        const rv = obj.get("spec_rev") orelse return;
        switch (rv) {
            .integer => |i| if (i >= 0 and i <= std.math.maxInt(u32)) {
                self.server_spec_rev = @intCast(i);
            },
            else => {},
        }
    }

    pub fn handshake(self: *SyncClient, auth_key: ?[32]u8) !void {
        const seq1 = self.nextSeq();
        var req_buf: std.ArrayList(u8) = .empty;
        defer req_buf.deinit(self.allocator);
        try req_buf.print(self.allocator, "{{\"op\":\"hello\",\"seq\":{d},\"proto\":\"{s}\"}}", .{ seq1, ProtoVersion });

        var parsed = try self.sendAndParse(req_buf.items);
        defer parsed.deinit();

        const obj = switch (parsed.value) {
            .object => |o| o,
            else => return fsys.refuse("change_malformed", ""),
        };
        const ok_val = obj.get("ok") orelse return fsys.refuse("change_malformed", "");
        const is_ok = switch (ok_val) {
            .bool => |b| b,
            else => return fsys.refuse("change_malformed", ""),
        };

        if (!is_ok) {
            const refuse_name = if (obj.get("refuse")) |rv| switch (rv) {
                .string => |s| s,
                else => "wire_error",
            } else "wire_error";

            if (std.mem.eql(u8, refuse_name, "auth_required")) {
                const nonce_opt: ?[]const u8 = if (obj.get("nonce")) |nv| switch (nv) {
                    .string => |s| if (isLowerHex(s, 32)) s else null,
                    else => null,
                } else if (obj.get("detail")) |dv| switch (dv) {
                    .string => |s| if (isLowerHex(s, 32)) s else null,
                    else => null,
                } else null;

                if (nonce_opt) |nonce| {
                    if (auth_key) |key| {
                        try self.sendAuth(&key, nonce);
                        const seq3 = self.nextSeq();
                        var hello2: std.ArrayList(u8) = .empty;
                        defer hello2.deinit(self.allocator);
                        try hello2.print(self.allocator, "{{\"op\":\"hello\",\"seq\":{d},\"proto\":\"{s}\"}}", .{ seq3, ProtoVersion });
                        var parsed2 = try self.sendAndParse(hello2.items);
                        defer parsed2.deinit();
                        const obj2 = try self.checkResponseOk(parsed2.value, seq3);
                        const pval = obj2.get("proto") orelse return fsys.refuse("proto_version", "");
                        if (pval != .string or !std.mem.eql(u8, pval.string, ProtoVersion)) {
                            return fsys.refuse("proto_version", "");
                        }
                        self.captureSpecRev(obj2);
                        return;
                    }
                }
            }
            return fsys.refuse(refuse_name, "");
        }

        _ = try self.checkResponseOk(parsed.value, seq1);
        const proto_val = obj.get("proto") orelse return fsys.refuse("proto_version", "");
        const proto_str = switch (proto_val) {
            .string => |s| s,
            else => return fsys.refuse("proto_version", ""),
        };
        if (!std.mem.eql(u8, proto_str, ProtoVersion)) {
            return fsys.refuse("proto_version", "");
        }
        self.captureSpecRev(obj);

        if (obj.get("nonce")) |nv| {
            if (nv == .string and nv.string.len > 0) {
                const key = auth_key orelse return fsys.refuse("auth_required", "");
                try self.sendAuth(&key, nv.string);
            }
        }
    }

    pub fn sendAuth(self: *SyncClient, key: *const [32]u8, nonce: []const u8) !void {
        const hmac_hex = try computeAuthHmac(key, nonce);
        const seq = self.nextSeq();
        var req: std.ArrayList(u8) = .empty;
        defer req.deinit(self.allocator);
        try req.appendSlice(self.allocator, "{\"op\":\"auth\",\"seq\":");
        try req.print(self.allocator, "{d},\"nonce\":", .{seq});
        try json.appendGoJSONString(&req, self.allocator, nonce);
        try req.appendSlice(self.allocator, ",\"hmac\":");
        try json.appendGoJSONString(&req, self.allocator, &hmac_hex);
        try req.append(self.allocator, '}');

        var parsed = try self.sendAndParse(req.items);
        defer parsed.deinit();
        _ = try self.checkResponseOk(parsed.value, seq);
    }

    pub fn heads(self: *SyncClient) !std.StringHashMap(?[]u8) {
        const seq = self.nextSeq();
        var req: std.ArrayList(u8) = .empty;
        defer req.deinit(self.allocator);
        try req.print(self.allocator, "{{\"op\":\"heads\",\"seq\":{d}}}", .{seq});

        var parsed = try self.sendAndParse(req.items);
        defer parsed.deinit();
        const obj = try self.checkResponseOk(parsed.value, seq);

        const heads_val = obj.get("heads") orelse return fsys.refuse("change_malformed", "");
        const heads_obj = switch (heads_val) {
            .object => |o| o,
            else => return fsys.refuse("change_malformed", ""),
        };

        var out = std.StringHashMap(?[]u8).init(self.allocator);
        errdefer {
            var it = out.iterator();
            while (it.next()) |kv| {
                self.allocator.free(kv.key_ptr.*);
                if (kv.value_ptr.*) |v| self.allocator.free(v);
            }
            out.deinit();
        }

        var it = heads_obj.iterator();
        while (it.next()) |kv| {
            const k_copy = try self.allocator.dupe(u8, kv.key_ptr.*);
            errdefer self.allocator.free(k_copy);
            const v_copy: ?[]u8 = switch (kv.value_ptr.*) {
                .null => null,
                .string => |s| try self.allocator.dupe(u8, s),
                else => return fsys.refuse("change_malformed", ""),
            };
            errdefer if (v_copy) |v| self.allocator.free(v);
            try out.put(k_copy, v_copy);
        }
        return out;
    }

    pub fn open(self: *SyncClient, stream_id_or_name: []const u8) !store.Stream {
        const seq = self.nextSeq();
        var req: std.ArrayList(u8) = .empty;
        defer req.deinit(self.allocator);
        try req.print(self.allocator, "{{\"op\":\"open\",\"seq\":{d},\"stream\":", .{seq});
        try json.appendGoJSONString(&req, self.allocator, stream_id_or_name);
        try req.append(self.allocator, '}');

        var parsed = try self.sendAndParse(req.items);
        defer parsed.deinit();
        const obj = try self.checkResponseOk(parsed.value, seq);

        const rec_val = obj.get("record") orelse return fsys.refuse("stream_malformed", "");
        return parseStreamValue(self.allocator, rec_val);
    }

    pub fn read(
        self: *SyncClient,
        stream_id_or_name: []const u8,
        after: ?[]const u8,
        limit: usize,
    ) !ReadPage {
        const seq = self.nextSeq();
        var req: std.ArrayList(u8) = .empty;
        defer req.deinit(self.allocator);
        try req.print(self.allocator, "{{\"op\":\"read\",\"seq\":{d},\"stream\":", .{seq});
        try json.appendGoJSONString(&req, self.allocator, stream_id_or_name);
        if (after) |a| {
            try req.appendSlice(self.allocator, ",\"after\":");
            try json.appendGoJSONString(&req, self.allocator, a);
        }
        try req.print(self.allocator, ",\"limit\":{d}}}", .{limit});

        var parsed = try self.sendAndParse(req.items);
        defer parsed.deinit();
        const obj = try self.checkResponseOk(parsed.value, seq);

        const head: ?[]u8 = if (obj.get("head")) |hv| switch (hv) {
            .null => null,
            .string => |s| try self.allocator.dupe(u8, s),
            else => return fsys.refuse("change_malformed", ""),
        } else null;
        errdefer if (head) |h| self.allocator.free(h);

        const changes_val = obj.get("changes") orelse return fsys.refuse("change_malformed", "");
        const changes_arr = switch (changes_val) {
            .array => |a| a,
            else => return fsys.refuse("change_malformed", ""),
        };

        var lines: std.ArrayList([]u8) = .empty;
        errdefer {
            for (lines.items) |l| self.allocator.free(l);
            lines.deinit(self.allocator);
        }
        for (changes_arr.items) |item| {
            const s = switch (item) {
                .string => |str| str,
                else => return fsys.refuse("change_malformed", ""),
            };
            const clean = std.mem.trimEnd(u8, s, "\r\n");
            const copy = try self.allocator.dupe(u8, clean);
            errdefer self.allocator.free(copy);
            try lines.append(self.allocator, copy);
        }

        const more: bool = if (obj.get("more")) |mv| switch (mv) {
            .bool => |b| b,
            else => false,
        } else false;

        return .{
            .head = head,
            .changes = try lines.toOwnedSlice(self.allocator),
            .more = more,
        };
    }

    pub fn create(self: *SyncClient, record: store.Stream) !void {
        const seq = self.nextSeq();
        const rec_line = try json.marshalStreamLine(self.allocator, record);
        defer self.allocator.free(rec_line);
        const rec_json = std.mem.trimEnd(u8, rec_line, "\n");

        var req: std.ArrayList(u8) = .empty;
        defer req.deinit(self.allocator);
        try req.print(self.allocator, "{{\"op\":\"create\",\"seq\":{d},\"record\":{s}}}", .{ seq, rec_json });

        var parsed = try self.sendAndParse(req.items);
        defer parsed.deinit();
        _ = try self.checkResponseOk(parsed.value, seq);
    }

    pub fn append(
        self: *SyncClient,
        stream_id: []const u8,
        expected_head: ?[]const u8,
        raw_changes: []const []const u8,
    ) ![]u8 {
        const seq = self.nextSeq();
        var req: std.ArrayList(u8) = .empty;
        defer req.deinit(self.allocator);
        try req.print(self.allocator, "{{\"op\":\"append\",\"seq\":{d},\"stream\":", .{seq});
        try json.appendGoJSONString(&req, self.allocator, stream_id);
        try req.appendSlice(self.allocator, ",\"expected_head\":");
        if (expected_head) |eh| {
            try json.appendGoJSONString(&req, self.allocator, eh);
        } else {
            try req.appendSlice(self.allocator, "null");
        }
        try req.appendSlice(self.allocator, ",\"changes\":[");
        for (raw_changes, 0..) |line, i| {
            if (i > 0) try req.append(self.allocator, ',');
            const clean = std.mem.trimEnd(u8, line, "\r\n");
            try json.appendGoJSONString(&req, self.allocator, clean);
        }
        try req.appendSlice(self.allocator, "]}");

        var parsed = try self.sendAndParse(req.items);
        defer parsed.deinit();
        const obj = try self.checkResponseOk(parsed.value, seq);

        const head_val = obj.get("head") orelse return fsys.refuse("change_malformed", "");
        return switch (head_val) {
            .string => |s| self.allocator.dupe(u8, s),
            else => fsys.refuse("change_malformed", ""),
        };
    }
};

fn parseStreamValue(allocator: Allocator, val: std.json.Value) !store.Stream {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try writeJsonValue(&out, allocator, val);
    var st = try json.parseStream(allocator, out.items);
    errdefer st.deinit(allocator);
    // Remote-supplied names land in the local record and get echoed to the
    // terminal; refuse anything outside the `[a-z0-9-]{1,32}` contract (#52).
    if (!ed25519.isValidName(st.name)) {
        return fsys.refuse("stream_malformed", "invalid stream name");
    }
    return st;
}

fn writeJsonValue(out: *std.ArrayList(u8), allocator: Allocator, val: std.json.Value) !void {
    switch (val) {
        .null => try out.appendSlice(allocator, "null"),
        .bool => |b| try out.appendSlice(allocator, if (b) "true" else "false"),
        .integer => |i| try out.print(allocator, "{d}", .{i}),
        .float => |f| try out.print(allocator, "{d}", .{f}),
        .number_string => |s| try out.appendSlice(allocator, s),
        .string => |s| try json.appendGoJSONString(out, allocator, s),
        .array => |arr| {
            try out.append(allocator, '[');
            for (arr.items, 0..) |item, idx| {
                if (idx > 0) try out.append(allocator, ',');
                try writeJsonValue(out, allocator, item);
            }
            try out.append(allocator, ']');
        },
        .object => |obj| {
            try out.append(allocator, '{');
            var it = obj.iterator();
            var idx: usize = 0;
            while (it.next()) |kv| : (idx += 1) {
                if (idx > 0) try out.append(allocator, ',');
                try json.appendGoJSONString(out, allocator, kv.key_ptr.*);
                try out.append(allocator, ':');
                try writeJsonValue(out, allocator, kv.value_ptr.*);
            }
            try out.append(allocator, '}');
        },
    }
}

fn freeHeadsMap(allocator: Allocator, map: *std.StringHashMap(?[]u8)) void {
    var it = map.iterator();
    while (it.next()) |kv| {
        allocator.free(kv.key_ptr.*);
        if (kv.value_ptr.*) |v| allocator.free(v);
    }
    map.deinit();
}

/// Fetches all raw Change lines for `st` from `client` and verifies every Change
/// (`parseChange`, `stream == st.id`, `validateCommitMessage`, parent chain, `verifyChange`).
fn fetchAndVerifyStreamChanges(
    allocator: Allocator,
    client: *SyncClient,
    st: store.Stream,
    after: ?[]const u8,
    expected_first_parent: ?[]const u8,
) ![][]u8 {
    var all_lines: std.ArrayList([]u8) = .empty;
    errdefer {
        for (all_lines.items) |l| allocator.free(l);
        all_lines.deinit(allocator);
    }

    var cursor: ?[]u8 = if (after) |a| try allocator.dupe(u8, a) else null;
    defer if (cursor) |c| allocator.free(c);

    while (true) {
        var page = try client.read(st.id, cursor, DefaultReadLimit);
        defer page.deinit(allocator);

        for (page.changes) |line| {
            const copy = try allocator.dupe(u8, line);
            errdefer allocator.free(copy);
            try all_lines.append(allocator, copy);
        }

        if (!page.more or page.changes.len == 0) break;

        var last_change = try json.parseChange(allocator, page.changes[page.changes.len - 1]);
        defer last_change.deinit(allocator);
        if (cursor) |c| allocator.free(c);
        cursor = try allocator.dupe(u8, last_change.id);
    }

    // Verify every Change before returning so the caller writes nothing on error.
    var prev_id: ?[]u8 = if (expected_first_parent) |p| try allocator.dupe(u8, p) else null;
    defer if (prev_id) |p| allocator.free(p);

    for (all_lines.items) |raw_line| {
        if (raw_line.len + 1 > MaxChangeBytes) {
            return fsys.refuse("change_too_large", "");
        }
        var c = try json.parseChange(allocator, raw_line);
        defer c.deinit(allocator);

        if (!std.mem.eql(u8, c.stream, st.id)) {
            return fsys.refuse("change_malformed", "stream mismatch");
        }
        try sign.validateCommitMessage(c.message);

        if (prev_id) |pid| {
            const cp = c.parent orelse return fsys.refuse("change_malformed", "parent mismatch");
            if (!std.mem.eql(u8, cp, pid)) {
                return fsys.refuse("change_malformed", "parent mismatch");
            }
        } else {
            if (c.parent != null) {
                return fsys.refuse("change_malformed", "non-null root parent");
            }
        }

        const ok = try ed25519.verifyChange(allocator, &c);
        if (!ok) {
            return fsys.refuse("sig_invalid", "");
        }

        if (prev_id) |p| allocator.free(p);
        prev_id = try allocator.dupe(u8, c.id);
    }

    return all_lines.toOwnedSlice(allocator);
}

/// Implements `flint clone <remote> --stream=<name|id> [--name=<ws>] --src=<dir> [--auth-key=<file>]`.
pub fn cmdClone(
    allocator: Allocator,
    io: Io,
    fs: FS,
    root: []const u8,
    env_remote: ?[]const u8,
    env_auth_key: ?[]const u8,
    dial_fn: DialFn,
    dial_ctx: ?*anyopaque,
    stdout: *Io.Writer,
    args: []const []const u8,
) !void {
    var remote_flag: []const u8 = "";
    var stream_flag: []const u8 = "";
    var name_flag: []const u8 = "default";
    var src_flag: []const u8 = "";
    var auth_key_flag: []const u8 = "";
    var read_timeout_ms: u64 = 0;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.startsWith(u8, a, "--remote=")) {
            remote_flag = a["--remote=".len..];
            if (remote_flag.len == 0) return fsys.refuse("usage", "");
        } else if (std.mem.eql(u8, a, "--remote")) {
            if (i + 1 >= args.len or args[i + 1].len == 0) return fsys.refuse("usage", "");
            i += 1;
            remote_flag = args[i];
        } else if (std.mem.startsWith(u8, a, "--stream=")) {
            stream_flag = a["--stream=".len..];
            if (stream_flag.len == 0) return fsys.refuse("usage", "");
        } else if (std.mem.eql(u8, a, "--stream")) {
            if (i + 1 >= args.len or args[i + 1].len == 0) return fsys.refuse("usage", "");
            i += 1;
            stream_flag = args[i];
        } else if (std.mem.startsWith(u8, a, "--name=")) {
            name_flag = a["--name=".len..];
            if (name_flag.len == 0) return fsys.refuse("usage", "");
        } else if (std.mem.eql(u8, a, "--name")) {
            if (i + 1 >= args.len or args[i + 1].len == 0) return fsys.refuse("usage", "");
            i += 1;
            name_flag = args[i];
        } else if (std.mem.startsWith(u8, a, "--src=")) {
            src_flag = a["--src=".len..];
            if (src_flag.len == 0) return fsys.refuse("usage", "");
        } else if (std.mem.eql(u8, a, "--src")) {
            if (i + 1 >= args.len or args[i + 1].len == 0) return fsys.refuse("usage", "");
            i += 1;
            src_flag = args[i];
        } else if (std.mem.startsWith(u8, a, "--auth-key=")) {
            auth_key_flag = a["--auth-key=".len..];
            if (auth_key_flag.len == 0) return fsys.refuse("usage", "");
        } else if (std.mem.eql(u8, a, "--auth-key")) {
            if (i + 1 >= args.len or args[i + 1].len == 0) return fsys.refuse("usage", "");
            i += 1;
            auth_key_flag = args[i];
        } else if (std.mem.startsWith(u8, a, "--read-timeout=")) {
            read_timeout_ms = try parseReadTimeoutSeconds(a["--read-timeout=".len..]);
        } else if (std.mem.eql(u8, a, "--read-timeout")) {
            if (i + 1 >= args.len or args[i + 1].len == 0) return fsys.refuse("usage", "");
            i += 1;
            read_timeout_ms = try parseReadTimeoutSeconds(args[i]);
        } else if (std.mem.startsWith(u8, a, "-")) {
            return fsys.refuse("usage", "");
        } else if (remote_flag.len == 0) {
            remote_flag = a;
        } else {
            return fsys.refuse("usage", "");
        }
    }

    if (stream_flag.len == 0 or src_flag.len == 0) {
        return fsys.refuse("usage", "");
    }
    if (!store.validWorkspaceName(name_flag)) {
        return fsys.refuse("ws_name_invalid", name_flag);
    }

    const abs_src = try fsys.cleanPath(allocator, src_flag);
    defer allocator.free(abs_src);
    if (!fs.exists(allocator, abs_src)) {
        // Unlike `init`, clone almost always targets a fresh directory —
        // create it rather than refusing `src_missing` (#32).
        fs.mkdir(allocator, abs_src) catch return fsys.refuse("src_missing", src_flag);
    }
    if (!fs.isDir(allocator, abs_src)) {
        return fsys.refuse("src_missing", src_flag);
    }

    const remote_url = try resolveRemoteUrl(allocator, fs, root, remote_flag, env_remote, null);
    defer allocator.free(remote_url);
    fsys.setErrContext("clone", remote_url);

    var auth_key = try loadAuthKey(allocator, fs, auth_key_flag, env_auth_key);
    defer if (auth_key) |*k| @memset(k, 0);

    var idx = try store.loadStoreIndex(allocator, fs, root);
    defer idx.deinit();

    if (idx.workspaceByName(name_flag) != null) {
        return fsys.refuse("ws_exists", name_flag);
    }
    if (idx.workspaces.items.len + 1 > MaxWorkspaces) {
        return fsys.refuse("store_too_large", "workspaces");
    }

    const transport = try dialRemote(dial_fn, dial_ctx, read_timeout_ms, allocator, io, remote_url);
    var client = SyncClient.init(allocator, transport);
    defer client.deinit();

    try client.handshake(auth_key);

    // Follow `forked_from` chain from target stream back to root ancestor.
    var chain: std.ArrayList(store.Stream) = .empty;
    defer {
        for (chain.items) |s| s.deinit(allocator);
        chain.deinit(allocator);
    }
    var seen = std.StringHashMap(void).init(allocator);
    defer seen.deinit();

    const target_stream = try client.open(stream_flag);
    try seen.put(target_stream.id, {});
    try chain.append(allocator, target_stream);

    while (chain.items[chain.items.len - 1].forked_from) |ff| {
        if (seen.contains(ff.stream)) {
            return fsys.refuse("stream_malformed", "fork cycle");
        }
        const parent_st = try client.open(ff.stream);
        errdefer parent_st.deinit(allocator);
        try seen.put(parent_st.id, {});
        try chain.append(allocator, parent_st);
    }

    // Reverse chain so index 0 is root ancestor and last is target stream.
    std.mem.reverse(store.Stream, chain.items);

    const StreamPayload = struct {
        record: store.Stream,
        raw_lines: [][]u8,
        /// When `existed` is true, the local log is a verified prefix of
        /// `raw_lines` and only `raw_lines[append_from..]` is appended.
        append_from: usize = 0,
        existed: bool = false,
    };
    var payloads: std.ArrayList(StreamPayload) = .empty;
    defer {
        for (payloads.items) |p| {
            for (p.raw_lines) |l| allocator.free(l);
            allocator.free(p.raw_lines);
        }
        payloads.deinit(allocator);
    }

    var total_new_changes: usize = 0;
    var new_streams_count: usize = 0;

    for (chain.items) |st| {
        const first_parent: ?[]const u8 = if (st.forked_from) |ff| ff.change else null;
        const lines = try fetchAndVerifyStreamChanges(allocator, &client, st, null, first_parent);
        errdefer {
            for (lines) |l| allocator.free(l);
            allocator.free(lines);
        }

        // Verify final head matches stream record head.
        if (lines.len > 0) {
            var last_c = try json.parseChange(allocator, lines[lines.len - 1]);
            defer last_c.deinit(allocator);
            const expected_h = st.head orelse return fsys.refuse("stream_malformed", "null head with changes");
            if (!std.mem.eql(u8, last_c.id, expected_h)) {
                return fsys.refuse("stream_malformed", "head mismatch");
            }
        } else {
            if (st.forked_from) |ff| {
                const expected_h = st.head orelse return fsys.refuse("stream_malformed", "fork null head");
                if (!std.mem.eql(u8, expected_h, ff.change)) {
                    return fsys.refuse("stream_malformed", "fork head mismatch");
                }
            } else if (st.head != null) {
                return fsys.refuse("stream_malformed", "non-null head on empty stream");
            }
        }

        // Spec §4: a local stream is never silently overwritten. Re-clone is
        // allowed only as a fast-forward: the existing local log must be a
        // verified prefix of the remote log, and the record must agree.
        if (idx.streamByID(st.id)) |local_rec| {
            if (!std.mem.eql(u8, local_rec.name, st.name) or
                !forkOriginEql(local_rec.forked_from, st.forked_from))
            {
                return fsys.refuse("stream_exists", local_rec.name);
            }
            const local_lines = try readStreamRawLines(allocator, fs, root, st.id);
            defer freeRawLines(allocator, local_lines);

            var is_prefix = local_lines.len <= lines.len;
            if (is_prefix) {
                for (local_lines, 0..) |ll, li| {
                    if (!std.mem.eql(u8, ll, lines[li])) {
                        is_prefix = false;
                        break;
                    }
                }
            }
            if (!is_prefix) {
                const local_changes = try store.readStreamChanges(allocator, fs, root, st.id);
                defer store.freeChanges(allocator, local_changes);
                var remote_in_local = false;
                if (st.head) |rh| {
                    if (local_rec.forked_from) |ff| {
                        if (std.mem.eql(u8, rh, ff.change)) remote_in_local = true;
                    }
                    for (local_changes) |c| {
                        if (std.mem.eql(u8, c.id, rh)) {
                            remote_in_local = true;
                            break;
                        }
                    }
                }
                if (remote_in_local) {
                    // Local is strictly ahead: re-clone would roll the head back.
                    return fsys.refuse("stream_exists", local_rec.name);
                }
                return fsys.refuse("fork_needed", "");
            }
            total_new_changes += lines.len - local_lines.len;
            try payloads.append(allocator, .{
                .record = st,
                .raw_lines = lines,
                .append_from = local_lines.len,
                .existed = true,
            });
        } else {
            if (idx.streamByName(st.name) != null) {
                return fsys.refuse("stream_exists", st.name);
            }
            new_streams_count += 1;
            total_new_changes += lines.len;
            try payloads.append(allocator, .{
                .record = st,
                .raw_lines = lines,
            });
        }
    }

    if (idx.streams.items.len + new_streams_count > MaxStreams) {
        return fsys.refuse("store_too_large", "streams");
    }
    if (idx.change_count + total_new_changes > store.MaxChanges) {
        return fsys.refuse("store_too_large", "changes");
    }

    const streams_dir = try store.streamsDir(allocator, root);
    defer allocator.free(streams_dir);
    const ws_dir = try store.workspaceDir(allocator, root, name_flag);
    defer allocator.free(ws_dir);
    const keys_dir = try store.keysDir(allocator, root);
    defer allocator.free(keys_dir);

    try fs.mkdir(allocator, streams_dir);
    try fs.mkdir(allocator, ws_dir);
    try fs.mkdir(allocator, keys_dir);

    for (payloads.items) |p| {
        const log_path = try store.streamLogPath(allocator, root, p.record.id);
        defer allocator.free(log_path);
        if (p.existed) {
            // Fast-forward re-clone: append only the missing suffix so the
            // local Change log stays append-only and never rewritten.
            if (p.raw_lines.len > p.append_from) {
                var log_buf: std.ArrayList(u8) = .empty;
                defer log_buf.deinit(allocator);
                for (p.raw_lines[p.append_from..]) |line| {
                    try log_buf.appendSlice(allocator, line);
                    try log_buf.append(allocator, '\n');
                }
                try checkLogAppendBound(allocator, fs, log_path, log_buf.items.len);
                try fs.appendSync(allocator, log_path, log_buf.items);
            }
        } else if (p.raw_lines.len > 0) {
            var log_buf: std.ArrayList(u8) = .empty;
            defer log_buf.deinit(allocator);
            for (p.raw_lines) |line| {
                try log_buf.appendSlice(allocator, line);
                try log_buf.append(allocator, '\n');
            }
            try checkLogAppendBound(allocator, fs, log_path, log_buf.items.len);
            try fs.writeFileSafe(allocator, log_path, log_buf.items);
        }
        try store.writeStreamRecord(allocator, fs, root, p.record);
    }

    const final_stream = chain.items[chain.items.len - 1];
    var clone_idx = try store.loadStoreIndex(allocator, fs, root);
    defer clone_idx.deinit();
    const all_changes = try store.loadAllStreamChanges(allocator, fs, root, &clone_idx);
    defer store.freeChanges(allocator, all_changes);

    const replay = try store.replayStreamAtoms(allocator, final_stream.head, all_changes);
    defer store.freeStoredAtoms(allocator, replay.atoms);

    try store.writeWorkspaceAtoms(allocator, fs, root, name_flag, replay.atoms);

    const ws_cfg = store.Workspace{
        .name = @constCast(name_flag),
        .src = abs_src,
        .stream = final_stream.id,
        .created = final_stream.created,
    };
    try store.writeWorkspaceConfig(allocator, fs, root, ws_cfg);

    const remote_cfg = store.RemoteConfig{
        .remote = remote_url,
        .stream = final_stream.id,
    };
    try store.writeWorkspaceRemote(allocator, fs, root, name_flag, remote_cfg);

    try stdout.print("flint: clone ok stream={s} changes={d}\n", .{ final_stream.name, replay.replayed });
}

fn resolveStreamAndWorkspace(
    allocator: Allocator,
    fs: FS,
    idx: *const store.StoreIndex,
    stream_flag: []const u8,
    ws_flag: []const u8,
) !struct { stream: store.Stream, ws_name: ?[]const u8 } {
    if (stream_flag.len > 0) {
        const st = idx.streamByName(stream_flag) orelse idx.streamByID(stream_flag) orelse {
            return fsys.refuse("stream_missing", stream_flag);
        };
        if (ws_flag.len > 0) {
            const ws = idx.workspaceByName(ws_flag) orelse return fsys.refuse("ws_missing", ws_flag);
            return .{ .stream = st.*, .ws_name = ws.name };
        }
        var matched_ws: ?[]const u8 = null;
        for (idx.workspaces.items) |ws| {
            if (std.mem.eql(u8, ws.stream, st.id)) {
                if (matched_ws == null) {
                    matched_ws = ws.name;
                } else {
                    matched_ws = null;
                    break;
                }
            }
        }
        return .{ .stream = st.*, .ws_name = matched_ws };
    }

    const ws = try store.resolveWorkspace(allocator, fs, idx, ws_flag, &.{});
    const st = idx.streamByID(ws.stream) orelse return fsys.refuse("stream_missing", ws.stream);
    return .{ .stream = st.*, .ws_name = ws.name };
}

/// Finds the earliest merge Change on `origin_stream_id`'s first-parent chain
/// whose `merged` edge names `missing_id` — the merge that folded an
/// unpublishable Change into publishable history (#65). Returns an owned copy
/// of the merge id, or null when no merge incorporated it.
fn findIncorporatingMerge(
    allocator: Allocator,
    fs: FS,
    root: []const u8,
    origin_stream_id: []const u8,
    missing_id: []const u8,
) !?[]u8 {
    var origin = try store.loadStream(allocator, fs, root, origin_stream_id);
    defer origin.deinit(allocator);

    var by_id = std.StringHashMap(store.Change).init(allocator);
    defer by_id.deinit();
    for (origin.changes) |c| try by_id.put(c.id, c);

    var found: ?[]const u8 = null;
    var cur: ?[]const u8 = origin.stream.head;
    while (cur) |cid| {
        const c = by_id.get(cid) orelse break;
        if (c.merged) |m| {
            if (std.mem.eql(u8, m, missing_id)) found = c.id;
        }
        cur = c.parent;
    }
    return if (found) |f| try allocator.dupe(u8, f) else null;
}

/// Re-anchors `st`'s `forked_from` and `head` to `new_origin_change`, a merge
/// Change on the same origin stream that incorporated the previous origin.
/// Rewrites `streams/<id>.json` and updates the in-memory record so the push
/// bookkeeping sees the re-anchored head (#65). Callers must only re-anchor a
/// bare fork pointer: a fork's own Changes chain onto the old origin and
/// cannot move without breaking their signatures.
fn reanchorForkRecord(
    allocator: Allocator,
    fs: FS,
    root: []const u8,
    st: *store.Stream,
    new_origin_change: []const u8,
) !void {
    const ff = st.forked_from orelse return;
    const new_head = try allocator.dupe(u8, new_origin_change);
    errdefer allocator.free(new_head);
    const new_ff = store.ForkOrigin{
        .stream = try allocator.dupe(u8, ff.stream),
        .change = try allocator.dupe(u8, new_origin_change),
    };
    errdefer new_ff.deinit(allocator);

    try store.writeStreamRecord(allocator, fs, root, .{
        .id = st.id,
        .name = st.name,
        .head = new_head,
        .created = st.created,
        .forked_from = new_ff,
    });

    if (st.head) |h| allocator.free(h);
    st.head = new_head;
    if (st.forked_from) |old| old.deinit(allocator);
    st.forked_from = new_ff;
}

fn pushSingleStream(
    allocator: Allocator,
    fs: FS,
    root: []const u8,
    client: *SyncClient,
    server_heads: *std.StringHashMap(?[]u8),
    st_id: []const u8,
) !struct { sent_changes: usize, was_created: bool } {
    var loaded = try store.loadStream(allocator, fs, root, st_id);
    defer loaded.deinit(allocator);

    const raw_lines = try readStreamRawLines(allocator, fs, root, st_id);
    defer freeRawLines(allocator, raw_lines);

    var was_created = false;
    var remote_head: ?[]const u8 = null;
    var remote_head_owned: ?[]u8 = null;
    defer if (remote_head_owned) |h| allocator.free(h);

    if (server_heads.get(st_id)) |rh_opt| {
        remote_head = rh_opt;
    } else {
        var init_head: ?[]const u8 = if (loaded.stream.forked_from) |ff| ff.change else null;
        var init_rec = store.Stream{
            .id = loaded.stream.id,
            .name = loaded.stream.name,
            .head = init_head,
            .forked_from = loaded.stream.forked_from,
            .created = loaded.stream.created,
        };
        client.create(init_rec) catch |cerr| {
            if (cerr != error.Refuse or
                !std.mem.eql(u8, fsys.last_refuse.code(), "change_missing"))
            {
                return cerr;
            }
            const ff = loaded.stream.forked_from orelse return cerr;
            if (loaded.changes.len != 0 or
                !store.optStrEql(loaded.stream.head, ff.change)) return cerr;
            // The fork origin exists only as an unreachable sibling line
            // (e.g. preserved by `pull --reset`); it can never join a remote
            // log — `stream` sits inside the signed preimage and `append`
            // only takes first-parent extensions of the remote head. When the
            // origin stream's first-parent chain holds the merge Change that
            // incorporated it, re-anchor the fork record to that merge so the
            // preserved line stays publishable through the merge's signed
            // `merged` link (#65).
            const mc = (try findIncorporatingMerge(allocator, fs, root, ff.stream, ff.change)) orelse return cerr;
            remote_head_owned = mc;
            init_head = mc;
            try reanchorForkRecord(allocator, fs, root, &loaded.stream, mc);
            init_rec = store.Stream{
                .id = loaded.stream.id,
                .name = loaded.stream.name,
                .head = init_head,
                .forked_from = loaded.stream.forked_from,
                .created = loaded.stream.created,
            };
            try client.create(init_rec);
        };
        was_created = true;
        remote_head = init_head;

        const k_copy = try allocator.dupe(u8, st_id);
        errdefer allocator.free(k_copy);
        const v_copy: ?[]u8 = if (init_head) |ih| try allocator.dupe(u8, ih) else null;
        errdefer if (v_copy) |v| allocator.free(v);
        try server_heads.put(k_copy, v_copy);
    }

    const local_head = loaded.stream.head;
    const heads_equal = if (local_head == null and remote_head == null)
        true
    else if (local_head != null and remote_head != null)
        std.mem.eql(u8, local_head.?, remote_head.?)
    else
        false;

    if (heads_equal) {
        return .{ .sent_changes = 0, .was_created = was_created };
    }

    // A bare fork pointer whose origin was re-anchored remotely (see the
    // create path above) converges locally when the remote head is exactly
    // the merge Change that incorporated the missing origin (#65).
    if (remote_head) |rh| {
        if (loaded.stream.forked_from) |ff| {
            if (loaded.changes.len == 0 and store.optStrEql(loaded.stream.head, ff.change)) {
                if (try findIncorporatingMerge(allocator, fs, root, ff.stream, ff.change)) |mc| {
                    defer allocator.free(mc);
                    if (std.mem.eql(u8, mc, rh)) {
                        try reanchorForkRecord(allocator, fs, root, &loaded.stream, mc);
                        return .{ .sent_changes = 0, .was_created = was_created };
                    }
                }
            }
        }
    }

    if (raw_lines.len == 0) {
        // Local has 0 changes in its own log, but remote_head differs -> stale_head.
        const new_h = try client.append(st_id, local_head, &.{});
        allocator.free(new_h);
        return .{ .sent_changes = 0, .was_created = was_created };
    }

    // The unsent suffix is the first-parent chain between the remote head and
    // the local head, not a positional log slice: `pull --reset` leaves
    // divergent local lines in the log as unreachable siblings, and a batch
    // must chain off `expected_head` (#65).
    var line_idx_by_id = std.StringHashMap(usize).init(allocator);
    defer line_idx_by_id.deinit();
    for (loaded.changes, 0..) |c, ci| try line_idx_by_id.put(c.id, ci);

    var suffix_rev: std.ArrayList(usize) = .empty;
    defer suffix_rev.deinit(allocator);

    const expected_head: ?[]const u8 = remote_head;
    var reached = remote_head == null;
    {
        var cur: ?[]const u8 = local_head;
        while (cur) |cid| {
            if (remote_head) |rh| {
                if (std.mem.eql(u8, cid, rh)) {
                    reached = true;
                    break;
                }
            }
            const li = line_idx_by_id.get(cid) orelse break;
            try suffix_rev.append(allocator, li);
            cur = loaded.changes[li].parent;
        }
    }

    if (!reached) {
        // Remote head is not on our first-parent chain (remote moved ahead /
        // diverged). Send the chain tip with its parent as expected_head so
        // the server rejects with `stale_head` over the wire.
        const tip_idx = if (local_head) |lh|
            line_idx_by_id.get(lh) orelse raw_lines.len - 1
        else
            raw_lines.len - 1;
        const exp = loaded.changes[tip_idx].parent;
        const h = try client.append(st_id, exp, raw_lines[tip_idx .. tip_idx + 1]);
        allocator.free(h);
        return fsys.refuse("stale_head", stale_head_recovery_hint);
    }

    if (suffix_rev.items.len == 0) {
        // Local head is behind remote head!
        return fsys.refuse("stale_head", stale_head_recovery_hint);
    }

    const send_lines = try allocator.alloc([]const u8, suffix_rev.items.len);
    defer allocator.free(send_lines);
    for (suffix_rev.items, 0..) |li, si| {
        send_lines[suffix_rev.items.len - 1 - si] = raw_lines[li];
    }

    var cur_expected: ?[]u8 = if (expected_head) |eh| try allocator.dupe(u8, eh) else null;
    defer if (cur_expected) |ce| allocator.free(ce);

    var sent: usize = 0;
    var batch_start: usize = 0;
    while (batch_start < send_lines.len) {
        const batch_end = @min(batch_start + MaxBatchChanges, send_lines.len);
        const batch = send_lines[batch_start..batch_end];
        const new_head = try client.append(st_id, cur_expected, batch);
        if (cur_expected) |ce| allocator.free(ce);
        cur_expected = new_head;
        sent += batch.len;
        batch_start = batch_end;
    }

    if (server_heads.getPtr(st_id)) |val_ptr| {
        if (val_ptr.*) |old_v| allocator.free(old_v);
        val_ptr.* = if (cur_expected) |ce| try allocator.dupe(u8, ce) else null;
    }

    return .{ .sent_changes = sent, .was_created = was_created };
}

/// Implements `flint push [--remote=<url>] [--stream=<s>] [--ws=<name>] [--auth-key=<file>]`.
pub fn cmdPush(
    allocator: Allocator,
    io: Io,
    fs: FS,
    root: []const u8,
    env_remote: ?[]const u8,
    env_auth_key: ?[]const u8,
    dial_fn: DialFn,
    dial_ctx: ?*anyopaque,
    stdout: *Io.Writer,
    args: []const []const u8,
) !void {
    var remote_flag: []const u8 = "";
    var stream_flag: []const u8 = "";
    var ws_flag: []const u8 = "";
    var auth_key_flag: []const u8 = "";
    var read_timeout_ms: u64 = 0;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.startsWith(u8, a, "--remote=")) {
            remote_flag = a["--remote=".len..];
            if (remote_flag.len == 0) return fsys.refuse("usage", "");
        } else if (std.mem.eql(u8, a, "--remote")) {
            if (i + 1 >= args.len or args[i + 1].len == 0) return fsys.refuse("usage", "");
            i += 1;
            remote_flag = args[i];
        } else if (std.mem.startsWith(u8, a, "--stream=")) {
            stream_flag = a["--stream=".len..];
            if (stream_flag.len == 0) return fsys.refuse("usage", "");
        } else if (std.mem.eql(u8, a, "--stream")) {
            if (i + 1 >= args.len or args[i + 1].len == 0) return fsys.refuse("usage", "");
            i += 1;
            stream_flag = args[i];
        } else if (std.mem.startsWith(u8, a, "--ws=")) {
            ws_flag = a["--ws=".len..];
            if (ws_flag.len == 0) return fsys.refuse("usage", "");
        } else if (std.mem.eql(u8, a, "--ws")) {
            if (i + 1 >= args.len or args[i + 1].len == 0) return fsys.refuse("usage", "");
            i += 1;
            ws_flag = args[i];
        } else if (std.mem.startsWith(u8, a, "--auth-key=")) {
            auth_key_flag = a["--auth-key=".len..];
            if (auth_key_flag.len == 0) return fsys.refuse("usage", "");
        } else if (std.mem.eql(u8, a, "--auth-key")) {
            if (i + 1 >= args.len or args[i + 1].len == 0) return fsys.refuse("usage", "");
            i += 1;
            auth_key_flag = args[i];
        } else if (std.mem.startsWith(u8, a, "--read-timeout=")) {
            read_timeout_ms = try parseReadTimeoutSeconds(a["--read-timeout=".len..]);
        } else if (std.mem.eql(u8, a, "--read-timeout")) {
            if (i + 1 >= args.len or args[i + 1].len == 0) return fsys.refuse("usage", "");
            i += 1;
            read_timeout_ms = try parseReadTimeoutSeconds(args[i]);
        } else {
            return fsys.refuse("usage", "");
        }
    }

    var idx = try store.loadStoreIndex(allocator, fs, root);
    defer idx.deinit();

    const target = try resolveStreamAndWorkspace(allocator, fs, &idx, stream_flag, ws_flag);
    const remote_url = try resolveRemoteUrl(allocator, fs, root, remote_flag, env_remote, target.ws_name);
    defer allocator.free(remote_url);
    fsys.setErrContext("push", remote_url);

    var auth_key = try loadAuthKey(allocator, fs, auth_key_flag, env_auth_key);
    defer if (auth_key) |*k| @memset(k, 0);

    // Build local `forked_from` ancestry chain ending with `target.stream`.
    var chain_ids: std.ArrayList([]const u8) = .empty;
    defer chain_ids.deinit(allocator);
    try chain_ids.append(allocator, target.stream.id);
    var cur_st = target.stream;
    while (cur_st.forked_from) |ff| {
        const parent_st = idx.streamByID(ff.stream) orelse break;
        try chain_ids.append(allocator, parent_st.id);
        cur_st = parent_st.*;
    }
    std.mem.reverse([]const u8, chain_ids.items);

    const transport = try dialRemote(dial_fn, dial_ctx, read_timeout_ms, allocator, io, remote_url);
    var client = SyncClient.init(allocator, transport);
    defer client.deinit();

    try client.handshake(auth_key);

    var server_heads = try client.heads();
    defer freeHeadsMap(allocator, &server_heads);

    // Ensure ancestor streams and their fork-point changes exist on the server first.
    for (chain_ids.items[0 .. chain_ids.items.len - 1]) |anc_id| {
        _ = try pushSingleStream(allocator, fs, root, &client, &server_heads, anc_id);
    }

    const res = try pushSingleStream(allocator, fs, root, &client, &server_heads, target.stream.id);

    if (target.ws_name) |wn| {
        const rc = store.RemoteConfig{
            .remote = remote_url,
            .stream = target.stream.id,
        };
        try store.writeWorkspaceRemote(allocator, fs, root, wn, rc);
    }

    if (res.sent_changes == 0 and !res.was_created) {
        try stdout.writeAll("flint: push up to date\n");
    } else {
        try stdout.print("flint: push ok stream={s} changes={d}\n", .{ target.stream.name, res.sent_changes });
    }
}

/// Implements `flint pull [--remote=<url>] [--stream=<s>] [--ws=<name>] [--auth-key=<file>]`.
pub fn cmdPull(
    allocator: Allocator,
    io: Io,
    fs: FS,
    root: []const u8,
    env_remote: ?[]const u8,
    env_auth_key: ?[]const u8,
    dial_fn: DialFn,
    dial_ctx: ?*anyopaque,
    stdout: *Io.Writer,
    args: []const []const u8,
) !void {
    var remote_flag: []const u8 = "";
    var stream_flag: []const u8 = "";
    var ws_flag: []const u8 = "";
    var auth_key_flag: []const u8 = "";
    var reset_flag = false;
    var read_timeout_ms: u64 = 0;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.startsWith(u8, a, "--remote=")) {
            remote_flag = a["--remote=".len..];
            if (remote_flag.len == 0) return fsys.refuse("usage", "");
        } else if (std.mem.eql(u8, a, "--remote")) {
            if (i + 1 >= args.len or args[i + 1].len == 0) return fsys.refuse("usage", "");
            i += 1;
            remote_flag = args[i];
        } else if (std.mem.startsWith(u8, a, "--stream=")) {
            stream_flag = a["--stream=".len..];
            if (stream_flag.len == 0) return fsys.refuse("usage", "");
        } else if (std.mem.eql(u8, a, "--stream")) {
            if (i + 1 >= args.len or args[i + 1].len == 0) return fsys.refuse("usage", "");
            i += 1;
            stream_flag = args[i];
        } else if (std.mem.startsWith(u8, a, "--ws=")) {
            ws_flag = a["--ws=".len..];
            if (ws_flag.len == 0) return fsys.refuse("usage", "");
        } else if (std.mem.eql(u8, a, "--ws")) {
            if (i + 1 >= args.len or args[i + 1].len == 0) return fsys.refuse("usage", "");
            i += 1;
            ws_flag = args[i];
        } else if (std.mem.startsWith(u8, a, "--auth-key=")) {
            auth_key_flag = a["--auth-key=".len..];
            if (auth_key_flag.len == 0) return fsys.refuse("usage", "");
        } else if (std.mem.eql(u8, a, "--auth-key")) {
            if (i + 1 >= args.len or args[i + 1].len == 0) return fsys.refuse("usage", "");
            i += 1;
            auth_key_flag = args[i];
        } else if (std.mem.eql(u8, a, "--reset")) {
            reset_flag = true;
        } else if (std.mem.startsWith(u8, a, "--read-timeout=")) {
            read_timeout_ms = try parseReadTimeoutSeconds(a["--read-timeout=".len..]);
        } else if (std.mem.eql(u8, a, "--read-timeout")) {
            if (i + 1 >= args.len or args[i + 1].len == 0) return fsys.refuse("usage", "");
            i += 1;
            read_timeout_ms = try parseReadTimeoutSeconds(args[i]);
        } else {
            return fsys.refuse("usage", "");
        }
    }

    var idx = try store.loadStoreIndex(allocator, fs, root);
    defer idx.deinit();

    const target = try resolveStreamAndWorkspace(allocator, fs, &idx, stream_flag, ws_flag);
    const remote_url = try resolveRemoteUrl(allocator, fs, root, remote_flag, env_remote, target.ws_name);
    defer allocator.free(remote_url);
    fsys.setErrContext("pull", remote_url);

    var auth_key = try loadAuthKey(allocator, fs, auth_key_flag, env_auth_key);
    defer if (auth_key) |*k| @memset(k, 0);

    var loaded = try store.loadStream(allocator, fs, root, target.stream.id);
    defer loaded.deinit(allocator);

    const transport = try dialRemote(dial_fn, dial_ctx, read_timeout_ms, allocator, io, remote_url);
    var client = SyncClient.init(allocator, transport);
    defer client.deinit();

    try client.handshake(auth_key);

    const remote_rec = try client.open(target.stream.id);
    defer remote_rec.deinit(allocator);

    const remote_head = remote_rec.head orelse {
        try stdout.writeAll("flint: pull up to date\n");
        return;
    };

    const local_head = loaded.stream.head;
    if (local_head) |lh| {
        if (std.mem.eql(u8, lh, remote_head)) {
            try stdout.writeAll("flint: pull up to date\n");
            return;
        }
    }

    if (reset_flag) {
        return pullResetToRemote(
            allocator,
            fs,
            root,
            &client,
            &idx,
            &loaded,
            remote_rec,
            remote_url,
            target.ws_name,
            stdout,
        );
    }

    // If `remote_head` is already in local stream changes (or equals `forked_from.change`),
    // local is already a superset of remote.
    if (loaded.stream.forked_from) |ff| {
        if (std.mem.eql(u8, remote_head, ff.change)) {
            try stdout.writeAll("flint: pull up to date\n");
            return;
        }
    }
    for (loaded.changes) |c| {
        if (std.mem.eql(u8, c.id, remote_head)) {
            try stdout.writeAll("flint: pull up to date\n");
            return;
        }
    }

    // Determine `after` parameter for `read`.
    // When a forked stream has no changes of its own yet, its `.jsonl` on the server is empty
    // or starts after `forked_from.change`, so `after` is null.
    const after_arg: ?[]const u8 = if (loaded.changes.len == 0) null else local_head;
    const expected_first_parent: ?[]const u8 = if (local_head) |lh|
        lh
    else if (loaded.stream.forked_from) |ff|
        ff.change
    else
        null;

    const fetched_lines = fetchAndVerifyStreamChanges(
        allocator,
        &client,
        loaded.stream,
        after_arg,
        expected_first_parent,
    ) catch |err| {
        if (err == error.Refuse and std.mem.eql(u8, fsys.last_refuse.code(), "change_missing")) {
            return fsys.refuse("fork_needed", "");
        }
        return err;
    };
    defer {
        for (fetched_lines) |l| allocator.free(l);
        allocator.free(fetched_lines);
    }

    if (fetched_lines.len == 0) {
        if (local_head != null) {
            return fsys.refuse("fork_needed", "");
        }
        try stdout.writeAll("flint: pull up to date\n");
        return;
    }

    if (idx.change_count + fetched_lines.len > store.MaxChanges) {
        return fsys.refuse("store_too_large", "changes");
    }

    var last_change = try json.parseChange(allocator, fetched_lines[fetched_lines.len - 1]);
    defer last_change.deinit(allocator);

    // The signed chain must reach the remote record's advertised head; a
    // proper signed prefix is still an incomplete pull (#58).
    if (!std.mem.eql(u8, last_change.id, remote_head)) {
        return fsys.refuse("stream_malformed", "head mismatch");
    }

    // Append raw lines to `streams/<id>.jsonl` first, then rewrite `streams/<id>.json`.
    var append_buf: std.ArrayList(u8) = .empty;
    defer append_buf.deinit(allocator);
    for (fetched_lines) |line| {
        try append_buf.appendSlice(allocator, line);
        try append_buf.append(allocator, '\n');
    }

    const log_path = try store.streamLogPath(allocator, root, loaded.stream.id);
    defer allocator.free(log_path);
    try checkLogAppendBound(allocator, fs, log_path, append_buf.items.len);
    try fs.appendSync(allocator, log_path, append_buf.items);

    const updated_stream = store.Stream{
        .id = loaded.stream.id,
        .name = loaded.stream.name,
        .head = last_change.id,
        .forked_from = loaded.stream.forked_from,
        .created = loaded.stream.created,
    };
    try store.writeStreamRecord(allocator, fs, root, updated_stream);

    if (target.ws_name) |wn| {
        const rc = store.RemoteConfig{
            .remote = remote_url,
            .stream = loaded.stream.id,
        };
        try store.writeWorkspaceRemote(allocator, fs, root, wn, rc);
    }

    try stdout.print("flint: pull ok stream={s} changes={d}\n", .{ loaded.stream.name, fetched_lines.len });
}

/// Implements `flint pull --reset` — the divergence-recovery path for the spec §4
/// journey "pull → merge → push". The local stream's `.jsonl` is append-only, so
/// reset fetches the full remote log, appends every remote Change the local log
/// lacks, then rolls the record head to the remote head. Changes the remote does
/// not have remain in the log as unreachable sibling lines (harmless: the
/// roll-forward rule only examines the last line's parent, and ancestor walks go
/// through `parent`/`merged` ids, not log order).
///
/// Safety: moving the head to the remote head orphans the local head, so reset
/// refuses `fork_needed` unless that head stays reachable through another
/// stream's ancestry — i.e. the user already ran `flint fork <stream> <aside>`.
/// The journey is then `merge <aside>` (the merge Change gets `parent` = remote
/// head and pushes cleanly) → `push`.
fn pullResetToRemote(
    allocator: Allocator,
    fs: FS,
    root: []const u8,
    client: *SyncClient,
    idx: *store.StoreIndex,
    loaded: *store.LoadedStream,
    remote_rec: store.Stream,
    remote_url: []const u8,
    ws_name: ?[]const u8,
    stdout: *Io.Writer,
) !void {
    const remote_head = remote_rec.head orelse {
        try stdout.writeAll("flint: pull up to date\n");
        return;
    };
    const local_head = loaded.stream.head;
    if (store.optStrEql(local_head, remote_head)) {
        try stdout.writeAll("flint: pull up to date\n");
        return;
    }

    // The two records must describe the same stream origin.
    if (!forkOriginEql(loaded.stream.forked_from, remote_rec.forked_from)) {
        return fsys.refuse("stream_malformed", "forked_from mismatch");
    }

    // Fetch and verify the whole remote log; the first Change's parent is the
    // fork point for a forked stream, else null.
    const first_parent: ?[]const u8 = if (remote_rec.forked_from) |ff| ff.change else null;
    const remote_lines = try fetchAndVerifyStreamChanges(allocator, client, remote_rec, null, first_parent);
    defer {
        for (remote_lines) |l| allocator.free(l);
        allocator.free(remote_lines);
    }

    // The remote record head must equal the last log line (or `forked_from.change`
    // on a forked stream whose own log is still empty).
    if (remote_lines.len > 0) {
        var last_c = try json.parseChange(allocator, remote_lines[remote_lines.len - 1]);
        defer last_c.deinit(allocator);
        if (!std.mem.eql(u8, last_c.id, remote_head)) {
            return fsys.refuse("stream_malformed", "head mismatch");
        }
    } else if (remote_rec.forked_from) |ff| {
        if (!std.mem.eql(u8, remote_head, ff.change)) {
            return fsys.refuse("stream_malformed", "fork head mismatch");
        }
    } else {
        return fsys.refuse("stream_malformed", "non-null head on empty stream");
    }

    var remote_changes: std.ArrayList(store.Change) = .empty;
    defer {
        for (remote_changes.items) |*c| c.deinit(allocator);
        remote_changes.deinit(allocator);
    }
    var remote_ids = std.StringHashMap(void).init(allocator);
    defer remote_ids.deinit();
    for (remote_lines) |line| {
        const c = try json.parseChange(allocator, line);
        try remote_changes.append(allocator, c);
        try remote_ids.put(c.id, {});
    }
    if (remote_rec.forked_from) |ff| try remote_ids.put(ff.change, {});

    var local_ids = std.StringHashMap(void).init(allocator);
    defer local_ids.deinit();
    for (loaded.changes) |c| try local_ids.put(c.id, {});
    if (loaded.stream.forked_from) |ff| try local_ids.put(ff.change, {});

    var missing: std.ArrayList([]const u8) = .empty;
    defer missing.deinit(allocator);
    for (remote_changes.items, 0..) |c, ri| {
        if (!local_ids.contains(c.id)) {
            try missing.append(allocator, remote_lines[ri]);
        }
    }

    // Orphan guard: rolling the head to `remote_head` unroots the local head.
    // Refuse unless another stream's ancestry reaches it (fork or merge).
    if (local_head) |lh| {
        if (!remote_ids.contains(lh)) {
            const all_changes = try store.loadAllStreamChanges(allocator, fs, root, idx);
            defer store.freeChanges(allocator, all_changes);
            var changes_by_id = std.StringHashMap(store.Change).init(allocator);
            defer changes_by_id.deinit();
            for (all_changes) |c| try changes_by_id.put(c.id, c);

            var preserved = false;
            for (idx.streams.items) |*other| {
                if (std.mem.eql(u8, other.id, loaded.stream.id)) continue;
                var anc = try merge.ancestorSet(allocator, other.head, &changes_by_id);
                const hit = anc.contains(lh);
                anc.deinit();
                if (hit) {
                    preserved = true;
                    break;
                }
            }
            if (!preserved) {
                return fsys.refuse("fork_needed", "");
            }
        }
    }

    if (idx.change_count + missing.items.len > store.MaxChanges) {
        return fsys.refuse("store_too_large", "changes");
    }

    var append_buf: std.ArrayList(u8) = .empty;
    defer append_buf.deinit(allocator);
    for (missing.items) |line| {
        try append_buf.appendSlice(allocator, line);
        try append_buf.append(allocator, '\n');
    }
    const log_path = try store.streamLogPath(allocator, root, loaded.stream.id);
    defer allocator.free(log_path);
    if (append_buf.items.len > 0) {
        try checkLogAppendBound(allocator, fs, log_path, append_buf.items.len);
        try fs.appendSync(allocator, log_path, append_buf.items);
    }

    const updated_stream = store.Stream{
        .id = loaded.stream.id,
        .name = loaded.stream.name,
        .head = remote_head,
        .forked_from = loaded.stream.forked_from,
        .created = loaded.stream.created,
    };
    try store.writeStreamRecord(allocator, fs, root, updated_stream);

    if (ws_name) |wn| {
        const rc = store.RemoteConfig{
            .remote = remote_url,
            .stream = loaded.stream.id,
        };
        try store.writeWorkspaceRemote(allocator, fs, root, wn, rc);
    }

    try stdout.print("flint: pull reset stream={s} changes={d} head={s}\n", .{ loaded.stream.name, missing.items.len, remote_head });
}

/// Implements `flint version [--remote=<url>] [--auth-key=<file>]` — prints
/// the client's spec revision (`SpecRev`, matching the repo-root `SPECREV`
/// file). When a remote is resolvable (`--remote` flag, then `FLINT_REMOTE`) it additionally
/// performs the `hello` handshake and reports the server's announced
/// `spec_rev` (`unannounced` on servers that predate the field).
/// No store is required.
pub fn cmdVersion(
    allocator: Allocator,
    io: Io,
    fs: FS,
    env_remote: ?[]const u8,
    env_auth_key: ?[]const u8,
    dial_fn: DialFn,
    dial_ctx: ?*anyopaque,
    stdout: *Io.Writer,
    args: []const []const u8,
) !void {
    var remote_flag: []const u8 = "";
    var auth_key_flag: []const u8 = "";

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.startsWith(u8, a, "--remote=")) {
            remote_flag = a["--remote=".len..];
            if (remote_flag.len == 0) return fsys.refuse("usage", "");
        } else if (std.mem.eql(u8, a, "--remote")) {
            if (i + 1 >= args.len or args[i + 1].len == 0) return fsys.refuse("usage", "");
            i += 1;
            remote_flag = args[i];
        } else if (std.mem.startsWith(u8, a, "--auth-key=")) {
            auth_key_flag = a["--auth-key=".len..];
            if (auth_key_flag.len == 0) return fsys.refuse("usage", "");
        } else if (std.mem.eql(u8, a, "--auth-key")) {
            if (i + 1 >= args.len or args[i + 1].len == 0) return fsys.refuse("usage", "");
            i += 1;
            auth_key_flag = args[i];
        } else {
            return fsys.refuse("usage", "");
        }
    }

    const remote_url = if (remote_flag.len > 0)
        remote_flag
    else if (env_remote) |e|
        e
    else
        "";
    if (remote_url.len > 0) {
        _ = try parseTcpRemoteUrl(remote_url);
        fsys.setErrContext("version", remote_url);
    }

    try stdout.print("flint: version spec_rev={d} proto={s}\n", .{ SpecRev, ProtoVersion });
    if (remote_url.len == 0) return;

    var auth_key = try loadAuthKey(allocator, fs, auth_key_flag, env_auth_key);
    defer if (auth_key) |*k| @memset(k, 0);

    const transport = try dial_fn(dial_ctx, allocator, io, remote_url);
    var client = SyncClient.init(allocator, transport);
    defer client.deinit();
    try client.handshake(auth_key);

    if (client.server_spec_rev) |rev| {
        try stdout.print("flint: remote {s} proto={s} spec_rev={d}\n", .{ remote_url, ProtoVersion, rev });
    } else {
        try stdout.print("flint: remote {s} proto={s} spec_rev=unannounced\n", .{ remote_url, ProtoVersion });
    }
}

/// In-process `FLINT-SYNC/1` server fixture (`flintd` equivalent) for conformance testing
/// over both in-memory transports and real loopback TCP sockets.
pub const InProcServer = struct {
    allocator: Allocator,
    fs: FS,
    store_root: []const u8,
    auth_key: ?[32]u8 = null,
    nonce_hex: [32]u8 = "000102030405060708090a0b0c0d0e0f".*,
    allow_authors: ?[]const []const u8 = null,
    /// When set, `hello` replies announce this `spec_rev` — mirrors the
    /// server-side `SPECREV` announcement tracked for `flintd`.
    spec_rev: ?u32 = null,
    tamper_read_sig: bool = false,
    force_refuse_op: ?[]const u8 = null,
    force_refuse_code: ?[]const u8 = null,

    pub const Session = struct {
        server: *InProcServer,
        authed: bool,
        closed: bool = false,

        pub fn init(server: *InProcServer) Session {
            return .{
                .server = server,
                .authed = server.auth_key == null,
                .closed = false,
            };
        }

        pub fn handleLine(self: *Session, allocator: Allocator, req_line: []const u8) ![]u8 {
            if (self.closed) return error.EndOfStream;
            const trimmed = std.mem.trimEnd(u8, req_line, "\r\n");
            var parsed = std.json.parseFromSlice(std.json.Value, allocator, trimmed, .{
                .allocate = .alloc_always,
            }) catch {
                return marshalRefuse(allocator, 0, "change_malformed", "invalid json");
            };
            defer parsed.deinit();

            const obj = switch (parsed.value) {
                .object => |o| o,
                else => return marshalRefuse(allocator, 0, "change_malformed", "not an object"),
            };

            const seq: u64 = if (obj.get("seq")) |sv| switch (sv) {
                .integer => |i| if (i >= 0) @intCast(i) else 0,
                else => 0,
            } else 0;

            const op = if (obj.get("op")) |ov| switch (ov) {
                .string => |s| s,
                else => return marshalRefuse(allocator, seq, "usage", "missing op"),
            } else return marshalRefuse(allocator, seq, "usage", "missing op");

            if (self.server.force_refuse_op) |f_op| {
                if (std.mem.eql(u8, op, f_op)) {
                    return marshalRefuse(allocator, seq, self.server.force_refuse_code orelse "wire_error", "");
                }
            }

            if (std.mem.eql(u8, op, "auth")) {
                return self.handleAuth(allocator, seq, obj);
            }

            if (!self.authed) {
                if (std.mem.eql(u8, op, "hello")) {
                    const proto = if (obj.get("proto")) |pv| switch (pv) {
                        .string => |s| s,
                        else => "",
                    } else "";
                    if (!std.mem.eql(u8, proto, ProtoVersion)) {
                        return marshalRefuse(allocator, seq, "proto_version", "");
                    }
                    return marshalRefuse(allocator, seq, "auth_required", &self.server.nonce_hex);
                }
                return marshalRefuse(allocator, seq, "auth_required", &self.server.nonce_hex);
            }

            if (std.mem.eql(u8, op, "hello")) {
                const proto = if (obj.get("proto")) |pv| switch (pv) {
                    .string => |s| s,
                    else => "",
                } else "";
                if (!std.mem.eql(u8, proto, ProtoVersion)) {
                    return marshalRefuse(allocator, seq, "proto_version", "");
                }
                var out: std.ArrayList(u8) = .empty;
                errdefer out.deinit(allocator);
                try out.print(
                    allocator,
                    "{{\"seq\":{d},\"ok\":true,\"proto\":\"{s}\",\"server\":\"flintd\"",
                    .{ seq, ProtoVersion },
                );
                if (self.server.spec_rev) |rev| {
                    try out.print(allocator, ",\"spec_rev\":{d}", .{rev});
                }
                try out.append(allocator, '}');
                return out.toOwnedSlice(allocator);
            }

            if (std.mem.eql(u8, op, "list")) {
                return self.handleList(allocator, seq);
            }
            if (std.mem.eql(u8, op, "heads")) {
                return self.handleHeads(allocator, seq);
            }
            if (std.mem.eql(u8, op, "open")) {
                return self.handleOpen(allocator, seq, obj);
            }
            if (std.mem.eql(u8, op, "read")) {
                return self.handleRead(allocator, seq, obj);
            }
            if (std.mem.eql(u8, op, "create")) {
                return self.handleCreate(allocator, seq, obj);
            }
            if (std.mem.eql(u8, op, "append")) {
                return self.handleAppend(allocator, seq, obj);
            }

            return marshalRefuse(allocator, seq, "usage", "unknown op");
        }

        fn handleAuth(self: *Session, allocator: Allocator, seq: u64, obj: std.json.ObjectMap) ![]u8 {
            const key = self.server.auth_key orelse {
                self.authed = true;
                return std.fmt.allocPrint(allocator, "{{\"seq\":{d},\"ok\":true}}", .{seq});
            };
            const nonce = if (obj.get("nonce")) |nv| switch (nv) {
                .string => |s| s,
                else => "",
            } else "";
            const hmac_str = if (obj.get("hmac")) |hv| switch (hv) {
                .string => |s| s,
                else => "",
            } else "";

            if (!std.mem.eql(u8, nonce, &self.server.nonce_hex) or !isLowerHex(hmac_str, 64)) {
                self.closed = true;
                return marshalRefuse(allocator, seq, "auth_failed", "");
            }

            const expected = computeAuthHmac(&key, nonce) catch {
                self.closed = true;
                return marshalRefuse(allocator, seq, "auth_failed", "");
            };

            if (!std.crypto.timing_safe.eql([64]u8, expected, hmac_str[0..64].*)) {
                self.closed = true;
                return marshalRefuse(allocator, seq, "auth_failed", "");
            }

            self.authed = true;
            return std.fmt.allocPrint(allocator, "{{\"seq\":{d},\"ok\":true}}", .{seq});
        }

        fn handleList(self: *Session, allocator: Allocator, seq: u64) ![]u8 {
            var idx = store.loadStoreIndex(allocator, self.server.fs, self.server.store_root) catch |err| {
                return marshalErrRefuse(allocator, seq, err);
            };
            defer idx.deinit();

            var out: std.ArrayList(u8) = .empty;
            errdefer out.deinit(allocator);
            try out.print(allocator, "{{\"seq\":{d},\"ok\":true,\"streams\":[", .{seq});
            for (idx.streams.items, 0..) |st, i| {
                if (i > 0) try out.append(allocator, ',');
                const line = try json.marshalStreamLine(allocator, st);
                defer allocator.free(line);
                try out.appendSlice(allocator, std.mem.trimEnd(u8, line, "\n"));
            }
            try out.appendSlice(allocator, "]}");
            return out.toOwnedSlice(allocator);
        }

        fn handleHeads(self: *Session, allocator: Allocator, seq: u64) ![]u8 {
            var idx = store.loadStoreIndex(allocator, self.server.fs, self.server.store_root) catch |err| {
                return marshalErrRefuse(allocator, seq, err);
            };
            defer idx.deinit();

            var out: std.ArrayList(u8) = .empty;
            errdefer out.deinit(allocator);
            try out.print(allocator, "{{\"seq\":{d},\"ok\":true,\"heads\":{{", .{seq});
            for (idx.streams.items, 0..) |st, i| {
                if (i > 0) try out.append(allocator, ',');
                try json.appendGoJSONString(&out, allocator, st.id);
                try out.append(allocator, ':');
                if (st.head) |h| {
                    try json.appendGoJSONString(&out, allocator, h);
                } else {
                    try out.appendSlice(allocator, "null");
                }
            }
            try out.appendSlice(allocator, "}}");
            return out.toOwnedSlice(allocator);
        }

        fn resolveServerStream(idx: *const store.StoreIndex, arg: []const u8) ?store.Stream {
            if (idx.streamByID(arg) orelse idx.streamByName(arg)) |st| return st.*;
            return null;
        }

        fn handleOpen(self: *Session, allocator: Allocator, seq: u64, obj: std.json.ObjectMap) ![]u8 {
            const s_arg = if (obj.get("stream")) |sv| switch (sv) {
                .string => |s| s,
                else => return marshalRefuse(allocator, seq, "stream_missing", ""),
            } else return marshalRefuse(allocator, seq, "stream_missing", "");

            var idx = store.loadStoreIndex(allocator, self.server.fs, self.server.store_root) catch |err| {
                return marshalErrRefuse(allocator, seq, err);
            };
            defer idx.deinit();

            const st = resolveServerStream(&idx, s_arg) orelse {
                return marshalRefuse(allocator, seq, "stream_missing", s_arg);
            };
            const rec_line = try json.marshalStreamLine(allocator, st);
            defer allocator.free(rec_line);
            const rec_json = std.mem.trimEnd(u8, rec_line, "\n");

            return std.fmt.allocPrint(
                allocator,
                "{{\"seq\":{d},\"ok\":true,\"record\":{s}}}",
                .{ seq, rec_json },
            );
        }

        fn handleRead(self: *Session, allocator: Allocator, seq: u64, obj: std.json.ObjectMap) ![]u8 {
            const s_arg = if (obj.get("stream")) |sv| switch (sv) {
                .string => |s| s,
                else => return marshalRefuse(allocator, seq, "stream_missing", ""),
            } else return marshalRefuse(allocator, seq, "stream_missing", "");

            const after_arg: ?[]const u8 = if (obj.get("after")) |av| switch (av) {
                .null => null,
                .string => |s| if (s.len > 0) s else null,
                else => return marshalRefuse(allocator, seq, "change_malformed", ""),
            } else null;

            const limit: usize = if (obj.get("limit")) |lv| switch (lv) {
                .integer => |i| if (i > 0 and i <= MaxBatchChanges) @intCast(i) else DefaultReadLimit,
                else => DefaultReadLimit,
            } else DefaultReadLimit;

            var idx = store.loadStoreIndex(allocator, self.server.fs, self.server.store_root) catch |err| {
                return marshalErrRefuse(allocator, seq, err);
            };
            defer idx.deinit();

            const st = resolveServerStream(&idx, s_arg) orelse {
                return marshalRefuse(allocator, seq, "stream_missing", s_arg);
            };

            var loaded = store.loadStream(allocator, self.server.fs, self.server.store_root, st.id) catch |err| {
                return marshalErrRefuse(allocator, seq, err);
            };
            defer loaded.deinit(allocator);

            const raw_lines = readStreamRawLines(allocator, self.server.fs, self.server.store_root, st.id) catch |err| {
                return marshalErrRefuse(allocator, seq, err);
            };
            defer freeRawLines(allocator, raw_lines);

            var start_idx: usize = 0;
            if (after_arg) |after_id| {
                var found = false;
                if (loaded.stream.forked_from) |ff| {
                    if (std.mem.eql(u8, after_id, ff.change)) {
                        start_idx = 0;
                        found = true;
                    }
                }
                if (!found) {
                    for (loaded.changes, 0..) |c, i_c| {
                        if (std.mem.eql(u8, c.id, after_id)) {
                            start_idx = i_c + 1;
                            found = true;
                            break;
                        }
                    }
                }
                if (!found) {
                    return marshalRefuse(allocator, seq, "change_missing", after_id);
                }
            }

            const end_idx = @min(start_idx + limit, raw_lines.len);
            const more = end_idx < raw_lines.len;
            const rec_line = try json.marshalStreamLine(allocator, loaded.stream);
            defer allocator.free(rec_line);
            const rec_json = std.mem.trimEnd(u8, rec_line, "\n");

            var out: std.ArrayList(u8) = .empty;
            errdefer out.deinit(allocator);
            try out.print(allocator, "{{\"seq\":{d},\"ok\":true,\"record\":{s},\"head\":", .{ seq, rec_json });
            if (loaded.stream.head) |h| {
                try json.appendGoJSONString(&out, allocator, h);
            } else {
                try out.appendSlice(allocator, "null");
            }
            try out.appendSlice(allocator, ",\"changes\":[");
            for (raw_lines[start_idx..end_idx], 0..) |line, i_l| {
                if (i_l > 0) try out.append(allocator, ',');
                if (self.server.tamper_read_sig and i_l == 0 and line.len > 12) {
                    const tampered = try allocator.dupe(u8, line);
                    defer allocator.free(tampered);
                    // Flip one hex character inside `"sig":"..."` near the end of the line.
                    const flip_pos = tampered.len - 4;
                    tampered[flip_pos] = if (tampered[flip_pos] == '0') '1' else '0';
                    try json.appendGoJSONString(&out, allocator, tampered);
                } else {
                    try json.appendGoJSONString(&out, allocator, line);
                }
            }
            try out.print(allocator, "],\"more\":{s}}}", .{if (more) "true" else "false"});
            return out.toOwnedSlice(allocator);
        }

        fn handleCreate(self: *Session, allocator: Allocator, seq: u64, obj: std.json.ObjectMap) ![]u8 {
            const rec_val = obj.get("record") orelse return marshalRefuse(allocator, seq, "stream_malformed", "");
            const rec = parseStreamValue(allocator, rec_val) catch |err| {
                return marshalErrRefuse(allocator, seq, err);
            };
            defer rec.deinit(allocator);

            // Spec §2.4 create validation:
            if (rec.forked_from) |ff| {
                const h = rec.head orelse return marshalRefuse(allocator, seq, "stream_malformed", "fork head null");
                if (!std.mem.eql(u8, h, ff.change)) {
                    return marshalRefuse(allocator, seq, "stream_malformed", "fork head != forked_from.change");
                }
            } else {
                if (rec.head != null) {
                    return marshalRefuse(allocator, seq, "stream_malformed", "fresh stream non-null head");
                }
            }

            var idx = store.loadStoreIndex(allocator, self.server.fs, self.server.store_root) catch |err| {
                return marshalErrRefuse(allocator, seq, err);
            };
            defer idx.deinit();

            if (idx.streamByID(rec.id) != null or idx.streamByName(rec.name) != null) {
                return marshalRefuse(allocator, seq, "stream_exists", rec.name);
            }
            if (idx.streams.items.len + 1 > MaxStreams) {
                return marshalRefuse(allocator, seq, "store_too_large", "streams");
            }

            if (rec.forked_from) |ff| {
                const all_changes = store.loadAllStreamChanges(allocator, self.server.fs, self.server.store_root, &idx) catch |err| {
                    return marshalErrRefuse(allocator, seq, err);
                };
                defer store.freeChanges(allocator, all_changes);
                var found_change = false;
                for (all_changes) |c| {
                    if (std.mem.eql(u8, c.id, ff.change)) {
                        found_change = true;
                        break;
                    }
                }
                if (!found_change) {
                    return marshalRefuse(allocator, seq, "change_missing", ff.change);
                }
            }

            const s_dir = try store.streamsDir(allocator, self.server.store_root);
            defer allocator.free(s_dir);
            try self.server.fs.mkdir(allocator, s_dir);
            store.writeStreamRecord(allocator, self.server.fs, self.server.store_root, rec) catch |err| {
                return marshalErrRefuse(allocator, seq, err);
            };

            return std.fmt.allocPrint(allocator, "{{\"seq\":{d},\"ok\":true}}", .{seq});
        }

        fn handleAppend(self: *Session, allocator: Allocator, seq: u64, obj: std.json.ObjectMap) ![]u8 {
            const s_arg = if (obj.get("stream")) |sv| switch (sv) {
                .string => |s| s,
                else => return marshalRefuse(allocator, seq, "stream_missing", ""),
            } else return marshalRefuse(allocator, seq, "stream_missing", "");

            const expected_head: ?[]const u8 = if (obj.get("expected_head")) |ehv| switch (ehv) {
                .null => null,
                .string => |s| s,
                else => return marshalRefuse(allocator, seq, "change_malformed", ""),
            } else null;

            const changes_val = obj.get("changes") orelse return marshalRefuse(allocator, seq, "change_malformed", "");
            const changes_arr = switch (changes_val) {
                .array => |a| a,
                else => return marshalRefuse(allocator, seq, "change_malformed", ""),
            };
            if (changes_arr.items.len == 0 or changes_arr.items.len > MaxBatchChanges) {
                return marshalRefuse(allocator, seq, "change_malformed", "batch size");
            }

            var idx = store.loadStoreIndex(allocator, self.server.fs, self.server.store_root) catch |err| {
                return marshalErrRefuse(allocator, seq, err);
            };
            defer idx.deinit();

            const st_entry = resolveServerStream(&idx, s_arg) orelse {
                return marshalRefuse(allocator, seq, "stream_missing", s_arg);
            };

            var loaded = store.loadStream(allocator, self.server.fs, self.server.store_root, st_entry.id) catch |err| {
                return marshalErrRefuse(allocator, seq, err);
            };
            defer loaded.deinit(allocator);

            const cur_head = loaded.stream.head;
            const head_matches = if (cur_head == null and expected_head == null)
                true
            else if (cur_head != null and expected_head != null)
                std.mem.eql(u8, cur_head.?, expected_head.?)
            else
                false;

            if (!head_matches) {
                return marshalRefuse(allocator, seq, "stale_head", "");
            }

            if (idx.change_count + changes_arr.items.len > store.MaxChanges) {
                return marshalRefuse(allocator, seq, "store_too_large", "changes");
            }

            var prev_id: ?[]u8 = if (expected_head) |eh| try allocator.dupe(u8, eh) else null;
            defer if (prev_id) |p| allocator.free(p);

            var log_buf: std.ArrayList(u8) = .empty;
            defer log_buf.deinit(allocator);

            for (changes_arr.items) |item| {
                const raw_line_in = switch (item) {
                    .string => |s| s,
                    else => return marshalRefuse(allocator, seq, "change_malformed", ""),
                };
                const raw_line = std.mem.trimEnd(u8, raw_line_in, "\r\n");
                if (raw_line.len + 1 > MaxChangeBytes) {
                    return marshalRefuse(allocator, seq, "change_too_large", "");
                }

                var c = json.parseChange(allocator, raw_line) catch |err| {
                    return marshalErrRefuse(allocator, seq, err);
                };
                defer c.deinit(allocator);

                if (!std.mem.eql(u8, c.stream, loaded.stream.id)) {
                    return marshalRefuse(allocator, seq, "change_malformed", "stream mismatch");
                }
                sign.validateCommitMessage(c.message) catch |err| {
                    return marshalErrRefuse(allocator, seq, err);
                };

                if (prev_id) |pid| {
                    const cp = c.parent orelse return marshalRefuse(allocator, seq, "change_malformed", "parent null");
                    if (!std.mem.eql(u8, cp, pid)) {
                        return marshalRefuse(allocator, seq, "change_malformed", "parent mismatch");
                    }
                } else {
                    if (c.parent != null) {
                        return marshalRefuse(allocator, seq, "change_malformed", "root parent non-null");
                    }
                }

                const ok = ed25519.verifyChange(allocator, &c) catch |err| {
                    return marshalErrRefuse(allocator, seq, err);
                };
                if (!ok) {
                    return marshalRefuse(allocator, seq, "sig_invalid", "");
                }

                if (self.server.allow_authors) |allowed| {
                    var found = false;
                    for (allowed) |pub_hex| {
                        if (std.mem.eql(u8, pub_hex, c.author)) {
                            found = true;
                            break;
                        }
                    }
                    if (!found) {
                        return marshalRefuse(allocator, seq, "author_not_allowed", c.author);
                    }
                }

                if (prev_id) |p| allocator.free(p);
                prev_id = try allocator.dupe(u8, c.id);

                try log_buf.appendSlice(allocator, raw_line);
                try log_buf.append(allocator, '\n');
            }

            const log_path = try store.streamLogPath(allocator, self.server.store_root, loaded.stream.id);
            defer allocator.free(log_path);
            try self.server.fs.appendSync(allocator, log_path, log_buf.items);

            const updated = store.Stream{
                .id = loaded.stream.id,
                .name = loaded.stream.name,
                .head = prev_id,
                .forked_from = loaded.stream.forked_from,
                .created = loaded.stream.created,
            };
            try store.writeStreamRecord(allocator, self.server.fs, self.server.store_root, updated);

            var out: std.ArrayList(u8) = .empty;
            errdefer out.deinit(allocator);
            try out.print(allocator, "{{\"seq\":{d},\"ok\":true,\"head\":", .{seq});
            try json.appendGoJSONString(&out, allocator, prev_id.?);
            try out.append(allocator, '}');
            return out.toOwnedSlice(allocator);
        }
    };

    fn marshalRefuse(allocator: Allocator, seq: u64, code: []const u8, detail: []const u8) ![]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        try out.print(allocator, "{{\"seq\":{d},\"ok\":false,\"refuse\":", .{seq});
        try json.appendGoJSONString(&out, allocator, code);
        try out.appendSlice(allocator, ",\"detail\":");
        try json.appendGoJSONString(&out, allocator, detail);
        try out.append(allocator, '}');
        return out.toOwnedSlice(allocator);
    }

    fn marshalErrRefuse(allocator: Allocator, seq: u64, err: anyerror) ![]u8 {
        if (err == error.Refuse) {
            return marshalRefuse(allocator, seq, fsys.last_refuse.code(), fsys.last_refuse.detail());
        }
        return marshalRefuse(allocator, seq, @errorName(err), "");
    }

    const InProcTransport = struct {
        session: Session,

        fn requestLineImpl(ptr: *anyopaque, allocator: Allocator, req_line: []const u8) anyerror![]u8 {
            const self: *InProcTransport = @ptrCast(@alignCast(ptr));
            return self.session.handleLine(allocator, req_line);
        }

        fn closeImpl(ptr: *anyopaque, allocator: Allocator) void {
            const self: *InProcTransport = @ptrCast(@alignCast(ptr));
            allocator.destroy(self);
        }
    };

    pub fn dial(
        dial_ctx: ?*anyopaque,
        allocator: Allocator,
        _: Io,
        remote_url: []const u8,
    ) anyerror!Transport {
        _ = try parseTcpRemoteUrl(remote_url);
        const srv_ptr = dial_ctx orelse return fsys.refuse("remote_missing", "");
        const srv: *InProcServer = @ptrCast(@alignCast(srv_ptr));
        const t = try allocator.create(InProcTransport);
        t.* = .{ .session = Session.init(srv) };
        return .{
            .ptr = t,
            .vtable = &.{
                .requestLine = InProcTransport.requestLineImpl,
                .close = InProcTransport.closeImpl,
            },
        };
    }

    /// Serves a single accepted `Io.net.Stream` connection using `InProcServer`.
    pub fn serveNetStream(self: *InProcServer, allocator: Allocator, io: Io, stream: Io.net.Stream) void {
        defer stream.close(io);
        var session = Session.init(self);
        var read_buf: [8192]u8 = undefined;
        var write_buf: [8192]u8 = undefined;
        var reader = stream.reader(io, &read_buf);
        var writer = stream.writer(io, &write_buf);
        const r = &reader.interface;
        const w = &writer.interface;

        while (!session.closed) {
            var line_buf: std.ArrayList(u8) = .empty;
            defer line_buf.deinit(allocator);

            var eof = false;
            while (true) {
                var b: [1]u8 = undefined;
                const n = r.readSliceShort(&b) catch {
                    eof = true;
                    break;
                };
                if (n == 0) {
                    eof = true;
                    break;
                }
                if (b[0] == '\n') break;
                line_buf.append(allocator, b[0]) catch return;
                // Real flintd refuses request lines over 4 MiB with
                // `store_too_large` and closes; mirror that bound so the
                // fixture does not accept requests flintd would reject.
                if (line_buf.items.len > MaxWireLineBytes) {
                    w.writeAll("{\"seq\":0,\"ok\":false,\"refuse\":\"store_too_large\",\"detail\":\"line exceeds 4 MiB\"}\n") catch return;
                    w.flush() catch return;
                    return;
                }
            }
            if (eof and line_buf.items.len == 0) break;

            const resp = session.handleLine(allocator, line_buf.items) catch return;
            defer allocator.free(resp);

            w.writeAll(resp) catch return;
            w.writeByte('\n') catch return;
            w.flush() catch return;
        }
    }
};

test "handshake: captures spec_rev when announced, tolerates absence, survives auth round" {
    const gpa = std.testing.allocator;

    var mem = try fsys.MemFS.init(gpa);
    defer mem.deinit();

    var server = InProcServer{
        .allocator = gpa,
        .fs = mem.fs(),
        .store_root = "/srv/FLINT",
    };

    // Field absent: handshake succeeds, server_spec_rev stays null.
    {
        const transport = try InProcServer.dial(&server, gpa, std.testing.io, "tcp://127.0.0.1:4748");
        var client = SyncClient.init(gpa, transport);
        defer client.deinit();
        try client.handshake(null);
        try std.testing.expectEqual(@as(?u32, null), client.server_spec_rev);
    }

    // Announced integer is captured.
    server.spec_rev = 7;
    {
        const transport = try InProcServer.dial(&server, gpa, std.testing.io, "tcp://127.0.0.1:4748");
        var client = SyncClient.init(gpa, transport);
        defer client.deinit();
        try client.handshake(null);
        try std.testing.expectEqual(@as(?u32, 7), client.server_spec_rev);
    }

    // Auth challenge round: spec_rev arrives on the post-auth hello reply.
    const secret = "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5";
    var key: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&key, secret);
    server.auth_key = key;
    {
        const transport = try InProcServer.dial(&server, gpa, std.testing.io, "tcp://127.0.0.1:4748");
        var client = SyncClient.init(gpa, transport);
        defer client.deinit();
        try client.handshake(key);
        try std.testing.expectEqual(@as(?u32, 7), client.server_spec_rev);
    }
}

test "cmdVersion: client spec_rev, remote spec_rev or unannounced, env fallback, refusals" {
    const gpa = std.testing.allocator;

    var mem = try fsys.MemFS.init(gpa);
    defer mem.deinit();
    const fs = mem.fs();

    var server = InProcServer{
        .allocator = gpa,
        .fs = fs,
        .store_root = "/srv/FLINT",
    };

    // Bare `version`: client rev only, no dial.
    {
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        try cmdVersion(gpa, std.testing.io, fs, null, null, InProcServer.dial, &server, &out.writer, &.{});
        const want = try std.fmt.allocPrint(gpa, "flint: version spec_rev={d} proto={s}\n", .{ SpecRev, ProtoVersion });
        defer gpa.free(want);
        try std.testing.expectEqualStrings(want, out.written());
    }

    // A server that does not announce `spec_rev` reports `unannounced`.
    {
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        try cmdVersion(gpa, std.testing.io, fs, null, null, InProcServer.dial, &server, &out.writer, &.{"--remote=tcp://127.0.0.1:4748"});
        const want = try std.fmt.allocPrint(gpa, "flint: version spec_rev={d} proto={s}\n" ++
            "flint: remote tcp://127.0.0.1:4748 proto={s} spec_rev=unannounced\n", .{ SpecRev, ProtoVersion, ProtoVersion });
        defer gpa.free(want);
        try std.testing.expectEqualStrings(want, out.written());
    }

    // Announced rev is reported verbatim; also exercises FLINT_REMOTE fallback.
    server.spec_rev = 42;
    {
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        try cmdVersion(gpa, std.testing.io, fs, "tcp://127.0.0.1:4748", null, InProcServer.dial, &server, &out.writer, &.{});
        try std.testing.expect(std.mem.indexOf(u8, out.written(), "spec_rev=42\n") != null);
    }

    // Malformed remote and stray args refuse before printing.
    try std.testing.expectError(error.Refuse, cmdVersion(gpa, std.testing.io, fs, null, null, InProcServer.dial, &server, undefined, &.{"--remote=nope"}));
    try std.testing.expectEqualStrings("remote_malformed", fsys.last_refuse.code());
    try std.testing.expectError(error.Refuse, cmdVersion(gpa, std.testing.io, fs, null, null, InProcServer.dial, &server, undefined, &.{"bogus"}));
    try std.testing.expectEqualStrings("usage", fsys.last_refuse.code());
}

test "parseStreamValue: remote stream names must match [a-z0-9-]{1,32} (#52)" {
    const gpa = std.testing.allocator;
    const head = "{\"id\":\"0199de2d-dc00-7000-8000-000000000999\",\"name\":";
    const tail = ",\"head\":null,\"created\":0,\"forked_from\":null}";

    for ([_][]const u8{
        "\"../../tmp/evil\"",
        "\"A\\u001b[2J\"",
        "\"Upper\"",
        "\"main stream\"",
        "\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
    }) |raw_name| {
        const doc = try std.mem.concat(gpa, u8, &.{ head, raw_name, tail });
        defer gpa.free(doc);
        const parsed = try std.json.parseFromSlice(std.json.Value, gpa, doc, .{});
        defer parsed.deinit();
        try std.testing.expectError(error.Refuse, parseStreamValue(gpa, parsed.value));
        try std.testing.expectEqualStrings("stream_malformed", fsys.last_refuse.code());
    }

    const good_doc = try std.mem.concat(gpa, u8, &.{ head, "\"main-2\"", tail });
    defer gpa.free(good_doc);
    const good_parsed = try std.json.parseFromSlice(std.json.Value, gpa, good_doc, .{});
    defer good_parsed.deinit();
    var st = try parseStreamValue(gpa, good_parsed.value);
    defer st.deinit(gpa);
    try std.testing.expectEqualStrings("main-2", st.name);
}

test "sync bounds: a producer-valid >1 MiB change appends and reads back (#60)" {
    const gpa = std.testing.allocator;
    var arena_inst = std.heap.ArenaAllocator.init(gpa);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    var srv_mem = try fsys.MemFS.init(gpa);
    defer srv_mem.deinit();
    const srv_fs = srv_mem.fs();
    try srv_fs.mkdir(gpa, "/srv/FLINT/streams");

    var server = InProcServer{
        .allocator = gpa,
        .fs = srv_fs,
        .store_root = "/srv/FLINT",
    };

    const transport = try InProcServer.dial(&server, gpa, std.testing.io, "tcp://127.0.0.1:4748");
    var client = SyncClient.init(gpa, transport);
    defer client.deinit();

    const stream_id = "0199de2d-dc00-7000-8000-00000000aa60";
    const record = store.Stream{ .id = stream_id, .name = "main", .created = 1 };
    try client.create(record);

    // 4096 const-atom adds — the shape a real `commit` emits at the documented
    // 4096-Atom bound, signed like any other Change.
    const ops = try arena.alloc(store.Op, 4096);
    for (ops, 0..) |*op, i| {
        const atom_id = try std.fmt.allocPrint(arena, "0199de2d-dc00-7000-8000-{d:0>12}", .{i});
        const name = try std.fmt.allocPrint(arena, "main.item_{d:0>4}", .{i});
        const hash = try std.fmt.allocPrint(arena, "{x:0>64}", .{i});
        const sig_hash = try std.fmt.allocPrint(arena, "{x:0>64}", .{i +% 0x1000});
        op.* = .{
            .type = try arena.dupe(u8, "add"),
            .atom_id = atom_id,
            .kind = try arena.dupe(u8, "const"),
            .new_name = name,
            .new_span = .{ .file = try arena.dupe(u8, "main.zig"), .start = 0, .end = 32 },
            .new_hash = hash,
            .new_sig_hash = sig_hash,
        };
    }

    var c = store.Change{
        .id = "0199de2d-dc00-7000-8000-00000000cc60",
        .stream = stream_id,
        .ts = 1760000000000,
        .author = "",
        .message = "maximum-atoms",
        .ops = ops,
        .sig = "",
    };
    var seed = ed25519.parseHex32Lower("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").?;
    try ed25519.signChangeWithSeed(arena, &c, &seed);

    const marshaled = try json.marshalChangeLine(arena, c);
    const raw_line = std.mem.trimEnd(u8, marshaled, "\r\n");

    // Guard the premise: the signed Change exceeds the old 1 MiB clamp but
    // stays under the documented 4 MiB per-line bound.
    try std.testing.expect(raw_line.len > 1024 * 1024);
    try std.testing.expect(raw_line.len + 1 <= MaxChangeBytes);

    // The fixture's append path enforces the same per-change bound as real
    // flintd — before this fix it refused the line the client just produced.
    const new_head = try client.append(stream_id, null, &.{raw_line});
    defer gpa.free(new_head);
    try std.testing.expectEqualStrings(c.id, new_head);

    // fetchAndVerifyStreamChanges is the clone/pull receive path: it must
    // accept and verify the line rather than refusing `change_too_large`.
    const fetched = try fetchAndVerifyStreamChanges(gpa, &client, record, null, null);
    defer {
        for (fetched) |l| gpa.free(l);
        gpa.free(fetched);
    }
    try std.testing.expectEqual(@as(usize, 1), fetched.len);
    try std.testing.expectEqualStrings(raw_line, fetched[0]);
}

test "change bound: a raw change line over the 4 MiB bound refuses change_too_large (#60)" {
    const gpa = std.testing.allocator;

    const OversizeRead = struct {
        change_line: []const u8,

        fn requestLineImpl(ptr: *anyopaque, allocator: Allocator, req_line: []const u8) anyerror![]u8 {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            _ = req_line;
            var out: std.ArrayList(u8) = .empty;
            errdefer out.deinit(allocator);
            try out.appendSlice(allocator, "{\"seq\":1,\"ok\":true,\"head\":null,\"changes\":[");
            try json.appendGoJSONString(&out, allocator, self.change_line);
            try out.appendSlice(allocator, "],\"more\":false}");
            return out.toOwnedSlice(allocator);
        }

        fn closeImpl(_: *anyopaque, _: Allocator) void {}
    };

    const oversized = try gpa.alloc(u8, MaxChangeBytes);
    defer gpa.free(oversized);
    @memset(oversized, 'x');

    var stub = OversizeRead{ .change_line = oversized };
    var client = SyncClient.init(gpa, .{
        .ptr = &stub,
        .vtable = &.{
            .requestLine = OversizeRead.requestLineImpl,
            .close = OversizeRead.closeImpl,
        },
    });
    defer client.deinit();

    const st = store.Stream{ .id = "x", .name = "main", .created = 0 };
    try std.testing.expectError(
        error.Refuse,
        fetchAndVerifyStreamChanges(gpa, &client, st, null, null),
    );
    try std.testing.expectEqualStrings("change_too_large", fsys.last_refuse.code());
}
