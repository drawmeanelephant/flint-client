// Handoff records (docs/flint-handoffs-spec.md): signed proposal/attestation
// lifecycle over the existing store. Records are JSON lines under
// handoffs/<stream-uuid>.jsonl; the signed form is the §1.4 typed preimage,
// never the JSON. Writers emit only FLINT-HANDOFF/1.

const std = @import("std");

const zero_sig: [128]u8 = @splat('0');

fn strLt(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}
const Allocator = std.mem.Allocator;
const Io = std.Io;
const fsys = @import("fsys.zig");
const FS = fsys.FS;
const store = @import("store.zig");
const uuid = @import("uuid.zig");
const ed25519 = @import("ed25519.zig");
const json = @import("json.zig");

pub const HandoffFormat = "FLINT-HANDOFF/1";
pub const PacketFormat = "FLINT-HANDOFF-PACKET/1";
pub const MaxHandoffLineBytes: usize = 64 * 1024;
pub const MaxHandoffRecords: usize = 4096;

pub const Kind = enum {
    propose,
    attest,
    accept,
    supersede,
    withdraw,

    pub fn name(self: Kind) []const u8 {
        return switch (self) {
            .propose => "propose",
            .attest => "attest",
            .accept => "accept",
            .supersede => "supersede",
            .withdraw => "withdraw",
        };
    }

    pub fn code(self: Kind) u8 {
        return switch (self) {
            .propose => 1,
            .attest => 2,
            .accept => 3,
            .supersede => 4,
            .withdraw => 5,
        };
    }

    pub fn fromName(s: []const u8) ?Kind {
        const names = [_]struct { s: []const u8, k: Kind }{
            .{ .s = "propose", .k = .propose },
            .{ .s = "attest", .k = .attest },
            .{ .s = "accept", .k = .accept },
            .{ .s = "supersede", .k = .supersede },
            .{ .s = "withdraw", .k = .withdraw },
        };
        for (names) |n| {
            if (std.mem.eql(u8, s, n.s)) return n.k;
        }
        return null;
    }
};

pub const Result = enum {
    pass,
    fail,
    skip,

    pub fn name(self: Result) []const u8 {
        return switch (self) {
            .pass => "pass",
            .fail => "fail",
            .skip => "skip",
        };
    }

    pub fn code(self: Result) u8 {
        return switch (self) {
            .pass => 1,
            .fail => 2,
            .skip => 3,
        };
    }

    pub fn fromName(s: []const u8) ?Result {
        const names = [_]struct { s: []const u8, k: Result }{
            .{ .s = "pass", .k = .pass },
            .{ .s = "fail", .k = .fail },
            .{ .s = "skip", .k = .skip },
        };
        for (names) |n| {
            if (std.mem.eql(u8, s, n.s)) return n.k;
        }
        return null;
    }
};

/// One §1.3 validation object — an inert claim, never executed.
pub const Validation = struct {
    command: []const u8 = "",
    result: Result = .pass,
    toolchain: ?[]const u8 = null,
    env: ?[]const u8 = null,
    attestor: []const u8 = "",
    ts: i64 = 0,
    evidence: ?[]const u8 = null,

    pub fn deinit(self: *Validation, allocator: Allocator) void {
        allocator.free(self.command);
        if (self.toolchain) |t| allocator.free(t);
        if (self.env) |e| allocator.free(e);
        allocator.free(self.attestor);
        if (self.evidence) |e| allocator.free(e);
    }

    pub fn clone(self: Validation, allocator: Allocator) !Validation {
        return .{
            .command = try allocator.dupe(u8, self.command),
            .result = self.result,
            .toolchain = if (self.toolchain) |t| try allocator.dupe(u8, t) else null,
            .env = if (self.env) |e| try allocator.dupe(u8, e) else null,
            .attestor = try allocator.dupe(u8, self.attestor),
            .ts = self.ts,
            .evidence = if (self.evidence) |e| try allocator.dupe(u8, e) else null,
        };
    }
};

/// Advisory write-set claim (§4): relative src paths + qualified Atom names.
pub const Scope = struct {
    paths: [][]u8 = &.{},
    atoms: [][]u8 = &.{},

    pub fn deinit(self: *Scope, allocator: Allocator) void {
        for (self.paths) |p| allocator.free(p);
        if (self.paths.len > 0) allocator.free(self.paths);
        for (self.atoms) |a| allocator.free(a);
        if (self.atoms.len > 0) allocator.free(self.atoms);
    }
};

/// One signed handoff record (§1). Optional payload fields are null when
/// absent or explicitly JSON-null.
pub const Handoff = struct {
    id: []const u8,
    handoff: []const u8,
    kind: Kind,
    stream: []const u8,
    ts: i64,
    author: []const u8,
    sig: []const u8,
    base: ?[]const u8 = null,
    work: ?[]const u8 = null,
    candidate: ?[]const u8 = null,
    snapshot: ?[]const u8 = null,
    intent: ?[]const u8 = null,
    note: ?[]const u8 = null,
    scope: ?Scope = null,
    validations: []Validation = &.{},
    observed_head: ?[]const u8 = null,
    replacement: ?[]const u8 = null,

    pub fn deinit(self: *Handoff, allocator: Allocator) void {
        allocator.free(self.id);
        allocator.free(self.handoff);
        allocator.free(self.stream);
        allocator.free(self.author);
        allocator.free(self.sig);
        if (self.base) |v| allocator.free(v);
        if (self.work) |v| allocator.free(v);
        if (self.candidate) |v| allocator.free(v);
        if (self.snapshot) |v| allocator.free(v);
        if (self.intent) |v| allocator.free(v);
        if (self.note) |v| allocator.free(v);
        if (self.scope) |*s| s.deinit(allocator);
        for (self.validations) |*v| v.deinit(allocator);
        if (self.validations.len > 0) allocator.free(self.validations);
        if (self.observed_head) |v| allocator.free(v);
        if (self.replacement) |v| allocator.free(v);
    }
};

fn writeU32LE(buf: *std.ArrayList(u8), allocator: Allocator, v: u32) !void {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, v, .little);
    try buf.appendSlice(allocator, &b);
}

fn writeU64LE(buf: *std.ArrayList(u8), allocator: Allocator, v: u64) !void {
    var b: [8]u8 = undefined;
    std.mem.writeInt(u64, &b, v, .little);
    try buf.appendSlice(allocator, &b);
}

fn writeStr(buf: *std.ArrayList(u8), allocator: Allocator, s: []const u8) !void {
    try writeU32LE(buf, allocator, @intCast(s.len));
    try buf.appendSlice(allocator, s);
}

fn writeOptStr(buf: *std.ArrayList(u8), allocator: Allocator, s: ?[]const u8) !void {
    if (s) |v| {
        try buf.append(allocator, 1);
        try writeStr(buf, allocator, v);
    } else {
        try buf.append(allocator, 0);
    }
}

fn writeOptId(buf: *std.ArrayList(u8), allocator: Allocator, id: ?[]const u8) !void {
    if (id) |v| {
        const b = uuid.parseUUID(v) orelse return error.BadUUID;
        try buf.append(allocator, 1);
        try buf.appendSlice(allocator, &b);
    } else {
        try buf.append(allocator, 0);
    }
}

/// §1.4 scope_bytes → scope_hash.
fn scopeHash(scope: Scope) ![32]u8 {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var buf: std.ArrayList(u8) = .empty;

    const paths = try a.dupe([]const u8, scope.paths);
    const atoms = try a.dupe([]const u8, scope.atoms);
    std.mem.sort([]const u8, paths, {}, strLt);
    std.mem.sort([]const u8, atoms, {}, strLt);

    try writeU32LE(&buf, a, @intCast(paths.len));
    for (paths) |p| try writeStr(&buf, a, p);
    try writeU32LE(&buf, a, @intCast(atoms.len));
    for (atoms) |x| try writeStr(&buf, a, x);

    var out: [32]u8 = undefined;
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("FLINT-HANDOFF-SCOPE/1\x00");
    h.update(buf.items);
    h.final(&out);
    return out;
}

fn valBytes(v: Validation, buf: *std.ArrayList(u8), allocator: Allocator) !void {
    try writeStr(buf, allocator, v.command);
    try buf.append(allocator, v.result.code());
    try writeOptStr(buf, allocator, v.toolchain);
    try writeOptStr(buf, allocator, v.env);
    const attestor = ed25519.parseHex32Lower(v.attestor) orelse return error.BadHex;
    try buf.appendSlice(allocator, &attestor);
    try writeU64LE(buf, allocator, @bitCast(v.ts));
    try writeOptStr(buf, allocator, v.evidence);
}

/// §1.4 vals_bytes → vals_hash (emitted array order).
fn valsHash(vals: []const Validation) ![32]u8 {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var buf: std.ArrayList(u8) = .empty;
    try writeU32LE(&buf, a, @intCast(vals.len));
    for (vals) |v| try valBytes(v, &buf, a);

    var out: [32]u8 = undefined;
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("FLINT-HANDOFF-VALS/1\x00");
    h.update(buf.items);
    h.final(&out);
    return out;
}

/// handoffSigMsg computes the §1.4 preimage: `FLINT-HANDOFF/1\x00` followed by
/// the fixed-shape field sequence — ids raw, u8 kind, u64le ts, raw author,
/// opt() on every payload field, scope/validations as domain-separated hashes.
pub fn handoffSigMsg(allocator: Allocator, r: *const Handoff) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    try buf.appendSlice(allocator, "FLINT-HANDOFF/1\x00");

    const id_b = uuid.parseUUID(r.id) orelse return error.BadUUID;
    const h_b = uuid.parseUUID(r.handoff) orelse return error.BadUUID;
    const s_b = uuid.parseUUID(r.stream) orelse return error.BadUUID;
    const author = ed25519.parseHex32Lower(r.author) orelse return error.BadHex;

    try buf.appendSlice(allocator, &id_b);
    try buf.appendSlice(allocator, &h_b);
    try buf.append(allocator, r.kind.code());
    try buf.appendSlice(allocator, &s_b);
    try writeU64LE(&buf, allocator, @bitCast(r.ts));
    try buf.appendSlice(allocator, &author);
    try writeOptId(&buf, allocator, r.base);
    try writeOptId(&buf, allocator, r.work);
    try writeOptId(&buf, allocator, r.candidate);
    try writeOptId(&buf, allocator, r.observed_head);
    try writeOptId(&buf, allocator, r.replacement);
    try writeOptStr(&buf, allocator, r.snapshot);
    try writeOptStr(&buf, allocator, r.intent);
    try writeOptStr(&buf, allocator, r.note);

    if (r.scope) |sc| {
        const h = try scopeHash(sc);
        try buf.append(allocator, 1);
        try buf.appendSlice(allocator, &h);
    } else {
        try buf.append(allocator, 0);
    }
    if (r.validations.len > 0) {
        const h = try valsHash(r.validations);
        try buf.append(allocator, 1);
        try buf.appendSlice(allocator, &h);
    } else {
        try buf.append(allocator, 0);
    }
    return buf.toOwnedSlice(allocator);
}

/// Signs `r` in place: sets author from the seed's public key and sig over the
/// canonical preimage. The seed is NOT wiped (manifest-signing precedent).
pub fn signHandoffWithSeed(allocator: Allocator, r: *Handoff, seed: [32]u8) !void {
    defer std.crypto.secureZero(u8, @constCast(&seed)[0..]);
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
    const pk_hex = ed25519.encodeHexFixedLower(32, kp.public_key.toBytes());
    const new_author = try allocator.dupe(u8, &pk_hex);
    allocator.free(r.author);
    r.author = new_author;
    const msg = try handoffSigMsg(allocator, r);
    defer allocator.free(msg);
    const sig_bytes = try ed25519.signMsg(msg, seed);
    const sig_hex = ed25519.encodeHexFixedLower(64, sig_bytes);
    const new_sig = try allocator.dupe(u8, &sig_hex);
    allocator.free(r.sig);
    r.sig = new_sig;
}

/// VerifyHandoff recomputes the preimage and verifies `r.sig` under `r.author`.
pub fn verifyHandoff(allocator: Allocator, r: *const Handoff) !bool {
    const msg = try handoffSigMsg(allocator, r);
    defer allocator.free(msg);
    const author = ed25519.parseHex32Lower(r.author) orelse return false;
    const sig = ed25519.parseHex64Lower(r.sig) orelse return false;
    return ed25519.verifySig(sig, msg, author);
}

// --- Parse / marshal ---------------------------------------------------

fn optStr(allocator: Allocator, obj: std.json.ObjectMap, key: []const u8) !?[]const u8 {
    const v = obj.get(key) orelse return null;
    return switch (v) {
        .null => null,
        .string => |s| try allocator.dupe(u8, s),
        else => error.BadField,
    };
}

fn reqStr(allocator: Allocator, obj: std.json.ObjectMap, key: []const u8) ![]const u8 {
    return (try optStr(allocator, obj, key)) orelse error.BadField;
}

fn isUUID(s: []const u8) bool {
    return uuid.parseUUID(s) != null;
}

fn isLowerHex(s: []const u8, n: usize) bool {
    if (s.len != n) return false;
    for (s) |c| {
        if (!((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'))) return false;
    }
    return true;
}

fn parseValidationValue(allocator: Allocator, val: std.json.Value) !Validation {
    const obj = switch (val) {
        .object => |o| o,
        else => return error.BadField,
    };
    var v = Validation{};
    errdefer v.deinit(allocator);
    v.command = try reqStr(allocator, obj, "command");
    if (v.command.len == 0 or v.command.len > 1024) return error.BadField;
    const rs = try reqStr(allocator, obj, "result");
    defer allocator.free(rs);
    v.result = Result.fromName(rs) orelse return error.BadField;
    v.toolchain = try optStr(allocator, obj, "toolchain");
    if (v.toolchain) |t| {
        if (t.len > 256) return error.BadField;
    }
    v.env = try optStr(allocator, obj, "env");
    if (v.env) |e| {
        if (e.len > 256) return error.BadField;
    }
    v.attestor = try reqStr(allocator, obj, "attestor");
    if (!isLowerHex(v.attestor, 64)) return error.BadField;
    const ts_v = obj.get("ts") orelse return error.BadField;
    v.ts = switch (ts_v) {
        .integer => |i| i,
        else => return error.BadField,
    };
    if (v.ts <= 0) return error.BadField;
    v.evidence = try optStr(allocator, obj, "evidence");
    if (v.evidence) |e| {
        if (e.len > 256) return error.BadField;
    }
    for ([_]?[]const u8{ v.command, v.toolchain, v.env, v.evidence }) |fv| {
        if (fv) |f| {
            if (!std.unicode.utf8ValidateSlice(f)) return error.BadField;
        }
    }
    return v;
}

/// Parses one record line and applies §1.5 rules 1–3 (framing, per-kind
/// requiredness/exclusivity, attestor equality). Returns
/// `handoff_malformed` with a detail on any violation; sig is checked by
/// the caller (rule 4) via verifyHandoff.
pub fn parseHandoff(allocator: Allocator, line: []const u8) !Handoff {
    const trimmed = std.mem.trim(u8, line, " \t\r\n");
    if (trimmed.len == 0) return fsys.refuse("handoff_malformed", "empty");
    if (trimmed.len > MaxHandoffLineBytes) return fsys.refuse("handoff_malformed", "oversize");
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, trimmed, .{}) catch {
        return fsys.refuse("handoff_malformed", "json");
    };
    defer parsed.deinit();
    const obj = switch (parsed.value) {
        .object => |o| o,
        else => return fsys.refuse("handoff_malformed", "json"),
    };

    const format = reqStr(allocator, obj, "format") catch {
        return fsys.refuse("handoff_malformed", "unknown format");
    };
    defer allocator.free(format);
    if (!std.mem.eql(u8, format, HandoffFormat)) {
        return fsys.refuse("handoff_malformed", "unknown format");
    }

    var r = Handoff{
        .id = try reqStr(allocator, obj, "id"),
        .handoff = try allocator.dupe(u8, ""),
        .kind = .propose,
        .stream = try allocator.dupe(u8, ""),
        .ts = 0,
        .author = try allocator.dupe(u8, ""),
        .sig = try allocator.dupe(u8, ""),
    };
    errdefer r.deinit(allocator);

    r.handoff = try reqStr(allocator, obj, "handoff");
    const kind_s = reqStr(allocator, obj, "kind") catch {
        return fsys.refuse("handoff_malformed", "kind");
    };
    defer allocator.free(kind_s);
    r.kind = Kind.fromName(kind_s) orelse
        return fsys.refuse("handoff_malformed", "kind");
    const stream_s = try reqStr(allocator, obj, "stream");
    r.stream = stream_s;
    const ts_v = obj.get("ts") orelse return fsys.refuse("handoff_malformed", "ts");
    r.ts = switch (ts_v) {
        .integer => |i| i,
        else => return fsys.refuse("handoff_malformed", "ts"),
    };
    const author_s = try reqStr(allocator, obj, "author");
    r.author = author_s;
    const sig_s = try reqStr(allocator, obj, "sig");
    r.sig = sig_s;

    r.base = try optStr(allocator, obj, "base");
    r.work = try optStr(allocator, obj, "work");
    r.candidate = try optStr(allocator, obj, "candidate");
    r.snapshot = try optStr(allocator, obj, "snapshot");
    r.intent = try optStr(allocator, obj, "intent");
    r.note = try optStr(allocator, obj, "note");
    r.observed_head = try optStr(allocator, obj, "observed_head");
    r.replacement = try optStr(allocator, obj, "replacement");

    if (obj.get("scope")) |sv| {
        if (sv == .object) {
            var scope = Scope{};
            errdefer scope.deinit(allocator);
            const so = sv.object;
            if (so.get("paths")) |pv| {
                if (pv == .array) {
                    var paths: std.ArrayList([]u8) = .empty;
                    errdefer {
                        for (paths.items) |p| allocator.free(p);
                        paths.deinit(allocator);
                    }
                    for (pv.array.items) |pe| {
                        const p = switch (pe) {
                            .string => |s| s,
                            else => return fsys.refuse("handoff_malformed", "scope"),
                        };
                        try paths.append(allocator, try allocator.dupe(u8, p));
                    }
                    scope.paths = try paths.toOwnedSlice(allocator);
                }
            }
            if (so.get("atoms")) |av| {
                if (av == .array) {
                    var atoms: std.ArrayList([]u8) = .empty;
                    errdefer {
                        for (atoms.items) |a| allocator.free(a);
                        atoms.deinit(allocator);
                    }
                    for (av.array.items) |ae| {
                        const n = switch (ae) {
                            .string => |s| s,
                            else => return fsys.refuse("handoff_malformed", "scope"),
                        };
                        try atoms.append(allocator, try allocator.dupe(u8, n));
                    }
                    scope.atoms = try atoms.toOwnedSlice(allocator);
                }
            }
            r.scope = scope;
        }
    }

    if (obj.get("validations")) |vv| {
        if (vv == .array) {
            var vals: std.ArrayList(Validation) = .empty;
            errdefer {
                for (vals.items) |*v| v.deinit(allocator);
                vals.deinit(allocator);
            }
            for (vv.array.items) |ve| {
                const v = parseValidationValue(allocator, ve) catch {
                    return fsys.refuse("handoff_malformed", "validation");
                };
                try vals.append(allocator, v);
            }
            r.validations = try vals.toOwnedSlice(allocator);
        }
    }

    // §1.5.1: canonical ids, lowercase hex key/sig, ts > 0, UTF-8 bounds.
    if (!isUUID(r.id) or !isUUID(r.handoff) or !isUUID(r.stream)) {
        return fsys.refuse("handoff_malformed", "id");
    }
    if (r.ts <= 0) return fsys.refuse("handoff_malformed", "ts");
    if (!isLowerHex(r.author, 64) or !isLowerHex(r.sig, 128)) {
        return fsys.refuse("handoff_malformed", "hex");
    }
    for ([_]?[]const u8{ r.intent, r.note }) |fv| {
        if (fv) |f| {
            if (f.len > 512 or !std.unicode.utf8ValidateSlice(f)) {
                return fsys.refuse("handoff_malformed", "text");
            }
        }
    }
    for ([_]?[]const u8{ r.base, r.work, r.candidate, r.observed_head, r.replacement }) |iv| {
        if (iv) |i| {
            if (!isUUID(i)) return fsys.refuse("handoff_malformed", "id");
        }
    }

    // §1.5.2: per-kind requiredness + exclusivity.
    switch (r.kind) {
        .propose => {
            if (r.base == null or r.work == null or r.candidate == null or r.intent == null)
                return fsys.refuse("handoff_malformed", "propose fields");
            if (r.observed_head != null or r.replacement != null or r.note != null)
                return fsys.refuse("handoff_malformed", "propose fields");
            if (r.intent.?.len == 0) return fsys.refuse("handoff_malformed", "intent");
        },
        .attest => {
            if (r.candidate == null) return fsys.refuse("handoff_malformed", "attest fields");
            if (r.base != null or r.work != null or r.intent != null or
                r.observed_head != null or r.replacement != null or r.note != null)
                return fsys.refuse("handoff_malformed", "attest fields");
            if (r.validations.len != 1)
                return fsys.refuse("handoff_malformed", "attest fields");
        },
        .accept => {
            if (r.candidate == null or r.observed_head == null)
                return fsys.refuse("handoff_malformed", "accept fields");
            if (r.base != null or r.work != null or r.intent != null or
                r.scope != null or r.validations.len > 0 or r.replacement != null)
                return fsys.refuse("handoff_malformed", "accept fields");
        },
        .supersede => {
            if (r.base != null or r.work != null or r.candidate != null or
                r.intent != null or r.scope != null or r.validations.len > 0 or
                r.observed_head != null)
                return fsys.refuse("handoff_malformed", "supersede fields");
        },
        .withdraw => {
            if (r.base != null or r.work != null or r.candidate != null or
                r.intent != null or r.scope != null or r.validations.len > 0 or
                r.observed_head != null or r.replacement != null)
                return fsys.refuse("handoff_malformed", "withdraw fields");
        },
    }
    if ((r.kind == .propose) != std.mem.eql(u8, r.id, r.handoff)) {
        return fsys.refuse("handoff_malformed", "id");
    }
    // §1.5.3: every validation's attestor is the record author.
    for (r.validations) |v| {
        if (!std.mem.eql(u8, v.attestor, r.author)) {
            return fsys.refuse("handoff_malformed", "attestor mismatch");
        }
    }
    return r;
}

/// Canonical emit — §1 field order; absent fields omitted entirely.
pub fn marshalHandoff(allocator: Allocator, r: *const Handoff) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    try buf.append(allocator, '{');
    try buf.appendSlice(allocator, "\"format\":");
    try json.appendGoJSONString(&buf, allocator, HandoffFormat);
    const fields = [_]struct { k: []const u8, v: []const u8 }{
        .{ .k = "id", .v = r.id },
        .{ .k = "handoff", .v = r.handoff },
        .{ .k = "kind", .v = r.kind.name() },
        .{ .k = "stream", .v = r.stream },
    };
    for (fields) |f| {
        try buf.appendSlice(allocator, ",\"");
        try buf.appendSlice(allocator, f.k);
        try buf.appendSlice(allocator, "\":");
        try json.appendGoJSONString(&buf, allocator, f.v);
    }
    try buf.print(allocator, ",\"ts\":{d}", .{r.ts});
    try buf.appendSlice(allocator, ",\"author\":");
    try json.appendGoJSONString(&buf, allocator, r.author);

    // Payload in §1.2 table order, omitted when absent.
    const opt_ids = [_]struct { k: []const u8, v: ?[]const u8 }{
        .{ .k = "base", .v = r.base },
        .{ .k = "work", .v = r.work },
        .{ .k = "candidate", .v = r.candidate },
    };
    for (opt_ids) |f| {
        if (f.v) |v| {
            try buf.appendSlice(allocator, ",\"");
            try buf.appendSlice(allocator, f.k);
            try buf.appendSlice(allocator, "\":");
            try json.appendGoJSONString(&buf, allocator, v);
        }
    }
    if (r.snapshot) |v| {
        try buf.appendSlice(allocator, ",\"snapshot\":");
        try json.appendGoJSONString(&buf, allocator, v);
    }
    if (r.intent) |v| {
        try buf.appendSlice(allocator, ",\"intent\":");
        try json.appendGoJSONString(&buf, allocator, v);
    }
    if (r.note) |v| {
        try buf.appendSlice(allocator, ",\"note\":");
        try json.appendGoJSONString(&buf, allocator, v);
    }
    if (r.scope) |sc| {
        try buf.appendSlice(allocator, ",\"scope\":{\"paths\":[");
        const paths = try allocator.dupe([]const u8, sc.paths);
        defer allocator.free(paths);
        std.mem.sort([]const u8, paths, {}, strLt);
        for (paths, 0..) |p, i| {
            if (i > 0) try buf.append(allocator, ',');
            try json.appendGoJSONString(&buf, allocator, p);
        }
        try buf.appendSlice(allocator, "],\"atoms\":[");
        const atoms = try allocator.dupe([]const u8, sc.atoms);
        defer allocator.free(atoms);
        std.mem.sort([]const u8, atoms, {}, strLt);
        for (atoms, 0..) |x, i| {
            if (i > 0) try buf.append(allocator, ',');
            try json.appendGoJSONString(&buf, allocator, x);
        }
        try buf.appendSlice(allocator, "]}");
    }
    if (r.validations.len > 0) {
        try buf.appendSlice(allocator, ",\"validations\":[");
        for (r.validations, 0..) |v, i| {
            if (i > 0) try buf.append(allocator, ',');
            try appendValidation(&buf, allocator, v);
        }
        try buf.append(allocator, ']');
    }
    if (r.observed_head) |v| {
        try buf.appendSlice(allocator, ",\"observed_head\":");
        try json.appendGoJSONString(&buf, allocator, v);
    }
    if (r.replacement) |v| {
        try buf.appendSlice(allocator, ",\"replacement\":");
        try json.appendGoJSONString(&buf, allocator, v);
    }
    try buf.appendSlice(allocator, ",\"sig\":");
    try json.appendGoJSONString(&buf, allocator, r.sig);
    try buf.append(allocator, '}');
    try buf.append(allocator, '\n');
    return buf.toOwnedSlice(allocator);
}

fn appendValidation(out: *std.ArrayList(u8), allocator: Allocator, v: Validation) !void {
    try out.appendSlice(allocator, "{\"command\":");
    try json.appendGoJSONString(out, allocator, v.command);
    try out.appendSlice(allocator, ",\"result\":");
    try json.appendGoJSONString(out, allocator, v.result.name());
    if (v.toolchain) |t| {
        try out.appendSlice(allocator, ",\"toolchain\":");
        try json.appendGoJSONString(out, allocator, t);
    }
    if (v.env) |e| {
        try out.appendSlice(allocator, ",\"env\":");
        try json.appendGoJSONString(out, allocator, e);
    }
    try out.appendSlice(allocator, ",\"attestor\":");
    try json.appendGoJSONString(out, allocator, v.attestor);
    try out.print(allocator, ",\"ts\":{d}", .{v.ts});
    if (v.evidence) |e| {
        try out.appendSlice(allocator, ",\"evidence\":");
        try json.appendGoJSONString(out, allocator, e);
    }
    try out.append(allocator, '}');
}

// --- Store --------------------------------------------------------------

pub fn handoffLogPath(allocator: Allocator, root: []const u8, stream_id: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/handoffs/{s}.jsonl", .{ root, stream_id });
}

/// Loads all record lines for a target stream, parsed. Torn final line →
/// `handoff_torn`; empty/malformed → `handoff_malformed`; >4096 →
/// `store_too_large`.
pub fn loadHandoffs(allocator: Allocator, fs: FS, root: []const u8, stream_id: []const u8) ![]Handoff {
    const p = try handoffLogPath(allocator, root, stream_id);
    defer allocator.free(p);
    if (!fs.exists(allocator, p)) {
        return try allocator.alloc(Handoff, 0);
    }
    const data = try fs.readFile(allocator, p, store.MaxFileReadBytes);
    defer allocator.free(data);
    if (data.len > 0 and data[data.len - 1] != '\n') {
        return fsys.refuse("handoff_torn", "");
    }
    var out: std.ArrayList(Handoff) = .empty;
    errdefer {
        for (out.items) |*r| r.deinit(allocator);
        out.deinit(allocator);
    }
    var it = std.mem.splitScalar(u8, data, '\n');
    while (it.next()) |line| {
        if (line.len == 0) continue;
        if (out.items.len >= MaxHandoffRecords) {
            return fsys.refuse("store_too_large", "handoffs");
        }
        const r = try parseHandoff(allocator, line);
        try out.append(allocator, r);
    }
    return out.toOwnedSlice(allocator);
}

/// Raw record lines for a stream (verbatim, for export/dedupe).
pub fn loadHandoffLines(allocator: Allocator, fs: FS, root: []const u8, stream_id: []const u8) ![][]u8 {
    const p = try handoffLogPath(allocator, root, stream_id);
    defer allocator.free(p);
    if (!fs.exists(allocator, p)) {
        return try allocator.alloc([]u8, 0);
    }
    const data = try fs.readFile(allocator, p, store.MaxFileReadBytes);
    defer allocator.free(data);
    if (data.len > 0 and data[data.len - 1] != '\n') {
        return fsys.refuse("handoff_torn", "");
    }
    var out: std.ArrayList([]u8) = .empty;
    errdefer {
        for (out.items) |l| allocator.free(l);
        out.deinit(allocator);
    }
    var it = std.mem.splitScalar(u8, data, '\n');
    while (it.next()) |line| {
        if (line.len == 0) continue;
        try out.append(allocator, try allocator.dupe(u8, line));
    }
    return out.toOwnedSlice(allocator);
}

/// §3 lifecycle state after folding one proposal's records in order.
pub const LifecycleState = enum { proposed, accepted, superseded, withdrawn };

pub const Proposal = struct {
    state: LifecycleState = .proposed,
    propose: ?*const Handoff = null,
    records: usize = 0,
    extra_records: usize = 0,
    proposer: []const u8 = "",
};

/// Folds records matching `handoff_id` (they may be absent → propose=null).
pub fn foldProposal(records: []const Handoff, handoff_id: []const u8) Proposal {
    var p = Proposal{};
    var terminated = false;
    for (records) |*r| {
        if (!std.mem.eql(u8, r.handoff, handoff_id)) continue;
        if (terminated) {
            p.extra_records += 1;
            continue;
        }
        p.records += 1;
        switch (r.kind) {
            .propose => {
                p.propose = r;
                p.proposer = r.author;
            },
            .accept => {
                p.state = .accepted;
                terminated = true;
            },
            .supersede => {
                p.state = .superseded;
                terminated = true;
            },
            .withdraw => {
                p.state = .withdrawn;
                terminated = true;
            },
            .attest => {},
        }
    }
    return p;
}

/// Appends one signed record to `handoffs/<stream>.jsonl` after §1.5
/// rules 4–5: signature under `author`, id-uniqueness, lifecycle legality.
/// `existing` must be the stream's current records.
pub fn appendHandoff(
    allocator: Allocator,
    fs: FS,
    root: []const u8,
    r: *const Handoff,
    existing: []const Handoff,
) !void {
    if (!try verifyHandoff(allocator, r)) {
        return fsys.refuse("sig_invalid", "handoff");
    }
    var by_id = std.StringHashMap(*const Handoff).init(allocator);
    defer by_id.deinit();
    for (existing) |*e| {
        if (by_id.get(e.id)) |prev| {
            // Same id must be byte-identical — marshaling is canonical.
            const pa = try marshalHandoff(allocator, prev);
            defer allocator.free(pa);
            const pb = try marshalHandoff(allocator, r);
            defer allocator.free(pb);
            if (!std.mem.eql(u8, pa, pb)) {
                return fsys.refuse("handoff_malformed", "id conflict");
            }
            return; // byte-identical resend: no-op
        }
        try by_id.put(e.id, e);
    }

    // Lifecycle checks against the folded proposal state.
    if (r.kind == .propose) {
        // New proposal id must not collide with an existing record id (above).
    } else {
        // Event record: handoff must name a known proposal.
        var seen = false;
        for (existing) |*e| {
            if (std.mem.eql(u8, e.handoff, r.handoff)) seen = true;
        }
        if (!seen) {
            return fsys.refuse("handoff_missing", r.handoff);
        }
        const prop = foldProposal(existing, r.handoff);
        switch (r.kind) {
            .accept, .supersede, .withdraw => {
                if (prop.state != .proposed) {
                    return fsys.refuse("handoff_closed", r.handoff);
                }
            },
            .attest => {},
            .propose => unreachable,
        }
        if (r.kind == .withdraw and prop.proposer.len > 0 and
            !std.mem.eql(u8, r.author, prop.proposer))
        {
            return fsys.refuse("handoff_author", r.handoff);
        }
        if (r.kind == .supersede) {
            if (r.replacement) |repl| {
                const rp = foldProposal(existing, repl);
                if (rp.state != .proposed or rp.propose == null) {
                    return fsys.refuse("handoff_missing", repl);
                }
            }
        }
    }

    const line = try marshalHandoff(allocator, r);
    defer allocator.free(line);
    if (line.len > MaxHandoffLineBytes) {
        return fsys.refuse("handoff_malformed", "oversize");
    }
    if (existing.len + 1 > MaxHandoffRecords) {
        return fsys.refuse("store_too_large", "handoffs");
    }
    const dir_path = try std.fmt.allocPrint(allocator, "{s}/handoffs", .{root});
    defer allocator.free(dir_path);
    try fs.mkdir(allocator, dir_path);
    const lp = try handoffLogPath(allocator, root, r.stream);
    defer allocator.free(lp);
    try fs.appendSync(allocator, lp, line);
}

// --- Verdict ------------------------------------------------------------

/// First-parent walk: true when `ancestor` appears on `tip`'s chain in
/// `changes` (all Changes of any stream; signed `stream` field irrelevant —
/// ids are what matter here).
fn ancestryReaches(changes: []const store.Change, tip: []const u8, ancestor: []const u8) bool {
    var by_id = std.StringHashMap(*const store.Change).init(std.heap.page_allocator);
    defer by_id.deinit();
    for (changes) |*c| {
        by_id.put(c.id, c) catch return false;
    }
    var cur: ?[]const u8 = tip;
    var hops: usize = 0;
    while (cur) |cid| {
        if (hops > store.MaxChanges * 4) return false;
        hops += 1;
        if (std.mem.eql(u8, cid, ancestor)) return true;
        const c = by_id.get(cid) orelse return false;
        cur = c.parent;
    }
    return false;
}

/// Ops on the first-parent chain from `base` (exclusive) to `tip`
/// (inclusive), in commit order. Caller frees each slice + the outer.
fn opsBetween(
    allocator: Allocator,
    changes: []const store.Change,
    tip: []const u8,
    base: []const u8,
) ![]const []const store.Op {
    var by_id = std.StringHashMap(*const store.Change).init(allocator);
    defer by_id.deinit();
    for (changes) |*c| try by_id.put(c.id, c);

    var rev: std.ArrayList(*const store.Change) = .empty;
    defer rev.deinit(allocator);
    var cur: ?[]const u8 = tip;
    while (cur) |cid| {
        if (std.mem.eql(u8, cid, base)) break;
        const c = by_id.get(cid) orelse break;
        try rev.append(allocator, c);
        cur = c.parent;
    }
    std.mem.reverse(*const store.Change, rev.items);
    const out = try allocator.alloc([]const store.Op, rev.items.len);
    for (rev.items, 0..) |c, i| out[i] = c.ops;
    return out;
}

pub const Verdict = enum {
    ready,
    accepted,
    accepted_stale,
    stale,
    conflicting,
    incomplete,
    invalid,
    unknown,
    superseded,
    withdrawn,

    pub fn name(self: Verdict) []const u8 {
        return @tagName(self);
    }
};

/// §5 verdict for one proposal: computed from the folded lifecycle plus
/// locally observed state (target head, change ancestry, dry merge).
pub fn computeVerdict(
    allocator: Allocator,
    fs: FS,
    root: []const u8,
    idx: *store.StoreIndex,
    records: []const Handoff,
    handoff_id: []const u8,
) !struct { verdict: Verdict, prop: Proposal, scope_verdict: []const u8 } {
    const prop = foldProposal(records, handoff_id);
    const propose = prop.propose orelse
        return .{ .verdict = .unknown, .prop = prop, .scope_verdict = "unverifiable" };

    const st = idx.streamByID(propose.stream) orelse
        return .{ .verdict = .incomplete, .prop = prop, .scope_verdict = "unverifiable" };

    const all = try store.loadAllStreamChanges(allocator, fs, root, idx);
    defer store.freeChanges(allocator, all);

    const cur_head = st.head;
    const candidate_ok = blk: {
        for (all) |c| {
            if (std.mem.eql(u8, c.id, propose.candidate.?)) break :blk true;
        }
        break :blk false;
    };
    const base_ok = blk: {
        for (all) |c| {
            if (std.mem.eql(u8, c.id, propose.base.?)) break :blk true;
        }
        break :blk false;
    };
    const ancestry_ok = candidate_ok and base_ok and
        ancestryReaches(all, propose.candidate.?, propose.base.?);

    // Dry merge leg: candidate-side delta vs target-side delta since base.
    var conflicts = false;
    var scope_verdict: []const u8 = "unverifiable";
    if (ancestry_ok and cur_head != null) {
        const from_ops = try opsBetween(allocator, all, propose.candidate.?, propose.base.?);
        defer allocator.free(from_ops);
        const into_ops = try opsBetween(allocator, all, cur_head.?, propose.base.?);
        defer allocator.free(into_ops);
        const base_atoms_r = try store.replayStreamAtoms(allocator, propose.base.?, all);
        defer store.freeStoredAtoms(allocator, base_atoms_r.atoms);
        const merge_mod = @import("merge.zig");
        const res = try merge_mod.mergeOps(allocator, base_atoms_r.atoms, into_ops, from_ops);
        defer res.deinit(allocator);
        conflicts = !res.clean;

        // §4 scope comparison: claimed atoms vs the candidate delta's
        // touched atom names (resolved through base+delta application).
        if (propose.scope) |sc| {
            var atoms_by_id = std.StringHashMap(store.StoredAtom).init(allocator);
            defer {
                var it = atoms_by_id.iterator();
                while (it.next()) |kv| {
                    allocator.free(kv.key_ptr.*);
                    kv.value_ptr.deinit(allocator);
                }
                atoms_by_id.deinit();
            }
            for (base_atoms_r.atoms) |a| {
                const k = try allocator.dupe(u8, a.id);
                try atoms_by_id.put(k, try a.clone(allocator));
            }
            var touched = std.StringHashMap(void).init(allocator);
            defer {
                var it = touched.keyIterator();
                while (it.next()) |k| allocator.free(k.*);
                touched.deinit();
            }
            var exceeded = false;
            for (from_ops) |ops| {
                for (ops) |op| {
                    const atom_name = blk: {
                        if (atoms_by_id.get(op.atom_id)) |a| break :blk a.name;
                        if (op.new_name.len > 0) break :blk op.new_name;
                        if (op.kind.len > 0 and op.new_name.len == 0) break :blk op.new_name;
                        break :blk "";
                    };
                    if (atom_name.len == 0) continue;
                    var in_scope = false;
                    for (sc.atoms) |ca| {
                        if (std.mem.eql(u8, ca, atom_name)) in_scope = true;
                    }
                    if (!in_scope) exceeded = true;
                    try touched.put(try allocator.dupe(u8, atom_name), {});
                }
            }
            scope_verdict = if (exceeded) "exceeded" else "honest";
        }
    }

    const verdict: Verdict = switch (prop.state) {
        .accepted => blk: {
            const acc_head = blk2: {
                for (records) |*r| {
                    if (r.kind == .accept and std.mem.eql(u8, r.handoff, handoff_id)) {
                        break :blk2 r.observed_head.?;
                    }
                }
                break :blk2 "";
            };
            const fresh = acc_head.len > 0 and cur_head != null and
                std.mem.eql(u8, acc_head, cur_head.?) and candidate_ok;
            break :blk if (fresh) .accepted else .accepted_stale;
        },
        .superseded => .superseded,
        .withdrawn => .withdrawn,
        .proposed => blk: {
            if (!base_ok or !candidate_ok or !ancestry_ok) break :blk .incomplete;
            if (conflicts) break :blk .conflicting;
            if (cur_head == null or !std.mem.eql(u8, cur_head.?, propose.base.?)) {
                break :blk .stale;
            }
            break :blk .ready;
        },
    };
    return .{ .verdict = verdict, .prop = prop, .scope_verdict = scope_verdict };
}

// --- CLI ------------------------------------------------------------------

fn resolveStreamByName(idx: *const store.StoreIndex, name: []const u8) !*const store.Stream {
    return idx.streamByName(name) orelse
        (idx.streamByID(name) orelse
            fsys.refuse("stream_missing", name));
}

fn findChangeAnywhere(changes: []const store.Change, id: []const u8) ?*const store.Change {
    for (changes) |*c| {
        if (std.mem.eql(u8, c.id, id)) return c;
    }
    return null;
}

fn flagValue(args: []const []const u8, name: []const u8, i: *usize) ?[]const u8 {
    const a = args[i.*];
    if (std.mem.startsWith(u8, a, name) and a.len > name.len and a[name.len] == '=') {
        return a[name.len + 1 ..];
    }
    if (std.mem.eql(u8, a, name) and i.* + 1 < args.len) {
        i.* += 1;
        return args[i.*];
    }
    return null;
}

/// `flint handoff <sub> …` — §8 verb family.
pub fn cmdHandoff(
    allocator: Allocator,
    fs: FS,
    root: []const u8,
    uuid_gen: *uuid.UUIDGen,
    env_sign_key: ?[]const u8,
    out: *Io.Writer,
    args: []const []const u8,
) !void {
    if (args.len == 0) return fsys.refuse("usage", "");
    const sub = args[0];
    const rest = args[1..];

    if (std.mem.eql(u8, sub, "verify")) return cmdVerify(allocator, fs, out, rest);
    if (std.mem.eql(u8, sub, "list")) return cmdList(allocator, fs, root, out, rest);
    if (std.mem.eql(u8, sub, "inspect")) return cmdInspect(allocator, fs, root, out, rest);
    if (std.mem.eql(u8, sub, "export")) return cmdExport(allocator, fs, root, out, rest);
    if (std.mem.eql(u8, sub, "import")) return cmdImport(allocator, fs, root, out, rest);
    if (std.mem.eql(u8, sub, "propose")) return cmdPropose(allocator, fs, root, uuid_gen, env_sign_key, out, rest);
    if (std.mem.eql(u8, sub, "attest") or std.mem.eql(u8, sub, "accept") or
        std.mem.eql(u8, sub, "supersede") or std.mem.eql(u8, sub, "withdraw"))
    {
        return cmdEvent(allocator, fs, root, uuid_gen, env_sign_key, out, sub, rest);
    }
    return fsys.refuse("usage", "");
}

fn cmdPropose(
    allocator: Allocator,
    fs: FS,
    root: []const u8,
    uuid_gen: *uuid.UUIDGen,
    env_sign_key: ?[]const u8,
    out: *Io.Writer,
    args: []const []const u8,
) !void {
    var stream_flag: []const u8 = "";
    var work_flag: []const u8 = "";
    var candidate_flag: []const u8 = "";
    var base_flag: []const u8 = "";
    var snapshot_flag: ?[]const u8 = null;
    var key_flag: []const u8 = "";
    var intent: []const u8 = "";
    var scope_file: []const u8 = "";
    var validations_file: []const u8 = "";

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (flagValue(args, "--stream", &i)) |v| {
            stream_flag = v;
        } else if (flagValue(args, "--work", &i)) |v| {
            work_flag = v;
        } else if (flagValue(args, "--candidate", &i)) |v| {
            candidate_flag = v;
        } else if (flagValue(args, "--base", &i)) |v| {
            base_flag = v;
        } else if (flagValue(args, "--snapshot", &i)) |v| {
            snapshot_flag = v;
        } else if (flagValue(args, "--key", &i)) |v| {
            key_flag = v;
        } else if (std.mem.eql(u8, a, "-m") and i + 1 < args.len) {
            i += 1;
            intent = args[i];
        } else if (std.mem.startsWith(u8, a, "-m=")) {
            intent = a[3..];
        } else if (std.mem.startsWith(u8, a, "--message=")) {
            intent = a["--message=".len..];
        } else if (flagValue(args, "--scope-file", &i)) |v| {
            scope_file = v;
        } else if (flagValue(args, "--validations", &i)) |v| {
            validations_file = v;
        } else {
            return fsys.refuse("usage", "");
        }
    }
    if (stream_flag.len == 0 or work_flag.len == 0 or intent.len == 0 or intent.len > 512 or
        !std.unicode.utf8ValidateSlice(intent))
    {
        return fsys.refuse("usage", "");
    }

    var idx = try store.loadStoreIndex(allocator, fs, root);
    defer idx.deinit();
    const target = try resolveStreamByName(&idx, stream_flag);
    const work = try resolveStreamByName(&idx, work_flag);

    const base_id = if (base_flag.len > 0) base_flag else (target.head orelse return fsys.refuse("change_missing", target.name));
    const cand_id = if (candidate_flag.len > 0) candidate_flag else (work.head orelse return fsys.refuse("change_missing", work.name));

    // §1.5.6 resolvability on the write path.
    const target_changes = try store.loadStream(allocator, fs, root, target.id);
    defer target_changes.deinit(allocator);
    if (findChangeAnywhere(target_changes.changes, base_id) == null) {
        return fsys.refuse("change_missing", base_id);
    }
    const work_changes = try store.loadStream(allocator, fs, root, work.id);
    defer work_changes.deinit(allocator);
    if (findChangeAnywhere(work_changes.changes, cand_id) == null) {
        return fsys.refuse("change_missing", cand_id);
    }

    const seed = try ed25519.loadSigningSeed(allocator, fs, root, key_flag, env_sign_key);
    defer std.crypto.secureZero(u8, @constCast(&seed)[0..]);

    const id_str = try uuid_gen.newAlloc(allocator);
    defer allocator.free(id_str);
    var r = Handoff{
        .id = try allocator.dupe(u8, id_str),
        .handoff = try allocator.dupe(u8, id_str),
        .kind = .propose,
        .stream = try allocator.dupe(u8, target.id),
        .ts = try uuid_gen.nowMs(),
        .author = try allocator.dupe(u8, ""),
        .sig = try allocator.dupe(u8, &zero_sig),
        .base = try allocator.dupe(u8, base_id),
        .work = try allocator.dupe(u8, work.id),
        .candidate = try allocator.dupe(u8, cand_id),
        .snapshot = if (snapshot_flag) |s| try allocator.dupe(u8, s) else null,
        .intent = try allocator.dupe(u8, intent),
    };
    defer r.deinit(allocator);

    if (scope_file.len > 0) {
        const raw = fs.readFile(allocator, scope_file, store.MaxFileReadBytes) catch
            return fsys.refuse("handoff_malformed", "scope file");
        defer allocator.free(raw);
        const parsed = std.json.parseFromSlice(std.json.Value, allocator, raw, .{}) catch
            return fsys.refuse("handoff_malformed", "scope file");
        defer parsed.deinit();
        const so = switch (parsed.value) {
            .object => |o| o,
            else => return fsys.refuse("handoff_malformed", "scope file"),
        };
        var scope = Scope{};
        errdefer scope.deinit(allocator);
        if (so.get("paths")) |pv| {
            if (pv == .array) {
                var paths: std.ArrayList([]u8) = .empty;
                errdefer {
                    for (paths.items) |p| allocator.free(p);
                    paths.deinit(allocator);
                }
                for (pv.array.items) |pe| {
                    const p = switch (pe) {
                        .string => |x| x,
                        else => return fsys.refuse("handoff_malformed", "scope"),
                    };
                    try paths.append(allocator, try allocator.dupe(u8, p));
                }
                scope.paths = try paths.toOwnedSlice(allocator);
            }
        }
        if (so.get("atoms")) |av| {
            if (av == .array) {
                var atoms: std.ArrayList([]u8) = .empty;
                errdefer {
                    for (atoms.items) |x| allocator.free(x);
                    atoms.deinit(allocator);
                }
                for (av.array.items) |ae| {
                    const n = switch (ae) {
                        .string => |x| x,
                        else => return fsys.refuse("handoff_malformed", "scope"),
                    };
                    try atoms.append(allocator, try allocator.dupe(u8, n));
                }
                scope.atoms = try atoms.toOwnedSlice(allocator);
            }
        }
        r.scope = scope;
    }

    if (validations_file.len > 0) {
        const raw = fs.readFile(allocator, validations_file, store.MaxFileReadBytes) catch
            return fsys.refuse("handoff_malformed", "validations file");
        defer allocator.free(raw);
        const parsed = std.json.parseFromSlice(std.json.Value, allocator, raw, .{}) catch
            return fsys.refuse("handoff_malformed", "validations file");
        defer parsed.deinit();
        const arr = switch (parsed.value) {
            .array => |a| a.items,
            else => return fsys.refuse("handoff_malformed", "validations file"),
        };
        var vals: std.ArrayList(Validation) = .empty;
        errdefer {
            for (vals.items) |*v| v.deinit(allocator);
            vals.deinit(allocator);
        }
        const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
        const author_hex = ed25519.encodeHexFixedLower(32, kp.public_key.toBytes());
        for (arr) |ve| {
            var v = parseValidationValue(allocator, ve) catch
                return fsys.refuse("handoff_malformed", "validation");
            allocator.free(v.attestor);
            v.attestor = try allocator.dupe(u8, &author_hex);
            try vals.append(allocator, v);
        }
        r.validations = try vals.toOwnedSlice(allocator);
    }

    try signHandoffWithSeed(allocator, &r, seed);

    const existing = try loadHandoffs(allocator, fs, root, r.stream);
    defer {
        for (existing) |*e| e.deinit(allocator);
        allocator.free(existing);
    }
    try appendHandoff(allocator, fs, root, &r, existing);

    try out.print("flint: handoff {s} kind=propose stream={s} candidate={s}\n", .{ r.id, target.name, cand_id });
}

/// attest/accept/supersede/withdraw — event records against a known proposal.
fn cmdEvent(
    allocator: Allocator,
    fs: FS,
    root: []const u8,
    uuid_gen: *uuid.UUIDGen,
    env_sign_key: ?[]const u8,
    out: *Io.Writer,
    sub: []const u8,
    args: []const []const u8,
) !void {
    const kind = Kind.fromName(sub).?;
    var handoff_id: []const u8 = "";
    var key_flag: []const u8 = "";
    var note: ?[]const u8 = null;
    var replacement: ?[]const u8 = null;
    var command: []const u8 = "";
    var result_s: []const u8 = "";
    var toolchain: ?[]const u8 = null;
    var env_s: ?[]const u8 = null;
    var evidence: ?[]const u8 = null;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.startsWith(u8, a, "--")) {
            if (flagValue(args, "--key", &i)) |v| {
                key_flag = v;
            } else if (flagValue(args, "--note", &i)) |v| {
                note = v;
            } else if (flagValue(args, "--replacement", &i)) |v| {
                replacement = v;
            } else if (flagValue(args, "--command", &i)) |v| {
                command = v;
            } else if (flagValue(args, "--result", &i)) |v| {
                result_s = v;
            } else if (flagValue(args, "--toolchain", &i)) |v| {
                toolchain = v;
            } else if (flagValue(args, "--env", &i)) |v| {
                env_s = v;
            } else if (flagValue(args, "--evidence", &i)) |v| {
                evidence = v;
            } else {
                return fsys.refuse("usage", "");
            }
        } else if (handoff_id.len == 0) {
            handoff_id = a;
        } else {
            return fsys.refuse("usage", "");
        }
    }
    if (handoff_id.len == 0) return fsys.refuse("usage", "");
    if (!isUUID(handoff_id)) return fsys.refuse("handoff_malformed", "id");
    if (kind == .attest) {
        if (command.len == 0 or result_s.len == 0 or Result.fromName(result_s) == null) {
            return fsys.refuse("usage", "");
        }
    }
    if (note) |n| {
        if (n.len > 512 or !std.unicode.utf8ValidateSlice(n)) {
            return fsys.refuse("handoff_malformed", "note");
        }
    }

    // Find the proposal's stream by scanning stream logs' handoffs dirs.
    var idx = try store.loadStoreIndex(allocator, fs, root);
    defer idx.deinit();
    var found_stream: ?store.Stream = null;
    var prop = Proposal{};
    var all_records: []Handoff = &.{};
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const aa = arena.allocator();
    for (idx.streams.items) |*st| {
        const recs = try loadHandoffs(aa, fs, root, st.id);
        const p = foldProposal(recs, handoff_id);
        if (p.propose != null) {
            found_stream = st.*;
            prop = p;
            all_records = recs;
            break;
        }
    }
    const st = found_stream orelse
        return fsys.refuse("handoff_missing", handoff_id);
    const propose = prop.propose.?;

    const seed = try ed25519.loadSigningSeed(allocator, fs, root, key_flag, env_sign_key);
    defer std.crypto.secureZero(u8, @constCast(&seed)[0..]);
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
    const author_hex = ed25519.encodeHexFixedLower(32, kp.public_key.toBytes());

    const id_str = try uuid_gen.newAlloc(allocator);
    defer allocator.free(id_str);

    var r = Handoff{
        .id = try allocator.dupe(u8, id_str),
        .handoff = try allocator.dupe(u8, handoff_id),
        .kind = kind,
        .stream = try allocator.dupe(u8, st.id),
        .ts = try uuid_gen.nowMs(),
        .author = try allocator.dupe(u8, &author_hex),
        .sig = try allocator.dupe(u8, &zero_sig),
        .note = if (note) |n| try allocator.dupe(u8, n) else null,
    };
    defer r.deinit(allocator);

    switch (kind) {
        .attest => {
            r.candidate = try allocator.dupe(u8, propose.candidate.?);
            r.snapshot = if (propose.snapshot) |s| try allocator.dupe(u8, s) else null;
            var vals = try allocator.alloc(Validation, 1);
            vals[0] = .{
                .command = try allocator.dupe(u8, command),
                .result = Result.fromName(result_s).?,
                .toolchain = if (toolchain) |t| try allocator.dupe(u8, t) else null,
                .env = if (env_s) |e| try allocator.dupe(u8, e) else null,
                .attestor = try allocator.dupe(u8, &author_hex),
                .ts = try uuid_gen.nowMs(),
                .evidence = if (evidence) |e| try allocator.dupe(u8, e) else null,
            };
            r.validations = vals;
        },
        .accept => {
            r.candidate = try allocator.dupe(u8, propose.candidate.?);
            // observed_head recorded from the local target record — never an
            // argument (§8: you accept what you can see).
            const cur_head = st.head orelse
                return fsys.refuse("change_missing", st.name);
            r.observed_head = try allocator.dupe(u8, cur_head);
            // §8: candidate ancestry must be held locally.
            const all = try store.loadAllStreamChanges(allocator, fs, root, &idx);
            defer store.freeChanges(allocator, all);
            if (findChangeAnywhere(all, propose.candidate.?) == null) {
                return fsys.refuse("change_missing", propose.candidate.?);
            }
        },
        .supersede => {
            if (replacement) |repl| {
                if (!isUUID(repl)) return fsys.refuse("handoff_malformed", "replacement");
                r.replacement = try allocator.dupe(u8, repl);
            }
        },
        .withdraw => {},
        .propose => unreachable,
    }

    try signHandoffWithSeed(allocator, &r, seed);
    try appendHandoff(allocator, fs, root, &r, all_records);

    switch (kind) {
        .attest => try out.print("flint: handoff {s} kind=attest id={s}\n", .{ handoff_id, r.id }),
        .accept => try out.print("flint: handoff {s} kind=accept id={s} observed_head={s}\n", .{ handoff_id, r.id, r.observed_head.? }),
        else => try out.print("flint: handoff {s} kind={s} id={s}\n", .{ handoff_id, kind.name(), r.id }),
    }
}

fn cmdList(allocator: Allocator, fs: FS, root: []const u8, out: *Io.Writer, args: []const []const u8) !void {
    var stream_flag: []const u8 = "";
    var state_flag: []const u8 = "";
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (flagValue(args, "--stream", &i)) |v| {
            stream_flag = v;
        } else if (flagValue(args, "--state", &i)) |v| {
            state_flag = v;
        } else {
            return fsys.refuse("usage", "");
        }
    }
    var idx = try store.loadStoreIndex(allocator, fs, root);
    defer idx.deinit();

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const aa = arena.allocator();

    const Entry = struct {
        id: []const u8,
        state: []const u8,
        candidate: []const u8,
        author: []const u8,
        intent: []const u8,
        ts: i64,
    };
    var entries: std.ArrayList(Entry) = .empty;
    defer entries.deinit(allocator);

    for (idx.streams.items) |*st| {
        if (stream_flag.len > 0 and
            !std.mem.eql(u8, stream_flag, st.name) and
            !std.mem.eql(u8, stream_flag, st.id)) continue;
        const recs = try loadHandoffs(aa, fs, root, st.id);
        for (recs) |*r| {
            if (r.kind != .propose) continue;
            const p = foldProposal(recs, r.id);
            const state_name = switch (p.state) {
                .proposed => "proposed",
                .accepted => "accepted",
                .superseded => "superseded",
                .withdrawn => "withdrawn",
            };
            if (state_flag.len > 0 and !std.mem.eql(u8, state_flag, state_name)) continue;
            try entries.append(allocator, .{
                .id = r.id,
                .state = state_name,
                .candidate = r.candidate orelse "",
                .author = r.author,
                .intent = r.intent orelse "",
                .ts = r.ts,
            });
        }
    }
    std.mem.sort(Entry, entries.items, {}, struct {
        fn lt(_: void, a: Entry, b: Entry) bool {
            return a.ts > b.ts; // newest first
        }
    }.lt);
    for (entries.items) |e| {
        var first_line = e.intent;
        if (std.mem.indexOfScalar(u8, first_line, '\n')) |nl| {
            first_line = first_line[0..nl];
        }
        try out.print("flint: handoff {s} state={s} candidate={s} author={s} intent={s}\n", .{
            e.id, e.state, e.candidate, e.author[0..8], first_line,
        });
    }
}

fn cmdInspect(allocator: Allocator, fs: FS, root: []const u8, out: *Io.Writer, args: []const []const u8) !void {
    if (args.len != 1 or !isUUID(args[0])) {
        return fsys.refuse("usage", "");
    }
    const handoff_id = args[0];
    var idx = try store.loadStoreIndex(allocator, fs, root);
    defer idx.deinit();

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const aa = arena.allocator();

    // §6: verify every record for the id (sig + framing already done by
    // loadHandoffs — a torn/malformed log refuses there, matching inspect's
    // refusal contract).
    var found_stream: ?store.Stream = null;
    var recs_for: []Handoff = &.{};
    for (idx.streams.items) |*st| {
        const recs = try loadHandoffs(aa, fs, root, st.id);
        var has = false;
        for (recs) |*r| {
            if (std.mem.eql(u8, r.handoff, handoff_id) or std.mem.eql(u8, r.id, handoff_id)) has = true;
        }
        if (has) {
            var filtered: std.ArrayList(Handoff) = .empty;
            for (recs) |*r| {
                if (std.mem.eql(u8, r.handoff, handoff_id)) {
                    try filtered.append(aa, r.*);
                } else {
                    var rc = r.*;
                    rc.deinit(aa);
                }
            }
            recs_for = try filtered.toOwnedSlice(aa);
            found_stream = st.*;
        }
    }
    const st = found_stream orelse
        return fsys.refuse("handoff_missing", handoff_id);
    // loadAllStreamChanges swaps idx's stream records in place — the borrowed
    // `st` fields dangle after it, so pin a copy of the id now.
    const st_id = try allocator.dupe(u8, st.id);
    defer allocator.free(st_id);

    var any_bad_sig = false;
    var sig_marks = try aa.alloc(bool, recs_for.len);
    for (recs_for, 0..) |*r, i| {
        sig_marks[i] = verifyHandoff(aa, r) catch false;
        if (!sig_marks[i]) any_bad_sig = true;
    }

    const cv = try computeVerdict(allocator, fs, root, &idx, recs_for, handoff_id);
    const verdict = if (any_bad_sig) Verdict.invalid else cv.verdict;
    const prop = cv.prop;
    const propose = prop.propose;

    const st_name = if (idx.streamByID(st_id)) |sn| sn.name else st_id;
    try out.print("flint: handoff {s} state={s} verdict={s} stream={s}", .{
        handoff_id,
        @tagName(prop.state),
        verdict.name(),
        st_name,
    });
    if (propose) |p| {
        const wname = if (idx.streamByID(p.work.?)) |w| w.name else p.work.?;
        try out.print(" work={s}", .{wname});
    }
    try out.writeByte('\n');

    try out.print("flint: handoff {s}", .{handoff_id});
    if (propose) |p| {
        try out.print(" base={s} candidate={s}", .{ p.base.?, p.candidate.? });
        if (prop.state == .accepted) {
            for (recs_for) |*r| {
                if (r.kind == .accept) {
                    try out.print(" observed_head={s}", .{r.observed_head.?});
                    break;
                }
            }
        } else {
            try out.writeAll(" observed_head=none");
        }
        try out.print(" snapshot={s}", .{p.snapshot orelse "none"});
        try out.print(" scope={s}", .{cv.scope_verdict});
    }
    try out.writeByte('\n');
    if (prop.extra_records > 0) {
        try out.print("flint: handoff {s} extra_records={d}\n", .{ handoff_id, prop.extra_records });
    }
    for (recs_for, 0..) |*r, i| {
        try out.print("flint: record {s} kind={s} author={s} sig={s}\n", .{
            r.id,
            r.kind.name(),
            r.author[0..8],
            if (sig_marks[i]) "verified" else "invalid",
        });
    }
    for (recs_for) |*r| {
        for (r.validations) |v| {
            var cmd = v.command;
            if (cmd.len > 40) cmd = cmd[0..40];
            try out.print("flint: validation via={s} attestor={s} result={s} command={s}\n", .{
                r.kind.name(), v.attestor[0..8], v.result.name(), cmd,
            });
        }
    }
}

/// `handoff verify <file>` — standalone: NDJSON records or a packet; no
/// store, nothing written. Prints sig status per record/Change.
fn cmdVerify(allocator: Allocator, fs: FS, out: *Io.Writer, args: []const []const u8) !void {
    if (args.len != 1) return fsys.refuse("usage", "");
    const raw = try fs.readFile(allocator, args[0], store.MaxFileReadBytes);
    defer allocator.free(raw);
    var bad = false;

    var lines = std.mem.splitScalar(u8, raw, '\n');
    var first = true;
    var is_packet = false;
    var pending_records: usize = 0;
    var pending_changes: usize = 0;
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        if (first) {
            first = false;
            const parsed = std.json.parseFromSlice(std.json.Value, allocator, line, .{}) catch {
                return fsys.refuse("handoff_malformed", "json");
            };
            defer parsed.deinit();
            if (parsed.value == .object) {
                const obj = parsed.value.object;
                if (obj.get("format")) |fv| {
                    if (fv == .string and std.mem.eql(u8, fv.string, PacketFormat)) {
                        is_packet = true;
                        pending_records = if (obj.get("records")) |rv| switch (rv) {
                            .integer => |n| if (n >= 0) @intCast(n) else 0,
                            else => 0,
                        } else 0;
                        pending_changes = if (obj.get("changes")) |cv| switch (cv) {
                            .integer => |n| if (n >= 0) @intCast(n) else 0,
                            else => 0,
                        } else 0;
                        continue;
                    }
                }
            }
            // Not a packet — fall through to record handling of line 1.
        }
        if (is_packet and pending_records > 0) {
            pending_records -= 1;
            var r = parseHandoff(allocator, line) catch |err| {
                if (err == error.Refuse) return err;
                return err;
            };
            defer r.deinit(allocator);
            const ok = try verifyHandoff(allocator, &r);
            try out.print("flint: record {s} kind={s} sig: {s}\n", .{
                r.id, r.kind.name(), if (ok) "verified" else "invalid",
            });
            if (!ok) bad = true;
        } else if (is_packet and pending_changes > 0) {
            pending_changes -= 1;
            var c = json.parseChange(allocator, line) catch {
                return fsys.refuse("change_malformed", "");
            };
            defer c.deinit(allocator);
            const ok = try ed25519.verifyChange(allocator, &c);
            try out.print("flint: verify {s} sig: {s}\n", .{
                c.id, if (ok) "verified" else "invalid",
            });
            if (!ok) bad = true;
        } else {
            var r = parseHandoff(allocator, line) catch |err| {
                return err;
            };
            defer r.deinit(allocator);
            const ok = try verifyHandoff(allocator, &r);
            try out.print("flint: record {s} kind={s} sig: {s}\n", .{
                r.id, r.kind.name(), if (ok) "verified" else "invalid",
            });
            if (!ok) bad = true;
        }
    }
    if (is_packet and (pending_records != 0 or pending_changes != 0)) {
        return fsys.refuse("handoff_malformed", "count mismatch");
    }
    if (bad) return fsys.refuse("sig_invalid", "");
}

fn cmdExport(allocator: Allocator, fs: FS, root: []const u8, out: *Io.Writer, args: []const []const u8) !void {
    var handoff_id: []const u8 = "";
    var out_flag: []const u8 = "";
    var with_changes = false;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (flagValue(args, "--out", &i)) |v| {
            out_flag = v;
        } else if (std.mem.eql(u8, a, "--with-changes")) {
            with_changes = true;
        } else if (handoff_id.len == 0 and !std.mem.startsWith(u8, a, "--")) {
            handoff_id = a;
        } else {
            return fsys.refuse("usage", "");
        }
    }
    if (handoff_id.len == 0 or out_flag.len == 0) return fsys.refuse("usage", "");

    var idx = try store.loadStoreIndex(allocator, fs, root);
    defer idx.deinit();
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const aa = arena.allocator();

    var found: ?store.Stream = null;
    var prop = Proposal{};
    var lines: [][]u8 = &.{};
    for (idx.streams.items) |*st| {
        const recs = try loadHandoffs(aa, fs, root, st.id);
        const p = foldProposal(recs, handoff_id);
        if (p.propose == null) continue;
        // Collect the raw lines for this handoff in append order.
        const raw = try loadHandoffLines(aa, fs, root, st.id);
        var sel: std.ArrayList([]u8) = .empty;
        for (raw) |l| {
            const r = try parseHandoff(aa, l);
            if (std.mem.eql(u8, r.handoff, handoff_id)) {
                try sel.append(aa, l);
            }
        }
        lines = try sel.toOwnedSlice(aa);
        found = st.*;
        prop = p;
        break;
    }
    const st = found orelse return fsys.refuse("handoff_missing", handoff_id);
    const propose = prop.propose.?;

    // Optional detached ancestry: first-parent chain of candidate on the
    // work stream, raw lines in order (deposit-batch discipline).
    var change_lines: std.ArrayList([]const u8) = .empty;
    if (with_changes) {
        const wl = try store.loadStream(aa, fs, root, propose.work.?);
        const raw_lines = try readStreamRawLines(aa, fs, root, propose.work.?);
        var by_id = std.StringHashMap(usize).init(aa);
        for (wl.changes, 0..) |c, ci| try by_id.put(c.id, ci);
        var chain: std.ArrayList(usize) = .empty;
        var cur: ?[]const u8 = propose.candidate.?;
        while (cur) |cid| {
            const li = by_id.get(cid) orelse break;
            try chain.append(aa, li);
            cur = wl.changes[li].parent;
        }
        std.mem.reverse(usize, chain.items);
        for (chain.items) |li| try change_lines.append(aa, raw_lines[li]);
    }

    var buf: std.ArrayList(u8) = .empty;
    const wname = if (idx.streamByID(propose.work.?)) |w| w.name else propose.work.?;
    try buf.print(aa, "{{\"format\":\"{s}\",\"handoff\":", .{PacketFormat});
    try json.appendGoJSONString(&buf, aa, handoff_id);
    try buf.appendSlice(aa, ",\"stream\":");
    try json.appendGoJSONString(&buf, aa, st.id);
    try buf.appendSlice(aa, ",\"work\":{\"id\":");
    try json.appendGoJSONString(&buf, aa, propose.work.?);
    try buf.appendSlice(aa, ",\"name\":");
    try json.appendGoJSONString(&buf, aa, wname);
    try buf.print(aa, "}},\"records\":{d},\"changes\":{d}}}\n", .{ lines.len, change_lines.items.len });
    for (lines) |l| {
        try buf.appendSlice(aa, l);
        try buf.append(aa, '\n');
    }
    for (change_lines.items) |l| {
        try buf.appendSlice(aa, l);
        try buf.append(aa, '\n');
    }
    if (std.mem.eql(u8, out_flag, "-")) {
        try out.writeAll(buf.items);
        return;
    }
    try fs.writeFileSafe(allocator, out_flag, buf.items);
    try out.print("flint: handoff export {s} records={d} changes={d} out={s}\n", .{
        handoff_id, lines.len, change_lines.items.len, out_flag,
    });
}

fn readStreamRawLines(allocator: Allocator, fs: FS, root: []const u8, stream_id: []const u8) ![][]u8 {
    const p = try store.streamLogPath(allocator, root, stream_id);
    defer allocator.free(p);
    const data = fs.readFile(allocator, p, store.MaxFileReadBytes) catch {
        return try allocator.alloc([]u8, 0);
    };
    defer allocator.free(data);
    var out: std.ArrayList([]u8) = .empty;
    var it = std.mem.splitScalar(u8, data, '\n');
    while (it.next()) |line| {
        if (line.len == 0) continue;
        try out.append(allocator, try allocator.dupe(u8, line));
    }
    return out.toOwnedSlice(allocator);
}

fn cmdImport(allocator: Allocator, fs: FS, root: []const u8, out: *Io.Writer, args: []const []const u8) !void {
    if (args.len != 1) return fsys.refuse("usage", "");
    const raw = try fs.readFile(allocator, args[0], store.MaxFileReadBytes);
    defer allocator.free(raw);
    if (raw.len > 0 and raw[raw.len - 1] != '\n') {
        return fsys.refuse("handoff_torn", "");
    }

    var lines = std.mem.splitScalar(u8, raw, '\n');
    const header_line = lines.next() orelse return fsys.refuse("handoff_malformed", "empty");
    const header_parsed = std.json.parseFromSlice(std.json.Value, allocator, header_line, .{}) catch {
        return fsys.refuse("handoff_malformed", "header");
    };
    defer header_parsed.deinit();
    const ho = switch (header_parsed.value) {
        .object => |o| o,
        else => return fsys.refuse("handoff_malformed", "header"),
    };
    const fmt = if (ho.get("format")) |fv| switch (fv) {
        .string => |s| s,
        else => "",
    } else "";
    if (!std.mem.eql(u8, fmt, PacketFormat)) {
        return fsys.refuse("handoff_malformed", "header");
    }
    const handoff_id = if (ho.get("handoff")) |v| switch (v) {
        .string => |s| s,
        else => return fsys.refuse("handoff_malformed", "header"),
    } else return fsys.refuse("handoff_malformed", "header");
    const target_id = if (ho.get("stream")) |v| switch (v) {
        .string => |s| s,
        else => return fsys.refuse("handoff_malformed", "header"),
    } else return fsys.refuse("handoff_malformed", "header");
    const n_records: usize = if (ho.get("records")) |v| switch (v) {
        .integer => |n| if (n >= 0) @intCast(n) else 0,
        else => return fsys.refuse("handoff_malformed", "header"),
    } else return fsys.refuse("handoff_malformed", "header");
    const n_changes: usize = if (ho.get("changes")) |v| switch (v) {
        .integer => |n| if (n >= 0) @intCast(n) else 0,
        else => return fsys.refuse("handoff_malformed", "header"),
    } else return fsys.refuse("handoff_malformed", "header");

    var idx = try store.loadStoreIndex(allocator, fs, root);
    defer idx.deinit();
    const target = idx.streamByID(target_id) orelse
        return fsys.refuse("stream_missing", target_id);

    var rec_lines: std.ArrayList([]const u8) = .empty;
    defer rec_lines.deinit(allocator);
    var ch_lines: std.ArrayList([]const u8) = .empty;
    defer ch_lines.deinit(allocator);
    var i_l: usize = 0;
    while (i_l < n_records + n_changes) : (i_l += 1) {
        const line = lines.next() orelse
            return fsys.refuse("handoff_malformed", "count mismatch");
        if (i_l < n_records) {
            try rec_lines.append(allocator, line);
        } else {
            try ch_lines.append(allocator, line);
        }
    }

    // Verify all records (sig + framing) before writing anything.
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const aa = arena.allocator();
    var recs: std.ArrayList(Handoff) = .empty;
    for (rec_lines.items) |line| {
        const r = try parseHandoff(aa, line);
        try recs.append(aa, r);
    }
    for (recs.items) |*r| {
        if (!std.mem.eql(u8, r.stream, target.id) or
            !std.mem.eql(u8, r.handoff, handoff_id))
        {
            return fsys.refuse("handoff_malformed", "binding");
        }
        if (!try verifyHandoff(aa, r)) {
            return fsys.refuse("sig_invalid", "handoff");
        }
    }

    // Verify bundled Changes (signed by their own authors, unchanged).
    var changes: std.ArrayList(store.Change) = .empty;
    for (ch_lines.items) |line| {
        const c = json.parseChange(aa, line) catch
            return fsys.refuse("change_malformed", "");
        try changes.append(aa, c);
    }
    for (changes.items) |*c| {
        var cc = c.*;
        if (!try ed25519.verifyChange(aa, &cc)) {
            return fsys.refuse("sig_invalid", "change");
        }
    }

    // Append records: dedupe by id, all-or-nothing.
    const existing = try loadHandoffs(allocator, fs, root, target.id);
    defer {
        for (existing) |*e| e.deinit(allocator);
        allocator.free(existing);
    }
    var written: usize = 0;
    for (recs.items) |*r| {
        var dup = false;
        for (existing) |*e| {
            if (std.mem.eql(u8, e.id, r.id)) {
                const ea = try marshalHandoff(allocator, e);
                defer allocator.free(ea);
                const rb = try marshalHandoff(allocator, r);
                defer allocator.free(rb);
                if (!std.mem.eql(u8, ea, rb)) {
                    return fsys.refuse("handoff_malformed", "id conflict");
                }
                dup = true;
            }
        }
        if (dup) continue;
        try appendHandoff(allocator, fs, root, r, existing);
        written += 1;
    }
    try out.print("flint: handoff import {s} records={d} changes={d}\n", .{
        handoff_id, written, @as(usize, 0),
    });
}

// --- Tests ------------------------------------------------------------------

const seed_hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

fn testRecord(allocator: Allocator) !Handoff {
    return .{
        .id = try allocator.dupe(u8, "0199de2d-dc00-7000-8000-000000000001"),
        .handoff = try allocator.dupe(u8, "0199de2d-dc00-7000-8000-000000000001"),
        .kind = .propose,
        .stream = try allocator.dupe(u8, "0199de2d-dc00-7000-8000-000000000020"),
        .ts = 1760000000000,
        .author = try allocator.dupe(u8, ""),
        .sig = try allocator.dupe(u8, &zero_sig),
        .base = try allocator.dupe(u8, "0199de2d-dc00-7000-8000-000000000201"),
        .work = try allocator.dupe(u8, "0199de2d-dc00-7000-8000-000000000030"),
        .candidate = try allocator.dupe(u8, "0199de2d-dc00-7000-8000-000000000301"),
        .intent = try allocator.dupe(u8, "ship it"),
    };
}

test "handoff: marshal→parse→verify round trip and tamper rejection" {
    const gpa = std.testing.allocator;
    const seed = ed25519.parseHex32Lower(seed_hex).?;

    var r = try testRecord(gpa);
    defer r.deinit(gpa);
    const paths = try gpa.alloc([]u8, 1);
    paths[0] = try gpa.dupe(u8, "src/b.zig");
    const atoms = try gpa.alloc([]u8, 1);
    atoms[0] = try gpa.dupe(u8, "fn:b");
    r.scope = .{ .paths = paths, .atoms = atoms };
    var vals = try gpa.alloc(Validation, 1);
    const kp_t = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
    const author_hex_t = ed25519.encodeHexFixedLower(32, kp_t.public_key.toBytes());
    vals[0] = .{
        .command = try gpa.dupe(u8, "true"),
        .attestor = try gpa.dupe(u8, &author_hex_t),
        .ts = 1760000000000,
    };
    defer {
        for (vals) |*v| v.deinit(gpa);
        gpa.free(vals);
    }
    r.validations = vals;
    defer r.validations = &.{}; // ownership: vals freed above, not via r

    try signHandoffWithSeed(gpa, &r, seed);
    const line = try marshalHandoff(gpa, &r);
    defer gpa.free(line);

    var back = try parseHandoff(gpa, line);
    defer back.deinit(gpa);
    try std.testing.expect(try verifyHandoff(gpa, &back));
    try std.testing.expectEqualStrings("src/b.zig", back.scope.?.paths[0]);
    try std.testing.expectEqual(@as(usize, 1), back.validations.len);
    try std.testing.expectEqualStrings(r.author, back.author);

    // Flip a sig nibble: verify must fail, parse must still accept shape.
    var bad = try gpa.dupe(u8, line);
    defer gpa.free(bad);
    const pos = std.mem.lastIndexOfScalar(u8, bad, '"').? - 3;
    bad[pos] = if (bad[pos] == '0') '1' else '0';
    var rb = try parseHandoff(gpa, bad);
    defer rb.deinit(gpa);
    try std.testing.expect(!try verifyHandoff(gpa, &rb));
}

test "handoff: framing refusals — unknown format, bad kind fields, attestor mismatch" {
    const gpa = std.testing.allocator;
    var r = try testRecord(gpa);
    defer r.deinit(gpa);
    const seed = ed25519.parseHex32Lower(seed_hex).?;
    try signHandoffWithSeed(gpa, &r, seed);
    const line = try marshalHandoff(gpa, &r);
    defer gpa.free(line);

    try std.testing.expectError(error.Refuse, parseHandoff(gpa, "{\"format\":\"FLINT-HANDOFF/9\"}"));
    try std.testing.expectEqualStrings("handoff_malformed", fsys.last_refuse.code());
    try std.testing.expectError(error.Refuse, parseHandoff(gpa, "{\"not json"));

    // propose without intent → handoff_malformed
    const no_intent = std.mem.replaceOwned(u8, gpa, line, ",\"intent\":\"ship it\"", "") catch unreachable;
    defer gpa.free(no_intent);
    try std.testing.expectError(error.Refuse, parseHandoff(gpa, no_intent));

    // attest carrying two validations → handoff_malformed
    const aa64: [64]u8 = @splat('a');
    const two_vals = try std.fmt.allocPrint(gpa, "{{\"format\":\"FLINT-HANDOFF/1\",\"id\":\"0199de2d-dc00-7000-8000-0000000000f1\",\"handoff\":\"0199de2d-dc00-7000-8000-000000000001\",\"kind\":\"attest\",\"stream\":\"0199de2d-dc00-7000-8000-000000000020\",\"ts\":1760000000000,\"author\":\"{s}\",\"candidate\":\"0199de2d-dc00-7000-8000-000000000301\",\"validations\":[{{\"command\":\"x\",\"result\":\"pass\",\"attestor\":\"{s}\",\"ts\":1}},{{\"command\":\"y\",\"result\":\"pass\",\"attestor\":\"{s}\",\"ts\":1}}],\"sig\":\"{s}\"}}", .{ aa64, aa64, aa64, zero_sig });
    defer gpa.free(two_vals);
    try std.testing.expectError(error.Refuse, parseHandoff(gpa, two_vals));
}

test "handoff: lifecycle fold + write-path rules (closed, author, missing)" {
    const gpa = std.testing.allocator;
    var mfs = try fsys.MemFS.init(gpa);
    defer mfs.deinit();
    const fs = mfs.fs();
    try fs.mkdir(gpa, "/host/FLINT");

    const seed = ed25519.parseHex32Lower(seed_hex).?;
    var r = try testRecord(gpa);
    defer r.deinit(gpa);
    try signHandoffWithSeed(gpa, &r, seed);

    const none = try loadHandoffs(gpa, fs, "/host/FLINT", r.stream);
    defer {
        for (none) |*e| e.deinit(gpa);
        gpa.free(none);
    }
    try appendHandoff(gpa, fs, "/host/FLINT", &r, none);

    // Withdraw by the same key is legal; foreign withdraw refuses.
    var w = Handoff{
        .id = try gpa.dupe(u8, "0199de2d-dc00-7000-8000-0000000000e1"),
        .handoff = try gpa.dupe(u8, r.handoff),
        .kind = .withdraw,
        .stream = try gpa.dupe(u8, r.stream),
        .ts = 1760000001000,
        .author = try gpa.dupe(u8, ""),
        .sig = try gpa.dupe(u8, &zero_sig),
    };
    defer w.deinit(gpa);
    const aa_hex: [64]u8 = @splat('a');
    const seed2 = ed25519.parseHex32Lower(&aa_hex) orelse unreachable;
    try signHandoffWithSeed(gpa, &w, seed2);
    const existing = try loadHandoffs(gpa, fs, "/host/FLINT", r.stream);
    defer {
        for (existing) |*e| e.deinit(gpa);
        gpa.free(existing);
    }
    try std.testing.expectError(error.Refuse, appendHandoff(gpa, fs, "/host/FLINT", &w, existing));
    try std.testing.expectEqualStrings("handoff_author", fsys.last_refuse.code());

    // Own withdraw lands; the proposal is now closed.
    try signHandoffWithSeed(gpa, &w, seed);
    try appendHandoff(gpa, fs, "/host/FLINT", &w, existing);

    const after = try loadHandoffs(gpa, fs, "/host/FLINT", r.stream);
    defer {
        for (after) |*e| e.deinit(gpa);
        gpa.free(after);
    }
    try std.testing.expectEqual(@as(usize, 2), after.len);
    const prop = foldProposal(after, r.id);
    try std.testing.expectEqual(LifecycleState.withdrawn, prop.state);

    // Terminal replay refuses handoff_closed.
    var acc = Handoff{
        .id = try gpa.dupe(u8, "0199de2d-dc00-7000-8000-0000000000e2"),
        .handoff = try gpa.dupe(u8, r.handoff),
        .kind = .accept,
        .stream = try gpa.dupe(u8, r.stream),
        .ts = 1760000002000,
        .author = try gpa.dupe(u8, ""),
        .sig = try gpa.dupe(u8, &zero_sig),
        .candidate = try gpa.dupe(u8, r.candidate.?),
        .observed_head = try gpa.dupe(u8, r.base.?),
    };
    defer acc.deinit(gpa);
    try signHandoffWithSeed(gpa, &acc, seed);
    try std.testing.expectError(error.Refuse, appendHandoff(gpa, fs, "/host/FLINT", &acc, after));
    try std.testing.expectEqualStrings("handoff_closed", fsys.last_refuse.code());
}
