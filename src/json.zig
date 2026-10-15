const std = @import("std");
const Allocator = std.mem.Allocator;
const fsys = @import("fsys.zig");
const store = @import("store.zig");
const ed25519 = @import("ed25519.zig");

const hex_digits = "0123456789abcdef";

/// Appends a JSON string literal with Go `encoding/json` HTML escaping:
/// `<`, `>`, `&`, U+2028 (`\xe2\x80\xa8`), U+2029 (`\xe2\x80\xa9`), `"`, `\`, `\n`, `\r`, `\t`,
/// and any control byte `< 0x20` as `\u00xx`.
pub fn appendGoJSONString(out: *std.ArrayList(u8), allocator: Allocator, s: []const u8) !void {
    try out.append(allocator, '"');
    var i: usize = 0;
    while (i < s.len) {
        const b = s[i];
        // Check for UTF-8 U+2028 (E2 80 A8) and U+2029 (E2 80 A9)
        if (b == 0xe2 and i + 2 < s.len and s[i + 1] == 0x80 and (s[i + 2] == 0xa8 or s[i + 2] == 0xa9)) {
            if (s[i + 2] == 0xa8) {
                try out.appendSlice(allocator, "\\u2028");
            } else {
                try out.appendSlice(allocator, "\\u2029");
            }
            i += 3;
            continue;
        }
        switch (b) {
            '"' => try out.appendSlice(allocator, "\\\""),
            '\\' => try out.appendSlice(allocator, "\\\\"),
            '\n' => try out.appendSlice(allocator, "\\n"),
            '\r' => try out.appendSlice(allocator, "\\r"),
            '\t' => try out.appendSlice(allocator, "\\t"),
            '<' => try out.appendSlice(allocator, "\\u003c"),
            '>' => try out.appendSlice(allocator, "\\u003e"),
            '&' => try out.appendSlice(allocator, "\\u0026"),
            0x00...0x08, 0x0b, 0x0c, 0x0e...0x1f => {
                const esc = [6]u8{ '\\', 'u', '0', '0', hex_digits[b >> 4], hex_digits[b & 0x0f] };
                try out.appendSlice(allocator, &esc);
            },
            else => try out.append(allocator, b),
        }
        i += 1;
    }
    try out.append(allocator, '"');
}

fn appendOptString(out: *std.ArrayList(u8), allocator: Allocator, s: ?[]const u8) !void {
    if (s) |val| {
        try appendGoJSONString(out, allocator, val);
    } else {
        try out.appendSlice(allocator, "null");
    }
}

fn appendInt64(out: *std.ArrayList(u8), allocator: Allocator, val: i64) !void {
    var buf: [32]u8 = undefined;
    const s = try std.fmt.bufPrint(&buf, "{d}", .{val});
    try out.appendSlice(allocator, s);
}

fn appendUint32(out: *std.ArrayList(u8), allocator: Allocator, val: u32) !void {
    var buf: [16]u8 = undefined;
    const s = try std.fmt.bufPrint(&buf, "{d}", .{val});
    try out.appendSlice(allocator, s);
}

/// Appends `Span` in Go struct field order: `{"file":...,"start":...,"end":...}`.
pub fn appendSpan(out: *std.ArrayList(u8), allocator: Allocator, sp: store.Span) !void {
    try out.appendSlice(allocator, "{\"file\":");
    try appendGoJSONString(out, allocator, sp.file);
    try out.appendSlice(allocator, ",\"start\":");
    try appendUint32(out, allocator, sp.start);
    try out.appendSlice(allocator, ",\"end\":");
    try appendUint32(out, allocator, sp.end);
    try out.append(allocator, '}');
}

fn metaLessThan(_: void, a: store.MetaEntry, b: store.MetaEntry) bool {
    return std.mem.lessThan(u8, a.key, b.key);
}

/// Appends `StoredAtom` in Go struct field order:
/// `id`, `kind`, `name`, `hash`, `sig_hash`, `span`, `metadata` (omitempty), `origin` (omitempty).
pub fn appendStoredAtom(out: *std.ArrayList(u8), allocator: Allocator, a: store.StoredAtom) !void {
    try out.appendSlice(allocator, "{\"id\":");
    try appendGoJSONString(out, allocator, a.id);
    try out.appendSlice(allocator, ",\"kind\":");
    try appendGoJSONString(out, allocator, a.kind);
    try out.appendSlice(allocator, ",\"name\":");
    try appendGoJSONString(out, allocator, a.name);
    try out.appendSlice(allocator, ",\"hash\":");
    try appendGoJSONString(out, allocator, a.hash);
    try out.appendSlice(allocator, ",\"sig_hash\":");
    try appendGoJSONString(out, allocator, a.sig_hash);
    try out.appendSlice(allocator, ",\"span\":");
    try appendSpan(out, allocator, a.span);

    if (a.metadata.len > 0) {
        const sorted_meta = try allocator.dupe(store.MetaEntry, a.metadata);
        defer allocator.free(sorted_meta);
        std.mem.sort(store.MetaEntry, sorted_meta, {}, metaLessThan);

        try out.appendSlice(allocator, ",\"metadata\":{");
        for (sorted_meta, 0..) |m, idx| {
            if (idx > 0) try out.append(allocator, ',');
            try appendGoJSONString(out, allocator, m.key);
            try out.append(allocator, ':');
            try appendGoJSONString(out, allocator, m.value);
        }
        try out.append(allocator, '}');
    }

    if (a.origin.len > 0) {
        try out.appendSlice(allocator, ",\"origin\":");
        try appendGoJSONString(out, allocator, a.origin);
    }

    try out.append(allocator, '}');
}

pub fn marshalStoredAtomLine(allocator: Allocator, a: store.StoredAtom) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try appendStoredAtom(&out, allocator, a);
    try out.append(allocator, '\n');
    return out.toOwnedSlice(allocator);
}

/// Appends `Op` in Go struct field order:
/// `type`, `atom_id`, `kind` (omitempty), `new_name` (omitempty), `new_span` (omitempty),
/// `new_hash` (omitempty), `new_sig_hash` (omitempty), `old_hash` (omitempty).
pub fn appendOp(out: *std.ArrayList(u8), allocator: Allocator, op: store.Op) !void {
    try out.appendSlice(allocator, "{\"type\":");
    try appendGoJSONString(out, allocator, op.type);
    try out.appendSlice(allocator, ",\"atom_id\":");
    try appendGoJSONString(out, allocator, op.atom_id);

    if (op.kind.len > 0) {
        try out.appendSlice(allocator, ",\"kind\":");
        try appendGoJSONString(out, allocator, op.kind);
    }
    if (op.new_name.len > 0) {
        try out.appendSlice(allocator, ",\"new_name\":");
        try appendGoJSONString(out, allocator, op.new_name);
    }
    if (op.new_span) |sp| {
        try out.appendSlice(allocator, ",\"new_span\":");
        try appendSpan(out, allocator, sp);
    }
    if (op.new_hash.len > 0) {
        try out.appendSlice(allocator, ",\"new_hash\":");
        try appendGoJSONString(out, allocator, op.new_hash);
    }
    if (op.new_sig_hash.len > 0) {
        try out.appendSlice(allocator, ",\"new_sig_hash\":");
        try appendGoJSONString(out, allocator, op.new_sig_hash);
    }
    if (op.old_hash.len > 0) {
        try out.appendSlice(allocator, ",\"old_hash\":");
        try appendGoJSONString(out, allocator, op.old_hash);
    }

    try out.append(allocator, '}');
}

pub fn marshalOpLine(allocator: Allocator, op: store.Op) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try appendOp(&out, allocator, op);
    try out.append(allocator, '\n');
    return out.toOwnedSlice(allocator);
}

/// Serializes `Change` as a single JSON line with sorted Ops and trailing `\n`
/// in Go struct field order: `id`, `parent`, `stream`, `ts`, `author`, `message`, `ops`, `merged`, `sig`.
pub fn marshalChangeLine(allocator: Allocator, c: store.Change) ![]u8 {
    const sorted_ops = try allocator.dupe(store.Op, c.ops);
    defer allocator.free(sorted_ops);
    store.sortOps(sorted_ops);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    try out.appendSlice(allocator, "{\"id\":");
    try appendGoJSONString(&out, allocator, c.id);
    try out.appendSlice(allocator, ",\"parent\":");
    try appendOptString(&out, allocator, c.parent);
    try out.appendSlice(allocator, ",\"stream\":");
    try appendGoJSONString(&out, allocator, c.stream);
    try out.appendSlice(allocator, ",\"ts\":");
    try appendInt64(&out, allocator, c.ts);
    try out.appendSlice(allocator, ",\"author\":");
    try appendGoJSONString(&out, allocator, c.author);
    try out.appendSlice(allocator, ",\"message\":");
    try appendGoJSONString(&out, allocator, c.message);
    try out.appendSlice(allocator, ",\"ops\":[");
    for (sorted_ops, 0..) |op, idx| {
        if (idx > 0) try out.append(allocator, ',');
        try appendOp(&out, allocator, op);
    }
    try out.appendSlice(allocator, "],\"merged\":");
    try appendOptString(&out, allocator, c.merged);
    try out.appendSlice(allocator, ",\"sig\":");
    try appendGoJSONString(&out, allocator, c.sig);
    try out.appendSlice(allocator, "}\n");

    return out.toOwnedSlice(allocator);
}

/// Serializes `Stream` as a single JSON line with trailing `\n`
/// in Go struct field order: `id`, `name`, `head`, `created`, `forked_from`.
pub fn marshalStreamLine(allocator: Allocator, st: store.Stream) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    try out.appendSlice(allocator, "{\"id\":");
    try appendGoJSONString(&out, allocator, st.id);
    try out.appendSlice(allocator, ",\"name\":");
    try appendGoJSONString(&out, allocator, st.name);
    try out.appendSlice(allocator, ",\"head\":");
    try appendOptString(&out, allocator, st.head);
    try out.appendSlice(allocator, ",\"created\":");
    try appendInt64(&out, allocator, st.created);
    try out.appendSlice(allocator, ",\"forked_from\":");
    if (st.forked_from) |ff| {
        try out.appendSlice(allocator, "{\"stream\":");
        try appendGoJSONString(&out, allocator, ff.stream);
        try out.appendSlice(allocator, ",\"change\":");
        try appendGoJSONString(&out, allocator, ff.change);
        try out.append(allocator, '}');
    } else {
        try out.appendSlice(allocator, "null");
    }
    try out.appendSlice(allocator, "}\n");

    return out.toOwnedSlice(allocator);
}

/// Serializes `Workspace` as a single JSON line with trailing `\n`
/// in Go struct field order: `name`, `src`, `stream`, `created`.
pub fn marshalWorkspaceLine(allocator: Allocator, ws: store.Workspace) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    try out.appendSlice(allocator, "{\"name\":");
    try appendGoJSONString(&out, allocator, ws.name);
    try out.appendSlice(allocator, ",\"src\":");
    try appendGoJSONString(&out, allocator, ws.src);
    try out.appendSlice(allocator, ",\"stream\":");
    try appendGoJSONString(&out, allocator, ws.stream);
    try out.appendSlice(allocator, ",\"created\":");
    try appendInt64(&out, allocator, ws.created);
    try out.appendSlice(allocator, "}\n");

    return out.toOwnedSlice(allocator);
}

/// Serializes `MergeReport` as a single JSON line with trailing `\n`
/// in Go struct field order: `into`, `from`, `ancestor`, `conflicts`.
pub fn marshalMergeReportLine(allocator: Allocator, mr: store.MergeReport) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    try out.appendSlice(allocator, "{\"into\":");
    try appendGoJSONString(&out, allocator, mr.into);
    try out.appendSlice(allocator, ",\"from\":");
    try appendGoJSONString(&out, allocator, mr.from);
    try out.appendSlice(allocator, ",\"ancestor\":");
    try appendGoJSONString(&out, allocator, mr.ancestor);
    try out.appendSlice(allocator, ",\"conflicts\":[");
    for (mr.conflicts, 0..) |c, idx| {
        if (idx > 0) try out.append(allocator, ',');
        try out.appendSlice(allocator, "{\"atom_id\":");
        try appendGoJSONString(&out, allocator, c.atom_id);
        try out.appendSlice(allocator, ",\"name\":");
        try appendGoJSONString(&out, allocator, c.name);
        try out.appendSlice(allocator, ",\"type\":");
        try appendGoJSONString(&out, allocator, c.type);
        try out.append(allocator, '}');
    }
    try out.appendSlice(allocator, "]}\n");

    return out.toOwnedSlice(allocator);
}

/// Serializes `RemoteConfig` as a single JSON line with trailing `\n`
/// in field order: `remote`, `stream`.
pub fn marshalRemoteConfigLine(allocator: Allocator, rc: store.RemoteConfig) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    try out.appendSlice(allocator, "{\"remote\":");
    try appendGoJSONString(&out, allocator, rc.remote);
    try out.appendSlice(allocator, ",\"stream\":");
    try appendGoJSONString(&out, allocator, rc.stream);
    try out.appendSlice(allocator, "}\n");

    return out.toOwnedSlice(allocator);
}

// JSON parsing helpers

fn getOptStrDupe(allocator: Allocator, obj: std.json.ObjectMap, key: []const u8) ![]const u8 {
    if (obj.get(key)) |v| {
        switch (v) {
            .string => |s| return allocator.dupe(u8, s),
            .null => return "",
            else => return error.InvalidJsonField,
        }
    }
    return "";
}

fn getNullableStrDupe(allocator: Allocator, obj: std.json.ObjectMap, key: []const u8) !?[]const u8 {
    if (obj.get(key)) |v| {
        switch (v) {
            .string => |s| return try allocator.dupe(u8, s),
            .null => return null,
            else => return error.InvalidJsonField,
        }
    }
    return null;
}

fn getInt64Default(obj: std.json.ObjectMap, key: []const u8) !i64 {
    if (obj.get(key)) |v| {
        switch (v) {
            .integer => |i| return i,
            else => return error.InvalidJsonField,
        }
    }
    return 0;
}

fn getUint32Default(obj: std.json.ObjectMap, key: []const u8) !u32 {
    if (obj.get(key)) |v| {
        switch (v) {
            .integer => |i| {
                if (i < 0 or i > std.math.maxInt(u32)) return error.InvalidJsonField;
                return @intCast(i);
            },
            else => return error.InvalidJsonField,
        }
    }
    return 0;
}

pub fn parseSpanValue(allocator: Allocator, val: std.json.Value) !store.Span {
    if (val != .object) return error.InvalidJsonField;
    const obj = val.object;
    const file = try getOptStrDupe(allocator, obj, "file");
    errdefer allocator.free(file);
    const start = try getUint32Default(obj, "start");
    const end = try getUint32Default(obj, "end");
    return .{
        .file = file,
        .start = start,
        .end = end,
    };
}

pub fn parseOpValue(allocator: Allocator, val: std.json.Value) !store.Op {
    if (val != .object) return error.InvalidJsonField;
    const obj = val.object;
    const t = try getOptStrDupe(allocator, obj, "type");
    errdefer allocator.free(t);
    const atom_id = try getOptStrDupe(allocator, obj, "atom_id");
    errdefer allocator.free(atom_id);
    const kind = try getOptStrDupe(allocator, obj, "kind");
    errdefer if (kind.len > 0) allocator.free(kind);
    const new_name = try getOptStrDupe(allocator, obj, "new_name");
    errdefer if (new_name.len > 0) allocator.free(new_name);

    var new_span: ?store.Span = null;
    if (obj.get("new_span")) |sp_val| {
        if (sp_val != .null) {
            new_span = try parseSpanValue(allocator, sp_val);
        }
    }
    errdefer if (new_span) |sp| sp.deinit(allocator);

    const new_hash = try getOptStrDupe(allocator, obj, "new_hash");
    errdefer if (new_hash.len > 0) allocator.free(new_hash);
    const new_sig_hash = try getOptStrDupe(allocator, obj, "new_sig_hash");
    errdefer if (new_sig_hash.len > 0) allocator.free(new_sig_hash);
    const old_hash = try getOptStrDupe(allocator, obj, "old_hash");

    return .{
        .type = t,
        .atom_id = atom_id,
        .kind = kind,
        .new_name = new_name,
        .new_span = new_span,
        .new_hash = new_hash,
        .new_sig_hash = new_sig_hash,
        .old_hash = old_hash,
    };
}

pub fn parseOp(allocator: Allocator, line: []const u8) !store.Op {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, line, .{});
    defer parsed.deinit();
    return parseOpValue(allocator, parsed.value);
}

pub fn parseStoredAtomValue(allocator: Allocator, val: std.json.Value) !store.StoredAtom {
    if (val != .object) return error.InvalidJsonField;
    const obj = val.object;
    const id = try getOptStrDupe(allocator, obj, "id");
    errdefer allocator.free(id);
    const kind = try getOptStrDupe(allocator, obj, "kind");
    errdefer allocator.free(kind);
    const name = try getOptStrDupe(allocator, obj, "name");
    errdefer allocator.free(name);
    const hash = try getOptStrDupe(allocator, obj, "hash");
    errdefer allocator.free(hash);
    const sig_hash = try getOptStrDupe(allocator, obj, "sig_hash");
    errdefer allocator.free(sig_hash);

    const span = if (obj.get("span")) |sp_val|
        try parseSpanValue(allocator, sp_val)
    else
        store.Span{ .file = try allocator.dupe(u8, ""), .start = 0, .end = 0 };
    errdefer span.deinit(allocator);

    var meta: []store.MetaEntry = &.{};
    if (obj.get("metadata")) |m_val| {
        if (m_val == .object) {
            const m_obj = m_val.object;
            if (m_obj.count() > 0) {
                meta = try allocator.alloc(store.MetaEntry, m_obj.count());
                var idx: usize = 0;
                errdefer {
                    for (meta[0..idx]) |e| e.deinit(allocator);
                    allocator.free(meta);
                }
                var it = m_obj.iterator();
                while (it.next()) |kv| {
                    if (kv.value_ptr.* != .string) return error.InvalidJsonField;
                    const k = try allocator.dupe(u8, kv.key_ptr.*);
                    errdefer allocator.free(k);
                    const v = try allocator.dupe(u8, kv.value_ptr.*.string);
                    meta[idx] = .{ .key = k, .value = v };
                    idx += 1;
                }
            }
        } else if (m_val != .null) {
            return error.InvalidJsonField;
        }
    }
    errdefer {
        for (meta) |e| e.deinit(allocator);
        if (meta.len > 0) allocator.free(meta);
    }

    const origin = try getOptStrDupe(allocator, obj, "origin");
    return .{
        .id = id,
        .kind = kind,
        .name = name,
        .hash = hash,
        .sig_hash = sig_hash,
        .span = span,
        .metadata = meta,
        .origin = origin,
    };
}

pub fn parseStoredAtom(allocator: Allocator, line: []const u8) !store.StoredAtom {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, line, .{});
    defer parsed.deinit();
    return parseStoredAtomValue(allocator, parsed.value);
}

/// Unmarshals a single JSONL line into a `Change` and validates all field encodings,
/// matching Go's `ParseChange` (`change_malformed` on any failure).
pub fn parseChange(allocator: Allocator, line: []const u8) !store.Change {
    if (std.mem.trim(u8, line, " \t\r\n").len == 0) {
        return fsys.refuse("change_malformed", "");
    }
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, line, .{}) catch {
        return fsys.refuse("change_malformed", "");
    };
    defer parsed.deinit();

    if (parsed.value != .object) {
        return fsys.refuse("change_malformed", "");
    }
    const obj = parsed.value.object;

    const ops_val = obj.get("ops") orelse return fsys.refuse("change_malformed", "");
    if (ops_val != .array) return fsys.refuse("change_malformed", "");

    const ts = getInt64Default(obj, "ts") catch return fsys.refuse("change_malformed", "");
    if (ts <= 0) return fsys.refuse("change_malformed", "");

    const id = getOptStrDupe(allocator, obj, "id") catch return fsys.refuse("change_malformed", "");
    errdefer allocator.free(id);
    const parent = getNullableStrDupe(allocator, obj, "parent") catch return fsys.refuse("change_malformed", "");
    errdefer if (parent) |p| allocator.free(p);
    const stream = getOptStrDupe(allocator, obj, "stream") catch return fsys.refuse("change_malformed", "");
    errdefer allocator.free(stream);
    const author = getOptStrDupe(allocator, obj, "author") catch return fsys.refuse("change_malformed", "");
    errdefer allocator.free(author);
    const message = getOptStrDupe(allocator, obj, "message") catch return fsys.refuse("change_malformed", "");
    errdefer allocator.free(message);
    const merged = getNullableStrDupe(allocator, obj, "merged") catch return fsys.refuse("change_malformed", "");
    errdefer if (merged) |m| allocator.free(m);
    const sig = getOptStrDupe(allocator, obj, "sig") catch return fsys.refuse("change_malformed", "");
    errdefer allocator.free(sig);

    var ops = try allocator.alloc(store.Op, ops_val.array.items.len);
    var oi: usize = 0;
    errdefer {
        for (ops[0..oi]) |op| op.deinit(allocator);
        allocator.free(ops);
    }
    while (oi < ops_val.array.items.len) : (oi += 1) {
        ops[oi] = parseOpValue(allocator, ops_val.array.items[oi]) catch {
            return fsys.refuse("change_malformed", "");
        };
    }

    const c = store.Change{
        .id = id,
        .parent = parent,
        .stream = stream,
        .ts = ts,
        .author = author,
        .message = message,
        .ops = ops,
        .merged = merged,
        .sig = sig,
    };
    errdefer c.deinit(allocator);

    if (ed25519.parseHex64Lower(c.sig) == null) {
        return fsys.refuse("change_malformed", "");
    }
    const msg = ed25519.sigMsg(allocator, &c) catch {
        return fsys.refuse("change_malformed", "");
    };
    allocator.free(msg);

    return c;
}

pub fn parseStream(allocator: Allocator, data: []const u8) !store.Stream {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, data, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidJsonField;
    const obj = parsed.value.object;

    const id = try getOptStrDupe(allocator, obj, "id");
    errdefer allocator.free(id);
    const name = try getOptStrDupe(allocator, obj, "name");
    errdefer allocator.free(name);
    const head = try getNullableStrDupe(allocator, obj, "head");
    errdefer if (head) |h| allocator.free(h);
    const created = try getInt64Default(obj, "created");

    var ff: ?store.ForkOrigin = null;
    if (obj.get("forked_from")) |ff_val| {
        if (ff_val == .object) {
            const ff_obj = ff_val.object;
            const s = try getOptStrDupe(allocator, ff_obj, "stream");
            errdefer allocator.free(s);
            const c = try getOptStrDupe(allocator, ff_obj, "change");
            ff = .{ .stream = s, .change = c };
        } else if (ff_val != .null) {
            return error.InvalidJsonField;
        }
    }

    return .{
        .id = id,
        .name = name,
        .head = head,
        .created = created,
        .forked_from = ff,
    };
}

pub fn parseWorkspace(allocator: Allocator, data: []const u8) !store.Workspace {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, data, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidJsonField;
    const obj = parsed.value.object;

    const name = try getOptStrDupe(allocator, obj, "name");
    errdefer allocator.free(name);
    const src = try getOptStrDupe(allocator, obj, "src");
    errdefer allocator.free(src);
    const stream = try getOptStrDupe(allocator, obj, "stream");
    errdefer allocator.free(stream);
    const created = try getInt64Default(obj, "created");

    return .{
        .name = name,
        .src = src,
        .stream = stream,
        .created = created,
    };
}

pub fn parseRemoteConfig(allocator: Allocator, data: []const u8) !store.RemoteConfig {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, data, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidJsonField;
    const obj = parsed.value.object;

    const remote = try getOptStrDupe(allocator, obj, "remote");
    errdefer allocator.free(remote);
    const stream = try getOptStrDupe(allocator, obj, "stream");
    return .{ .remote = remote, .stream = stream };
}

/// Parses the JSON document written to `ws/<name>/MERGE.json` by a
/// conflicted `merge` (`into`, `from`, `ancestor`, `conflicts`).
pub fn parseMergeReport(allocator: Allocator, data: []const u8) !store.MergeReport {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, data, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidJsonField;
    const obj = parsed.value.object;

    const into = try getOptStrDupe(allocator, obj, "into");
    errdefer allocator.free(into);
    const from = try getOptStrDupe(allocator, obj, "from");
    errdefer allocator.free(from);
    const ancestor = try getOptStrDupe(allocator, obj, "ancestor");
    errdefer allocator.free(ancestor);

    var conflicts: std.ArrayList(store.MergeConflict) = .empty;
    errdefer {
        for (conflicts.items) |c| c.deinit(allocator);
        conflicts.deinit(allocator);
    }
    if (obj.get("conflicts")) |cv| {
        const arr = switch (cv) {
            .array => |a| a,
            else => return error.InvalidJsonField,
        };
        for (arr.items) |item| {
            const co = switch (item) {
                .object => |o| o,
                else => return error.InvalidJsonField,
            };
            const atom_id = try getOptStrDupe(allocator, co, "atom_id");
            errdefer allocator.free(atom_id);
            const name = try getOptStrDupe(allocator, co, "name");
            errdefer allocator.free(name);
            const t = try getOptStrDupe(allocator, co, "type");
            try conflicts.append(allocator, .{ .atom_id = atom_id, .name = name, .type = t });
        }
    }
    return .{ .into = into, .from = from, .ancestor = ancestor, .conflicts = try conflicts.toOwnedSlice(allocator) };
}

test "Go JSON HTML escaping and Change roundtrip" {
    const gpa = std.testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);

    try appendGoJSONString(&out, gpa, "a<b>c&d\xe2\x80\xa8\xe2\x80\xa9\x08\n\"\\");
    try std.testing.expectEqualStrings(
        "\"a\\u003cb\\u003ec\\u0026d\\u2028\\u2029\\u0008\\n\\\"\\\\\"",
        out.items,
    );
}
