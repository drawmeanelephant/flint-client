const std = @import("std");
const Allocator = std.mem.Allocator;
const fsys = @import("fsys.zig");
const store = @import("store.zig");
const uuid = @import("uuid.zig");
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

/// Serializes the stage-base record (`ws/<name>/BASE.json`) as a single JSON
/// line with trailing `\n`: `{"head":"<id>"}` or `{"head":null}` (#67).
pub fn marshalStageBaseLine(allocator: Allocator, head: ?[]const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    try out.appendSlice(allocator, "{\"head\":");
    if (head) |h| {
        try appendGoJSONString(&out, allocator, h);
    } else {
        try out.appendSlice(allocator, "null");
    }
    try out.appendSlice(allocator, "}\n");

    return out.toOwnedSlice(allocator);
}

/// Appends one `files` entry of a snapshot manifest in field order:
/// `path`, `blob` (nullable — `"blob":null` marks an explicitly incomplete
/// entry), `bytes`, `mode`, `reason` (present only on null-blob entries).
pub fn appendManifestEntry(out: *std.ArrayList(u8), allocator: Allocator, e: store.ManifestEntry) !void {
    try out.appendSlice(allocator, "{\"path\":");
    try appendGoJSONString(out, allocator, e.path);
    try out.appendSlice(allocator, ",\"blob\":");
    if (e.blob.len == 0) {
        try out.appendSlice(allocator, "null");
    } else {
        try appendGoJSONString(out, allocator, e.blob);
    }
    try out.appendSlice(allocator, ",\"bytes\":");
    try appendInt64(out, allocator, @intCast(e.bytes));
    try out.appendSlice(allocator, ",\"mode\":");
    try appendInt64(out, allocator, e.mode);
    if (e.reason.len > 0) {
        try out.appendSlice(allocator, ",\"reason\":");
        try appendGoJSONString(out, allocator, e.reason);
    }
    try out.append(allocator, '}');
}

fn manifestEntryLessThan(_: void, a: store.ManifestEntry, b: store.ManifestEntry) bool {
    return std.mem.lessThan(u8, a.path, b.path);
}

/// Appends the canonical manifest object — `stream`, `change`, `author`,
/// `files` sorted by path — WITHOUT `sig`: this is the `flint-manifest-v1`
/// signature preimage (docs/flint-blobs-spec.md §5).
pub fn appendManifestBody(out: *std.ArrayList(u8), allocator: Allocator, m: store.Manifest) !void {
    const sorted = try allocator.dupe(store.ManifestEntry, m.files);
    defer allocator.free(sorted);
    std.mem.sort(store.ManifestEntry, sorted, {}, manifestEntryLessThan);

    try out.appendSlice(allocator, "{\"stream\":");
    try appendGoJSONString(out, allocator, m.stream);
    try out.appendSlice(allocator, ",\"change\":");
    try appendGoJSONString(out, allocator, m.change);
    try out.appendSlice(allocator, ",\"author\":");
    try appendGoJSONString(out, allocator, m.author);
    try out.appendSlice(allocator, ",\"files\":[");
    for (sorted, 0..) |e, idx| {
        if (idx > 0) try out.append(allocator, ',');
        try appendManifestEntry(out, allocator, e);
    }
    try out.appendSlice(allocator, "]}");
}

/// Serializes a signed manifest as a single JSON line with trailing `\n`
/// in field order: `stream`, `change`, `author`, `files`, `sig`.
pub fn marshalManifestLine(allocator: Allocator, m: store.Manifest) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try appendManifestBody(&out, allocator, m);
    _ = out.pop();
    try out.appendSlice(allocator, ",\"sig\":");
    try appendGoJSONString(&out, allocator, m.sig);
    try out.appendSlice(allocator, "}\n");
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

/// Parses `ws/<name>/BASE.json` — the stream head a pending stage was last
/// staged against (`{"head":...}`).
pub fn parseStageBase(allocator: Allocator, data: []const u8) !?[]const u8 {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, data, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidJsonField;
    return try getNullableStrDupe(allocator, parsed.value.object, "head");
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

/// Unmarshals a single signed manifest line. Field/type failures and
/// contract violations (bad path spellings, malformed blob ids, missing
/// fields, or a null blob without a `reason`) return an error; callers map
/// it to `manifest_torn`.
pub fn parseManifest(allocator: Allocator, line: []const u8) !store.Manifest {
    if (std.mem.trim(u8, line, " \t\r\n").len == 0) {
        return error.InvalidJsonField;
    }
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, line, .{}) catch {
        return error.InvalidJsonField;
    };
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidJsonField;
    const obj = parsed.value.object;

    const stream = try getOptStrDupe(allocator, obj, "stream");
    errdefer allocator.free(stream);
    const change = try getOptStrDupe(allocator, obj, "change");
    errdefer allocator.free(change);
    const author = try getOptStrDupe(allocator, obj, "author");
    errdefer allocator.free(author);
    const sig = try getOptStrDupe(allocator, obj, "sig");
    errdefer allocator.free(sig);
    if (stream.len == 0 or change.len == 0 or author.len == 0 or sig.len == 0) {
        return error.InvalidJsonField;
    }

    const files_val = obj.get("files") orelse return error.InvalidJsonField;
    if (files_val != .array) return error.InvalidJsonField;

    var files = try allocator.alloc(store.ManifestEntry, files_val.array.items.len);
    var fi: usize = 0;
    errdefer {
        for (files[0..fi]) |f| f.deinit(allocator);
        allocator.free(files);
    }
    for (files_val.array.items) |item| {
        if (item != .object) return error.InvalidJsonField;
        const fo = item.object;
        const path = try getOptStrDupe(allocator, fo, "path");
        errdefer allocator.free(path);
        if (!store.validManifestPath(path)) return error.InvalidJsonField;

        const blob = try getOptStrDupe(allocator, fo, "blob");
        errdefer if (blob.len > 0) allocator.free(blob);
        if (blob.len > 0) {
            if (ed25519.parseHex32Lower(blob) == null) return error.InvalidJsonField;
        }

        const reason = try getOptStrDupe(allocator, fo, "reason");
        errdefer if (reason.len > 0) allocator.free(reason);
        const reason_ok = reason.len == 0 or
            std.mem.eql(u8, reason, "too_large") or
            std.mem.eql(u8, reason, "unsupported");
        if (!reason_ok) return error.InvalidJsonField;
        // A null blob must carry a reason; a present blob must not.
        if ((blob.len == 0) != (reason.len > 0)) return error.InvalidJsonField;

        const bytes_i = getInt64Default(fo, "bytes") catch return error.InvalidJsonField;
        if (bytes_i < 0) return error.InvalidJsonField;
        const mode_i = getInt64Default(fo, "mode") catch return error.InvalidJsonField;
        if (mode_i < 0 or mode_i > std.math.maxInt(u32)) return error.InvalidJsonField;

        files[fi] = .{
            .path = path,
            .blob = blob,
            .bytes = @intCast(bytes_i),
            .mode = @intCast(mode_i),
            .reason = reason,
        };
        fi += 1;
    }

    return .{
        .stream = stream,
        .change = change,
        .author = author,
        .files = files,
        .sig = sig,
    };
}

// ---------------------------------------------------------------------------
// Handoff records (docs/flint-handoffs-spec.md §1)

pub const handoff_format = "FLINT-HANDOFF/1";
pub const MaxHandoffTextBytes: usize = 512;
pub const MaxHandoffCommandBytes: usize = 1024;
pub const MaxHandoffContextBytes: usize = 256;
/// `snapshot` is an opaque reference until #77 fixes its shape; bounded so a
/// record line stays well under the 64 KiB log bound.
pub const MaxHandoffSnapshotBytes: usize = 1024;

fn refuseHandoffMalformed(detail: []const u8) error{Refuse} {
    return fsys.refuse("handoff_malformed", detail);
}

fn getRequiredStrDupe(allocator: Allocator, obj: std.json.ObjectMap, key: []const u8) ![]const u8 {
    const v = obj.get(key) orelse return refuseHandoffMalformed(key);
    return switch (v) {
        .string => |s| allocator.dupe(u8, s),
        else => refuseHandoffMalformed(key),
    };
}

/// Reads an optional UUID field: absent or explicit `null` → `null`; a string
/// must be canonical; anything else is malformed.
fn getOptUUIDDupe(allocator: Allocator, obj: std.json.ObjectMap, key: []const u8) !?[]const u8 {
    const v = obj.get(key) orelse return null;
    return switch (v) {
        .string => |s| blk: {
            if (uuid.parseUUID(s) == null) return refuseHandoffMalformed(key);
            break :blk try allocator.dupe(u8, s);
        },
        .null => null,
        else => refuseHandoffMalformed(key),
    };
}

/// Reads an optional free-text field bounded to `max` bytes of valid UTF-8.
/// An explicit `null` or absent key yields `null`; empty strings are kept so
/// per-kind requiredness can refuse them.
fn getOptTextDupe(allocator: Allocator, obj: std.json.ObjectMap, key: []const u8, max: usize) !?[]const u8 {
    const v = obj.get(key) orelse return null;
    return switch (v) {
        .string => |s| blk: {
            if (s.len > max or !std.unicode.utf8ValidateSlice(s)) {
                return refuseHandoffMalformed(key);
            }
            break :blk try allocator.dupe(u8, s);
        },
        .null => null,
        else => refuseHandoffMalformed(key),
    };
}

fn getRequiredTextDupe(allocator: Allocator, obj: std.json.ObjectMap, key: []const u8, min: usize, max: usize) ![]const u8 {
    const v = obj.get(key) orelse return refuseHandoffMalformed(key);
    return switch (v) {
        .string => |s| blk: {
            if (s.len < min or s.len > max or !std.unicode.utf8ValidateSlice(s)) {
                return refuseHandoffMalformed(key);
            }
            break :blk try allocator.dupe(u8, s);
        },
        else => refuseHandoffMalformed(key),
    };
}

fn getRequiredTs(obj: std.json.ObjectMap, key: []const u8) !i64 {
    const v = obj.get(key) orelse return refuseHandoffMalformed(key);
    return switch (v) {
        .integer => |i| if (i <= 0) refuseHandoffMalformed(key) else i,
        else => refuseHandoffMalformed(key),
    };
}

fn requireHexField(s: []const u8, comptime n: usize, key: []const u8) !void {
    if (ed25519.parseHexFixedLower(n, s) == null) {
        return refuseHandoffMalformed(key);
    }
}

fn parseHandoffValidationValue(allocator: Allocator, val: std.json.Value, lax: bool) !store.HandoffValidation {
    if (val != .object) return refuseHandoffMalformed("validations");
    const obj = val.object;

    const command = try getRequiredTextDupe(allocator, obj, "command", 1, MaxHandoffCommandBytes);
    errdefer allocator.free(command);

    const result = try getRequiredStrDupe(allocator, obj, "result");
    errdefer allocator.free(result);
    if (store.handoffResultCode(result) == 0) return refuseHandoffMalformed("result");

    const toolchain = try getOptTextDupe(allocator, obj, "toolchain", MaxHandoffContextBytes);
    errdefer if (toolchain) |t| allocator.free(t);
    const env = try getOptTextDupe(allocator, obj, "env", MaxHandoffContextBytes);
    errdefer if (env) |e| allocator.free(e);

    // `lax` (a --validations file, never a stored record) leaves attestor/ts
    // for the writer to fill with the signing key and the current time.
    var attestor: []const u8 = "";
    errdefer if (attestor.len > 0) allocator.free(attestor);
    if (lax) {
        const a = try getOptTextDupe(allocator, obj, "attestor", MaxHandoffTextBytes);
        if (a) |av| {
            if (av.len > 0) {
                try requireHexField(av, 32, "attestor");
                attestor = av;
            } else {
                allocator.free(av);
            }
        }
    } else {
        attestor = try getRequiredStrDupe(allocator, obj, "attestor");
        try requireHexField(attestor, 32, "attestor");
    }

    var ts: i64 = 0;
    if (lax) {
        if (obj.get("ts")) |tv| {
            ts = switch (tv) {
                .integer => |i| if (i <= 0) return refuseHandoffMalformed("ts") else i,
                else => return refuseHandoffMalformed("ts"),
            };
        }
    } else {
        ts = try getRequiredTs(obj, "ts");
    }

    const evidence = try getOptTextDupe(allocator, obj, "evidence", MaxHandoffContextBytes);
    errdefer if (evidence) |e| allocator.free(e);

    return .{
        .command = command,
        .result = result,
        .toolchain = toolchain orelse "",
        .env = env orelse "",
        .attestor = attestor,
        .ts = ts,
        .evidence = evidence orelse "",
    };
}

fn parseHandoffScopeValue(allocator: Allocator, val: std.json.Value) !?store.HandoffScope {
    if (val != .object) return refuseHandoffMalformed("scope");
    const obj = val.object;

    var paths: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (paths.items) |p| allocator.free(p);
        paths.deinit(allocator);
    }
    if (obj.get("paths")) |pv| {
        if (pv != .array) return refuseHandoffMalformed("scope");
        for (pv.array.items) |item| {
            const s = switch (item) {
                .string => |x| x,
                else => return refuseHandoffMalformed("scope"),
            };
            if (!store.validManifestPath(s)) return refuseHandoffMalformed("scope");
            try paths.append(allocator, try allocator.dupe(u8, s));
        }
    }

    var atoms: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (atoms.items) |a| allocator.free(a);
        atoms.deinit(allocator);
    }
    if (obj.get("atoms")) |av| {
        if (av != .array) return refuseHandoffMalformed("scope");
        for (av.array.items) |item| {
            const s = switch (item) {
                .string => |x| x,
                else => return refuseHandoffMalformed("scope"),
            };
            if (s.len == 0 or s.len > MaxHandoffTextBytes or !std.unicode.utf8ValidateSlice(s)) {
                return refuseHandoffMalformed("scope");
            }
            try atoms.append(allocator, try allocator.dupe(u8, s));
        }
    }

    // An empty object reads identically to an omitted field (§1.2).
    if (paths.items.len == 0 and atoms.items.len == 0) {
        return null;
    }
    return .{
        .paths = try paths.toOwnedSlice(allocator),
        .atoms = try atoms.toOwnedSlice(allocator),
    };
}

fn requireAbsent(obj: std.json.ObjectMap, key: []const u8) !void {
    if (obj.get(key)) |v| {
        if (v != .null) return refuseHandoffMalformed(key);
    }
}

/// Parses one `FLINT-HANDOFF/1` record line enforcing spec §1.5 rules 1–3
/// (framing, per-kind requiredness and exclusivity, attestor equality).
/// Violations refuse `handoff_malformed`; signature and lifecycle checks are
/// the caller's job.
pub fn parseHandoffRecord(allocator: Allocator, line: []const u8) !store.HandoffRecord {
    if (std.mem.trim(u8, line, " \t\r\n").len == 0) {
        return refuseHandoffMalformed("");
    }
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, line, .{}) catch {
        return refuseHandoffMalformed("");
    };
    defer parsed.deinit();
    if (parsed.value != .object) return refuseHandoffMalformed("");
    const obj = parsed.value.object;

    const format = try getRequiredStrDupe(allocator, obj, "format");
    defer allocator.free(format);
    if (!std.mem.eql(u8, format, handoff_format)) {
        return refuseHandoffMalformed("unknown format");
    }

    const id = try getRequiredStrDupe(allocator, obj, "id");
    errdefer allocator.free(id);
    if (uuid.parseUUID(id) == null) return refuseHandoffMalformed("id");
    const handoff = try getRequiredStrDupe(allocator, obj, "handoff");
    errdefer allocator.free(handoff);
    if (uuid.parseUUID(handoff) == null) return refuseHandoffMalformed("handoff");

    const kind = try getRequiredStrDupe(allocator, obj, "kind");
    errdefer allocator.free(kind);
    if (store.handoffKindCode(kind) == 0) return refuseHandoffMalformed("kind");

    const stream = try getRequiredStrDupe(allocator, obj, "stream");
    errdefer allocator.free(stream);
    if (uuid.parseUUID(stream) == null) return refuseHandoffMalformed("stream");

    const ts = try getRequiredTs(obj, "ts");

    const author = try getRequiredStrDupe(allocator, obj, "author");
    errdefer allocator.free(author);
    try requireHexField(author, 32, "author");
    const sig = try getRequiredStrDupe(allocator, obj, "sig");
    errdefer allocator.free(sig);
    try requireHexField(sig, 64, "sig");

    const base = try getOptUUIDDupe(allocator, obj, "base");
    errdefer if (base) |v| allocator.free(v);
    const work = try getOptUUIDDupe(allocator, obj, "work");
    errdefer if (work) |v| allocator.free(v);
    const candidate = try getOptUUIDDupe(allocator, obj, "candidate");
    errdefer if (candidate) |v| allocator.free(v);
    const observed_head = try getOptUUIDDupe(allocator, obj, "observed_head");
    errdefer if (observed_head) |v| allocator.free(v);
    const replacement = try getOptUUIDDupe(allocator, obj, "replacement");
    errdefer if (replacement) |v| allocator.free(v);

    const snapshot = try getOptTextDupe(allocator, obj, "snapshot", MaxHandoffSnapshotBytes);
    errdefer if (snapshot) |v| allocator.free(v);
    const intent = try getOptTextDupe(allocator, obj, "intent", MaxHandoffTextBytes);
    errdefer if (intent) |v| allocator.free(v);
    const note = try getOptTextDupe(allocator, obj, "note", MaxHandoffTextBytes);
    errdefer if (note) |v| allocator.free(v);

    var scope: ?store.HandoffScope = null;
    errdefer if (scope) |s| s.deinit(allocator);
    if (obj.get("scope")) |sv| {
        if (sv != .null) {
            scope = try parseHandoffScopeValue(allocator, sv);
        }
    }

    var validations: []store.HandoffValidation = &.{};
    errdefer {
        for (validations) |v| v.deinit(allocator);
        if (validations.len > 0) allocator.free(validations);
    }
    if (obj.get("validations")) |vv| {
        if (vv != .null) {
            if (vv != .array) return refuseHandoffMalformed("validations");
            if (vv.array.items.len > 0) {
                var list = try allocator.alloc(store.HandoffValidation, vv.array.items.len);
                var vi: usize = 0;
                errdefer {
                    for (list[0..vi]) |v| v.deinit(allocator);
                    allocator.free(list);
                }
                while (vi < vv.array.items.len) : (vi += 1) {
                    list[vi] = try parseHandoffValidationValue(allocator, vv.array.items[vi], false);
                }
                validations = list;
            }
        }
    }

    // §1.5 rule 2 — per-kind required fields and exclusivity.
    const is_propose = std.mem.eql(u8, kind, "propose");
    const is_attest = std.mem.eql(u8, kind, "attest");
    const is_accept = std.mem.eql(u8, kind, "accept");
    const is_supersede = std.mem.eql(u8, kind, "supersede");
    if (is_propose != std.mem.eql(u8, id, handoff)) {
        return refuseHandoffMalformed("handoff");
    }
    if (is_propose) {
        if (base == null or work == null or candidate == null) {
            return refuseHandoffMalformed("missing required field");
        }
        if (intent == null or intent.?.len == 0) {
            return refuseHandoffMalformed("intent");
        }
        try requireAbsent(obj, "observed_head");
        try requireAbsent(obj, "replacement");
        try requireAbsent(obj, "note");
    } else if (is_attest) {
        if (candidate == null) return refuseHandoffMalformed("candidate");
        if (validations.len != 1) return refuseHandoffMalformed("validations");
        try requireAbsent(obj, "base");
        try requireAbsent(obj, "work");
        try requireAbsent(obj, "intent");
        try requireAbsent(obj, "note");
        try requireAbsent(obj, "scope");
        try requireAbsent(obj, "observed_head");
        try requireAbsent(obj, "replacement");
    } else if (is_accept) {
        if (candidate == null or observed_head == null) {
            return refuseHandoffMalformed("missing required field");
        }
        try requireAbsent(obj, "base");
        try requireAbsent(obj, "work");
        try requireAbsent(obj, "snapshot");
        try requireAbsent(obj, "intent");
        try requireAbsent(obj, "scope");
        try requireAbsent(obj, "validations");
        try requireAbsent(obj, "replacement");
    } else if (is_supersede) {
        if (candidate == null) return refuseHandoffMalformed("candidate");
        try requireAbsent(obj, "base");
        try requireAbsent(obj, "work");
        try requireAbsent(obj, "snapshot");
        try requireAbsent(obj, "intent");
        try requireAbsent(obj, "scope");
        try requireAbsent(obj, "validations");
        try requireAbsent(obj, "observed_head");
    } else {
        // withdraw: carries no ids, only an optional note.
        try requireAbsent(obj, "base");
        try requireAbsent(obj, "work");
        try requireAbsent(obj, "candidate");
        try requireAbsent(obj, "snapshot");
        try requireAbsent(obj, "intent");
        try requireAbsent(obj, "scope");
        try requireAbsent(obj, "validations");
        try requireAbsent(obj, "observed_head");
        try requireAbsent(obj, "replacement");
    }

    // §1.5 rule 3 — every embedded attestor equals the record author.
    for (validations) |v| {
        if (!std.mem.eql(u8, v.attestor, author)) {
            return refuseHandoffMalformed("attestor mismatch");
        }
    }

    var rec = store.HandoffRecord{
        .id = id,
        .handoff = handoff,
        .kind = kind,
        .stream = stream,
        .ts = ts,
        .author = author,
        .sig = sig,
        .base = base,
        .work = work,
        .candidate = candidate,
        .snapshot = snapshot,
        .intent = intent,
        .note = note,
        .scope = scope,
        .validations = validations,
        .observed_head = observed_head,
        .replacement = replacement,
    };
    // §1.2 — empty strings read identically to omitted fields.
    if (rec.snapshot) |v| {
        if (v.len == 0) {
            allocator.free(v);
            rec.snapshot = null;
        }
    }
    if (rec.note) |v| {
        if (v.len == 0) {
            allocator.free(v);
            rec.note = null;
        }
    }
    return rec;
}

fn appendHandoffValidation(out: *std.ArrayList(u8), allocator: Allocator, v: store.HandoffValidation) !void {
    try out.appendSlice(allocator, "{\"command\":");
    try appendGoJSONString(out, allocator, v.command);
    try out.appendSlice(allocator, ",\"result\":");
    try appendGoJSONString(out, allocator, v.result);
    if (v.toolchain.len > 0) {
        try out.appendSlice(allocator, ",\"toolchain\":");
        try appendGoJSONString(out, allocator, v.toolchain);
    }
    if (v.env.len > 0) {
        try out.appendSlice(allocator, ",\"env\":");
        try appendGoJSONString(out, allocator, v.env);
    }
    try out.appendSlice(allocator, ",\"attestor\":");
    try appendGoJSONString(out, allocator, v.attestor);
    try out.appendSlice(allocator, ",\"ts\":");
    try appendInt64(out, allocator, v.ts);
    if (v.evidence.len > 0) {
        try out.appendSlice(allocator, ",\"evidence\":");
        try appendGoJSONString(out, allocator, v.evidence);
    }
    try out.append(allocator, '}');
}

fn strLessThan(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

fn appendHandoffScope(out: *std.ArrayList(u8), allocator: Allocator, scope: store.HandoffScope) !void {
    const paths = try allocator.dupe([]const u8, scope.paths);
    defer allocator.free(paths);
    std.mem.sort([]const u8, paths, {}, strLessThan);
    const atoms = try allocator.dupe([]const u8, scope.atoms);
    defer allocator.free(atoms);
    std.mem.sort([]const u8, atoms, {}, strLessThan);

    try out.appendSlice(allocator, "{\"paths\":[");
    for (paths, 0..) |p, i| {
        if (i > 0) try out.append(allocator, ',');
        try appendGoJSONString(out, allocator, p);
    }
    try out.appendSlice(allocator, "],\"atoms\":[");
    for (atoms, 0..) |a, i| {
        if (i > 0) try out.append(allocator, ',');
        try appendGoJSONString(out, allocator, a);
    }
    try out.appendSlice(allocator, "]}");
}

/// Serializes a handoff record as one JSON line in the spec §1 field order —
/// envelope fields first (`sig` included), then payload fields — with
/// trailing `\n`. Absent optionals are never emitted.
pub fn marshalHandoffRecord(allocator: Allocator, r: store.HandoffRecord) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    try out.appendSlice(allocator, "{\"format\":");
    try appendGoJSONString(&out, allocator, handoff_format);
    try out.appendSlice(allocator, ",\"id\":");
    try appendGoJSONString(&out, allocator, r.id);
    try out.appendSlice(allocator, ",\"handoff\":");
    try appendGoJSONString(&out, allocator, r.handoff);
    try out.appendSlice(allocator, ",\"kind\":");
    try appendGoJSONString(&out, allocator, r.kind);
    try out.appendSlice(allocator, ",\"stream\":");
    try appendGoJSONString(&out, allocator, r.stream);
    try out.appendSlice(allocator, ",\"ts\":");
    try appendInt64(&out, allocator, r.ts);
    try out.appendSlice(allocator, ",\"author\":");
    try appendGoJSONString(&out, allocator, r.author);
    try out.appendSlice(allocator, ",\"sig\":");
    try appendGoJSONString(&out, allocator, r.sig);

    if (r.base) |v| {
        try out.appendSlice(allocator, ",\"base\":");
        try appendGoJSONString(&out, allocator, v);
    }
    if (r.work) |v| {
        try out.appendSlice(allocator, ",\"work\":");
        try appendGoJSONString(&out, allocator, v);
    }
    if (r.candidate) |v| {
        try out.appendSlice(allocator, ",\"candidate\":");
        try appendGoJSONString(&out, allocator, v);
    }
    if (r.snapshot) |v| {
        try out.appendSlice(allocator, ",\"snapshot\":");
        try appendGoJSONString(&out, allocator, v);
    }
    if (r.intent) |v| {
        try out.appendSlice(allocator, ",\"intent\":");
        try appendGoJSONString(&out, allocator, v);
    }
    if (r.note) |v| {
        try out.appendSlice(allocator, ",\"note\":");
        try appendGoJSONString(&out, allocator, v);
    }
    if (r.scope) |s| {
        try out.appendSlice(allocator, ",\"scope\":");
        try appendHandoffScope(&out, allocator, s);
    }
    if (r.validations.len > 0) {
        try out.appendSlice(allocator, ",\"validations\":[");
        for (r.validations, 0..) |v, i| {
            if (i > 0) try out.append(allocator, ',');
            try appendHandoffValidation(&out, allocator, v);
        }
        try out.append(allocator, ']');
    }
    if (r.observed_head) |v| {
        try out.appendSlice(allocator, ",\"observed_head\":");
        try appendGoJSONString(&out, allocator, v);
    }
    if (r.replacement) |v| {
        try out.appendSlice(allocator, ",\"replacement\":");
        try appendGoJSONString(&out, allocator, v);
    }
    try out.appendSlice(allocator, "}\n");

    return out.toOwnedSlice(allocator);
}

/// Parses a `--scope-file` document (`{"paths":[…],"atoms":[…]}`) — absent or
/// empty reads as no scope claim (§1.2).
pub fn parseHandoffScopeDoc(allocator: Allocator, data: []const u8) !?store.HandoffScope {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, data, .{}) catch {
        return refuseHandoffMalformed("scope");
    };
    defer parsed.deinit();
    return try parseHandoffScopeValue(allocator, parsed.value);
}

/// Parses a `--validations` document — a JSON array of §1.3 objects. Entries
/// may omit `attestor`/`ts`; the writer fills them with the signer and now.
pub fn parseHandoffValidationsDoc(allocator: Allocator, data: []const u8) ![]store.HandoffValidation {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, data, .{}) catch {
        return refuseHandoffMalformed("validations");
    };
    defer parsed.deinit();
    if (parsed.value != .array) return refuseHandoffMalformed("validations");

    var list = try allocator.alloc(store.HandoffValidation, parsed.value.array.items.len);
    var i: usize = 0;
    errdefer {
        for (list[0..i]) |v| v.deinit(allocator);
        allocator.free(list);
    }
    while (i < parsed.value.array.items.len) : (i += 1) {
        list[i] = try parseHandoffValidationValue(allocator, parsed.value.array.items[i], true);
    }
    return list;
}

/// Peeks a log line's `format` field without validating the record: returns
/// the format string (allocated), `null` when the line carries no string
/// `format`, or an error when the line is not a JSON object at all.
pub fn peekHandoffFormat(allocator: Allocator, line: []const u8) !?[]u8 {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, line, .{}) catch {
        return error.InvalidJsonField;
    };
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidJsonField;
    const v = parsed.value.object.get("format") orelse return null;
    return switch (v) {
        .string => |s| try allocator.dupe(u8, s),
        else => null,
    };
}

/// Extracts a best-effort `handoff` field from a line that may not validate —
/// used to attribute invalid records to a proposal during inspection.
pub fn peekHandoffField(allocator: Allocator, line: []const u8, key: []const u8) !?[]u8 {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, line, .{}) catch {
        return error.InvalidJsonField;
    };
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidJsonField;
    const v = parsed.value.object.get(key) orelse return null;
    return switch (v) {
        .string => |s| try allocator.dupe(u8, s),
        else => null,
    };
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
