const std = @import("std");
const Allocator = std.mem.Allocator;
const fsys = @import("fsys.zig");
const FS = fsys.FS;
const uuid = @import("uuid.zig");
const json = @import("json.zig");

pub const MaxFileReadBytes: usize = fsys.MaxFileReadBytes;
pub const MaxAtoms: usize = 4096;
pub const MaxChanges: usize = 4096;

/// Span locates an Atom within a source file relative to the workspace src root.
pub const Span = struct {
    file: []const u8,
    start: u32,
    end: u32,

    pub fn deinit(self: Span, allocator: Allocator) void {
        allocator.free(self.file);
    }

    pub fn clone(self: Span, allocator: Allocator) !Span {
        return .{
            .file = try allocator.dupe(u8, self.file),
            .start = self.start,
            .end = self.end,
        };
    }

    pub fn eql(a: ?Span, b: ?Span) bool {
        if (a == null and b == null) return true;
        if (a == null or b == null) return false;
        return std.mem.eql(u8, a.?.file, b.?.file) and a.?.start == b.?.start and a.?.end == b.?.end;
    }
};

pub const MetaEntry = struct {
    key: []const u8,
    value: []const u8,

    pub fn deinit(self: MetaEntry, allocator: Allocator) void {
        allocator.free(self.key);
        allocator.free(self.value);
    }

    pub fn clone(self: MetaEntry, allocator: Allocator) !MetaEntry {
        const k = try allocator.dupe(u8, self.key);
        errdefer allocator.free(k);
        const v = try allocator.dupe(u8, self.value);
        return .{ .key = k, .value = v };
    }
};

/// StoredAtom is the JSON representation of an Atom in ATOMS.jsonl.
pub const StoredAtom = struct {
    id: []const u8,
    kind: []const u8,
    name: []const u8,
    hash: []const u8,
    sig_hash: []const u8,
    span: Span,
    metadata: []const MetaEntry = &.{},
    origin: []const u8 = "",

    pub fn deinit(self: StoredAtom, allocator: Allocator) void {
        allocator.free(self.id);
        allocator.free(self.kind);
        allocator.free(self.name);
        allocator.free(self.hash);
        allocator.free(self.sig_hash);
        self.span.deinit(allocator);
        for (self.metadata) |m| m.deinit(allocator);
        if (self.metadata.len > 0) allocator.free(self.metadata);
        if (self.origin.len > 0) allocator.free(self.origin);
    }

    pub fn clone(self: StoredAtom, allocator: Allocator) !StoredAtom {
        const id = try allocator.dupe(u8, self.id);
        errdefer allocator.free(id);
        const kind = try allocator.dupe(u8, self.kind);
        errdefer allocator.free(kind);
        const name = try allocator.dupe(u8, self.name);
        errdefer allocator.free(name);
        const hash = try allocator.dupe(u8, self.hash);
        errdefer allocator.free(hash);
        const sig_hash = try allocator.dupe(u8, self.sig_hash);
        errdefer allocator.free(sig_hash);
        const span = try self.span.clone(allocator);
        errdefer span.deinit(allocator);

        var meta: []MetaEntry = &.{};
        if (self.metadata.len > 0) {
            meta = try allocator.alloc(MetaEntry, self.metadata.len);
            var i: usize = 0;
            errdefer {
                for (meta[0..i]) |m| m.deinit(allocator);
                allocator.free(meta);
            }
            while (i < self.metadata.len) : (i += 1) {
                meta[i] = try self.metadata[i].clone(allocator);
            }
        }
        errdefer {
            for (meta) |m| m.deinit(allocator);
            if (meta.len > 0) allocator.free(meta);
        }

        const origin = if (self.origin.len > 0) try allocator.dupe(u8, self.origin) else "";
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
};

/// Op is a staged or committed operation on an Atom (`STAGE.jsonl` / `Change.ops`).
pub const Op = struct {
    type: []const u8,
    atom_id: []const u8,
    kind: []const u8 = "",
    new_name: []const u8 = "",
    new_span: ?Span = null,
    new_hash: []const u8 = "",
    new_sig_hash: []const u8 = "",
    old_hash: []const u8 = "",

    pub fn deinit(self: Op, allocator: Allocator) void {
        allocator.free(self.type);
        allocator.free(self.atom_id);
        if (self.kind.len > 0) allocator.free(self.kind);
        if (self.new_name.len > 0) allocator.free(self.new_name);
        if (self.new_span) |sp| sp.deinit(allocator);
        if (self.new_hash.len > 0) allocator.free(self.new_hash);
        if (self.new_sig_hash.len > 0) allocator.free(self.new_sig_hash);
        if (self.old_hash.len > 0) allocator.free(self.old_hash);
    }

    pub fn clone(self: Op, allocator: Allocator) !Op {
        const t = try allocator.dupe(u8, self.type);
        errdefer allocator.free(t);
        const aid = try allocator.dupe(u8, self.atom_id);
        errdefer allocator.free(aid);
        const k = if (self.kind.len > 0) try allocator.dupe(u8, self.kind) else "";
        errdefer if (k.len > 0) allocator.free(k);
        const nn = if (self.new_name.len > 0) try allocator.dupe(u8, self.new_name) else "";
        errdefer if (nn.len > 0) allocator.free(nn);
        const ns = if (self.new_span) |sp| try sp.clone(allocator) else null;
        errdefer if (ns) |sp| sp.deinit(allocator);
        const nh = if (self.new_hash.len > 0) try allocator.dupe(u8, self.new_hash) else "";
        errdefer if (nh.len > 0) allocator.free(nh);
        const nsh = if (self.new_sig_hash.len > 0) try allocator.dupe(u8, self.new_sig_hash) else "";
        errdefer if (nsh.len > 0) allocator.free(nsh);
        const oh = if (self.old_hash.len > 0) try allocator.dupe(u8, self.old_hash) else "";
        return .{
            .type = t,
            .atom_id = aid,
            .kind = k,
            .new_name = nn,
            .new_span = ns,
            .new_hash = nh,
            .new_sig_hash = nsh,
            .old_hash = oh,
        };
    }
};

/// Change is the JSON representation of a signed Change line in `streams/<id>.jsonl`.
pub const Change = struct {
    id: []const u8,
    parent: ?[]const u8 = null,
    stream: []const u8,
    ts: i64,
    author: []const u8,
    message: []const u8,
    ops: []const Op = &.{},
    merged: ?[]const u8 = null,
    sig: []const u8,

    pub fn deinit(self: Change, allocator: Allocator) void {
        allocator.free(self.id);
        if (self.parent) |p| allocator.free(p);
        allocator.free(self.stream);
        allocator.free(self.author);
        allocator.free(self.message);
        for (self.ops) |op| op.deinit(allocator);
        allocator.free(self.ops);
        if (self.merged) |m| allocator.free(m);
        allocator.free(self.sig);
    }

    pub fn clone(self: Change, allocator: Allocator) !Change {
        const id = try allocator.dupe(u8, self.id);
        errdefer allocator.free(id);
        const parent = if (self.parent) |p| try allocator.dupe(u8, p) else null;
        errdefer if (parent) |p| allocator.free(p);
        const stream = try allocator.dupe(u8, self.stream);
        errdefer allocator.free(stream);
        const author = try allocator.dupe(u8, self.author);
        errdefer allocator.free(author);
        const message = try allocator.dupe(u8, self.message);
        errdefer allocator.free(message);

        const ops = try allocator.alloc(Op, self.ops.len);
        var i: usize = 0;
        errdefer {
            for (ops[0..i]) |op| op.deinit(allocator);
            allocator.free(ops);
        }
        while (i < self.ops.len) : (i += 1) {
            ops[i] = try self.ops[i].clone(allocator);
        }

        const merged = if (self.merged) |m| try allocator.dupe(u8, m) else null;
        errdefer if (merged) |m| allocator.free(m);
        const sig = try allocator.dupe(u8, self.sig);
        return .{
            .id = id,
            .parent = parent,
            .stream = stream,
            .ts = self.ts,
            .author = author,
            .message = message,
            .ops = ops,
            .merged = merged,
            .sig = sig,
        };
    }
};

/// ForkOrigin records the Stream and Change a forked Stream started from.
pub const ForkOrigin = struct {
    stream: []const u8,
    change: []const u8,

    pub fn deinit(self: ForkOrigin, allocator: Allocator) void {
        allocator.free(self.stream);
        allocator.free(self.change);
    }

    pub fn clone(self: ForkOrigin, allocator: Allocator) !ForkOrigin {
        const s = try allocator.dupe(u8, self.stream);
        errdefer allocator.free(s);
        const c = try allocator.dupe(u8, self.change);
        return .{ .stream = s, .change = c };
    }
};

/// Stream is the JSON record stored at `<store>/streams/<id>.json`.
pub const Stream = struct {
    id: []const u8,
    name: []const u8,
    head: ?[]const u8 = null,
    created: i64,
    forked_from: ?ForkOrigin = null,

    pub fn deinit(self: Stream, allocator: Allocator) void {
        allocator.free(self.id);
        allocator.free(self.name);
        if (self.head) |h| allocator.free(h);
        if (self.forked_from) |ff| ff.deinit(allocator);
    }

    pub fn clone(self: Stream, allocator: Allocator) !Stream {
        const id = try allocator.dupe(u8, self.id);
        errdefer allocator.free(id);
        const name = try allocator.dupe(u8, self.name);
        errdefer allocator.free(name);
        const head = if (self.head) |h| try allocator.dupe(u8, h) else null;
        errdefer if (head) |h| allocator.free(h);
        const ff = if (self.forked_from) |f| try f.clone(allocator) else null;
        return .{
            .id = id,
            .name = name,
            .head = head,
            .created = self.created,
            .forked_from = ff,
        };
    }
};

/// Workspace is the JSON record stored at `<store>/ws/<name>/WORKSPACE.json`.
pub const Workspace = struct {
    name: []const u8,
    src: []const u8,
    stream: []const u8,
    created: i64,

    pub fn deinit(self: Workspace, allocator: Allocator) void {
        allocator.free(self.name);
        allocator.free(self.src);
        allocator.free(self.stream);
    }

    pub fn clone(self: Workspace, allocator: Allocator) !Workspace {
        const name = try allocator.dupe(u8, self.name);
        errdefer allocator.free(name);
        const src = try allocator.dupe(u8, self.src);
        errdefer allocator.free(src);
        const stream = try allocator.dupe(u8, self.stream);
        return .{
            .name = name,
            .src = src,
            .stream = stream,
            .created = self.created,
        };
    }
};

/// StageBase is the JSON record stored at `<store>/ws/<name>/BASE.json`: the
/// stream head the pending `STAGE.jsonl` was last staged against (#67).
pub const StageBase = struct {
    head: ?[]const u8,

    pub fn deinit(self: StageBase, allocator: Allocator) void {
        if (self.head) |h| allocator.free(h);
    }
};

/// MergeConflict is one conflict entry in `MERGE.json` and merge output.
pub const MergeConflict = struct {
    atom_id: []const u8,
    name: []const u8,
    type: []const u8,

    pub fn deinit(self: MergeConflict, allocator: Allocator) void {
        allocator.free(self.atom_id);
        allocator.free(self.name);
        allocator.free(self.type);
    }

    pub fn clone(self: MergeConflict, allocator: Allocator) !MergeConflict {
        const aid = try allocator.dupe(u8, self.atom_id);
        errdefer allocator.free(aid);
        const name = try allocator.dupe(u8, self.name);
        errdefer allocator.free(name);
        const t = try allocator.dupe(u8, self.type);
        return .{ .atom_id = aid, .name = name, .type = t };
    }
};

/// MergeReport is the JSON document written to `ws/<name>/MERGE.json` on conflict.
pub const MergeReport = struct {
    into: []const u8,
    from: []const u8,
    ancestor: []const u8,
    conflicts: []const MergeConflict = &.{},

    pub fn deinit(self: MergeReport, allocator: Allocator) void {
        allocator.free(self.into);
        allocator.free(self.from);
        allocator.free(self.ancestor);
        for (self.conflicts) |c| c.deinit(allocator);
        allocator.free(self.conflicts);
    }
};

/// RemoteConfig is stored at `ws/<name>/REMOTE.json` (M106e).
pub const RemoteConfig = struct {
    remote: []const u8,
    stream: []const u8,

    pub fn deinit(self: RemoteConfig, allocator: Allocator) void {
        allocator.free(self.remote);
        allocator.free(self.stream);
    }
};

// Store path helpers matching Go's `store.go`

pub fn streamsDir(allocator: Allocator, root: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/streams", .{fsys.cleanMemPath(root)});
}

pub fn streamRecordPath(allocator: Allocator, root: []const u8, id: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/streams/{s}.json", .{ fsys.cleanMemPath(root), id });
}

pub fn streamLogPath(allocator: Allocator, root: []const u8, id: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/streams/{s}.jsonl", .{ fsys.cleanMemPath(root), id });
}

pub fn workspacesDir(allocator: Allocator, root: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/ws", .{fsys.cleanMemPath(root)});
}

pub fn workspaceDir(allocator: Allocator, root: []const u8, ws: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/ws/{s}", .{ fsys.cleanMemPath(root), ws });
}

pub fn workspaceConfigPath(allocator: Allocator, root: []const u8, ws: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/ws/{s}/WORKSPACE.json", .{ fsys.cleanMemPath(root), ws });
}

pub fn workspaceAtomsPath(allocator: Allocator, root: []const u8, ws: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/ws/{s}/ATOMS.jsonl", .{ fsys.cleanMemPath(root), ws });
}

pub fn workspaceStagePath(allocator: Allocator, root: []const u8, ws: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/ws/{s}/STAGE.jsonl", .{ fsys.cleanMemPath(root), ws });
}

pub fn workspaceBasePath(allocator: Allocator, root: []const u8, ws: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/ws/{s}/BASE.json", .{ fsys.cleanMemPath(root), ws });
}

pub fn workspaceMergePath(allocator: Allocator, root: []const u8, ws: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/ws/{s}/MERGE.json", .{ fsys.cleanMemPath(root), ws });
}

pub fn workspaceRemotePath(allocator: Allocator, root: []const u8, ws: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/ws/{s}/REMOTE.json", .{ fsys.cleanMemPath(root), ws });
}

pub fn keysDir(allocator: Allocator, root: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/keys", .{fsys.cleanMemPath(root)});
}

pub fn keyFilePath(allocator: Allocator, root: []const u8, name: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/keys/{s}", .{ fsys.cleanMemPath(root), name });
}

/// ReadJSONLLinesWithCode splits a JSONL payload into lines and enforces the ADR 0049
/// torn-append rule: any non-empty payload whose final byte is not '\n' is
/// refused with `stream_torn`. An empty line inside the JSONL is refused with
/// `empty_refuse_code` (`change_malformed`, `atom_malformed`, or `stage_malformed`).
pub fn readJSONLLinesWithCode(allocator: Allocator, data: []const u8, empty_refuse_code: []const u8) ![]const []const u8 {
    if (data.len == 0) return &.{};
    if (data[data.len - 1] != '\n') {
        return fsys.refuse("stream_torn", "");
    }
    const trimmed = data[0 .. data.len - 1];
    var out: std.ArrayList([]const u8) = .empty;
    errdefer out.deinit(allocator);

    var it = std.mem.splitScalar(u8, trimmed, '\n');
    while (it.next()) |line| {
        if (line.len == 0) {
            return fsys.refuse(empty_refuse_code, "");
        }
        try out.append(allocator, line);
    }
    return out.toOwnedSlice(allocator);
}

pub fn readJSONLLines(allocator: Allocator, data: []const u8) ![]const []const u8 {
    return readJSONLLinesWithCode(allocator, data, "change_malformed");
}

pub fn opTypeCode(t: []const u8) u8 {
    if (std.mem.eql(u8, t, "add")) return 1;
    if (std.mem.eql(u8, t, "modify")) return 2;
    if (std.mem.eql(u8, t, "delete")) return 3;
    if (std.mem.eql(u8, t, "move")) return 4;
    if (std.mem.eql(u8, t, "rename")) return 5;
    return 0;
}

fn opLessThan(_: void, a: Op, b: Op) bool {
    const ua = uuid.parseUUID(a.atom_id);
    const ub = uuid.parseUUID(b.atom_id);
    if (ua != null and ub != null) {
        const ord = std.mem.order(u8, &ua.?, &ub.?);
        if (ord != .eq) return ord == .lt;
    } else if (!std.mem.eql(u8, a.atom_id, b.atom_id)) {
        return std.mem.lessThan(u8, a.atom_id, b.atom_id);
    }
    return opTypeCode(a.type) < opTypeCode(b.type);
}

pub fn sortOps(ops: []Op) void {
    std.mem.sort(Op, ops, {}, opLessThan);
}

fn storedAtomLessThan(_: void, a: StoredAtom, b: StoredAtom) bool {
    if (!std.mem.eql(u8, a.span.file, b.span.file)) {
        return std.mem.lessThan(u8, a.span.file, b.span.file);
    }
    if (a.span.start != b.span.start) {
        return a.span.start < b.span.start;
    }
    if (!std.mem.eql(u8, a.kind, b.kind)) {
        return std.mem.lessThan(u8, a.kind, b.kind);
    }
    if (!std.mem.eql(u8, a.name, b.name)) {
        return std.mem.lessThan(u8, a.name, b.name);
    }
    return std.mem.lessThan(u8, a.id, b.id);
}

pub fn sortStoredAtoms(atoms: []StoredAtom) void {
    std.mem.sort(StoredAtom, atoms, {}, storedAtomLessThan);
}

/// Resolves the store root directory per `docs/flint-client-spec.md` §2.1:
/// 1. `--store <dir>` flag
/// 2. `FLINT_STORE` env var
/// 3. Walk up from `cwd` for a directory containing `.flint/` or `FLINT/`
/// 4. Refuse `store_not_found` naming where it looked (`cwd`).
pub fn resolveStoreRoot(
    allocator: Allocator,
    fs: FS,
    store_flag: []const u8,
    env_flint_store: ?[]const u8,
    cwd: []const u8,
) ![]u8 {
    if (store_flag.len > 0) {
        return fsys.cleanPath(allocator, store_flag);
    }
    if (env_flint_store) |env_val| {
        if (env_val.len > 0) {
            return fsys.cleanPath(allocator, env_val);
        }
    }

    const clean_cwd = try fsys.cleanPath(allocator, if (cwd.len > 0) cwd else ".");
    defer allocator.free(clean_cwd);

    var cur: []const u8 = clean_cwd;
    while (true) {
        const dot_flint = try fsys.joinPath(allocator, &.{ cur, ".flint" });
        if (fs.exists(allocator, dot_flint) and fs.isDir(allocator, dot_flint)) {
            return dot_flint;
        }
        allocator.free(dot_flint);

        const upper_flint = try fsys.joinPath(allocator, &.{ cur, "FLINT" });
        if (fs.exists(allocator, upper_flint) and fs.isDir(allocator, upper_flint)) {
            return upper_flint;
        }
        allocator.free(upper_flint);

        const parent = fsys.dirName(cur);
        if (std.mem.eql(u8, parent, cur)) break;
        cur = parent;
    }

    return fsys.refuse("store_not_found", clean_cwd);
}

pub fn optStrEql(a: ?[]const u8, b: ?[]const u8) bool {
    if (a == null and b == null) return true;
    if (a == null or b == null) return false;
    return std.mem.eql(u8, a.?, b.?);
}

/// StoreIndex holds the in-memory index built on each invocation from flat files.
pub const StoreIndex = struct {
    allocator: Allocator,
    root: []u8,
    streams: std.ArrayList(Stream) = .empty,
    workspaces: std.ArrayList(Workspace) = .empty,
    change_count: usize = 0,

    pub fn deinit(self: *StoreIndex) void {
        self.allocator.free(self.root);
        for (self.streams.items) |st| st.deinit(self.allocator);
        self.streams.deinit(self.allocator);
        for (self.workspaces.items) |ws| ws.deinit(self.allocator);
        self.workspaces.deinit(self.allocator);
    }

    pub fn streamByID(self: *const StoreIndex, id: []const u8) ?*const Stream {
        for (self.streams.items) |*st| {
            if (std.mem.eql(u8, st.id, id)) return st;
        }
        return null;
    }

    pub fn streamByName(self: *const StoreIndex, name: []const u8) ?*const Stream {
        for (self.streams.items) |*st| {
            if (std.mem.eql(u8, st.name, name)) return st;
        }
        return null;
    }

    pub fn workspaceByName(self: *const StoreIndex, name: []const u8) ?*const Workspace {
        for (self.workspaces.items) |*ws| {
            if (std.mem.eql(u8, ws.name, name)) return ws;
        }
        return null;
    }
};

/// LoadStoreIndex scans `<root>/streams` and `<root>/ws` into memory.
pub fn loadStoreIndex(allocator: Allocator, fs: FS, root: []const u8) !StoreIndex {
    var idx = StoreIndex{
        .allocator = allocator,
        .root = try allocator.dupe(u8, fsys.cleanMemPath(root)),
    };
    errdefer idx.deinit();

    const s_dir = try streamsDir(allocator, root);
    defer allocator.free(s_dir);

    if (fs.exists(allocator, s_dir)) {
        const entries = try fs.list(allocator, s_dir);
        defer FS.freeDirEntries(allocator, entries);

        for (entries) |e| {
            if (e.is_dir) continue;
            if (std.mem.endsWith(u8, e.name, ".json")) {
                const p = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ s_dir, e.name });
                defer allocator.free(p);
                const b = try fs.readFile(allocator, p, MaxFileReadBytes);
                defer allocator.free(b);
                const st = json.parseStream(allocator, b) catch {
                    return fsys.refuse("stream_malformed", e.name);
                };
                if (st.id.len == 0 or st.name.len == 0) {
                    st.deinit(allocator);
                    return fsys.refuse("stream_malformed", e.name);
                }
                errdefer st.deinit(allocator);
                try idx.streams.append(allocator, st);
            } else if (std.mem.endsWith(u8, e.name, ".jsonl")) {
                const p = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ s_dir, e.name });
                defer allocator.free(p);
                const b = try fs.readFile(allocator, p, MaxFileReadBytes);
                defer allocator.free(b);
                const lines = try readJSONLLines(allocator, b);
                defer allocator.free(lines);
                idx.change_count += lines.len;
                if (idx.change_count > MaxChanges) {
                    return fsys.refuse("store_too_large", "changes");
                }
            }
        }
    }

    const w_dir = try workspacesDir(allocator, root);
    defer allocator.free(w_dir);

    if (fs.exists(allocator, w_dir)) {
        const entries = try fs.list(allocator, w_dir);
        defer FS.freeDirEntries(allocator, entries);

        for (entries) |e| {
            if (!e.is_dir) continue;
            const cfg_path = try workspaceConfigPath(allocator, root, e.name);
            defer allocator.free(cfg_path);
            if (!fs.exists(allocator, cfg_path)) continue;
            const b = try fs.readFile(allocator, cfg_path, MaxFileReadBytes);
            defer allocator.free(b);
            const ws = json.parseWorkspace(allocator, b) catch {
                return fsys.refuse("ws_malformed", e.name);
            };
            if (ws.name.len == 0) {
                ws.deinit(allocator);
                return fsys.refuse("ws_malformed", e.name);
            }
            errdefer ws.deinit(allocator);
            try idx.workspaces.append(allocator, ws);
        }
    }

    return idx;
}

/// ReadStreamChanges reads and parses `streams/<id>.jsonl` via torn-aware `readJSONLLines`.
pub fn readStreamChanges(allocator: Allocator, fs: FS, root: []const u8, stream_id: []const u8) ![]Change {
    const p = try streamLogPath(allocator, root, stream_id);
    defer allocator.free(p);
    if (!fs.exists(allocator, p)) {
        return try allocator.alloc(Change, 0);
    }
    const b = try fs.readFile(allocator, p, MaxFileReadBytes);
    defer allocator.free(b);

    const lines = try readJSONLLines(allocator, b);
    defer allocator.free(lines);

    if (lines.len > MaxChanges) {
        return fsys.refuse("store_too_large", "changes");
    }

    var changes: std.ArrayList(Change) = .empty;
    errdefer {
        for (changes.items) |c| c.deinit(allocator);
        changes.deinit(allocator);
    }

    for (lines) |line| {
        const c = try json.parseChange(allocator, line);
        errdefer c.deinit(allocator);
        try changes.append(allocator, c);
    }
    return changes.toOwnedSlice(allocator);
}

pub fn freeChanges(allocator: Allocator, changes: []Change) void {
    for (changes) |c| c.deinit(allocator);
    allocator.free(changes);
}

/// WriteStreamRecord writes `streams/<id>.json` crash-safely via `writeFileSafe`.
pub fn writeStreamRecord(allocator: Allocator, fs: FS, root: []const u8, st: Stream) !void {
    const p = try streamRecordPath(allocator, root, st.id);
    defer allocator.free(p);
    const data = try json.marshalStreamLine(allocator, st);
    defer allocator.free(data);
    try fs.writeFileSafe(allocator, p, data);
}

pub const LoadedStream = struct {
    stream: Stream,
    changes: []Change,

    pub fn deinit(self: LoadedStream, allocator: Allocator) void {
        self.stream.deinit(allocator);
        freeChanges(allocator, self.changes);
    }
};

/// LoadStream reads the Stream record and its Change log, rolling a stale
/// record head forward when the log's last Change has `parent == record.head`.
pub fn loadStream(allocator: Allocator, fs: FS, root: []const u8, stream_id: []const u8) !LoadedStream {
    const rec_path = try streamRecordPath(allocator, root, stream_id);
    defer allocator.free(rec_path);
    if (!fs.exists(allocator, rec_path)) {
        return fsys.refuse("stream_missing", stream_id);
    }
    const b = try fs.readFile(allocator, rec_path, MaxFileReadBytes);
    defer allocator.free(b);

    var st = json.parseStream(allocator, b) catch {
        return fsys.refuse("stream_malformed", stream_id);
    };
    if (st.id.len == 0 or st.name.len == 0) {
        st.deinit(allocator);
        return fsys.refuse("stream_malformed", stream_id);
    }
    errdefer st.deinit(allocator);

    const changes = try readStreamChanges(allocator, fs, root, stream_id);
    errdefer freeChanges(allocator, changes);

    if (changes.len > 0) {
        const last = changes[changes.len - 1];
        if (optStrEql(last.parent, st.head) and (st.head == null or !std.mem.eql(u8, st.head.?, last.id))) {
            const new_head = try allocator.dupe(u8, last.id);
            if (st.head) |old_h| allocator.free(old_h);
            st.head = new_head;
            try writeStreamRecord(allocator, fs, root, st);
        }
    }

    return .{
        .stream = st,
        .changes = changes,
    };
}

fn streamLessThanByID(_: void, a: Stream, b: Stream) bool {
    return std.mem.lessThan(u8, a.id, b.id);
}

/// LoadAllStreamChanges scans all streams in deterministic ID order, rolling
/// any stale records forward and returning all Changes across the store.
pub fn loadAllStreamChanges(allocator: Allocator, fs: FS, root: []const u8, idx: *StoreIndex) ![]Change {
    std.mem.sort(Stream, idx.streams.items, {}, streamLessThanByID);

    var seen_logs = std.StringHashMap(void).init(allocator);
    defer {
        var it = seen_logs.iterator();
        while (it.next()) |kv| allocator.free(kv.key_ptr.*);
        seen_logs.deinit();
    }

    var all: std.ArrayList(Change) = .empty;
    errdefer {
        for (all.items) |c| c.deinit(allocator);
        all.deinit(allocator);
    }

    for (idx.streams.items) |*st_slot| {
        const loaded = try loadStream(allocator, fs, root, st_slot.id);
        defer allocator.free(loaded.changes);

        st_slot.deinit(allocator);
        st_slot.* = loaded.stream;

        const log_name = try std.fmt.allocPrint(allocator, "{s}.jsonl", .{st_slot.id});
        errdefer allocator.free(log_name);
        try seen_logs.put(log_name, {});

        for (loaded.changes) |c| {
            try all.append(allocator, c);
        }
    }

    const s_dir = try streamsDir(allocator, root);
    defer allocator.free(s_dir);
    if (fs.exists(allocator, s_dir)) {
        const entries = try fs.list(allocator, s_dir);
        defer FS.freeDirEntries(allocator, entries);

        for (entries) |e| {
            if (e.is_dir or !std.mem.endsWith(u8, e.name, ".jsonl") or seen_logs.contains(e.name)) {
                continue;
            }
            const sid = e.name[0 .. e.name.len - ".jsonl".len];
            const orphan_changes = try readStreamChanges(allocator, fs, root, sid);
            defer allocator.free(orphan_changes);
            for (orphan_changes) |c| {
                try all.append(allocator, c);
            }
        }
    }

    if (all.items.len > MaxChanges) {
        return fsys.refuse("store_too_large", "changes");
    }

    return all.toOwnedSlice(allocator);
}

pub const AtomKey = struct {
    file: []const u8,
    kind: []const u8,
    name: []const u8,
};

pub const AtomKeyContext = struct {
    pub fn hash(_: AtomKeyContext, k: AtomKey) u64 {
        var h = std.hash.Wyhash.init(0);
        h.update(k.file);
        h.update("\x00");
        h.update(k.kind);
        h.update("\x00");
        h.update(k.name);
        return h.final();
    }

    pub fn eql(_: AtomKeyContext, a: AtomKey, b: AtomKey) bool {
        return std.mem.eql(u8, a.file, b.file) and
            std.mem.eql(u8, a.kind, b.kind) and
            std.mem.eql(u8, a.name, b.name);
    }
};

pub fn freeStoredAtoms(allocator: Allocator, atoms: []StoredAtom) void {
    for (atoms) |a| a.deinit(allocator);
    allocator.free(atoms);
}

pub fn freeOps(allocator: Allocator, ops: []Op) void {
    for (ops) |op| op.deinit(allocator);
    allocator.free(ops);
}

/// LoadWorkspaceAtoms reads `ws/<name>/ATOMS.jsonl` and enforces the 4096-Atom bound.
pub fn loadWorkspaceAtoms(allocator: Allocator, fs: FS, root: []const u8, ws: []const u8) ![]StoredAtom {
    const p = try workspaceAtomsPath(allocator, root, ws);
    defer allocator.free(p);
    if (!fs.exists(allocator, p)) {
        return try allocator.alloc(StoredAtom, 0);
    }
    const b = try fs.readFile(allocator, p, MaxFileReadBytes);
    defer allocator.free(b);

    const lines = try readJSONLLinesWithCode(allocator, b, "atom_malformed");
    defer allocator.free(lines);

    if (lines.len > MaxAtoms) {
        return fsys.refuse("store_too_large", "atoms");
    }

    var atoms: std.ArrayList(StoredAtom) = .empty;
    errdefer {
        for (atoms.items) |a| a.deinit(allocator);
        atoms.deinit(allocator);
    }

    for (lines) |line| {
        const a = json.parseStoredAtom(allocator, line) catch {
            return fsys.refuse("atom_malformed", "");
        };
        if (a.id.len == 0 or a.kind.len == 0 or a.name.len == 0) {
            a.deinit(allocator);
            return fsys.refuse("atom_malformed", "");
        }
        errdefer a.deinit(allocator);
        try atoms.append(allocator, a);
    }

    return atoms.toOwnedSlice(allocator);
}

/// WriteWorkspaceAtoms writes `ws/<name>/ATOMS.jsonl` deterministically via `writeFileSafe`.
pub fn writeWorkspaceAtoms(allocator: Allocator, fs: FS, root: []const u8, ws: []const u8, atoms: []const StoredAtom) !void {
    if (atoms.len > MaxAtoms) {
        return fsys.refuse("store_too_large", "atoms");
    }
    const sorted = try allocator.dupe(StoredAtom, atoms);
    defer allocator.free(sorted);
    sortStoredAtoms(sorted);

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    for (sorted) |a| {
        try json.appendStoredAtom(&buf, allocator, a);
        try buf.append(allocator, '\n');
    }

    const p = try workspaceAtomsPath(allocator, root, ws);
    defer allocator.free(p);
    try fs.writeFileSafe(allocator, p, buf.items);
}

/// LoadWorkspaceStage reads `ws/<name>/STAGE.jsonl` if present.
pub fn loadWorkspaceStage(allocator: Allocator, fs: FS, root: []const u8, ws: []const u8) ![]Op {
    const p = try workspaceStagePath(allocator, root, ws);
    defer allocator.free(p);
    if (!fs.exists(allocator, p)) {
        return try allocator.alloc(Op, 0);
    }
    const b = try fs.readFile(allocator, p, MaxFileReadBytes);
    defer allocator.free(b);

    const lines = try readJSONLLinesWithCode(allocator, b, "stage_malformed");
    defer allocator.free(lines);

    if (lines.len > MaxAtoms) {
        return fsys.refuse("store_too_large", "atoms");
    }

    var ops: std.ArrayList(Op) = .empty;
    errdefer {
        for (ops.items) |op| op.deinit(allocator);
        ops.deinit(allocator);
    }

    for (lines) |line| {
        const op = json.parseOp(allocator, line) catch {
            return fsys.refuse("stage_malformed", "");
        };
        if (op.type.len == 0 or op.atom_id.len == 0) {
            op.deinit(allocator);
            return fsys.refuse("stage_malformed", "");
        }
        errdefer op.deinit(allocator);
        try ops.append(allocator, op);
    }

    return ops.toOwnedSlice(allocator);
}

/// WriteWorkspaceStage writes `ws/<name>/STAGE.jsonl` deterministically via `writeFileSafe`.
pub fn writeWorkspaceStage(allocator: Allocator, fs: FS, root: []const u8, ws: []const u8, ops: []const Op) !void {
    if (ops.len > MaxAtoms) {
        return fsys.refuse("store_too_large", "atoms");
    }
    const sorted = try allocator.dupe(Op, ops);
    defer allocator.free(sorted);
    sortOps(sorted);

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    for (sorted) |op| {
        try json.appendOp(&buf, allocator, op);
        try buf.append(allocator, '\n');
    }

    const p = try workspaceStagePath(allocator, root, ws);
    defer allocator.free(p);
    try fs.writeFileSafe(allocator, p, buf.items);
}

/// LoadWorkspaceStageBase reads `ws/<name>/BASE.json` — the stream head the
/// pending stage was last staged against — or returns `null` when the file is
/// absent. Absence means unknown provenance (e.g. a stage written before this
/// record existed), never "the latest head" (#67).
pub fn loadWorkspaceStageBase(allocator: Allocator, fs: FS, root: []const u8, ws: []const u8) !?StageBase {
    const p = try workspaceBasePath(allocator, root, ws);
    defer allocator.free(p);
    if (!fs.exists(allocator, p)) return null;
    const b = try fs.readFile(allocator, p, MaxFileReadBytes);
    defer allocator.free(b);
    const head = json.parseStageBase(allocator, b) catch {
        return fsys.refuse("ws_malformed", ws);
    };
    return .{ .head = head };
}

/// WriteWorkspaceStageBase writes `ws/<name>/BASE.json` via `writeFileSafe`.
pub fn writeWorkspaceStageBase(allocator: Allocator, fs: FS, root: []const u8, ws: []const u8, head: ?[]const u8) !void {
    const p = try workspaceBasePath(allocator, root, ws);
    defer allocator.free(p);
    const data = try json.marshalStageBaseLine(allocator, head);
    defer allocator.free(data);
    try fs.writeFileSafe(allocator, p, data);
}

/// WriteWorkspaceConfig writes `ws/<name>/WORKSPACE.json` via `writeFileSafe`.
pub fn writeWorkspaceConfig(allocator: Allocator, fs: FS, root: []const u8, ws: Workspace) !void {
    const p = try workspaceConfigPath(allocator, root, ws.name);
    defer allocator.free(p);
    const data = try json.marshalWorkspaceLine(allocator, ws);
    defer allocator.free(data);
    try fs.writeFileSafe(allocator, p, data);
}

/// WriteWorkspaceRemote writes `ws/<name>/REMOTE.json` via `writeFileSafe`.
pub fn writeWorkspaceRemote(allocator: Allocator, fs: FS, root: []const u8, ws_name: []const u8, rc: RemoteConfig) !void {
    const p = try workspaceRemotePath(allocator, root, ws_name);
    defer allocator.free(p);
    const data = try json.marshalRemoteConfigLine(allocator, rc);
    defer allocator.free(data);
    try fs.writeFileSafe(allocator, p, data);
}

/// LoadWorkspaceRemote reads `ws/<name>/REMOTE.json` if present, or returns `null`.
pub fn loadWorkspaceRemote(allocator: Allocator, fs: FS, root: []const u8, ws_name: []const u8) !?RemoteConfig {
    const p = try workspaceRemotePath(allocator, root, ws_name);
    defer allocator.free(p);
    if (!fs.exists(allocator, p)) return null;
    const raw = try fs.readFile(allocator, p, MaxFileReadBytes);
    defer allocator.free(raw);
    return try json.parseRemoteConfig(allocator, raw);
}

/// LoadWorkspaceMerge reads `ws/<name>/MERGE.json` — the marker a conflicted
/// `merge` leaves behind — or returns `null` when no merge is in progress.
pub fn loadWorkspaceMerge(allocator: Allocator, fs: FS, root: []const u8, ws_name: []const u8) !?MergeReport {
    const p = try workspaceMergePath(allocator, root, ws_name);
    defer allocator.free(p);
    if (!fs.exists(allocator, p)) return null;
    const raw = try fs.readFile(allocator, p, MaxFileReadBytes);
    defer allocator.free(raw);
    return try json.parseMergeReport(allocator, raw);
}

/// CheckStaleHead re-reads the Stream record (rolling forward if the log moved)
/// and refuses with `stale_head` if the head no longer equals `expected_head`.
pub fn checkStaleHead(
    allocator: Allocator,
    fs: FS,
    root: []const u8,
    stream_id: []const u8,
    expected_head: ?[]const u8,
) !Stream {
    const loaded = try loadStream(allocator, fs, root, stream_id);
    freeChanges(allocator, loaded.changes);
    errdefer loaded.stream.deinit(allocator);

    if (!optStrEql(loaded.stream.head, expected_head)) {
        return fsys.refuse("stale_head", "");
    }
    return loaded.stream;
}

/// AppendStreamChange executes steps (1) and (2) of ADR 0049's commit order:
/// re-read the Stream record to check `stale_head`, append the Change JSON line
/// with `appendSync`, and rewrite the Stream record with the new head.
pub fn appendStreamChange(
    allocator: Allocator,
    fs: FS,
    root: []const u8,
    stream_id: []const u8,
    expected_head: ?[]const u8,
    c: Change,
) !Stream {
    var st = try checkStaleHead(allocator, fs, root, stream_id, expected_head);
    errdefer st.deinit(allocator);

    const line = try json.marshalChangeLine(allocator, c);
    defer allocator.free(line);

    const log_path = try streamLogPath(allocator, root, stream_id);
    defer allocator.free(log_path);
    try fs.appendSync(allocator, log_path, line);

    const new_head = try allocator.dupe(u8, c.id);
    if (st.head) |old_h| allocator.free(old_h);
    st.head = new_head;

    try writeStreamRecord(allocator, fs, root, st);
    return st;
}

pub fn validWorkspaceName(name: []const u8) bool {
    if (name.len == 0 or name.len > 32) return false;
    for (name) |c| {
        const ok = (c >= 'a' and c <= 'z') or (c >= '0' and c <= '9') or c == '-';
        if (!ok) return false;
    }
    return true;
}

/// ApplyOpsToAtomMap applies a Change's Ops to an Atom table indexed by AtomID.
/// When `mark_merge_origin` is true, added/modified/moved/renamed Atoms are marked
/// with `origin = "merge"` (ADR 0049 §2).
pub fn applyOpsToAtomMap(
    allocator: Allocator,
    atoms_by_id: *std.StringHashMap(StoredAtom),
    ops: []const Op,
    mark_merge_origin: bool,
) !void {
    const sorted = try allocator.dupe(Op, ops);
    defer allocator.free(sorted);
    sortOps(sorted);

    for (sorted) |op| {
        if (std.mem.eql(u8, op.type, "add")) {
            const sp = if (op.new_span) |nsp|
                try nsp.clone(allocator)
            else
                Span{ .file = try allocator.dupe(u8, ""), .start = 0, .end = 0 };
            errdefer sp.deinit(allocator);

            const id = try allocator.dupe(u8, op.atom_id);
            errdefer allocator.free(id);
            const kind = try allocator.dupe(u8, op.kind);
            errdefer allocator.free(kind);
            const name = try allocator.dupe(u8, op.new_name);
            errdefer allocator.free(name);
            const hash = try allocator.dupe(u8, op.new_hash);
            errdefer allocator.free(hash);
            const sig_hash = try allocator.dupe(u8, op.new_sig_hash);
            errdefer allocator.free(sig_hash);
            const origin = if (mark_merge_origin) try allocator.dupe(u8, "merge") else "";
            errdefer if (origin.len > 0) allocator.free(origin);

            const new_atom = StoredAtom{
                .id = id,
                .kind = kind,
                .name = name,
                .hash = hash,
                .sig_hash = sig_hash,
                .span = sp,
                .origin = origin,
            };

            if (atoms_by_id.fetchRemove(op.atom_id)) |old_kv| {
                allocator.free(old_kv.key);
                old_kv.value.deinit(allocator);
            }
            const k = try allocator.dupe(u8, op.atom_id);
            errdefer allocator.free(k);
            try atoms_by_id.put(k, new_atom);
        } else if (std.mem.eql(u8, op.type, "modify")) {
            if (atoms_by_id.getPtr(op.atom_id)) |a_ptr| {
                const new_h = try allocator.dupe(u8, op.new_hash);
                allocator.free(a_ptr.hash);
                a_ptr.hash = new_h;
                if (op.new_sig_hash.len > 0) {
                    const new_sh = try allocator.dupe(u8, op.new_sig_hash);
                    allocator.free(a_ptr.sig_hash);
                    a_ptr.sig_hash = new_sh;
                }
                if (op.new_span) |nsp| {
                    const sp_copy = try nsp.clone(allocator);
                    a_ptr.span.deinit(allocator);
                    a_ptr.span = sp_copy;
                }
                if (mark_merge_origin and !std.mem.eql(u8, a_ptr.origin, "merge")) {
                    const m_orig = try allocator.dupe(u8, "merge");
                    if (a_ptr.origin.len > 0) allocator.free(a_ptr.origin);
                    a_ptr.origin = m_orig;
                }
            } else {
                const sp = if (op.new_span) |nsp|
                    try nsp.clone(allocator)
                else
                    Span{ .file = try allocator.dupe(u8, ""), .start = 0, .end = 0 };
                errdefer sp.deinit(allocator);
                const id = try allocator.dupe(u8, op.atom_id);
                errdefer allocator.free(id);
                const kind = try allocator.dupe(u8, "");
                errdefer allocator.free(kind);
                const name = try allocator.dupe(u8, "");
                errdefer allocator.free(name);
                const hash = try allocator.dupe(u8, op.new_hash);
                errdefer allocator.free(hash);
                const sig_hash = try allocator.dupe(u8, op.new_sig_hash);
                errdefer allocator.free(sig_hash);
                const origin = if (mark_merge_origin) try allocator.dupe(u8, "merge") else "";
                errdefer if (origin.len > 0) allocator.free(origin);
                const k = try allocator.dupe(u8, op.atom_id);
                errdefer allocator.free(k);
                try atoms_by_id.put(k, .{
                    .id = id,
                    .kind = kind,
                    .name = name,
                    .hash = hash,
                    .sig_hash = sig_hash,
                    .span = sp,
                    .origin = origin,
                });
            }
        } else if (std.mem.eql(u8, op.type, "delete")) {
            if (atoms_by_id.fetchRemove(op.atom_id)) |old_kv| {
                allocator.free(old_kv.key);
                old_kv.value.deinit(allocator);
            }
        } else if (std.mem.eql(u8, op.type, "move")) {
            if (atoms_by_id.getPtr(op.atom_id)) |a_ptr| {
                if (op.new_span) |nsp| {
                    const sp_copy = try nsp.clone(allocator);
                    a_ptr.span.deinit(allocator);
                    a_ptr.span = sp_copy;
                }
                if (mark_merge_origin and !std.mem.eql(u8, a_ptr.origin, "merge")) {
                    const m_orig = try allocator.dupe(u8, "merge");
                    if (a_ptr.origin.len > 0) allocator.free(a_ptr.origin);
                    a_ptr.origin = m_orig;
                }
            }
        } else if (std.mem.eql(u8, op.type, "rename")) {
            if (atoms_by_id.getPtr(op.atom_id)) |a_ptr| {
                const new_n = try allocator.dupe(u8, op.new_name);
                allocator.free(a_ptr.name);
                a_ptr.name = new_n;
                if (mark_merge_origin and !std.mem.eql(u8, a_ptr.origin, "merge")) {
                    const m_orig = try allocator.dupe(u8, "merge");
                    if (a_ptr.origin.len > 0) allocator.free(a_ptr.origin);
                    a_ptr.origin = m_orig;
                }
            }
        }
    }
}

pub const ReplayResult = struct {
    atoms: []StoredAtom,
    replayed: usize,
};

/// ReplayStreamAtoms materializes the Atom table at `head_id` by replaying Ops
/// along the parent chain, root -> head (ADR 0049 / M103d).
pub fn replayStreamAtoms(
    allocator: Allocator,
    head_id: ?[]const u8,
    all_changes: []const Change,
) !ReplayResult {
    if (head_id == null or head_id.?.len == 0) {
        return .{
            .atoms = try allocator.alloc(StoredAtom, 0),
            .replayed = 0,
        };
    }

    var changes_by_id = std.StringHashMap(Change).init(allocator);
    defer changes_by_id.deinit();
    for (all_changes) |c| {
        try changes_by_id.put(c.id, c);
    }

    var chain: std.ArrayList(Change) = .empty;
    defer chain.deinit(allocator);

    var seen = std.StringHashMap(void).init(allocator);
    defer seen.deinit();

    var cur: []const u8 = head_id.?;
    while (cur.len > 0) {
        if (seen.contains(cur)) {
            return fsys.refuse("change_malformed", cur);
        }
        try seen.put(cur, {});
        const c = changes_by_id.get(cur) orelse {
            return fsys.refuse("change_missing", cur);
        };
        try chain.append(allocator, c);
        if (c.parent == null) break;
        cur = c.parent.?;
    }

    std.mem.reverse(Change, chain.items);

    var atoms_by_id = std.StringHashMap(StoredAtom).init(allocator);
    defer {
        var it = atoms_by_id.iterator();
        while (it.next()) |kv| {
            allocator.free(kv.key_ptr.*);
            kv.value_ptr.deinit(allocator);
        }
        atoms_by_id.deinit();
    }

    for (chain.items) |c| {
        try applyOpsToAtomMap(allocator, &atoms_by_id, c.ops, false);
    }

    var out: std.ArrayList(StoredAtom) = .empty;
    errdefer {
        for (out.items) |a| a.deinit(allocator);
        out.deinit(allocator);
    }

    var it = atoms_by_id.iterator();
    while (it.next()) |kv| {
        const cloned = try kv.value_ptr.clone(allocator);
        errdefer cloned.deinit(allocator);
        try out.append(allocator, cloned);
    }

    const slice = try out.toOwnedSlice(allocator);
    sortStoredAtoms(slice);
    return .{
        .atoms = slice,
        .replayed = chain.items.len,
    };
}

/// Selects the workspace for commands (`add`, `status`, `commit`, `log`, `merge`)
/// per `resolveWorkspace` in `workspace.go`.
pub fn resolveWorkspace(
    allocator: Allocator,
    fs: FS,
    idx: *const StoreIndex,
    ws_flag: []const u8,
    path_args: []const []const u8,
) !*const Workspace {
    if (ws_flag.len > 0) {
        return idx.workspaceByName(ws_flag) orelse fsys.refuse("ws_missing", ws_flag);
    }
    if (idx.workspaces.items.len == 1) {
        return &idx.workspaces.items[0];
    }
    if (path_args.len > 0) {
        var matched: ?*const Workspace = null;
        for (idx.workspaces.items) |*ws| {
            var all_under = true;
            for (path_args) |p| {
                const cp = fsys.cleanMemPath(p);
                if (!std.mem.eql(u8, cp, ws.src)) {
                    const prefix = try std.fmt.allocPrint(allocator, "{s}/", .{ws.src});
                    defer allocator.free(prefix);
                    if (!std.mem.startsWith(u8, cp, prefix)) {
                        all_under = false;
                        break;
                    }
                }
            }
            if (all_under) {
                if (matched != null) {
                    matched = null;
                    break;
                }
                matched = ws;
            }
        }
        if (matched) |m| return m;
    }
    if (idx.workspaces.items.len == 0) {
        return fsys.refuse("ws_missing", "");
    }

    // Multiple workspaces and no path matched: check if exactly one has a stage.
    var with_stage: ?*const Workspace = null;
    var count: usize = 0;
    for (idx.workspaces.items) |*ws| {
        const stg_path = try workspaceStagePath(allocator, idx.root, ws.name);
        defer allocator.free(stg_path);
        if (fs.exists(allocator, stg_path)) {
            with_stage = ws;
            count += 1;
        }
    }
    if (count == 1) {
        return with_stage.?;
    }
    return fsys.refuse("ws_ambiguous", "");
}

/// Folds newly produced Ops into the existing staged Ops per ADR 0049 §1 and §2 step 2:
/// - add + modify -> add (with newest hash, sig_hash, and span)
/// - add + delete -> nothing (removed from stage)
/// - modify + modify -> modify (first old_hash -> last new_hash)
/// - modify + delete -> delete (first old_hash)
pub fn foldStageOps(
    allocator: Allocator,
    existing: []const Op,
    incoming: []const Op,
    current_atoms: []const StoredAtom,
) ![]Op {
    var by_atom = std.StringHashMap(Op).init(allocator);
    defer {
        var it = by_atom.iterator();
        while (it.next()) |kv| {
            allocator.free(kv.key_ptr.*);
            kv.value_ptr.deinit(allocator);
        }
        by_atom.deinit();
    }

    for (existing) |op| {
        const cloned = try op.clone(allocator);
        errdefer cloned.deinit(allocator);
        if (by_atom.fetchRemove(op.atom_id)) |old_kv| {
            allocator.free(old_kv.key);
            old_kv.value.deinit(allocator);
        }
        const k = try allocator.dupe(u8, op.atom_id);
        errdefer allocator.free(k);
        try by_atom.put(k, cloned);
    }

    var span_by_id = std.StringHashMap(Span).init(allocator);
    defer span_by_id.deinit();
    for (current_atoms) |a| {
        try span_by_id.put(a.id, a.span);
    }

    for (incoming) |op| {
        const prev_ptr = by_atom.getPtr(op.atom_id);
        if (prev_ptr == null) {
            const cloned = try op.clone(allocator);
            errdefer cloned.deinit(allocator);
            const k = try allocator.dupe(u8, op.atom_id);
            errdefer allocator.free(k);
            try by_atom.put(k, cloned);
            continue;
        }
        const prev = prev_ptr.?;
        if (std.mem.eql(u8, prev.type, "add")) {
            if (std.mem.eql(u8, op.type, "modify")) {
                const nh = try allocator.dupe(u8, op.new_hash);
                if (prev.new_hash.len > 0) allocator.free(prev.new_hash);
                prev.new_hash = nh;

                const nsh = try allocator.dupe(u8, op.new_sig_hash);
                if (prev.new_sig_hash.len > 0) allocator.free(prev.new_sig_hash);
                prev.new_sig_hash = nsh;

                if (span_by_id.get(op.atom_id)) |sp| {
                    const sp_copy = try sp.clone(allocator);
                    if (prev.new_span) |old_sp| old_sp.deinit(allocator);
                    prev.new_span = sp_copy;
                }
            } else if (std.mem.eql(u8, op.type, "delete")) {
                if (by_atom.fetchRemove(op.atom_id)) |old_kv| {
                    allocator.free(old_kv.key);
                    old_kv.value.deinit(allocator);
                }
            }
        } else if (std.mem.eql(u8, prev.type, "modify")) {
            if (std.mem.eql(u8, op.type, "modify")) {
                const nh = try allocator.dupe(u8, op.new_hash);
                if (prev.new_hash.len > 0) allocator.free(prev.new_hash);
                prev.new_hash = nh;

                const nsh = try allocator.dupe(u8, op.new_sig_hash);
                if (prev.new_sig_hash.len > 0) allocator.free(prev.new_sig_hash);
                prev.new_sig_hash = nsh;
            } else if (std.mem.eql(u8, op.type, "delete")) {
                const first_old_hash = try allocator.dupe(u8, prev.old_hash);
                errdefer allocator.free(first_old_hash);
                const t_del = try allocator.dupe(u8, "delete");
                errdefer allocator.free(t_del);
                const aid = try allocator.dupe(u8, op.atom_id);
                errdefer allocator.free(aid);

                prev.deinit(allocator);
                prev.* = .{
                    .type = t_del,
                    .atom_id = aid,
                    .old_hash = first_old_hash,
                };
            }
        } else {
            const cloned = try op.clone(allocator);
            prev.deinit(allocator);
            prev.* = cloned;
        }
    }

    // Refresh NewSpan on staged adds whose span shifted on an unchanged re-add.
    var it = by_atom.iterator();
    while (it.next()) |kv| {
        if (std.mem.eql(u8, kv.value_ptr.type, "add")) {
            if (span_by_id.get(kv.key_ptr.*)) |sp| {
                const sp_copy = try sp.clone(allocator);
                if (kv.value_ptr.new_span) |old_sp| old_sp.deinit(allocator);
                kv.value_ptr.new_span = sp_copy;
            }
        }
    }

    var out: std.ArrayList(Op) = .empty;
    errdefer {
        for (out.items) |op| op.deinit(allocator);
        out.deinit(allocator);
    }

    var it2 = by_atom.iterator();
    while (it2.next()) |kv| {
        const cloned = try kv.value_ptr.clone(allocator);
        errdefer cloned.deinit(allocator);
        try out.append(allocator, cloned);
    }

    const slice = try out.toOwnedSlice(allocator);
    sortOps(slice);
    return slice;
}
