// Content layer (docs/flint-blobs-spec.md, client spec review #77):
// whole-file content-addressed blobs plus signed, complete-inventory
// manifest lines bound to each Change. Commit captures the tracked source
// inventory (independent of declaration parsing, §2); `checkout`
// materializes exactly one signed snapshot all-or-nothing.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const fsys = @import("fsys.zig");
const FS = fsys.FS;
const store = @import("store.zig");
const json = @import("json.zig");
const ed25519 = @import("ed25519.zig");
const uuid = @import("uuid.zig");

/// Per-blob decoded size bound (spec §6): the 3.6 MB hex wire form fits the
/// 4 MiB line bound with envelope headroom.
pub const MaxBlobBytes: usize = 1_800_000;
/// Manifest log line cap mirrors the Change bound (one line per Change).
pub const MaxManifestLines: usize = store.MaxChanges;
/// Domain-separated signature preimage prefix for manifest records — a
/// distinct `sig_msg` domain, so a manifest signature can never stand in for
/// a Change signature or vice versa (spec §5).
pub const manifest_domain = "flint-manifest-v1\n";

pub const ManifestFile = struct {
    path: []const u8,
    blob: ?[]const u8,
    bytes: u64,
    mode: u32,
    reason: ?[]const u8,

    pub fn deinit(self: ManifestFile, allocator: Allocator) void {
        allocator.free(self.path);
        if (self.blob) |b| allocator.free(b);
        if (self.reason) |r| allocator.free(r);
    }
};

pub const Manifest = struct {
    stream: []const u8,
    change: []const u8,
    author: []const u8,
    files: []ManifestFile,
    sig: []const u8,

    pub fn deinit(self: Manifest, allocator: Allocator) void {
        allocator.free(self.stream);
        allocator.free(self.change);
        allocator.free(self.author);
        for (self.files) |f| f.deinit(allocator);
        allocator.free(self.files);
        allocator.free(self.sig);
    }
};

/// Canonical manifest bytes (no `sig`, no trailing newline) under the
/// manifest domain — the signature preimage from spec §5.
fn manifestSigMsg(allocator: Allocator, m: *const Manifest) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    try buf.appendSlice(allocator, manifest_domain);
    const canonical = try marshalManifestBody(allocator, m);
    defer allocator.free(canonical);
    try buf.appendSlice(allocator, canonical);
    return buf.toOwnedSlice(allocator);
}

fn marshalManifestBody(allocator: Allocator, m: *const Manifest) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, "{\"stream\":");
    try json.appendGoJSONString(&out, allocator, m.stream);
    try out.appendSlice(allocator, ",\"change\":");
    try json.appendGoJSONString(&out, allocator, m.change);
    try out.appendSlice(allocator, ",\"author\":");
    try json.appendGoJSONString(&out, allocator, m.author);
    try out.appendSlice(allocator, ",\"files\":[");
    for (m.files, 0..) |f, i| {
        if (i > 0) try out.append(allocator, ',');
        try out.appendSlice(allocator, "{\"path\":");
        try json.appendGoJSONString(&out, allocator, f.path);
        try out.appendSlice(allocator, ",\"blob\":");
        if (f.blob) |b| {
            try json.appendGoJSONString(&out, allocator, b);
        } else {
            try out.appendSlice(allocator, "null");
        }
        try out.appendSlice(allocator, ",\"bytes\":");
        var numbuf: [24]u8 = undefined;
        try out.appendSlice(allocator, std.fmt.bufPrint(&numbuf, "{d}", .{f.bytes}) catch unreachable);
        try out.appendSlice(allocator, ",\"mode\":");
        try out.appendSlice(allocator, std.fmt.bufPrint(&numbuf, "{d}", .{f.mode}) catch unreachable);
        if (f.reason) |r| {
            try out.appendSlice(allocator, ",\"reason\":");
            try json.appendGoJSONString(&out, allocator, r);
        }
        try out.append(allocator, '}');
    }
    try out.appendSlice(allocator, "]}");
    return out.toOwnedSlice(allocator);
}

/// Canonical signed manifest line: body fields plus `sig`, trailing `\n`.
pub fn marshalManifestLine(allocator: Allocator, m: *const Manifest) ![]u8 {
    const body = try marshalManifestBody(allocator, m);
    defer allocator.free(body);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, body[0 .. body.len - 1]); // strip '}'
    try out.appendSlice(allocator, ",\"sig\":");
    try json.appendGoJSONString(&out, allocator, m.sig);
    try out.appendSlice(allocator, "}\n");
    return out.toOwnedSlice(allocator);
}

fn isHex64(s: []const u8) bool {
    if (s.len != 64) return false;
    for (s) |c| {
        if (!std.ascii.isHex(c) or std.ascii.isUpper(c)) return false;
    }
    return true;
}

fn isValidManifestPath(p: []const u8) bool {
    if (p.len == 0 or p[0] == '/' or std.mem.endsWith(u8, p, "/")) return false;
    var it = std.mem.splitScalar(u8, p, '/');
    while (it.next()) |seg| {
        if (seg.len == 0 or std.mem.eql(u8, seg, ".") or std.mem.eql(u8, seg, "..")) return false;
    }
    return true;
}

/// Parses one manifest line (no trailing newline). Structural errors refuse
/// `manifest_torn` — a manifest line that fails to parse makes the log's
/// contents unusable rather than silently partial.
pub fn parseManifestLine(allocator: Allocator, line: []const u8) !Manifest {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, line, .{}) catch
        return fsys.refuse("manifest_torn", "");
    defer parsed.deinit();
    if (parsed.value != .object) return fsys.refuse("manifest_torn", "");

    const obj = parsed.value.object;
    const stream_v = obj.get("stream") orelse return fsys.refuse("manifest_torn", "");
    const change_v = obj.get("change") orelse return fsys.refuse("manifest_torn", "");
    const author_v = obj.get("author") orelse return fsys.refuse("manifest_torn", "");
    const files_v = obj.get("files") orelse return fsys.refuse("manifest_torn", "");
    const sig_v = obj.get("sig") orelse return fsys.refuse("manifest_torn", "");

    if (stream_v != .string or change_v != .string or author_v != .string or sig_v != .string) {
        return fsys.refuse("manifest_torn", "");
    }
    if (uuid.parseUUID(stream_v.string) == null or uuid.parseUUID(change_v.string) == null) {
        return fsys.refuse("manifest_torn", "");
    }
    if (author_v.string.len != 64) return fsys.refuse("manifest_torn", "");
    if (sig_v.string.len != 128) return fsys.refuse("manifest_torn", "");
    if (files_v != .array) return fsys.refuse("manifest_torn", "");

    var files: std.ArrayList(ManifestFile) = .empty;
    errdefer {
        for (files.items) |f| f.deinit(allocator);
        files.deinit(allocator);
    }

    for (files_v.array.items) |fv| {
        if (fv != .object) return fsys.refuse("manifest_torn", "");
        const fo = fv.object;
        const path_v = fo.get("path") orelse return fsys.refuse("manifest_torn", "");
        const blob_v = fo.get("blob") orelse return fsys.refuse("manifest_torn", "");
        const bytes_v = fo.get("bytes") orelse return fsys.refuse("manifest_torn", "");
        const mode_v = fo.get("mode") orelse return fsys.refuse("manifest_torn", "");
        if (path_v != .string or mode_v != .integer) return fsys.refuse("manifest_torn", "");
        if (!isValidManifestPath(path_v.string)) return fsys.refuse("manifest_torn", "");
        const bytes: u64 = switch (bytes_v) {
            .integer => |n| if (n < 0) return fsys.refuse("manifest_torn", "") else @intCast(n),
            else => return fsys.refuse("manifest_torn", ""),
        };
        if (mode_v.integer < 0) return fsys.refuse("manifest_torn", "");
        var blob: ?[]const u8 = null;
        switch (blob_v) {
            .null => {},
            .string => |b| {
                if (!isHex64(b)) return fsys.refuse("manifest_torn", "");
                blob = try allocator.dupe(u8, b);
            },
            else => return fsys.refuse("manifest_torn", ""),
        }
        errdefer if (blob) |b| allocator.free(b);
        var reason: ?[]const u8 = null;
        if (fo.get("reason")) |rv| {
            if (rv != .string) return fsys.refuse("manifest_torn", "");
            reason = try allocator.dupe(u8, rv.string);
        }
        if (blob == null and reason == null) return fsys.refuse("manifest_torn", "");
        try files.append(allocator, .{
            .path = try allocator.dupe(u8, path_v.string),
            .blob = blob,
            .bytes = bytes,
            .mode = @intCast(mode_v.integer),
            .reason = reason,
        });
    }

    // Inventory must be path-sorted and duplicate-free (canonical writer
    // guarantees it; enforce on read so a reordered line can't smuggle
    // two mappings for one path).
    for (files.items[1..], 0..) |f, i| {
        if (std.mem.order(u8, files.items[i].path, f.path) != .lt) {
            return fsys.refuse("manifest_torn", "");
        }
    }

    return .{
        .stream = try allocator.dupe(u8, stream_v.string),
        .change = try allocator.dupe(u8, change_v.string),
        .author = try allocator.dupe(u8, author_v.string),
        .files = try files.toOwnedSlice(allocator),
        .sig = try allocator.dupe(u8, sig_v.string),
    };
}

/// Recomputes the manifest preimage and verifies `sig` against `author`.
pub fn verifyManifest(allocator: Allocator, m: *const Manifest) !bool {
    const author_bytes = ed25519.parseHex32Lower(m.author) orelse
        return fsys.refuse("manifest_torn", "");
    const sig_bytes = ed25519.parseHex64Lower(m.sig) orelse
        return fsys.refuse("manifest_torn", "");
    const msg = try manifestSigMsg(allocator, m);
    defer allocator.free(msg);
    return ed25519.verifySig(sig_bytes, msg, author_bytes);
}

/// Signs the manifest in place with `seed`: author is the seed's public key.
pub fn signManifest(allocator: Allocator, m: *Manifest, seed: [32]u8) !void {
    const pk = try ed25519.derivePublic(seed);
    var pkbuf: [64]u8 = undefined;
    ed25519.encodeHexLower(&pkbuf, &pk);
    m.author = try allocator.dupe(u8, &pkbuf);
    errdefer allocator.free(m.author);
    const msg = try manifestSigMsg(allocator, m);
    defer allocator.free(msg);
    const sig = try ed25519.signMsg(msg, seed);
    var sigbuf: [128]u8 = undefined;
    ed25519.encodeHexLower(&sigbuf, &sig);
    m.sig = try allocator.dupe(u8, &sigbuf);
}

// --- Store layout -----------------------------------------------------------

pub fn blobPath(allocator: Allocator, root: []const u8, blob_id: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/blobs/{s}/{s}", .{ root, blob_id[0..2], blob_id[2..] });
}

pub fn manifestLogPath(allocator: Allocator, root: []const u8, stream_id: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/manifests/{s}.jsonl", .{ root, stream_id });
}

/// Reads and hashes-checks a blob. Refuses `blob_missing` when absent and
/// `blob_malformed` when the bytes don't match the content id.
fn readBlobChecked(allocator: Allocator, fs: FS, root: []const u8, blob_id: []const u8) ![]u8 {
    const path = try blobPath(allocator, root, blob_id);
    defer allocator.free(path);
    if (!fs.exists(allocator, path)) {
        return fsys.refuse("blob_missing", blob_id[0..12]);
    }
    const data = fs.readFile(allocator, path, MaxBlobBytes + 1) catch |err| switch (err) {
        error.Refuse => return err,
        else => return fsys.refuse("blob_missing", blob_id[0..12]),
    };
    errdefer allocator.free(data);
    if (data.len > MaxBlobBytes) return fsys.refuse("blob_malformed", blob_id[0..12]);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &digest, .{});
    var hexbuf: [64]u8 = undefined;
    ed25519.encodeHexLower(&hexbuf, &digest);
    if (!std.mem.eql(u8, &hexbuf, blob_id)) {
        return fsys.refuse("blob_malformed", blob_id[0..12]);
    }
    return data;
}

// --- Inventory scan (spec §2) -----------------------------------------------

fn pathWithin(prefix: []const u8, path: []const u8) bool {
    if (prefix.len == 0) return false;
    return std.mem.startsWith(u8, path, prefix) and
        (path.len == prefix.len or path[prefix.len] == '/');
}

/// Recursively inventories `dir_rel` (relative to `src_root`), appending
/// ManifestFile entries. `exclude_abs` — the resolved store root — is
/// pruned so a store beneath src is never captured.
fn walkInventory(
    allocator: Allocator,
    fs: FS,
    src_root: []const u8,
    dir_rel: []const u8,
    exclude_abs: ?[]const u8,
    out: *std.ArrayList(ManifestFile),
) !void {
    const dir_abs = if (dir_rel.len == 0)
        try allocator.dupe(u8, src_root)
    else
        try fsys.joinPath(allocator, &.{ src_root, dir_rel });
    defer allocator.free(dir_abs);

    if (exclude_abs) |ex| {
        // Prune the store root: dir_abs IS the store or sits inside it.
        if (std.mem.eql(u8, dir_abs, ex) or pathWithin(ex, dir_abs)) return;
    }

    const entries = fs.list(allocator, dir_abs) catch {
        // An unreadable directory is an explicitly-incomplete entry, never a
        // silent omission (spec §2).
        if (dir_rel.len > 0) {
            try out.append(allocator, .{
                .path = try allocator.dupe(u8, dir_rel),
                .blob = null,
                .bytes = 0,
                .mode = 0,
                .reason = try allocator.dupe(u8, "unsupported"),
            });
        }
        return;
    };
    defer fsys.FS.freeDirEntries(allocator, entries);

    for (entries) |e| {
        const rel = if (dir_rel.len == 0)
            try allocator.dupe(u8, e.name)
        else
            try std.fmt.allocPrint(allocator, "{s}/{s}", .{ dir_rel, e.name });
        defer allocator.free(rel);

        const abs = try fsys.joinPath(allocator, &.{ src_root, rel });
        defer allocator.free(abs);

        if (exclude_abs) |ex| {
            if (std.mem.eql(u8, abs, ex) or pathWithin(ex, abs)) continue;
        }

        const st = fs.stat(allocator, abs) catch {
            // Unreadable entry — record as unsupported rather than omit.
            try out.append(allocator, .{
                .path = try allocator.dupe(u8, rel),
                .blob = null,
                .bytes = 0,
                .mode = 0,
                .reason = try allocator.dupe(u8, "unsupported"),
            });
            continue;
        };

        switch (st.kind) {
            .directory => try walkInventory(allocator, fs, src_root, rel, exclude_abs, out),
            .file => {
                if (st.size > MaxBlobBytes) {
                    try out.append(allocator, .{
                        .path = try allocator.dupe(u8, rel),
                        .blob = null,
                        .bytes = st.size,
                        .mode = 0,
                        .reason = try allocator.dupe(u8, "too_large"),
                    });
                    continue;
                }
                const data = fs.readFile(allocator, abs, MaxBlobBytes) catch {
                    try out.append(allocator, .{
                        .path = try allocator.dupe(u8, rel),
                        .blob = null,
                        .bytes = st.size,
                        .mode = 0,
                        .reason = try allocator.dupe(u8, "unsupported"),
                    });
                    continue;
                };
                defer allocator.free(data);
                var digest: [32]u8 = undefined;
                std.crypto.hash.sha2.Sha256.hash(data, &digest, .{});
                var hexbuf: [64]u8 = undefined;
                ed25519.encodeHexLower(&hexbuf, &digest);
                const id_hex = try allocator.dupe(u8, &hexbuf);
                try out.append(allocator, .{
                    .path = try allocator.dupe(u8, rel),
                    .blob = id_hex,
                    .bytes = data.len,
                    .mode = st.mode,
                    .reason = null,
                });
            },
            else => {
                try out.append(allocator, .{
                    .path = try allocator.dupe(u8, rel),
                    .blob = null,
                    .bytes = 0,
                    .mode = 0,
                    .reason = try allocator.dupe(u8, "unsupported"),
                });
            },
        }
    }
}

/// Scans the tracked source root into a sorted complete inventory
/// (spec §2). `store_root` — the resolved store directory — is pruned
/// wherever it appears inside src.
pub fn scanInventory(
    allocator: Allocator,
    fs: FS,
    src_root: []const u8,
    store_root: []const u8,
) ![]ManifestFile {
    var files: std.ArrayList(ManifestFile) = .empty;
    errdefer {
        for (files.items) |f| f.deinit(allocator);
        files.deinit(allocator);
    }
    const ex = if (store_root.len > 0) store_root else null;
    try walkInventory(allocator, fs, src_root, "", ex, &files);
    std.mem.sort(ManifestFile, files.items, {}, struct {
        fn lt(_: void, a: ManifestFile, b: ManifestFile) bool {
            return std.mem.order(u8, a.path, b.path) == .lt;
        }
    }.lt);
    return files.toOwnedSlice(allocator);
}

/// Writes each entry's blob into `<store>/blobs/` (idempotent —
/// content-addressed writes skip existing files). Blob bytes are read from
/// src during the scan; write by re-reading is avoided by hashing up front
/// and writing on demand here.
pub fn writeBlobBytes(allocator: Allocator, fs: FS, root: []const u8, blob_id: []const u8, data: []const u8) !void {
    const path = try blobPath(allocator, root, blob_id);
    defer allocator.free(path);
    if (fs.exists(allocator, path)) return;
    try fs.writeFileSafe(allocator, path, data);
}

/// Appends one canonical signed manifest line to `manifests/<stream>.jsonl`
/// (create-on-first-use), enforcing the line-count bound.
pub fn appendManifestLine(allocator: Allocator, fs: FS, root: []const u8, m: *const Manifest) !void {
    const line = try marshalManifestLine(allocator, m);
    defer allocator.free(line);
    if (line.len > fsys.MaxFileReadBytes) {
        return fsys.refuse("store_too_large", "manifest line");
    }
    const mdir = try std.fmt.allocPrint(allocator, "{s}/manifests", .{root});
    defer allocator.free(mdir);
    try fs.mkdir(allocator, mdir);
    const path = try manifestLogPath(allocator, root, m.stream);
    defer allocator.free(path);
    if (fs.exists(allocator, path)) {
        const existing = try fs.readFile(allocator, path, fsys.MaxFileReadBytes);
        defer allocator.free(existing);
        if (std.mem.count(u8, existing, "\n") >= MaxManifestLines) {
            return fsys.refuse("store_too_large", "manifests");
        }
    }
    try fs.appendSync(allocator, path, line);
}

/// Loads every manifest line for a stream; a missing log is empty.
pub fn loadManifestLog(allocator: Allocator, fs: FS, root: []const u8, stream_id: []const u8) ![]Manifest {
    const path = try manifestLogPath(allocator, root, stream_id);
    defer allocator.free(path);
    var out: std.ArrayList(Manifest) = .empty;
    errdefer {
        for (out.items) |m| m.deinit(allocator);
        out.deinit(allocator);
    }
    if (!fs.exists(allocator, path)) return out.toOwnedSlice(allocator);
    const raw = try fs.readFile(allocator, path, fsys.MaxFileReadBytes);
    defer allocator.free(raw);
    if (raw.len == 0) return out.toOwnedSlice(allocator);
    if (raw[raw.len - 1] != '\n') return fsys.refuse("manifest_torn", "");
    var it = std.mem.splitScalar(u8, raw, '\n');
    while (it.next()) |line| {
        if (line.len == 0) continue;
        try out.append(allocator, try parseManifestLine(allocator, line));
    }
    return out.toOwnedSlice(allocator);
}

/// Finds the manifest for `change_id` in a stream's log, or null.
pub fn manifestForChange(log: []const Manifest, change_id: []const u8) ?*const Manifest {
    for (log) |*m| {
        if (std.mem.eql(u8, m.change, change_id)) return m;
    }
    return null;
}

/// Two inventories are equal when every entry's (path, blob, bytes, mode,
/// reason) matches — used by commit's `nothing_to_commit` content check.
pub fn inventoriesEqual(a: []const ManifestFile, b: []const ManifestFile) bool {
    if (a.len != b.len) return false;
    for (a, b) |fa, fb| {
        if (!std.mem.eql(u8, fa.path, fb.path)) return false;
        const ba = fa.blob orelse "";
        const bb = fb.blob orelse "";
        if (!std.mem.eql(u8, ba, bb)) return false;
        const ra = fa.reason orelse "";
        const rb = fb.reason orelse "";
        if (!std.mem.eql(u8, ra, rb)) return false;
        if (fa.bytes != fb.bytes or fa.mode != fb.mode) return false;
    }
    return true;
}

// --- checkout verb ----------------------------------------------------------

/// Implements `flint checkout [--stream=<s>|--ws=<n>] [--change=<id>] --into=<dir> [--force]`.
/// Materializes the complete signed inventory for one revision — defaults to
/// the stream head. All-or-nothing: every blob resolves and verifies before
/// any file is written (spec §4).
pub fn cmdCheckout(
    allocator: Allocator,
    fs: FS,
    root: []const u8,
    out: *Io.Writer,
    args: []const []const u8,
) !void {
    var stream_flag: []const u8 = "";
    var ws_flag: []const u8 = "";
    var change_flag: ?[]const u8 = null;
    var into: ?[]const u8 = null;
    var force = false;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.startsWith(u8, a, "--stream=")) {
            stream_flag = a["--stream=".len..];
        } else if (std.mem.eql(u8, a, "--stream") and i + 1 < args.len) {
            i += 1;
            stream_flag = args[i];
        } else if (std.mem.startsWith(u8, a, "--ws=")) {
            ws_flag = a["--ws=".len..];
        } else if (std.mem.eql(u8, a, "--ws") and i + 1 < args.len) {
            i += 1;
            ws_flag = args[i];
        } else if (std.mem.startsWith(u8, a, "--change=")) {
            change_flag = a["--change=".len..];
        } else if (std.mem.eql(u8, a, "--change") and i + 1 < args.len) {
            i += 1;
            change_flag = args[i];
        } else if (std.mem.startsWith(u8, a, "--into=")) {
            into = a["--into=".len..];
        } else if (std.mem.eql(u8, a, "--into") and i + 1 < args.len) {
            i += 1;
            into = args[i];
        } else if (std.mem.eql(u8, a, "--force")) {
            force = true;
        } else {
            return fsys.refuse("usage", "");
        }
    }

    if (into == null or into.?.len == 0) return fsys.refuse("usage", "");
    const into_dir = into.?;

    var idx = try store.loadStoreIndex(allocator, fs, root);
    defer idx.deinit();

    var stream_id: []const u8 = "";
    if (ws_flag.len > 0) {
        const ws = try store.resolveWorkspace(allocator, fs, &idx, ws_flag, &.{});
        stream_id = ws.stream;
    } else if (stream_flag.len > 0) {
        stream_id = blk: {
            if (idx.streamByName(stream_flag)) |st| break :blk st.id;
            for (idx.streams.items) |*st| {
                if (std.mem.eql(u8, st.id, stream_flag)) break :blk st.id;
            }
            return fsys.refuse("stream_missing", stream_flag);
        };
    } else {
        return fsys.refuse("usage", "");
    }

    var loaded = try store.loadStream(allocator, fs, root, stream_id);
    defer loaded.deinit(allocator);

    const target = change_flag orelse (loaded.stream.head orelse
        return fsys.refuse("blob_missing", "no snapshot"));

    const target_change = blk: {
        for (loaded.changes) |*c| {
            if (std.mem.eql(u8, c.id, target)) break :blk c;
        }
        return fsys.refuse("change_missing", target);
    };

    const log = try loadManifestLog(allocator, fs, root, stream_id);
    defer {
        for (log) |m| m.deinit(allocator);
        allocator.free(log);
    }
    const manifest = manifestForChange(log, target) orelse
        return fsys.refuse("blob_missing", target);

    if (!std.mem.eql(u8, manifest.author, target_change.author)) {
        return fsys.refuse("sig_invalid", "manifest author does not match change author");
    }
    if (!try verifyManifest(allocator, manifest)) {
        return fsys.refuse("sig_invalid", "manifest signature");
    }

    // Destination must be absent or empty unless --force.
    if (fs.exists(allocator, into_dir)) {
        if (!fs.isDir(allocator, into_dir)) return fsys.refuse("checkout_exists", into_dir);
        if (!force) {
            if (fs.list(allocator, into_dir) catch null) |existing| {
                defer fsys.FS.freeDirEntries(allocator, existing);
                if (existing.len > 0) {
                    return fsys.refuse("checkout_exists", into_dir);
                }
            }
        }
    }

    // Resolve and verify every blob before writing anything.
    var blob_data = try allocator.alloc([]u8, manifest.files.len);
    var filled: usize = 0;
    defer {
        for (blob_data[0..filled]) |d| allocator.free(d);
        allocator.free(blob_data);
    }
    var total_bytes: u64 = 0;
    for (manifest.files, 0..) |f, j| {
        if (f.blob == null) {
            return fsys.refuse("blob_missing", f.path);
        }
        blob_data[j] = readBlobChecked(allocator, fs, root, f.blob.?) catch |err| switch (err) {
            error.Refuse => return err,
            else => return err,
        };
        if (blob_data[j].len != f.bytes) {
            return fsys.refuse("blob_malformed", f.path);
        }
        filled += 1;
        total_bytes += f.bytes;
    }

    for (manifest.files, 0..) |f, j| {
        const dest = try fsys.joinPath(allocator, &.{ into_dir, f.path });
        defer allocator.free(dest);
        // Defense in depth: the parser already rejects .. / absolute paths.
        try fs.writeFileSafe(allocator, dest, blob_data[j]);
        if (f.mode == 0o755) try fs.setMode(allocator, dest, 0o755);
    }

    try out.print(
        "flint: checkout ok stream={s} change={s} files={d} bytes={d}\n",
        .{ loaded.stream.name, target, manifest.files.len, total_bytes },
    );
}

test "content: manifest marshal/parse round trip and signature verify" {
    const gpa = std.testing.allocator;

    const seed: [32]u8 = @splat(7);
    const cid = "0199de2d-dc00-7000-8000-000000000201";
    const sid = "0199de2d-dc00-7000-8000-000000000020";
    var blob_a: [64]u8 = undefined;
    var blob_b: [64]u8 = undefined;
    const da: [32]u8 = @splat(0xab);
    const db: [32]u8 = @splat(0xcd);
    ed25519.encodeHexLower(&blob_a, &da);
    ed25519.encodeHexLower(&blob_b, &db);

    var m = Manifest{
        .stream = try gpa.dupe(u8, sid),
        .change = try gpa.dupe(u8, cid),
        .author = "",
        .files = try gpa.dupe(ManifestFile, &.{
            .{ .path = try gpa.dupe(u8, "README.md"), .blob = try gpa.dupe(u8, &blob_a), .bytes = 10, .mode = 0o644, .reason = null },
            .{ .path = try gpa.dupe(u8, "src/main.zig"), .blob = try gpa.dupe(u8, &blob_b), .bytes = 20, .mode = 0o755, .reason = null },
        }),
        .sig = "",
    };
    defer m.deinit(gpa);
    try signManifest(gpa, &m, seed);

    const line = try marshalManifestLine(gpa, &m);
    defer gpa.free(line);
    try std.testing.expect(std.mem.endsWith(u8, line, "\n"));

    var parsed = try parseManifestLine(gpa, line[0 .. line.len - 1]);
    defer parsed.deinit(gpa);
    try std.testing.expectEqualStrings(m.change, parsed.change);
    try std.testing.expectEqual(@as(usize, 2), parsed.files.len);
    try std.testing.expectEqual(@as(u32, 0o755), parsed.files[1].mode);
    try std.testing.expect(try verifyManifest(gpa, &parsed));

    // Tamper: a different (valid-hex) author key must fail verification —
    // the signature is bound to the Change author's key, not any signer.
    const other_seed: [32]u8 = @splat(9);
    const other_pk = try ed25519.derivePublic(other_seed);
    var pkbuf: [64]u8 = undefined;
    ed25519.encodeHexLower(&pkbuf, &other_pk);
    var tampered = parsed;
    tampered.author = try gpa.dupe(u8, &pkbuf);
    defer gpa.free(tampered.author);
    try std.testing.expect(!(try verifyManifest(gpa, &tampered)));
}

test "content: inventory scan covers non-atom files and prunes the store" {
    const gpa = std.testing.allocator;
    var mem = try fsys.MemFS.init(gpa);
    defer mem.deinit();
    const fs = mem.fs();

    try fs.writeFileSafe(gpa, "/host/src/main.zig", "pub const a: u32 = 1;\n");
    try fs.writeFileSafe(gpa, "/host/src/README.md", "# docs only\n");
    try fs.writeFileSafe(gpa, "/host/src/assets/icon.bin", "\x00\x01\x02\x03");
    // The store sits inside src here: it must never be captured.
    try fs.writeFileSafe(gpa, "/host/src/.flint/streams/x.jsonl", "{}\n");

    const inv = try scanInventory(gpa, fs, "/host/src", "/host/src/.flint");
    defer {
        for (inv) |f| f.deinit(gpa);
        gpa.free(inv);
    }
    try std.testing.expectEqual(@as(usize, 3), inv.len);
    try std.testing.expectEqualStrings("README.md", inv[0].path);
    try std.testing.expectEqualStrings("assets/icon.bin", inv[1].path);
    try std.testing.expectEqualStrings("main.zig", inv[2].path);
    for (inv) |f| try std.testing.expect(f.blob != null);
}

test "content: torn or unsorted manifest log refuses manifest_torn; missing log is empty" {
    const gpa = std.testing.allocator;
    var mem = try fsys.MemFS.init(gpa);
    defer mem.deinit();
    const fs = mem.fs();
    const root = "/host/FLINT";
    const sid = "0199de2d-dc00-7000-8000-000000000020";

    const empty = try loadManifestLog(gpa, fs, root, sid);
    try std.testing.expectEqual(@as(usize, 0), empty.len);

    try fs.mkdir(gpa, "/host/FLINT/manifests");
    const p = try manifestLogPath(gpa, root, sid);
    defer gpa.free(p);
    try fs.writeFileSafe(gpa, p, "{\"stream\":\"x\"\n");
    try std.testing.expectError(error.Refuse, loadManifestLog(gpa, fs, root, sid));

    // Unsorted entries refuse — a canonical writer sorts; smuggled
    // duplicate mappings must not load.
    const zeros64 = "0000000000000000000000000000000000000000000000000000000000000000";
    const zeros128 = zeros64 ++ zeros64;
    const ab = "abababababababababababababababababababababababababababababababab";
    const bad_line = try std.fmt.allocPrint(gpa, "{{\"stream\":\"{s}\",\"change\":\"0199de2d-dc00-7000-8000-000000000201\",\"author\":\"{s}\",\"files\":[{{\"path\":\"b\",\"blob\":\"{s}\",\"bytes\":1,\"mode\":644}},{{\"path\":\"a\",\"blob\":\"{s}\",\"bytes\":1,\"mode\":644}}],\"sig\":\"{s}\"}}\n", .{ sid, zeros64, ab, ab, zeros128 });
    defer gpa.free(bad_line);
    try fs.writeFileSafe(gpa, p, bad_line);
    try std.testing.expectError(error.Refuse, loadManifestLog(gpa, fs, root, sid));
}

test "content: blob read verifies sha256 and refuses blob_malformed on corruption" {
    const gpa = std.testing.allocator;
    var mem = try fsys.MemFS.init(gpa);
    defer mem.deinit();
    const fs = mem.fs();
    const root = "/host/FLINT";

    const data = "pub const a: u32 = 1;\n";
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &digest, .{});
    var id: [64]u8 = undefined;
    ed25519.encodeHexLower(&id, &digest);

    // Missing blob -> blob_missing.
    try std.testing.expectError(error.Refuse, readBlobChecked(gpa, fs, root, &id));

    try writeBlobBytes(gpa, fs, root, &id, data);
    const got = try readBlobChecked(gpa, fs, root, &id);
    defer gpa.free(got);
    try std.testing.expectEqualStrings(data, got);

    // Corrupt the stored bytes -> blob_malformed.
    const bp = try blobPath(gpa, root, &id);
    defer gpa.free(bp);
    try fs.writeFileSafe(gpa, bp, "tampered\n");
    try std.testing.expectError(error.Refuse, readBlobChecked(gpa, fs, root, &id));
}
