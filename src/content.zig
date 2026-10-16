const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Sha256 = std.crypto.hash.sha2.Sha256;
const fsys = @import("fsys.zig");
const FS = fsys.FS;
const store = @import("store.zig");
const ed25519 = @import("ed25519.zig");

/// PendingWrite is a freshly captured blob payload not yet present in the
/// store. `id` is the 64-char lowercase hex SHA-256 of `data`.
pub const PendingWrite = struct {
    id: []u8,
    data: []u8,
};

/// CaptureResult pairs the deterministic inventory (manifest `files`) with the
/// blob payloads the store does not yet hold, all from one consistent walk.
pub const CaptureResult = struct {
    entries: []store.ManifestEntry,
    pending: []PendingWrite,

    pub fn deinit(self: CaptureResult, allocator: Allocator) void {
        for (self.entries) |e| e.deinit(allocator);
        if (self.entries.len > 0) allocator.free(self.entries);
        for (self.pending) |p| {
            allocator.free(p.id);
            allocator.free(p.data);
        }
        if (self.pending.len > 0) allocator.free(self.pending);
    }
};

/// Abs-normalizes `p` against `cwd` so store/src/destination comparisons are
/// made on one path shape (MemFS paths are already absolute; host paths may
/// arrive relative to the invocation cwd).
pub fn absNormalize(allocator: Allocator, cwd: []const u8, p: []const u8) ![]u8 {
    const cleaned = try fsys.cleanPath(allocator, p);
    defer allocator.free(cleaned);
    if (cleaned.len > 0 and cleaned[0] == '/') {
        return allocator.dupe(u8, cleaned);
    }
    return fsys.joinPath(allocator, &.{ cwd, cleaned });
}

/// PathInside reports whether `child` equals `parent` or sits beneath it.
fn pathInside(child: []const u8, parent: []const u8) bool {
    if (parent.len == 0) return false;
    if (std.mem.eql(u8, child, parent)) return true;
    return child.len > parent.len and
        std.mem.startsWith(u8, child, parent) and
        child[parent.len] == '/';
}

/// ModeField converts POSIX permission bits to the manifest's octal-digit
/// integer spelling: 0o644 → 644, 0o755 → 755 (docs/flint-blobs-spec.md §1).
pub fn modeField(mode_bits: u32) u32 {
    return ((mode_bits >> 6) & 7) * 100 + ((mode_bits >> 3) & 7) * 10 + (mode_bits & 7);
}

/// ModeFromField reverses `modeField` for materialization; each digit is
/// masked so a malformed field can only weaken, never widen, permissions.
pub fn modeFromField(field: u32) u32 {
    return (((field / 100 % 10) & 7) << 6) | (((field / 10 % 10) & 7) << 3) | ((field % 10) & 7);
}

fn appendEntry(
    allocator: Allocator,
    out: *std.ArrayList(store.ManifestEntry),
    path: []const u8,
    blob: []const u8,
    bytes: u64,
    mode: u32,
    reason: []const u8,
) !void {
    const p = try allocator.dupe(u8, path);
    errdefer allocator.free(p);
    const b = if (blob.len > 0) try allocator.dupe(u8, blob) else "";
    errdefer if (b.len > 0) allocator.free(b);
    const r = if (reason.len > 0) try allocator.dupe(u8, reason) else "";
    try out.append(allocator, .{ .path = p, .blob = b, .bytes = bytes, .mode = mode, .reason = r });
}

fn walkInventory(
    allocator: Allocator,
    fs: FS,
    root_abs: []const u8,
    src_abs: []const u8,
    dir_abs: []const u8,
    out: *std.ArrayList(store.ManifestEntry),
    pending: *std.ArrayList(PendingWrite),
) !void {
    const listing = try fs.list(allocator, dir_abs);
    defer FS.freeDirEntries(allocator, listing);

    for (listing) |e| {
        const child = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ dir_abs, e.name });
        defer allocator.free(child);

        // The resolved store root beneath the source root is never captured.
        if (e.kind == .dir and pathInside(child, root_abs)) continue;

        const st = fs.stat(allocator, child) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        const rel = child[src_abs.len + 1 ..];

        switch (st.kind) {
            .dir => {
                if (pathInside(child, root_abs)) continue;
                try walkInventory(allocator, fs, root_abs, src_abs, child, out, pending);
            },
            .file => {
                if (st.size > store.MaxBlobBytes) {
                    try appendEntry(allocator, out, rel, "", st.size, modeField(st.mode), "too_large");
                    continue;
                }
                const data = fs.readFile(allocator, child, store.MaxBlobBytes) catch |err| {
                    if (err == error.Refuse and std.mem.eql(u8, fsys.last_refuse.code(), "store_too_large")) {
                        try appendEntry(allocator, out, rel, "", st.size, modeField(st.mode), "too_large");
                        continue;
                    }
                    if (err == error.FileNotFound) continue;
                    return err;
                };
                var digest: [32]u8 = undefined;
                Sha256.hash(data, &digest, .{});
                const hex = std.fmt.bytesToHex(digest, .lower);

                try appendEntry(allocator, out, rel, &hex, data.len, modeField(st.mode), "");

                // Dedupe: land the payload only when no pending write or
                // existing blob already covers this content id.
                var covered = false;
                for (pending.items) |pw| {
                    if (std.mem.eql(u8, pw.id, &hex)) {
                        covered = true;
                        break;
                    }
                }
                if (!covered) {
                    const bp = try store.blobPath(allocator, root_abs, &hex);
                    defer allocator.free(bp);
                    covered = fs.exists(allocator, bp);
                }
                if (covered) {
                    allocator.free(data);
                } else {
                    const id_dup = try allocator.dupe(u8, &hex);
                    errdefer allocator.free(id_dup);
                    try pending.append(allocator, .{ .id = id_dup, .data = data });
                }
            },
            else => try appendEntry(allocator, out, rel, "", 0, 0, "unsupported"),
        }
    }
}

/// CaptureSnapshot walks the tracked source root per docs/flint-blobs-spec.md
/// §2: every regular file hashed whole, non-regular entries recorded as
/// `"reason":"unsupported"`, over-cap files as `"reason":"too_large"`, the
/// resolved store root excluded, sorted by path.
pub fn captureSnapshot(allocator: Allocator, fs: FS, cwd: []const u8, root: []const u8, src: []const u8) !CaptureResult {
    const src_abs = try absNormalize(allocator, cwd, src);
    defer allocator.free(src_abs);
    const root_abs = try absNormalize(allocator, cwd, root);
    defer allocator.free(root_abs);

    if (!fs.isDir(allocator, src_abs)) {
        return fsys.refuse("src_missing", src);
    }
    // A source root inside the resolved store would capture the store itself
    // (key material included) — track nothing rather than recurse into it.
    if (pathInside(src_abs, root_abs)) {
        return .{
            .entries = try allocator.alloc(store.ManifestEntry, 0),
            .pending = try allocator.alloc(PendingWrite, 0),
        };
    }

    var entries: std.ArrayList(store.ManifestEntry) = .empty;
    errdefer {
        for (entries.items) |e| e.deinit(allocator);
        entries.deinit(allocator);
    }
    var pending: std.ArrayList(PendingWrite) = .empty;
    errdefer {
        for (pending.items) |p| {
            allocator.free(p.id);
            allocator.free(p.data);
        }
        pending.deinit(allocator);
    }

    try walkInventory(allocator, fs, root_abs, src_abs, src_abs, &entries, &pending);

    const slice = try entries.toOwnedSlice(allocator);
    std.mem.sort(store.ManifestEntry, slice, {}, struct {
        fn lt(_: void, a: store.ManifestEntry, b: store.ManifestEntry) bool {
            return std.mem.lessThan(u8, a.path, b.path);
        }
    }.lt);
    return .{
        .entries = slice,
        .pending = try pending.toOwnedSlice(allocator),
    };
}

/// WritePendingBlobs lands captured payloads under `blobs/<2>/<62>` via the
/// crash-safe write. Content addressing makes repeats idempotent; blobs land
/// before the manifest that references them (§1 commit order).
pub fn writePendingBlobs(allocator: Allocator, fs: FS, cwd: []const u8, root: []const u8, pending: []const PendingWrite) !void {
    const root_abs = try absNormalize(allocator, cwd, root);
    defer allocator.free(root_abs);
    for (pending) |pw| {
        const bp = try store.blobPath(allocator, root_abs, pw.id);
        defer allocator.free(bp);
        if (fs.exists(allocator, bp)) continue;
        try fs.writeFileSafe(allocator, bp, pw.data);
    }
}

/// SignSnapshot builds the signed manifest line for `change_id` bound to
/// `stream_id`. `entries` is cloned so the caller keeps ownership of its
/// inventory. The seed is consumed only for signing — `signChangeWithSeed`
/// still wipes it afterwards.
pub fn signSnapshot(
    allocator: Allocator,
    stream_id: []const u8,
    change_id: []const u8,
    seed: [32]u8,
    entries: []const store.ManifestEntry,
) !store.Manifest {
    defer std.crypto.secureZero(u8, @constCast(&seed)[0..]);
    const pub_bytes = try ed25519.derivePublic(seed);
    const pub_hex = std.fmt.bytesToHex(pub_bytes, .lower);

    var files = try allocator.alloc(store.ManifestEntry, entries.len);
    var i: usize = 0;
    errdefer {
        for (files[0..i]) |f| f.deinit(allocator);
        allocator.free(files);
    }
    while (i < entries.len) : (i += 1) {
        files[i] = try entries[i].clone(allocator);
    }

    var m = store.Manifest{
        .stream = try allocator.dupe(u8, stream_id),
        .change = try allocator.dupe(u8, change_id),
        .author = try allocator.dupe(u8, &pub_hex),
        .files = files,
        .sig = try allocator.dupe(u8, ""),
    };
    errdefer m.deinit(allocator);
    try ed25519.signManifestWithSeed(allocator, &m, seed);
    return m;
}

/// HasUnmaterializedMergeMarks reports whether the workspace Atom table still
/// carries `origin = "merge"` atoms — semantic content the merged head
/// describes but src does not (docs/flint-blobs-spec.md §7). While any mark
/// remains, a captured inventory would attest bytes the revision does not
/// own, so the honest outcome is no manifest at all.
pub fn hasUnmaterializedMergeMarks(atoms: []const store.StoredAtom) bool {
    for (atoms) |a| {
        if (std.mem.eql(u8, a.origin, "merge")) return true;
    }
    return false;
}

fn readBlobVerified(allocator: Allocator, fs: FS, root_abs: []const u8, hex_id: []const u8, path: []const u8) ![]u8 {
    const bp = try store.blobPath(allocator, root_abs, hex_id);
    defer allocator.free(bp);
    const data = fs.readFile(allocator, bp, store.MaxBlobBytes) catch |err| {
        if (err == error.FileNotFound) {
            return fsys.refuse("blob_missing", path);
        }
        return err;
    };
    errdefer allocator.free(data);
    var digest: [32]u8 = undefined;
    Sha256.hash(data, &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    if (!std.mem.eql(u8, &hex, hex_id)) {
        return fsys.refuse("blob_malformed", path);
    }
    return data;
}

fn findChange(changes: []const store.Change, id: []const u8) ?*const store.Change {
    for (changes) |*c| {
        if (std.mem.eql(u8, c.id, id)) return c;
    }
    return null;
}

/// Implements `flint checkout [--stream=<s>] [--ws=<n>] --change=<id>|--head
/// --into=<dir> [--force]` — docs/flint-blobs-spec.md §4/§8.
/// Resolves a stream record head to its Change, walking `forked_from`
/// ancestry when the head is not in the stream's own log — the bare-fork and
/// re-anchored-fork cases where the head Change lives on an origin stream's
/// log (#88). Returns a caller-owned clone.
fn resolveHeadChange(
    allocator: Allocator,
    fs: FS,
    root: []const u8,
    stream_id: []const u8,
    stream_label: []const u8,
) !store.Change {
    var cur_id = try allocator.dupe(u8, stream_id);
    defer allocator.free(cur_id);
    var target: ?[]u8 = null;
    defer if (target) |t| allocator.free(t);
    var hops: usize = 0;
    while (hops < store.MaxChanges) : (hops += 1) {
        const loaded = try store.loadStream(allocator, fs, root, cur_id);
        defer loaded.deinit(allocator);
        if (target == null) {
            target = try allocator.dupe(u8, loaded.stream.head orelse
                return fsys.refuse("change_missing", stream_label));
        }
        if (findChange(loaded.changes, target.?)) |found| {
            return try found.clone(allocator);
        }
        const ff = loaded.stream.forked_from orelse {
            return fsys.refuse("change_missing", target.?);
        };
        const nid = try allocator.dupe(u8, ff.stream);
        allocator.free(cur_id);
        cur_id = nid;
    }
    return fsys.refuse("store_too_large", "fork ancestry");
}

pub fn cmdCheckout(
    allocator: Allocator,
    fs: FS,
    root: []const u8,
    cwd: []const u8,
    out: *Io.Writer,
    args: []const []const u8,
) !void {
    var stream_flag: []const u8 = "";
    var ws_flag: []const u8 = "";
    var change_flag: []const u8 = "";
    var into_flag: []const u8 = "";
    var want_head = false;
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
            into_flag = a["--into=".len..];
        } else if (std.mem.eql(u8, a, "--into") and i + 1 < args.len) {
            i += 1;
            into_flag = args[i];
        } else if (std.mem.eql(u8, a, "--head")) {
            want_head = true;
        } else if (std.mem.eql(u8, a, "--force")) {
            force = true;
        } else {
            return fsys.refuse("usage", "");
        }
    }

    if (into_flag.len == 0 or (change_flag.len == 0) == !want_head) {
        return fsys.refuse("usage", "");
    }

    var idx = try store.loadStoreIndex(allocator, fs, root);
    defer idx.deinit();

    // Resolve the bound stream and target Change (docs §4: snapshot identity
    // is the Change id; the manifest's `stream` field binds it).
    var stream_id: []const u8 = "";
    var stream_label: []const u8 = "";
    var target_id: []const u8 = "";
    var bound: ?store.Change = null;
    defer if (bound) |b| {
        var bb = b;
        bb.deinit(allocator);
    };

    if (stream_flag.len == 0 and ws_flag.len > 0) {
        const ws = idx.workspaceByName(ws_flag) orelse {
            return fsys.refuse("ws_missing", ws_flag);
        };
        stream_flag = ws.stream;
    }

    if (stream_flag.len > 0) {
        const st = idx.streamByName(stream_flag) orelse
            (idx.streamByID(stream_flag) orelse {
                return fsys.refuse("stream_missing", stream_flag);
            });
        if (want_head) {
            bound = try resolveHeadChange(allocator, fs, root, st.id, st.name);
        } else {
            // An explicitly stream-scoped --change must live in that
            // stream's own log — the pinned selector policy.
            const loaded = try store.loadStream(allocator, fs, root, st.id);
            defer loaded.deinit(allocator);
            const found = findChange(loaded.changes, change_flag) orelse {
                return fsys.refuse("change_missing", change_flag);
            };
            bound = try found.clone(allocator);
        }
    } else if (want_head) {
        var resolved_id: []const u8 = "";
        var resolved_name: []const u8 = "";
        if (idx.workspaces.items.len == 1) {
            resolved_id = idx.workspaces.items[0].stream;
            resolved_name = idx.workspaces.items[0].name;
        } else if (idx.streams.items.len == 1) {
            resolved_id = idx.streams.items[0].id;
            resolved_name = idx.streams.items[0].name;
        } else {
            return fsys.refuse("usage", "");
        }
        bound = try resolveHeadChange(allocator, fs, root, resolved_id, resolved_name);
    } else {
        // Search every stream log for the Change; its own `stream` field
        // binds the manifest log (detached lines included).
        const all = try store.loadAllStreamChanges(allocator, fs, root, &idx);
        defer store.freeChanges(allocator, all);
        const found = findChange(all, change_flag) orelse {
            return fsys.refuse("change_missing", change_flag);
        };
        bound = try found.clone(allocator);
        target_id = change_flag;
    }

    // The manifest log is keyed by the stream the Change was signed for
    // (the manifest's `stream` field binds it — §4), not by any searched log.
    // `bound` owns its strings; `loaded`/`all` Change storage does not
    // outlive this block, so target ids are taken from the clone.
    stream_id = bound.?.stream;
    target_id = bound.?.id;
    stream_label = if (idx.streamByID(stream_id)) |st| st.name else stream_id;

    const manifests = try store.loadManifests(allocator, fs, root, stream_id);
    defer store.freeManifests(allocator, manifests);

    const m = store.manifestForChange(manifests, target_id) orelse {
        // A Change with no manifest line is a content-less revision.
        return fsys.refuse("blob_missing", target_id);
    };

    if (!std.mem.eql(u8, m.stream, bound.?.stream) or !std.mem.eql(u8, m.change, bound.?.id)) {
        return fsys.refuse("manifest_torn", "");
    }
    if (!std.mem.eql(u8, m.author, bound.?.author)) {
        return fsys.refuse("sig_invalid", "");
    }
    if (!try ed25519.verifyChange(allocator, &bound.?)) {
        return fsys.refuse("sig_invalid", "");
    }
    if (!try ed25519.verifyManifest(allocator, m.*)) {
        return fsys.refuse("sig_invalid", "");
    }

    const root_abs = try absNormalize(allocator, cwd, root);
    defer allocator.free(root_abs);
    const dest_abs = try absNormalize(allocator, cwd, into_flag);
    defer allocator.free(dest_abs);

    if (pathInside(dest_abs, root_abs)) {
        return fsys.refuse("checkout_exists", into_flag);
    }

    // All-or-nothing: every blob presence + id check resolves before any
    // write; a null-blob entry names its path rather than silently omitting.
    var payloads = try allocator.alloc([]u8, m.files.len);
    var loaded_count: usize = 0;
    defer {
        for (payloads[0..loaded_count]) |d| allocator.free(d);
        allocator.free(payloads);
    }
    var total_bytes: u64 = 0;
    for (m.files, 0..) |e, fi| {
        // Store-prefix spellings: the materialized path must never land
        // inside the resolved store root — a torn-manifest signal regardless
        // of what the entry's blob field says.
        const full = try fsys.joinPath(allocator, &.{ dest_abs, e.path });
        defer allocator.free(full);
        if (pathInside(full, root_abs)) {
            return fsys.refuse("manifest_torn", e.path);
        }
        if (e.blob.len == 0) {
            return fsys.refuse("blob_missing", e.path);
        }
        payloads[fi] = try readBlobVerified(allocator, fs, root_abs, e.blob, e.path);
        loaded_count += 1;
        total_bytes += e.bytes;
    }

    // Destination checks: --into must be absent or an empty real directory
    // unless --force; no prefix component may be a link or non-directory,
    // so manifest paths cannot escape through unsafe link traversal.
    const dest_st = fs.stat(allocator, dest_abs) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
    if (dest_st) |st| {
        if (st.kind != .dir) {
            return fsys.refuse("checkout_exists", into_flag);
        }
        if (!force) {
            const existing = try fs.list(allocator, dest_abs);
            defer FS.freeDirEntries(allocator, existing);
            if (existing.len > 0) {
                return fsys.refuse("checkout_exists", into_flag);
            }
        }
    }

    for (m.files) |e| {
        var prefix = try allocator.dupe(u8, dest_abs);
        defer allocator.free(prefix);
        var seg_it = std.mem.splitScalar(u8, e.path, '/');
        var last = seg_it.next() orelse continue;
        while (seg_it.next()) |seg| {
            const next_prefix = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ prefix, last });
            allocator.free(prefix);
            prefix = next_prefix;
            last = seg;
            const pst = fs.stat(allocator, prefix) catch |err| switch (err) {
                error.FileNotFound => break,
                else => return err,
            };
            if (pst.kind != .dir) {
                return fsys.refuse("checkout_exists", e.path);
            }
        }
    }

    try fs.mkdir(allocator, dest_abs);
    for (m.files, 0..) |e, fi| {
        const full = try fsys.joinPath(allocator, &.{ dest_abs, e.path });
        defer allocator.free(full);
        try fs.writeFileSafe(allocator, full, payloads[fi]);
        if (e.mode > 0) {
            try fs.setMode(full, modeFromField(e.mode));
        }
    }

    try out.print(
        "flint: checkout ok stream={s} change={s} files={d} bytes={d}\n",
        .{ stream_label, target_id, m.files.len, total_bytes },
    );
}

test "content: modeField octal-digit spelling roundtrips" {
    try std.testing.expectEqual(@as(u32, 644), modeField(0o644));
    try std.testing.expectEqual(@as(u32, 755), modeField(0o755));
    try std.testing.expectEqual(@as(u32, 600), modeField(0o600));
    try std.testing.expectEqual(@as(u32, 0o644), modeFromField(644));
    try std.testing.expectEqual(@as(u32, 0o755), modeFromField(755));
    // Malformed digits can only weaken, never widen, permission bits.
    try std.testing.expectEqual(@as(u32, 0o111), modeFromField(999));
    try std.testing.expectEqual(@as(u32, 0), modeFromField(0));
}

test "manifest: canonical line has Go field order, sorted files, null-blob reasons" {
    const gpa = std.testing.allocator;
    const json = @import("json.zig");
    const ed = @import("ed25519.zig");

    const seed = ed.parseHex32Lower("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").?;
    const entries = [_]store.ManifestEntry{
        .{ .path = "b/main.zig", .blob = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", .bytes = 12, .mode = 644 },
        .{ .path = "a/README.md", .blob = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", .bytes = 4, .mode = 644 },
        .{ .path = "link", .reason = "unsupported" },
    };
    var m = try signSnapshot(gpa, "0199de2d-dc00-7000-8000-0000000000aa", "0199de2d-dc00-7000-8000-0000000000bb", seed, &entries);
    defer m.deinit(gpa);

    // Canonical body: sorted files, Go order, no sig.
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(gpa);
    try json.appendManifestBody(&body, gpa, m);
    try std.testing.expectEqualStrings(
        "{\"stream\":\"0199de2d-dc00-7000-8000-0000000000aa\",\"change\":\"0199de2d-dc00-7000-8000-0000000000bb\",\"author\":\"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a\",\"files\":[{\"path\":\"a/README.md\",\"blob\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"bytes\":4,\"mode\":644},{\"path\":\"b/main.zig\",\"blob\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"bytes\":12,\"mode\":644},{\"path\":\"link\",\"blob\":null,\"bytes\":0,\"mode\":0,\"reason\":\"unsupported\"}]}",
        body.items,
    );

    const line = try json.marshalManifestLine(gpa, m);
    defer gpa.free(line);
    try std.testing.expect(std.mem.startsWith(u8, line, body.items[0 .. body.items.len - 1]));
    try std.testing.expect(std.mem.indexOf(u8, line, ",\"sig\":\"") != null);
    try std.testing.expect(std.mem.endsWith(u8, line, "\"}\n"));

    // Round trip: the stored line parses and its signature verifies.
    const parsed = try json.parseManifest(gpa, std.mem.trim(u8, line, "\n"));
    defer parsed.deinit(gpa);
    try std.testing.expect(try ed.verifyManifest(gpa, parsed));

    // A manifest naming the real author but signed under another key fails.
    const other_seed = ed.parseHex32Lower("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb").?;
    var m2 = try signSnapshot(gpa, m.stream, m.change, seed, &entries);
    defer m2.deinit(gpa);
    try ed.signManifestWithSeed(gpa, &m2, other_seed);
    try std.testing.expect(!try ed.verifyManifest(gpa, m2));
}

test "manifest paths: traversal, absolute, and empty segments refuse" {
    try std.testing.expect(store.validManifestPath("a/b/c.zig"));
    try std.testing.expect(store.validManifestPath("README.md"));
    try std.testing.expect(!store.validManifestPath("../x"));
    try std.testing.expect(!store.validManifestPath("a/../x"));
    try std.testing.expect(!store.validManifestPath("/abs"));
    try std.testing.expect(!store.validManifestPath("a//b"));
    try std.testing.expect(!store.validManifestPath("./x"));
    try std.testing.expect(!store.validManifestPath(""));
    try std.testing.expect(!store.validManifestPath("a/./b"));
}

test "capture: store subtree is excluded and non-regular entries recorded" {
    const gpa = std.testing.allocator;
    var mem = try fsys.MemFS.init(gpa);
    defer mem.deinit();
    const fs = mem.fs();

    try fs.writeFileSafe(gpa, "/host/src/main.zig", "pub fn a() void {}\n");
    try fs.writeFileSafe(gpa, "/host/src/README.md", "hi\n");
    try mem.addSymlink("/host/src/link.sh", "main.zig");
    // The resolved store lives beneath src — it must never be captured.
    try fs.writeFileSafe(gpa, "/host/src/.flint/keys/default", "seed");

    const cap = try captureSnapshot(gpa, fs, "/host", "/host/src/.flint", "/host/src");
    defer cap.deinit(gpa);

    try std.testing.expectEqual(@as(usize, 3), cap.entries.len);
    try std.testing.expectEqualStrings("README.md", cap.entries[0].path);
    try std.testing.expectEqualStrings("link.sh", cap.entries[1].path);
    try std.testing.expectEqualStrings("unsupported", cap.entries[1].reason);
    try std.testing.expectEqualStrings("main.zig", cap.entries[2].path);
    for (cap.entries) |e| {
        try std.testing.expect(std.mem.indexOf(u8, e.path, ".flint") == null);
    }
}
