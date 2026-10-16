const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const fsys = @import("fsys.zig");
const FS = fsys.FS;
const store = @import("store.zig");
const uuid = @import("uuid.zig");
const ed25519 = @import("ed25519.zig");
const content = @import("content.zig");
const report = @import("report.zig");

pub const loadSigningSeed = ed25519.loadSigningSeed;
pub const signChangeWithSeed = ed25519.signChangeWithSeed;
pub const verifyChange = ed25519.verifyChange;
pub const derivePublic = ed25519.derivePublic;
pub const signMsg = ed25519.signMsg;
pub const verifySig = ed25519.verifySig;
pub const sigMsg = ed25519.sigMsg;
pub const opsHash = ed25519.opsHash;
pub const opBytes = ed25519.opBytes;
pub const cmdKeygen = ed25519.cmdKeygen;
pub const cmdVerify = ed25519.cmdVerify;

/// Optional test hook invoked after the Change is built and signed, immediately
/// before `appendStreamChange` re-reads the Stream record for `stale_head`.
pub var before_commit_append: ?*const fn (?*anyopaque) void = null;
pub var before_commit_append_ctx: ?*anyopaque = null;

pub fn validateCommitMessage(msg: []const u8) !void {
    if (msg.len < 1 or msg.len > 512 or !std.unicode.utf8ValidateSlice(msg)) {
        return fsys.refuse("message_invalid", "");
    }
}

/// Implements `flint commit [--ws=<name>] [--key=<k>] -m <msg>`.
pub fn cmdCommit(
    allocator: Allocator,
    fs: FS,
    root: []const u8,
    uuid_gen: *uuid.UUIDGen,
    env_sign_key: ?[]const u8,
    out: *Io.Writer,
    args: []const []const u8,
) !void {
    var ws_flag: []const u8 = "";
    var key_flag: []const u8 = "";
    var msg: []const u8 = "";
    var has_msg = false;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.startsWith(u8, a, "--ws=")) {
            ws_flag = a["--ws=".len..];
        } else if (std.mem.eql(u8, a, "--ws") and i + 1 < args.len) {
            i += 1;
            ws_flag = args[i];
        } else if (std.mem.startsWith(u8, a, "--key=")) {
            key_flag = a["--key=".len..];
        } else if (std.mem.eql(u8, a, "--key") and i + 1 < args.len) {
            i += 1;
            key_flag = args[i];
        } else if (std.mem.eql(u8, a, "-m") or std.mem.eql(u8, a, "--message")) {
            if (i + 1 >= args.len) {
                return fsys.refuse("usage", "");
            }
            i += 1;
            msg = args[i];
            has_msg = true;
        } else if (std.mem.startsWith(u8, a, "-m=")) {
            msg = a["-m=".len..];
            has_msg = true;
        } else if (std.mem.startsWith(u8, a, "--message=")) {
            msg = a["--message=".len..];
            has_msg = true;
        } else {
            return fsys.refuse("usage", "");
        }
    }

    if (!has_msg) {
        return fsys.refuse("usage", "");
    }
    try validateCommitMessage(msg);

    var idx = try store.loadStoreIndex(allocator, fs, root);
    defer idx.deinit();

    const ws = try store.resolveWorkspace(allocator, fs, &idx, ws_flag, &.{});

    if (report.active) |r| {
        const sname = if (idx.streamByID(ws.stream)) |st| st.name else ws.stream;
        try r.setScope(ws.name, sname);
    }

    const stage = try store.loadWorkspaceStage(allocator, fs, root, ws.name);
    defer store.freeOps(allocator, stage);

    // Content capture (blobs spec §2/§3): inventory the tracked source root
    // and compare it against the head revision's manifest. The store root is
    // pruned so a store beneath src is never captured. An empty stage commits
    // when — and only when — the inventory changed; otherwise the stage is
    // genuinely empty and `nothing_to_commit` stands.
    const inv = try content.scanInventory(allocator, fs, ws.src, root);
    defer {
        for (inv) |f| f.deinit(allocator);
        allocator.free(inv);
    }

    var prev_files: []const content.ManifestFile = &.{};
    var head_log: []content.Manifest = &.{};
    defer {
        for (head_log) |m| m.deinit(allocator);
        if (head_log.len > 0) allocator.free(head_log);
    }
    {
        head_log = try content.loadManifestLog(allocator, fs, root, ws.stream);
        const head_st = idx.streamByID(ws.stream) orelse idx.streamByName(ws.stream);
        if (head_st) |st| {
            if (st.head) |hid| {
                if (content.manifestForChange(head_log, hid)) |pm| prev_files = pm.files;
            }
        }
    }

    const content_changed = !content.inventoriesEqual(inv, prev_files);
    if (stage.len == 0 and !content_changed) {
        return fsys.refuse("nothing_to_commit", "");
    }
    if (idx.change_count + 1 > store.MaxChanges) {
        return fsys.refuse("store_too_large", "changes");
    }

    // A commit during an in-progress merge (`MERGE.json` present) is the
    // resolution: the Change records `merged = report.from` so the merged-in
    // head becomes reachable, and MERGE.json is removed on success.
    const merge_report = try store.loadWorkspaceMerge(allocator, fs, root, ws.name);
    defer if (merge_report) |mr| mr.deinit(allocator);

    // ADR 0049: load the signing key BEFORE any write (including before
    // `loadStream`, which could roll forward a stale stream record) so a
    // missing or malformed secret leaves the store byte-identical.
    var seed = try ed25519.loadSigningSeed(allocator, fs, root, key_flag, env_sign_key);
    defer std.crypto.secureZero(u8, &seed);

    const loaded = try store.loadStream(allocator, fs, root, ws.stream);
    defer loaded.deinit(allocator);

    const expected_head = loaded.stream.head;

    // Staging-base guard (#67): STAGE.jsonl was diffed against the stream head
    // `add` recorded in ws/<ws>/BASE.json. A pull, pull --reset, or another
    // workspace's commit can move the head afterwards; committing would
    // silently reparent the old staged intent onto the new head, so refuse
    // `stage_stale` instead. Re-running `add` re-stamps the base — that is the
    // documented explicit restage; there is no bypass flag. A stage without
    // BASE.json (written before this guard existed) has unknown provenance and
    // refuses the same way rather than silently assuming the latest head.
    // The stage-stale guard protects staged *ops* against silent reparenting.
    // A content-only commit (empty stage, changed inventory) carries no
    // staged intent, so BASE.json is not required.
    const stage_base = try store.loadWorkspaceStageBase(allocator, fs, root, ws.name);
    defer if (stage_base) |sb| sb.deinit(allocator);

    if (report.active) |r| {
        try r.setScope(ws.name, loaded.stream.name);
        try r.observeBaseHead(if (stage_base) |sb| sb.head else null);
        try r.observeResultHead(expected_head);
    }

    if (stage.len == 0) {
        // no staged ops: nothing to guard
    } else if (stage_base) |sb| {
        if (!store.optStrEql(sb.head, expected_head)) {
            const detail = try std.fmt.allocPrint(
                allocator,
                "staged against {s}; stream head is now {s}; re-run add to restage",
                .{ sb.head orelse "none", expected_head orelse "none" },
            );
            defer allocator.free(detail);
            return fsys.refuse("stage_stale", detail);
        }
    } else {
        return fsys.refuse("stage_stale", "stage base unknown; re-run add to restage");
    }

    const ts = try uuid_gen.nowMs();
    const change_id = try uuid_gen.new();

    var c = store.Change{
        .id = &change_id,
        .parent = expected_head,
        .stream = loaded.stream.id,
        .ts = ts,
        .author = "",
        .message = msg,
        .ops = stage,
        .merged = if (merge_report) |mr| mr.from else null,
        .sig = "",
    };
    defer {
        if (c.author.len > 0) allocator.free(c.author);
        if (c.sig.len > 0) allocator.free(c.sig);
    }

    // Sign the manifest BEFORE signChangeWithSeed: that call zeroes the
    // seed buffer (ADR 0049 key hygiene), so any later use would sign with
    // a wiped key.
    var manifest = content.Manifest{
        .stream = try allocator.dupe(u8, loaded.stream.id),
        .change = try allocator.dupe(u8, c.id),
        .author = "",
        .files = inv,
        .sig = "",
    };
    defer {
        manifest.files = &.{}; // ownership stays with `inv`
        manifest.deinit(allocator);
    }
    try content.signManifest(allocator, &manifest, seed);

    try ed25519.signChangeWithSeed(allocator, &c, &seed);

    if (before_commit_append) |hook| {
        hook(before_commit_append_ctx);
    }

    // Commit order: (1) append Change + FileSync, (2) rewrite Stream record,
    // (3) remove STAGE.jsonl.
    if (report.active) |r| r.beginLocalWrites();
    var updated_st = try store.appendStreamChange(allocator, fs, root, loaded.stream.id, expected_head, c);
    updated_st.deinit(allocator);

    // Step (3): write referenced blobs, then append the signed manifest —
    // content lands before the manifest that names it (spec §1 order).
    for (inv) |f| {
        if (f.blob) |bid| {
            const src_file = try fsys.joinPath(allocator, &.{ ws.src, f.path });
            defer allocator.free(src_file);
            const bytes = try fs.readFile(allocator, src_file, content.MaxBlobBytes);
            defer allocator.free(bytes);
            try content.writeBlobBytes(allocator, fs, root, bid, bytes);
        }
    }
    try content.appendManifestLine(allocator, fs, root, &manifest);

    const stage_path = try store.workspaceStagePath(allocator, root, ws.name);
    defer allocator.free(stage_path);
    // A content-only commit (empty stage) may never have written STAGE.jsonl.
    if (fs.exists(allocator, stage_path)) {
        try fs.remove(allocator, stage_path);
    }

    const base_path = try store.workspaceBasePath(allocator, root, ws.name);
    defer allocator.free(base_path);
    if (fs.exists(allocator, base_path)) {
        try fs.remove(allocator, base_path);
    }

    if (merge_report != null) {
        const merge_path = try store.workspaceMergePath(allocator, root, ws.name);
        defer allocator.free(merge_path);
        try fs.remove(allocator, merge_path);
    }

    if (report.active) |r| {
        try r.observeResultHead(c.id);
        try r.noteAffected(c.id);
        r.localApplied();
        try r.fieldStr("id", c.id);
        try r.fieldInt("ops", c.ops.len);
        try r.fieldStr("message", msg);
        try r.fieldOptStrOmitNull("merged", c.merged);
        try r.fieldBool("merge_resolution", merge_report != null);
    }

    const parent_str = c.parent orelse "none";
    try out.print(
        "flint: commit ok id={s} ops={d} parent={s}\n",
        .{ c.id, c.ops.len, parent_str },
    );
    if (merge_report) |mr| {
        try out.print("flint: merge completed merged={s}\n", .{mr.from});
    }
}

fn firstMessageLine(msg: []const u8) []const u8 {
    var line = msg;
    if (std.mem.indexOfScalar(u8, line, '\n')) |nl| {
        line = line[0..nl];
    }
    if (std.mem.endsWith(u8, line, "\r")) {
        line = line[0 .. line.len - 1];
    }
    return line;
}

/// Implements `flint log [--stream=<name>] [--ws=<name>]`.
pub fn cmdLog(
    allocator: Allocator,
    fs: FS,
    root: []const u8,
    out: *Io.Writer,
    args: []const []const u8,
) !void {
    var stream_flag: []const u8 = "";
    var ws_flag: []const u8 = "";

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
        } else {
            return fsys.refuse("usage", "");
        }
    }

    var idx = try store.loadStoreIndex(allocator, fs, root);
    defer idx.deinit();

    var stream_id: []const u8 = "";
    if (stream_flag.len > 0) {
        const st = idx.streamByName(stream_flag) orelse {
            return fsys.refuse("stream_missing", stream_flag);
        };
        stream_id = st.id;
    } else {
        const ws = try store.resolveWorkspace(allocator, fs, &idx, ws_flag, &.{});
        stream_id = ws.stream;
    }

    const stream_id_copy = try allocator.dupe(u8, stream_id);
    defer allocator.free(stream_id_copy);

    const loaded = try store.loadStream(allocator, fs, root, stream_id_copy);
    defer loaded.deinit(allocator);

    const log_cap: usize = 64;
    var printed: usize = 0;
    var idx_rev: usize = loaded.changes.len;
    while (idx_rev > 0 and printed < log_cap) {
        idx_rev -= 1;
        const c = loaded.changes[idx_rev];
        const parent_str = if (c.parent) |p| (if (p.len > 0) p else "none") else "none";
        const author_prefix = if (c.author.len > 8) c.author[0..8] else c.author;
        try out.print(
            "flint: change {s} parent={s} ops={d} author={s} msg={s}\n",
            .{ c.id, parent_str, c.ops.len, author_prefix, firstMessageLine(c.message) },
        );
        printed += 1;
    }
}
