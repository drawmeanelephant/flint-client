const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const fsys = @import("fsys.zig");
const FS = fsys.FS;
const store = @import("store.zig");
const uuid = @import("uuid.zig");
const ed25519 = @import("ed25519.zig");

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

    const stage = try store.loadWorkspaceStage(allocator, fs, root, ws.name);
    defer store.freeOps(allocator, stage);

    if (stage.len == 0) {
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

    try ed25519.signChangeWithSeed(allocator, &c, &seed);

    if (before_commit_append) |hook| {
        hook(before_commit_append_ctx);
    }

    // Commit order: (1) append Change + FileSync, (2) rewrite Stream record,
    // (3) remove STAGE.jsonl.
    var updated_st = try store.appendStreamChange(allocator, fs, root, loaded.stream.id, expected_head, c);
    updated_st.deinit(allocator);

    const stage_path = try store.workspaceStagePath(allocator, root, ws.name);
    defer allocator.free(stage_path);
    try fs.remove(allocator, stage_path);

    if (merge_report != null) {
        const merge_path = try store.workspaceMergePath(allocator, root, ws.name);
        defer allocator.free(merge_path);
        try fs.remove(allocator, merge_path);
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
