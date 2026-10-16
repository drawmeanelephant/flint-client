const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const store = @import("store.zig");
const fsys = @import("fsys.zig");
const json = @import("json.zig");
const content = @import("content.zig");
const ed25519 = @import("ed25519.zig");

const main = @import("main.zig");
const TestHarness = main.TestHarness;
const rfc8032_seed_hex = main.rfc8032_seed_hex;

fn commitId(gpa: Allocator, out: []const u8) ![]u8 {
    const prefix = "flint: commit ok id=";
    try std.testing.expect(std.mem.startsWith(u8, out, prefix));
    const rest = out[prefix.len..];
    const end = std.mem.indexOfScalar(u8, rest, ' ') orelse rest.len;
    return gpa.dupe(u8, rest[0..end]);
}

fn streamIdByName(gpa: Allocator, mfs: fsys.FS, root: []const u8, name: []const u8) ![]u8 {
    var idx = try store.loadStoreIndex(gpa, mfs, root);
    defer idx.deinit();
    const st = idx.streamByName(name).?;
    return gpa.dupe(u8, st.id);
}

fn headChangeId(gpa: Allocator, mfs: fsys.FS, root: []const u8, stream: []const u8) ![]u8 {
    var idx = try store.loadStoreIndex(gpa, mfs, root);
    defer idx.deinit();
    const st = idx.streamByName(stream).?;
    return gpa.dupe(u8, st.head.?);
}

fn expectFileBytes(gpa: Allocator, mfs: fsys.FS, path: []const u8, want: []const u8) !void {
    const got = try mfs.readFile(gpa, path, store.MaxFileReadBytes);
    defer gpa.free(got);
    try std.testing.expectEqualStrings(want, got);
}

fn countBlobs(gpa: Allocator, mfs: fsys.FS, root: []const u8) !usize {
    const blobs = try std.fmt.allocPrint(gpa, "{s}/blobs", .{root});
    defer gpa.free(blobs);
    const dirs = mfs.list(gpa, blobs) catch return 0;
    defer fsys.FS.freeDirEntries(gpa, dirs);
    var count: usize = 0;
    for (dirs) |d| {
        if (d.kind != .dir) continue;
        const sub = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ blobs, d.name });
        defer gpa.free(sub);
        const files = try mfs.list(gpa, sub);
        defer fsys.FS.freeDirEntries(gpa, files);
        count += files.len;
    }
    return count;
}

fn readStoreFile(gpa: Allocator, mfs: fsys.FS, path: []const u8) ![]u8 {
    return mfs.readFile(gpa, path, store.MaxFileReadBytes);
}

fn runExpect(
    h: *TestHarness,
    gpa: Allocator,
    args: []const []const u8,
    want_rc: u8,
) !void {
    const res = try h.runCmd(args);
    defer gpa.free(res.out);
    try std.testing.expectEqual(want_rc, res.rc);
}

fn runOut(
    h: *TestHarness,
    gpa: Allocator,
    args: []const []const u8,
    want_rc: u8,
) ![]u8 {
    const res = try h.runCmd(args);
    errdefer gpa.free(res.out);
    try std.testing.expectEqual(want_rc, res.rc);
    return res.out;
}

test "checkout: mixed inventory round trip is byte-equal with modes" {
    const gpa = std.testing.allocator;
    var h = try TestHarness.init(gpa);
    defer h.deinit();
    h.env_sign_key = rfc8032_seed_hex;
    const mfs = h.mem.fs();

    const zig_src = "pub fn a() void {}\n";
    const go_src = "package main\n\nfunc F() int {\n\treturn 1\n}\n";
    const readme = "hello docs\n";
    const cfg = "{\"k\": 1}\n";
    const py = "print('hi')\n";
    const bin = [_]u8{ 0x00, 0x01, 0xfe, 0xff, 0x7f };
    const script = "#!/bin/sh\necho ok\n";

    try mfs.writeFileSafe(gpa, "/host/src/main.zig", zig_src);
    try mfs.writeFileSafe(gpa, "/host/src/lib.go", go_src);
    try mfs.writeFileSafe(gpa, "/host/src/README.md", readme);
    try mfs.writeFileSafe(gpa, "/host/src/build.json", cfg);
    try mfs.writeFileSafe(gpa, "/host/src/app.py", py);
    try mfs.writeFileSafe(gpa, "/host/src/asset.bin", &bin);
    try mfs.writeFileSafe(gpa, "/host/src/run.sh", script);
    try mfs.setMode("/host/src/run.sh", 0o755);

    try runExpect(h, gpa, &.{ "init", "--name=w", "--src=/host/src" }, 0);
    try runExpect(h, gpa, &.{ "add", "/host/src" }, 0);
    const commit_out = try runOut(h, gpa, &.{ "commit", "-m", "snapshot" }, 0);
    defer gpa.free(commit_out);
    const change_id = try commitId(gpa, commit_out);
    defer gpa.free(change_id);

    // `add` only parsed the two declaration files; the manifest must hold all 7.
    {
        const res = try h.runCmd(&.{ "checkout", "--head", "--into=/host/out" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        const want = try std.fmt.allocPrint(
            gpa,
            "flint: checkout ok stream=main change={s} files=7 bytes={d}\n",
            .{ change_id, zig_src.len + go_src.len + readme.len + cfg.len + py.len + bin.len + script.len },
        );
        defer gpa.free(want);
        try std.testing.expectEqualStrings(want, res.out);
    }

    try expectFileBytes(gpa, mfs, "/host/out/main.zig", zig_src);
    try expectFileBytes(gpa, mfs, "/host/out/lib.go", go_src);
    try expectFileBytes(gpa, mfs, "/host/out/README.md", readme);
    try expectFileBytes(gpa, mfs, "/host/out/build.json", cfg);
    try expectFileBytes(gpa, mfs, "/host/out/app.py", py);
    try expectFileBytes(gpa, mfs, "/host/out/asset.bin", &bin);
    try expectFileBytes(gpa, mfs, "/host/out/run.sh", script);
    try std.testing.expectEqual(@as(?u32, 0o755), h.mem.getMode("/host/out/run.sh"));

    // Repeated checkout never changes store history.
    const sid = try streamIdByName(gpa, mfs, h.root, "main");
    defer gpa.free(sid);
    const log_path = try store.streamLogPath(gpa, h.root, sid);
    defer gpa.free(log_path);
    const mlog_path = try store.manifestLogPath(gpa, h.root, sid);
    defer gpa.free(mlog_path);
    const log_before = try readStoreFile(gpa, mfs, log_path);
    defer gpa.free(log_before);
    const mlog_before = try readStoreFile(gpa, mfs, mlog_path);
    defer gpa.free(mlog_before);

    try runExpect(h, gpa, &.{ "checkout", "--change", change_id, "--into=/host/out2" }, 0);
    try expectFileBytes(gpa, mfs, "/host/out2/run.sh", script);

    const log_after = try readStoreFile(gpa, mfs, log_path);
    defer gpa.free(log_after);
    const mlog_after = try readStoreFile(gpa, mfs, mlog_path);
    defer gpa.free(mlog_after);
    try std.testing.expectEqualStrings(log_before, log_after);
    try std.testing.expectEqualStrings(mlog_before, mlog_after);
}

test "checkout: two eras materialize independently and a forked snapshot does not substitute main" {
    const gpa = std.testing.allocator;
    var h = try TestHarness.init(gpa);
    defer h.deinit();
    h.env_sign_key = rfc8032_seed_hex;
    const mfs = h.mem.fs();

    const a_v1 = "pub fn a() void {}\n";
    const notes_v1 = "era one\n";
    const gone = "will be deleted\n";
    const a_v2 = "pub fn a() void {}\npub fn b() void {}\n";
    const notes_v2 = "era two\n";

    try mfs.writeFileSafe(gpa, "/host/src/a.zig", a_v1);
    try mfs.writeFileSafe(gpa, "/host/src/notes.md", notes_v1);
    try mfs.writeFileSafe(gpa, "/host/src/gone.txt", gone);

    try runExpect(h, gpa, &.{ "init", "--name=w", "--src=/host/src" }, 0);
    try runExpect(h, gpa, &.{ "add", "/host/src" }, 0);
    const c1_out = try runOut(h, gpa, &.{ "commit", "-m", "era1" }, 0);
    defer gpa.free(c1_out);
    const c1 = try commitId(gpa, c1_out);
    defer gpa.free(c1);

    try mfs.writeFileSafe(gpa, "/host/src/a.zig", a_v2);
    try mfs.writeFileSafe(gpa, "/host/src/notes.md", notes_v2);
    try mfs.remove(gpa, "/host/src/gone.txt");
    try runExpect(h, gpa, &.{ "add", "/host/src" }, 0);
    try runExpect(h, gpa, &.{ "commit", "-m", "era2" }, 0);

    // Era 1 checkout reproduces its own tree, including the later-deleted file.
    {
        const res = try h.runCmd(&.{ "checkout", "--change", c1, "--into=/host/e1" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expect(std.mem.indexOf(u8, res.out, "files=3") != null);
    }
    try expectFileBytes(gpa, mfs, "/host/e1/a.zig", a_v1);
    try expectFileBytes(gpa, mfs, "/host/e1/notes.md", notes_v1);
    try expectFileBytes(gpa, mfs, "/host/e1/gone.txt", gone);

    // Era 2 head checkout reflects the deletion.
    try runExpect(h, gpa, &.{ "checkout", "--head", "--into=/host/e2" }, 0);
    try expectFileBytes(gpa, mfs, "/host/e2/a.zig", a_v2);
    try expectFileBytes(gpa, mfs, "/host/e2/notes.md", notes_v2);
    try std.testing.expect(!mfs.exists(gpa, "/host/e2/gone.txt"));

    // A forked stream's snapshot is bound to the fork, not to main.
    try runExpect(h, gpa, &.{ "fork", "main", "side" }, 0);
    const side_src = "pub fn side() void {}\n";
    try mfs.writeFileSafe(gpa, "/host/srcb/side.zig", side_src);
    try runExpect(h, gpa, &.{ "init", "--name=b", "--src=/host/srcb", "--stream=side" }, 0);
    try runExpect(h, gpa, &.{ "add", "--ws=b", "/host/srcb" }, 0);
    const c3_out = try runOut(h, gpa, &.{ "commit", "--ws=b", "-m", "side work" }, 0);
    defer gpa.free(c3_out);
    const c3 = try commitId(gpa, c3_out);
    defer gpa.free(c3);

    try runExpect(h, gpa, &.{ "checkout", "--stream=side", "--change", c3, "--into=/host/e3" }, 0);
    try expectFileBytes(gpa, mfs, "/host/e3/side.zig", side_src);
    try std.testing.expect(!mfs.exists(gpa, "/host/e3/a.zig"));

    // Bare --change resolves the bound stream on its own.
    try runExpect(h, gpa, &.{ "checkout", "--change", c3, "--into=/host/e4" }, 0);
    try expectFileBytes(gpa, mfs, "/host/e4/side.zig", side_src);

    // The shared ancestor is not present in the fork's own log.
    {
        const res = try h.runCmd(&.{ "checkout", "--stream=side", "--change", c1, "--into=/host/e5" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        const want = try std.fmt.allocPrint(gpa, "flint: refuse change_missing {s}\n", .{c1});
        defer gpa.free(want);
        try std.testing.expectEqualStrings(want, res.out);
    }
}

test "checkout: content-only commits capture non-semantic changes and dedupe blobs" {
    const gpa = std.testing.allocator;
    var h = try TestHarness.init(gpa);
    defer h.deinit();
    h.env_sign_key = rfc8032_seed_hex;
    const mfs = h.mem.fs();

    const v1 = "pub fn a() void {}\n";
    const v2 = "// a comment-only change\npub fn a() void {}\n";
    const dup = "duplicated payload\n";

    try mfs.writeFileSafe(gpa, "/host/src/a.zig", v1);
    try mfs.writeFileSafe(gpa, "/host/src/dup1.txt", dup);
    try runExpect(h, gpa, &.{ "init", "--name=w", "--src=/host/src" }, 0);
    try runExpect(h, gpa, &.{ "add", "/host/src" }, 0);
    try runExpect(h, gpa, &.{ "commit", "-m", "base" }, 0);

    const blobs_era1 = try countBlobs(gpa, mfs, h.root);

    // Comment-only edit (canonical hash unchanged → zero Ops) plus an opaque
    // duplicate file. A bare commit — no `add` — must still capture both.
    try mfs.writeFileSafe(gpa, "/host/src/a.zig", v2);
    try mfs.writeFileSafe(gpa, "/host/src/dup2.txt", dup);
    {
        const res = try h.runCmd(&.{ "commit", "-m", "content only" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expect(std.mem.indexOf(u8, res.out, "ops=0") != null);
    }

    // The committed Change really carries an empty ops array.
    {
        const sid = try streamIdByName(gpa, mfs, h.root, "main");
        defer gpa.free(sid);
        const loaded = try store.loadStream(gpa, mfs, h.root, sid);
        defer loaded.deinit(gpa);
        const head = loaded.changes[loaded.changes.len - 1];
        try std.testing.expectEqual(@as(usize, 0), head.ops.len);
    }

    // Identical content deduplicates: dup2.txt shares dup1.txt's blob.
    const blobs_era2 = try countBlobs(gpa, mfs, h.root);
    try std.testing.expectEqual(blobs_era1 + 1, blobs_era2);

    // The content-only state materializes with the comment edit intact.
    try runExpect(h, gpa, &.{ "checkout", "--head", "--into=/host/out" }, 0);
    try expectFileBytes(gpa, mfs, "/host/out/a.zig", v2);
    try expectFileBytes(gpa, mfs, "/host/out/dup2.txt", dup);

    // No-op capture/commit: nothing changed since the head snapshot.
    {
        const res = try h.runCmd(&.{ "commit", "-m", "noop" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse nothing_to_commit\n", res.out);
    }
}

test "checkout: missing, corrupt, substituted, torn, and content-less content refuses honestly" {
    const gpa = std.testing.allocator;
    var h = try TestHarness.init(gpa);
    defer h.deinit();
    h.env_sign_key = rfc8032_seed_hex;
    const mfs = h.mem.fs();

    const f1 = "pub fn a() void {}\n";
    try mfs.writeFileSafe(gpa, "/host/src/a.zig", f1);
    try runExpect(h, gpa, &.{ "init", "--name=w", "--src=/host/src" }, 0);
    try runExpect(h, gpa, &.{ "add", "/host/src" }, 0);
    const c1_out = try runOut(h, gpa, &.{ "commit", "-m", "base" }, 0);
    defer gpa.free(c1_out);
    const c1 = try commitId(gpa, c1_out);
    defer gpa.free(c1);

    const sid = try streamIdByName(gpa, mfs, h.root, "main");
    defer gpa.free(sid);
    const mlog_path = try store.manifestLogPath(gpa, h.root, sid);
    defer gpa.free(mlog_path);
    const mlog_raw = try readStoreFile(gpa, mfs, mlog_path);
    defer gpa.free(mlog_raw);
    const manifest = try json.parseManifest(gpa, std.mem.trim(u8, mlog_raw, "\n"));
    defer manifest.deinit(gpa);
    const blob_hex = try gpa.dupe(u8, manifest.files[0].blob);
    defer gpa.free(blob_hex);
    const blob_path = try store.blobPath(gpa, h.root, blob_hex);
    defer gpa.free(blob_path);
    const blob_bytes = try readStoreFile(gpa, mfs, blob_path);
    defer gpa.free(blob_bytes);

    // Corrupt blob bytes → blob_malformed naming the path.
    try mfs.writeFileSafe(gpa, blob_path, "tampered");
    {
        const res = try h.runCmd(&.{ "checkout", "--head", "--into=/host/out" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse blob_malformed a.zig\n", res.out);
    }
    // Missing blob → blob_missing naming the path.
    try mfs.remove(gpa, blob_path);
    {
        const res = try h.runCmd(&.{ "checkout", "--head", "--into=/host/out" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse blob_missing a.zig\n", res.out);
    }
    try mfs.writeFileSafe(gpa, blob_path, blob_bytes);

    // Path→blob substitution of a different valid id → sig_invalid (a valid
    // hash alone is not revision authenticity).
    const other_id = "ff11111111111111111111111111111111111111111111111111111111111111";
    const forged = try std.mem.replaceOwned(u8, gpa, mlog_raw, blob_hex, other_id);
    defer gpa.free(forged);
    try mfs.writeFileSafe(gpa, mlog_path, forged);
    {
        const res = try h.runCmd(&.{ "checkout", "--head", "--into=/host/out" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse sig_invalid\n", res.out);
    }
    try mfs.writeFileSafe(gpa, mlog_path, mlog_raw);

    // Torn final line → manifest_torn.
    try mfs.appendSync(gpa, mlog_path, "{\"stream\":\"partial");
    {
        const res = try h.runCmd(&.{ "checkout", "--head", "--into=/host/out" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse manifest_torn\n", res.out);
    }
    try mfs.writeFileSafe(gpa, mlog_path, mlog_raw);

    // Content-less revision (crashed commit / pre-content store): the Change
    // exists but no manifest line binds it.
    try mfs.remove(gpa, mlog_path);
    {
        const res = try h.runCmd(&.{ "checkout", "--head", "--into=/host/out" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        const want = try std.fmt.allocPrint(gpa, "flint: refuse blob_missing {s}\n", .{c1});
        defer gpa.free(want);
        try std.testing.expectEqualStrings(want, res.out);
    }

    // Pre-content stores remain verifiable: the Change log still checks out.
    try runExpect(h, gpa, &.{ "verify", "--all" }, 0);

    // The first content-enabled commit on a content-less tip records a full
    // inventory from scratch (stage is empty; src drives the diff).
    {
        const res = try h.runCmd(&.{ "commit", "-m", "capture" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expect(std.mem.indexOf(u8, res.out, "ops=0") != null);
    }
    try runExpect(h, gpa, &.{ "checkout", "--head", "--into=/host/out" }, 0);
    try expectFileBytes(gpa, mfs, "/host/out/a.zig", f1);
}

test "checkout: a crashed capture leaves a valid content-less store" {
    const gpa = std.testing.allocator;
    var h = try TestHarness.init(gpa);
    defer h.deinit();
    h.env_sign_key = rfc8032_seed_hex;
    const mfs = h.mem.fs();

    try mfs.writeFileSafe(gpa, "/host/src/a.zig", "pub fn a() void {}\n");
    try runExpect(h, gpa, &.{ "init", "--name=w", "--src=/host/src" }, 0);
    try runExpect(h, gpa, &.{ "add", "/host/src" }, 0);

    // Fault the manifest append so the commit dies between steps (2) and (3):
    // Change + stream record durable, no manifest line.
    const FailManifest = struct {
        fn hook(_: ?*anyopaque, op: []const u8, path: []const u8) anyerror!void {
            if (std.mem.eql(u8, op, "append") and std.mem.indexOf(u8, path, "manifests/") != null) {
                return error.Crash;
            }
        }
    };
    h.mem.before_write = FailManifest.hook;
    {
        const res = try h.runCmd(&.{ "commit", "-m", "crash" });
        defer gpa.free(res.out);
        h.mem.before_write = null;
        try std.testing.expectEqual(@as(u8, 1), res.rc);
    }

    // The head Change is valid history but checkout refuses content it lacks.
    try runExpect(h, gpa, &.{ "verify", "--all" }, 0);
    const head = try headChangeId(gpa, mfs, h.root, "main");
    defer gpa.free(head);
    {
        const res = try h.runCmd(&.{ "checkout", "--head", "--into=/host/out" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        const want = try std.fmt.allocPrint(gpa, "flint: refuse blob_missing {s}\n", .{head});
        defer gpa.free(want);
        try std.testing.expectEqualStrings(want, res.out);
    }
    try std.testing.expect(!mfs.exists(gpa, "/host/out/a.zig"));
}

test "checkout: destination containment, --force, and traversal refusals" {
    const gpa = std.testing.allocator;
    var h = try TestHarness.init(gpa);
    defer h.deinit();
    h.env_sign_key = rfc8032_seed_hex;
    const mfs = h.mem.fs();

    const sub_file = "nested\n";
    try mfs.writeFileSafe(gpa, "/host/src/sub/f.txt", sub_file);
    try mfs.writeFileSafe(gpa, "/host/src/main.zig", "pub fn a() void {}\n");
    try runExpect(h, gpa, &.{ "init", "--name=w", "--src=/host/src" }, 0);
    try runExpect(h, gpa, &.{ "add", "/host/src" }, 0);
    const c1_out = try runOut(h, gpa, &.{ "commit", "-m", "base" }, 0);
    defer gpa.free(c1_out);
    const c1 = try commitId(gpa, c1_out);
    defer gpa.free(c1);

    // Usage: missing --into, missing target, or both targets at once.
    for ([_][]const []const u8{
        &.{ "checkout", "--head" },
        &.{ "checkout", "--into=/host/x" },
        &.{ "checkout", "--head", "--change", c1, "--into=/host/x" },
    }) |bad_args| {
        const res = try h.runCmd(bad_args);
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 2), res.rc);
    }

    // Non-empty destination without --force; --force materializes anyway.
    try mfs.writeFileSafe(gpa, "/host/full/junk.txt", "keep me\n");
    {
        const res = try h.runCmd(&.{ "checkout", "--head", "--into=/host/full" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse checkout_exists /host/full\n", res.out);
    }
    try runExpect(h, gpa, &.{ "checkout", "--head", "--into=/host/full", "--force" }, 0);
    try expectFileBytes(gpa, mfs, "/host/full/sub/f.txt", sub_file);
    try expectFileBytes(gpa, mfs, "/host/full/junk.txt", "keep me\n");

    // A destination that is a file, or inside the store, refuses.
    {
        const res = try h.runCmd(&.{ "checkout", "--head", "--into=/host/full/junk.txt", "--force" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse checkout_exists /host/full/junk.txt\n", res.out);
    }
    {
        const res = try h.runCmd(&.{ "checkout", "--head", "--into=/host/FLINT/loot" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse checkout_exists /host/FLINT/loot\n", res.out);
    }

    // Unsafe link traversal: a symlink as a path prefix inside the destination
    // must not redirect the write outside --into.
    try mem_add_link(h, "/host/out/sub", "/host/src");
    {
        const res = try h.runCmd(&.{ "checkout", "--head", "--into=/host/out", "--force" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse checkout_exists sub/f.txt\n", res.out);
    }

    // A crafted but correctly signed manifest line with traversal paths is
    // rejected at load: path validation runs before materialization.
    const sid = try streamIdByName(gpa, mfs, h.root, "main");
    defer gpa.free(sid);
    const mlog_path = try store.manifestLogPath(gpa, h.root, sid);
    defer gpa.free(mlog_path);
    const good_log = try readStoreFile(gpa, mfs, mlog_path);
    defer gpa.free(good_log);

    const seed = ed25519.parseHex32Lower(rfc8032_seed_hex).?;
    const evil_entries = [_]store.ManifestEntry{
        .{ .path = "../escape.txt", .reason = "unsupported" },
    };
    var evil = try content.signSnapshot(gpa, sid, c1, seed, &evil_entries);
    defer evil.deinit(gpa);
    const evil_line = try json.marshalManifestLine(gpa, evil);
    defer gpa.free(evil_line);
    try mfs.writeFileSafe(gpa, mlog_path, evil_line);
    {
        const res = try h.runCmd(&.{ "checkout", "--change", c1, "--into=/host/e" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse manifest_torn\n", res.out);
    }

    // Store-prefix spellings: a path resolving inside the store root under
    // --into is the same refusal. --into=/host puts the joined path beneath
    // the resolved store at /host/FLINT.
    const store_entries = [_]store.ManifestEntry{
        .{ .path = "FLINT/loot.txt", .reason = "unsupported" },
    };
    var store_evil = try content.signSnapshot(gpa, sid, c1, seed, &store_entries);
    defer store_evil.deinit(gpa);
    const store_line = try json.marshalManifestLine(gpa, store_evil);
    defer gpa.free(store_line);
    try mfs.writeFileSafe(gpa, mlog_path, store_line);
    {
        const res = try h.runCmd(&.{ "checkout", "--change", c1, "--into=/host" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse manifest_torn FLINT/loot.txt\n", res.out);
    }
    try mfs.writeFileSafe(gpa, mlog_path, good_log);
    try std.testing.expect(!mfs.exists(gpa, "/host/FLINT/loot.txt"));

    // A symlink in the source root is an explicit unsupported entry: it is
    // tracked honestly and refuses blob_missing rather than being followed.
    try mem_add_link(h, "/host/src/dangling", "nowhere");
    try runExpect(h, gpa, &.{ "add", "/host/src" }, 0);
    try runExpect(h, gpa, &.{ "commit", "-m", "with link" }, 0);
    {
        const res = try h.runCmd(&.{ "checkout", "--head", "--into=/host/linkout" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse blob_missing dangling\n", res.out);
    }
    try std.testing.expect(!mfs.exists(gpa, "/host/linkout/sub/f.txt"));
}

fn mem_add_link(h: *TestHarness, path: []const u8, target: []const u8) !void {
    try h.mem.addSymlink(path, target);
}

test "checkout: unmaterialized merge head refuses blob_missing until resolved" {
    const gpa = std.testing.allocator;
    var h = try TestHarness.init(gpa);
    defer h.deinit();
    h.env_sign_key = rfc8032_seed_hex;
    const mfs = h.mem.fs();

    const base = "package calc\n\nfunc X() int {\n\treturn 1\n}\n\nfunc Y() int {\n\treturn 2\n}\n";
    const into_edit = "package calc\n\nfunc X() int {\n\treturn 10\n}\n\nfunc Y() int {\n\treturn 2\n}\n";
    const from_edit = "package calc\n\nfunc X() int {\n\treturn 1\n}\n\nfunc Y() int {\n\treturn 20\n}\n";
    const merged = "package calc\n\nfunc X() int {\n\treturn 10\n}\n\nfunc Y() int {\n\treturn 20\n}\n";

    try mfs.writeFileSafe(gpa, "/host/SRCA/calc.go", base);
    try mfs.writeFileSafe(gpa, "/host/SRCB/calc.go", base);

    try runExpect(h, gpa, &.{ "init", "--name=a", "--src=/host/SRCA" }, 0);
    try runExpect(h, gpa, &.{ "add", "/host/SRCA" }, 0);
    try runExpect(h, gpa, &.{ "commit", "-m", "base" }, 0);
    try runExpect(h, gpa, &.{ "fork", "main", "feature" }, 0);
    try runExpect(h, gpa, &.{ "init", "--name=b", "--src=/host/SRCB", "--stream=feature" }, 0);

    try mfs.writeFileSafe(gpa, "/host/SRCB/calc.go", from_edit);
    try runExpect(h, gpa, &.{ "add", "--ws=b", "/host/SRCB" }, 0);
    try runExpect(h, gpa, &.{ "commit", "--ws=b", "-m", "feature edit" }, 0);

    try mfs.writeFileSafe(gpa, "/host/SRCA/calc.go", into_edit);
    try runExpect(h, gpa, &.{ "add", "/host/SRCA" }, 0);
    try runExpect(h, gpa, &.{ "commit", "-m", "main edit" }, 0);

    {
        const res = try h.runCmd(&.{ "merge", "feature", "--ws=a" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expect(std.mem.indexOf(u8, res.out, "flint: merge ok conflicts=0") != null);
        try std.testing.expect(std.mem.indexOf(u8, res.out, "src not materialized files=1") != null);
    }

    // The merged head is signed history, but its accepted content is not in
    // src — no manifest advertises it, so checkout refuses instead of
    // materializing a last-writer-wins tree.
    {
        const res = try h.runCmd(&.{ "checkout", "--ws=a", "--head", "--into=/host/m" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expect(std.mem.startsWith(u8, res.out, "flint: refuse blob_missing "));
    }
    try std.testing.expect(!mfs.exists(gpa, "/host/m/calc.go"));

    // Materialize the merged bytes, restage, commit — the new head is a
    // complete snapshot and checks out byte-equal to the resolved tree.
    try mfs.writeFileSafe(gpa, "/host/SRCA/calc.go", merged);
    try runExpect(h, gpa, &.{ "add", "/host/SRCA" }, 0);
    try runExpect(h, gpa, &.{ "commit", "-m", "materialize merge" }, 0);
    try runExpect(h, gpa, &.{ "checkout", "--ws=a", "--head", "--into=/host/m" }, 0);
    try expectFileBytes(gpa, mfs, "/host/m/calc.go", merged);
}

test "checkout: host filesystem round trip preserves modes and link policy" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var rbuf: [4096]u8 = undefined;
    const tmp_len = try tmp.dir.realPath(io, &rbuf);
    const tmp_abs = rbuf[0..tmp_len];

    var host_fs = fsys.HostFS.init(io);
    const fs = host_fs.fs();

    const src_dir = try std.fmt.allocPrint(gpa, "{s}/src", .{tmp_abs});
    defer gpa.free(src_dir);
    const store_dir = try std.fmt.allocPrint(gpa, "{s}/.flint", .{tmp_abs});
    defer gpa.free(store_dir);

    const script = "#!/bin/sh\necho hi\n";
    const run_path = try std.fmt.allocPrint(gpa, "{s}/run.sh", .{src_dir});
    defer gpa.free(run_path);
    try fs.writeFileSafe(gpa, run_path, script);
    try fs.setMode(run_path, 0o755);
    const doc_path = try std.fmt.allocPrint(gpa, "{s}/sub/doc.md", .{src_dir});
    defer gpa.free(doc_path);
    try fs.writeFileSafe(gpa, doc_path, "doc\n");
    const zig_path = try std.fmt.allocPrint(gpa, "{s}/main.zig", .{src_dir});
    defer gpa.free(zig_path);
    try fs.writeFileSafe(gpa, zig_path, "pub fn a() void {}\n");

    var out_w: Io.Writer.Allocating = .init(gpa);
    defer out_w.deinit();
    var err_w: Io.Writer.Allocating = .init(gpa);
    defer err_w.deinit();
    const ctx = main.Context{
        .allocator = gpa,
        .io = io,
        .fs = fs,
        .stdout = &out_w.writer,
        .stderr = &err_w.writer,
        .cwd = tmp_abs,
        .env_flint_store = store_dir,
        .env_flint_sign_key = rfc8032_seed_hex,
    };

    try std.testing.expectEqual(@as(u8, 0), main.runWithContext(ctx, &.{ "init", "--name=w", "--src", src_dir }));
    try std.testing.expectEqual(@as(u8, 0), main.runWithContext(ctx, &.{ "add", src_dir }));
    try std.testing.expectEqual(@as(u8, 0), main.runWithContext(ctx, &.{ "commit", "-m", "base" }));

    const into_dir = try std.fmt.allocPrint(gpa, "{s}/out", .{tmp_abs});
    defer gpa.free(into_dir);
    try std.testing.expectEqual(@as(u8, 0), main.runWithContext(ctx, &.{ "checkout", "--head", "--into", into_dir }));

    const out_script = try std.fmt.allocPrint(gpa, "{s}/run.sh", .{into_dir});
    defer gpa.free(out_script);
    const got = try fs.readFile(gpa, out_script, store.MaxFileReadBytes);
    defer gpa.free(got);
    try std.testing.expectEqualStrings(script, got);
    const st = try Io.Dir.statFile(.cwd(), io, out_script, .{});
    try std.testing.expectEqual(@as(u32, 0o755), fsys.permissionsMode(st.permissions) & 0o777);

    // A real symlink in src rides the manifest as unsupported and refuses
    // blob_missing — it is never followed into the destination.
    try tmp.dir.symLink(io, "../etc", "src/link", .{});
    try std.testing.expectEqual(@as(u8, 0), main.runWithContext(ctx, &.{ "add", src_dir }));
    try std.testing.expectEqual(@as(u8, 0), main.runWithContext(ctx, &.{ "commit", "-m", "link" }));

    out_w.clearRetainingCapacity();
    const out2_dir = try std.fmt.allocPrint(gpa, "{s}/out2", .{tmp_abs});
    defer gpa.free(out2_dir);
    const rc = main.runWithContext(ctx, &.{ "checkout", "--head", "--into", out2_dir });
    try std.testing.expectEqual(@as(u8, 1), rc);
    try std.testing.expectEqualStrings("flint: refuse blob_missing link\n", out_w.written());
}
