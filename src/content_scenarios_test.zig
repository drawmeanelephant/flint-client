// CLI-level content-layer journeys (blobs spec §10): complete snapshot
// capture + all-or-nothing checkout for issue #78 (B1/B2).
const std = @import("std");
const store = @import("store.zig");
const content = @import("content.zig");
const fsys = @import("fsys.zig");
const json = @import("json.zig");
const sign = @import("sign.zig");
const merge = @import("merge.zig");
const uuid = @import("uuid.zig");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const main = @import("main.zig");
const TestHarness = main.TestHarness;
const rfc8032_seed_hex = main.rfc8032_seed_hex;

test "checkout: complete snapshot round trip, two eras, content-only commit, corrupt blob" {
    const gpa = std.testing.allocator;
    var h = try TestHarness.init(gpa);
    defer h.deinit();
    h.env_sign_key = rfc8032_seed_hex;
    const mfs = h.mem.fs();

    // Mixed tree: parsed source + opaque files (spec §10 matrix).
    try mfs.writeFileSafe(gpa, "/host/src/main.zig", "pub const a: u32 = 1;\n");
    try mfs.writeFileSafe(gpa, "/host/src/README.md", "# hello\n");
    try mfs.writeFileSafe(gpa, "/host/src/assets/icon.bin", "\x00\x01\x02\xff");

    {
        const res = try h.runCmd(&.{ "init", "--name=w", "--src=/host/src" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }
    {
        const res = try h.runCmd(&.{ "add", "/host/src" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }
    {
        const res = try h.runCmd(&.{ "commit", "-m", "era one" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }

    var idx = try store.loadStoreIndex(gpa, mfs, h.root);
    defer idx.deinit();
    const ws = idx.workspaces.items[0];
    var first_id: []u8 = &.{};
    defer gpa.free(first_id);
    {
        const loaded = try store.loadStream(gpa, mfs, h.root, ws.stream);
        defer loaded.deinit(gpa);
        first_id = try gpa.dupe(u8, loaded.stream.head.?);
    }

    // Era two: comment-only edit (no atom change) + delete README.
    try mfs.writeFileSafe(gpa, "/host/src/main.zig", "// rewritten comment\npub const a: u32 = 1;\n");
    try mfs.remove(gpa, "/host/src/README.md");
    h.now += 5;
    {
        const res = try h.runCmd(&.{ "commit", "-m", "era two" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expect(std.mem.indexOf(u8, res.out, "ops=") != null);
    }
    var second_id: []u8 = &.{};
    defer gpa.free(second_id);
    {
        const loaded = try store.loadStream(gpa, mfs, h.root, ws.stream);
        defer loaded.deinit(gpa);
        second_id = try gpa.dupe(u8, loaded.stream.head.?);
    }

    // Checkout era two (head) then era one (--change): exact snapshot each.
    {
        const res = try h.runCmd(&.{ "checkout", "--stream=main", "--into=/host/out2" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }
    try std.testing.expect(!mfs.exists(gpa, "/host/out2/README.md"));
    const two_main = try mfs.readFile(gpa, "/host/out2/main.zig", store.MaxFileReadBytes);
    defer gpa.free(two_main);
    try std.testing.expectEqualStrings("// rewritten comment\npub const a: u32 = 1;\n", two_main);

    {
        const arg = try std.fmt.allocPrint(gpa, "--change={s}", .{first_id});
        defer gpa.free(arg);
        const res1 = try h.runCmd(&.{ "checkout", "--stream=main", "--into=/host/out1", arg });
        defer gpa.free(res1.out);
        try std.testing.expectEqual(@as(u8, 0), res1.rc);
    }
    // Non-empty destination refuses without --force.
    {
        const res = try h.runCmd(&.{ "checkout", "--stream=main", "--into=/host/out1" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expect(std.mem.startsWith(u8, res.out, "flint: refuse checkout_exists"));
    }

    // Corrupt the era-two blob -> blob_malformed, nothing written.
    {
        const mlog = try content.loadManifestLog(gpa, mfs, h.root, ws.stream);
        defer {
            for (mlog) |m| m.deinit(gpa);
            gpa.free(mlog);
        }
        const m2 = content.manifestForChange(mlog, second_id).?;
        const corrupt_id = m2.files[0].blob.?;
        const bp = try content.blobPath(gpa, h.root, corrupt_id);
        defer gpa.free(bp);
        try mfs.writeFileSafe(gpa, bp, "tampered-bytes");

        const res = try h.runCmd(&.{ "checkout", "--stream=main", "--into=/host/out3" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expect(std.mem.startsWith(u8, res.out, "flint: refuse blob_malformed"));
        try std.testing.expect(!mfs.exists(gpa, "/host/out3"));
    }
}

test "commit, log, and key resolution refusals" {
    const gpa = std.testing.allocator;
    var host_fs = fsys.HostFS.init(std.testing.io);
    const hfs = host_fs.fs();
    const sample_go = try hfs.readFile(gpa, "testdata/corpus/go/sample.go", store.MaxFileReadBytes);
    defer gpa.free(sample_go);

    var h = try TestHarness.init(gpa);
    defer h.deinit();
    h.env_sign_key = rfc8032_seed_hex;
    const mfs = h.mem.fs();
    try mfs.writeFileSafe(gpa, "/host/src/go/sample.go", sample_go);

    {
        const res = try h.runCmd(&.{ "init", "--name=w", "--src=/host/src" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }

    // 1. Content-only commit (blobs spec §3): an empty stage still commits
    //    when the source inventory differs — the Change carries ops=[].
    //    Repeating it with no content delta is nothing_to_commit.
    {
        const res = try h.runCmd(&.{ "commit", "-m", "empty" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expect(std.mem.indexOf(u8, res.out, "ops=0 parent=none") != null);
    }
    {
        const res = try h.runCmd(&.{ "commit", "-m", "empty again" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse nothing_to_commit\n", res.out);
    }

    {
        const res = try h.runCmd(&.{ "add", "/host/src" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }

    // 2. message_invalid: empty, > 512 bytes, invalid UTF-8.
    const too_long = try gpa.alloc(u8, 513);
    defer gpa.free(too_long);
    @memset(too_long, 'x');
    const bad_utf8 = [_]u8{ 0xff, 0xfe, 0xfd };
    for ([_][]const u8{ "", too_long, &bad_utf8 }) |bad_msg| {
        const res = try h.runCmd(&.{ "commit", "-m", bad_msg });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse message_invalid\n", res.out);
    }

    // 3. secret_not_found: store remains byte-identical, no file written!
    var idx = try store.loadStoreIndex(gpa, mfs, h.root);
    defer idx.deinit();
    const ws = idx.workspaces.items[0];
    const log_path = try store.streamLogPath(gpa, h.root, ws.stream);
    defer gpa.free(log_path);
    const stage_path = try store.workspaceStagePath(gpa, h.root, "w");
    defer gpa.free(stage_path);
    const stage_before = if (mfs.exists(gpa, stage_path))
        try mfs.readFile(gpa, stage_path, store.MaxFileReadBytes)
    else
        try gpa.dupe(u8, "");
    defer gpa.free(stage_before);
    // The content-only commit above already wrote a Change — compare log
    // bytes rather than asserting absence.
    const log_before = if (mfs.exists(gpa, log_path))
        try mfs.readFile(gpa, log_path, store.MaxFileReadBytes)
    else
        try gpa.dupe(u8, "");
    defer gpa.free(log_before);

    h.env_sign_key = null;
    const WriteSpy = struct {
        wrote_any: bool = false,
        fn hook(ctx: ?*anyopaque, _: []const u8, _: []const u8) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.wrote_any = true;
        }
    };
    var spy = WriteSpy{};
    h.mem.before_write_ctx = &spy;
    h.mem.before_write = WriteSpy.hook;

    {
        const res = try h.runCmd(&.{ "commit", "-m", "no secret" });
        defer gpa.free(res.out);
        h.mem.before_write = null;
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse secret_not_found\n", res.out);
    }
    try std.testing.expect(!spy.wrote_any);
    const log_after = if (mfs.exists(gpa, log_path))
        try mfs.readFile(gpa, log_path, store.MaxFileReadBytes)
    else
        try gpa.dupe(u8, "");
    defer gpa.free(log_after);
    try std.testing.expectEqualStrings(log_before, log_after);
    const stage_after = if (mfs.exists(gpa, stage_path))
        try mfs.readFile(gpa, stage_path, store.MaxFileReadBytes)
    else
        try gpa.dupe(u8, "");
    defer gpa.free(stage_after);
    try std.testing.expectEqualStrings(stage_before, stage_after);

    // 4. secret_malformed: short key file content, uppercase hex, non-hex; seed never leaks to stdout/stderr.
    try mfs.writeFileSafe(gpa, "/host/FLINT/keys/bad", "deadbeef\n");
    {
        const res = try h.runCmd(&.{ "commit", "--key=bad", "-m", "bad secret file" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse secret_malformed\n", res.out);
        try std.testing.expect(std.mem.indexOf(u8, res.out, "deadbeef") == null);
    }
    try mfs.remove(gpa, "/host/FLINT/keys/bad");

    const upper_seed = "9D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60";
    const g_seed = "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg";
    for ([_][]const u8{ upper_seed, g_seed }) |bad_hex| {
        h.env_sign_key = bad_hex;
        const res = try h.runCmd(&.{ "commit", "-m", "bad secret" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse secret_malformed\n", res.out);
        try std.testing.expect(std.mem.indexOf(u8, res.out, bad_hex[0..8]) == null);
    }
    h.env_sign_key = rfc8032_seed_hex;

    // 5. stale_head: concurrent head move before appendStreamChange.
    const StaleCtx = struct {
        gpa: Allocator,
        fs: fsys.FS,
        root: []const u8,
        stream_id: []const u8,
        created: i64,
        fn hook(ctx: ?*anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            const moved = "0199de2d-dc00-7000-8000-000000000777";
            store.writeStreamRecord(self.gpa, self.fs, self.root, .{
                .id = self.stream_id,
                .name = "main",
                .head = moved,
                .created = self.created,
                .forked_from = null,
            }) catch {};
        }
    };
    var sctx = StaleCtx{
        .gpa = gpa,
        .fs = mfs,
        .root = h.root,
        .stream_id = ws.stream,
        .created = h.now * 1000,
    };
    sign.before_commit_append_ctx = &sctx;
    sign.before_commit_append = StaleCtx.hook;
    {
        const res = try h.runCmd(&.{ "commit", "-m", "concurrent move" });
        defer gpa.free(res.out);
        sign.before_commit_append = null;
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse stale_head\n", res.out);
    }
    {
        const log_now = if (mfs.exists(gpa, log_path))
            try mfs.readFile(gpa, log_path, store.MaxFileReadBytes)
        else
            try gpa.dupe(u8, "");
        defer gpa.free(log_now);
        try std.testing.expectEqualStrings(log_before, log_now);
    }

    // Restore stream record head to null and test stream_torn on streams/<id>.jsonl.
    try store.writeStreamRecord(gpa, mfs, h.root, .{
        .id = ws.stream,
        .name = "main",
        .head = null,
        .created = h.now * 1000,
        .forked_from = null,
    });
    try mfs.writeFileSafe(gpa, log_path, "{\"id\":\"0199de2d-dc00-7000-8000-000000000100\"}");
    {
        const res = try h.runCmd(&.{"log"});
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse stream_torn\n", res.out);
    }

    // 6. Test sole key in `<store>/keys/default` resolution when env_sign_key is null,
    // and ensure seed never appears in any store file outside `<store>/keys/`.
    try mfs.remove(gpa, log_path);
    // The content-only commit in step 1 moved the head; the reset stream now
    // reads empty, so the earlier stage base is stale — `add` restamps it.
    {
        const res = try h.runCmd(&.{ "add", "/host/src" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }
    h.env_sign_key = null;
    {
        const res = try h.runCmd(&.{ "keygen", "--name=default" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }
    {
        const res = try h.runCmd(&.{ "commit", "-m", "signed by sole store key" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expect(std.mem.startsWith(u8, res.out, "flint: commit ok id="));
    }
    const key_raw = try mfs.readFile(gpa, "/host/FLINT/keys/default", store.MaxFileReadBytes);
    defer gpa.free(key_raw);
    const key_seed = std.mem.trimEnd(u8, key_raw, "\n");
    const log_raw = try mfs.readFile(gpa, log_path, store.MaxFileReadBytes);
    defer gpa.free(log_raw);
    try std.testing.expect(std.mem.indexOf(u8, log_raw, key_seed) == null);
}
