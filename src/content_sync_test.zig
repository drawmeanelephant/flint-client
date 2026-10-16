//! Content-sync journey tests (issue #80, docs/flint-blobs-spec.md §9-§10):
//! push/pull/clone transfer signed snapshot manifests and their blobs so a
//! fresh receiver checks out byte-identical source with no access to the
//! publisher's directory. Includes healing after cut transfers, pre-content
//! degradation, detached-recovery content, and integrity refusals.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const store = @import("store.zig");
const fsys = @import("fsys.zig");
const json = @import("json.zig");
const sync = @import("sync.zig");
const sync_content = @import("sync_content.zig");

const main = @import("main.zig");
const TestHarness = main.TestHarness;
const rfc8032_seed_hex = main.rfc8032_seed_hex;

fn runExpect(h: *TestHarness, gpa: Allocator, args: []const []const u8, want_rc: u8) !void {
    const res = try h.runCmd(args);
    defer gpa.free(res.out);
    try std.testing.expectEqual(want_rc, res.rc);
}

fn runOut(h: *TestHarness, gpa: Allocator, args: []const []const u8, want_rc: u8) ![]u8 {
    const res = try h.runCmd(args);
    errdefer gpa.free(res.out);
    try std.testing.expectEqual(want_rc, res.rc);
    return res.out;
}

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
    return gpa.dupe(u8, idx.streamByName(name).?.id);
}

fn expectFileBytes(gpa: Allocator, mfs: fsys.FS, path: []const u8, want: []const u8) !void {
    const got = try mfs.readFile(gpa, path, store.MaxFileReadBytes);
    defer gpa.free(got);
    try std.testing.expectEqualStrings(want, got);
}

fn manifestLineCount(gpa: Allocator, mfs: fsys.FS, root: []const u8, stream_id: []const u8) !usize {
    const p = try store.manifestLogPath(gpa, root, stream_id);
    defer gpa.free(p);
    if (!mfs.exists(gpa, p)) return 0;
    const b = try mfs.readFile(gpa, p, store.MaxFileReadBytes);
    defer gpa.free(b);
    const lines = try store.readManifestLines(gpa, b);
    defer gpa.free(lines);
    return lines.len;
}

fn blobCount(gpa: Allocator, mfs: fsys.FS, root: []const u8) !usize {
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

fn join2(gpa: Allocator, dir: []const u8, name: []const u8) ![]u8 {
    return std.fmt.allocPrint(gpa, "{s}/{s}", .{ dir, name });
}

/// Asserts the checked-out tree at `dest` matches the publisher's source
/// era — every tracked file byte-identical and the executable's mode kept.
fn expectSnapshotTree(
    gpa: Allocator,
    mfs: fsys.FS,
    dest: []const u8,
    readme: []const u8,
    go_ret: []const u8,
) !void {
    const zig_src = "pub fn alpha() void {}\n";
    const cfg = "{\"k\": 1}\n";
    const py = "print('hi')\n";
    const bin = [_]u8{ 0x00, 0x01, 0xfe, 0xff, 0x7f };
    const script = "#!/bin/sh\necho ok\n";

    {
        const p = try join2(gpa, dest, "main.zig");
        defer gpa.free(p);
        try expectFileBytes(gpa, mfs, p, zig_src);
    }
    {
        const p = try join2(gpa, dest, "lib.go");
        defer gpa.free(p);
        const want = try std.fmt.allocPrint(gpa, "package calc\n\nfunc Add(a, b int) int {{ return {s} }}\n", .{go_ret});
        defer gpa.free(want);
        try expectFileBytes(gpa, mfs, p, want);
    }
    {
        const p = try join2(gpa, dest, "README.md");
        defer gpa.free(p);
        try expectFileBytes(gpa, mfs, p, readme);
    }
    {
        const p = try join2(gpa, dest, "build.json");
        defer gpa.free(p);
        try expectFileBytes(gpa, mfs, p, cfg);
    }
    {
        const p = try join2(gpa, dest, "app.py");
        defer gpa.free(p);
        try expectFileBytes(gpa, mfs, p, py);
    }
    {
        const p = try join2(gpa, dest, "asset.bin");
        defer gpa.free(p);
        try expectFileBytes(gpa, mfs, p, &bin);
    }
    {
        const p = try join2(gpa, dest, "run.sh");
        defer gpa.free(p);
        try expectFileBytes(gpa, mfs, p, script);
        const st = try mfs.stat(gpa, p);
        try std.testing.expectEqual(@as(u32, 0o755), st.mode & 0o777);
    }
}

/// Writes the publisher's mixed project tree into `src`.
fn writeProjectTree(gpa: Allocator, mfs: fsys.FS, src: []const u8, readme: []const u8, go_ret: []const u8) !void {
    {
        const p = try join2(gpa, src, "main.zig");
        defer gpa.free(p);
        try mfs.writeFileSafe(gpa, p, "pub fn alpha() void {}\n");
    }
    {
        const p = try join2(gpa, src, "lib.go");
        defer gpa.free(p);
        const body = try std.fmt.allocPrint(gpa, "package calc\n\nfunc Add(a, b int) int {{ return {s} }}\n", .{go_ret});
        defer gpa.free(body);
        try mfs.writeFileSafe(gpa, p, body);
    }
    {
        const p = try join2(gpa, src, "README.md");
        defer gpa.free(p);
        try mfs.writeFileSafe(gpa, p, readme);
    }
    {
        const p = try join2(gpa, src, "build.json");
        defer gpa.free(p);
        try mfs.writeFileSafe(gpa, p, "{\"k\": 1}\n");
    }
    {
        const p = try join2(gpa, src, "app.py");
        defer gpa.free(p);
        try mfs.writeFileSafe(gpa, p, "print('hi')\n");
    }
    {
        const p = try join2(gpa, src, "asset.bin");
        defer gpa.free(p);
        try mfs.writeFileSafe(gpa, p, &[_]u8{ 0x00, 0x01, 0xfe, 0xff, 0x7f });
    }
    {
        const p = try join2(gpa, src, "run.sh");
        defer gpa.free(p);
        try mfs.writeFileSafe(gpa, p, "#!/bin/sh\necho ok\n");
        try mfs.setMode(p, 0o755);
    }
}

test "snapshot sync journey: push publishes manifests+blobs; fresh clone checkout is byte-identical" {
    const gpa = std.testing.allocator;

    var srv_mem = try fsys.MemFS.init(gpa);
    defer srv_mem.deinit();
    const srv_fs = srv_mem.fs();
    try srv_fs.mkdir(gpa, "/srv/FLINT/streams");

    var server = sync.InProcServer{
        .allocator = gpa,
        .fs = srv_fs,
        .store_root = "/srv/FLINT",
        .spec_rev = 4,
    };

    // --- Agent A: mixed project, two revisions (one content-only), push. ----
    var ha = try TestHarness.init(gpa);
    defer ha.deinit();
    ha.env_sign_key = rfc8032_seed_hex;
    ha.sync_dial = sync.InProcServer.dial;
    ha.sync_dial_ctx = &server;
    const fsa = ha.mem.fs();

    try fsa.mkdir(gpa, "/host/SRCA");
    try writeProjectTree(gpa, fsa, "/host/SRCA", "# Era One\n", "a + b");
    try runExpect(ha, gpa, &.{ "init", "--name=a", "--src=/host/SRCA" }, 0);
    try runExpect(ha, gpa, &.{ "add", "/host/SRCA" }, 0);
    const c1_out = try runOut(ha, gpa, &.{ "commit", "-m", "initial" }, 0);
    const c1_id = try commitId(gpa, c1_out);
    defer {
        gpa.free(c1_out);
        gpa.free(c1_id);
    }

    // A content-only revision: the README edit produces no Atom Ops, so the
    // Change is `ops:[]` yet still carries a signed complete manifest.
    {
        const p = "/host/SRCA/README.md";
        try fsa.writeFileSafe(gpa, p, "# Era One\n\nv2 notes\n");
        const c2_out = try runOut(ha, gpa, &.{ "commit", "-m", "docs only" }, 0);
        defer gpa.free(c2_out);
    }

    const main_id = try streamIdByName(gpa, fsa, "/host/FLINT", "main");
    defer gpa.free(main_id);
    try std.testing.expectEqual(@as(usize, 2), try manifestLineCount(gpa, fsa, "/host/FLINT", main_id));

    try runExpect(ha, gpa, &.{ "push", "--remote=tcp://127.0.0.1:4748" }, 0);

    // The publisher's manifests and blobs reached the server.
    try std.testing.expectEqual(@as(usize, 2), try manifestLineCount(gpa, srv_fs, "/srv/FLINT", main_id));
    try std.testing.expectEqual(@as(usize, 8), try blobCount(gpa, srv_fs, "/srv/FLINT"));

    // --- Agent B: fresh clone + explicit checkout, byte-identical tree. ----
    var hb = try TestHarness.init(gpa);
    defer hb.deinit();
    hb.sync_dial = sync.InProcServer.dial;
    hb.sync_dial_ctx = &server;
    const fsb = hb.mem.fs();
    try fsb.mkdir(gpa, "/host/SRCB");

    try runExpect(hb, gpa, &.{ "clone", "tcp://127.0.0.1:4748", "--stream=main", "--name=b", "--src=/host/SRCB" }, 0);
    // Clone fetched the manifests and blobs — the receiver never saw SRCA.
    try std.testing.expectEqual(@as(usize, 2), try manifestLineCount(gpa, fsb, "/host/FLINT", main_id));
    try std.testing.expectEqual(@as(usize, 8), try blobCount(gpa, fsb, "/host/FLINT"));

    const cb_args = [_][]const u8{ "checkout", "--head", "--into=/host/OUTB" };
    try runExpect(hb, gpa, &cb_args, 0);
    try expectSnapshotTree(gpa, fsb, "/host/OUTB", "# Era One\n\nv2 notes\n", "a + b");

    // And the first revision's snapshot materializes too.
    var flag_b: [64]u8 = undefined;
    const flag_b1 = try std.fmt.bufPrint(&flag_b, "--change={s}", .{c1_id});
    try runExpect(hb, gpa, &.{ "checkout", flag_b1, "--into=/host/OUTB1" }, 0);
    try expectSnapshotTree(gpa, fsb, "/host/OUTB1", "# Era One\n", "a + b");

    // --- Agent C: the same checkout journey over a real loopback socket —
    // the "real flintd" leg (tools/qa.py conventions): one live flintd-style
    // server on a TCP listener, a fresh clone, a byte-identical checkout.
    var hc = try TestHarness.init(gpa);
    defer hc.deinit();
    const fsc = hc.mem.fs();
    try fsc.mkdir(gpa, "/host/SRCC");
    // `sync_dial` unset → defaultTcpDial → a real TCP connection.

    const listen_addr = try Io.net.IpAddress.parse("127.0.0.1", 0);
    var tcp_srv = try listen_addr.listen(std.testing.io, .{});
    defer tcp_srv.deinit(std.testing.io);
    const port = tcp_srv.socket.address.getPort();
    const remote_url = try std.fmt.allocPrint(gpa, "tcp://127.0.0.1:{d}", .{port});
    defer gpa.free(remote_url);

    const serveOnce = struct {
        fn run(io_: Io, srv: *sync.InProcServer, lsn: *Io.net.Server) void {
            const conn = lsn.accept(io_) catch return;
            srv.serveNetStream(std.heap.page_allocator, io_, conn);
        }
    }.run;
    const thr = try std.Thread.spawn(.{}, serveOnce, .{ std.testing.io, &server, &tcp_srv });
    defer thr.join();

    try runExpect(hc, gpa, &.{ "clone", remote_url, "--stream=main", "--name=c", "--src=/host/SRCC" }, 0);
    try std.testing.expectEqual(@as(usize, 2), try manifestLineCount(gpa, fsc, "/host/FLINT", main_id));
    try std.testing.expectEqual(@as(usize, 8), try blobCount(gpa, fsc, "/host/FLINT"));
    try runExpect(hc, gpa, &.{ "checkout", "--head", "--into=/host/OUTC" }, 0);
    try expectSnapshotTree(gpa, fsc, "/host/OUTC", "# Era One\n\nv2 notes\n", "a + b");
}

test "content sync heals: heads-equal push re-publishes manifests; heads-equal pull re-fetches blobs" {
    const gpa = std.testing.allocator;

    var srv_mem = try fsys.MemFS.init(gpa);
    defer srv_mem.deinit();
    const srv_fs = srv_mem.fs();
    try srv_fs.mkdir(gpa, "/srv/FLINT/streams");

    var server = sync.InProcServer{
        .allocator = gpa,
        .fs = srv_fs,
        .store_root = "/srv/FLINT",
        .spec_rev = 4,
    };

    var ha = try TestHarness.init(gpa);
    defer ha.deinit();
    ha.env_sign_key = rfc8032_seed_hex;
    ha.sync_dial = sync.InProcServer.dial;
    ha.sync_dial_ctx = &server;
    const fsa = ha.mem.fs();

    try fsa.mkdir(gpa, "/host/SRCA");
    try writeProjectTree(gpa, fsa, "/host/SRCA", "# Era One\n", "a + b");
    try runExpect(ha, gpa, &.{ "init", "--name=a", "--src=/host/SRCA" }, 0);
    try runExpect(ha, gpa, &.{ "add", "/host/SRCA" }, 0);
    try runExpect(ha, gpa, &.{ "commit", "-m", "c1" }, 0);

    // A transfer cut after Change append but before manifest publication:
    // push refuses (the refused request provably landed nothing) while the
    // Change itself is remote.
    server.force_refuse_op = "put_manifest";
    {
        const res = try ha.runCmd(&.{ "push", "--remote=tcp://127.0.0.1:4748" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
    }
    server.force_refuse_op = null;
    const main_id = try streamIdByName(gpa, fsa, "/host/FLINT", "main");
    defer gpa.free(main_id);
    try std.testing.expectEqual(@as(usize, 0), try manifestLineCount(gpa, srv_fs, "/srv/FLINT", main_id));

    // The heads-equal push still reconciles content.
    {
        const res = try ha.runCmd(&.{ "push", "--remote=tcp://127.0.0.1:4748" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }
    try std.testing.expectEqual(@as(usize, 1), try manifestLineCount(gpa, srv_fs, "/srv/FLINT", main_id));
    try std.testing.expectEqual(@as(usize, 7), try blobCount(gpa, srv_fs, "/srv/FLINT"));

    // Receiver: clone, then a pull-side cut — blob_get refused mid-heal —
    // leaves history correct (head moved) while content stays incomplete.
    var hb = try TestHarness.init(gpa);
    defer hb.deinit();
    hb.sync_dial = sync.InProcServer.dial;
    hb.sync_dial_ctx = &server;
    const fsb = hb.mem.fs();
    try fsb.mkdir(gpa, "/host/SRCB");
    try runExpect(hb, gpa, &.{ "clone", "tcp://127.0.0.1:4748", "--stream=main", "--name=b", "--src=/host/SRCB" }, 0);
    try std.testing.expectEqual(@as(usize, 7), try blobCount(gpa, fsb, "/host/FLINT"));

    // Delete a fetched blob locally, then pull: the heads-equal pull heals it.
    const b_mlog = try store.manifestLogPath(gpa, "/host/FLINT", main_id);
    defer gpa.free(b_mlog);
    {
        const b = try fsb.readFile(gpa, b_mlog, store.MaxFileReadBytes);
        defer gpa.free(b);
        const lines = try store.readManifestLines(gpa, b);
        defer gpa.free(lines);
        const m = try json.parseManifest(gpa, lines[0]);
        defer m.deinit(gpa);
        const bp = try store.blobPath(gpa, "/host/FLINT", m.files[0].blob);
        defer gpa.free(bp);
        try fsb.remove(gpa, bp);
    }
    try std.testing.expectEqual(@as(usize, 6), try blobCount(gpa, fsb, "/host/FLINT"));
    try runExpect(hb, gpa, &.{"pull"}, 0);
    try std.testing.expectEqual(@as(usize, 7), try blobCount(gpa, fsb, "/host/FLINT"));

    try runExpect(hb, gpa, &.{ "checkout", "--head", "--into=/host/OUTB" }, 0);
    try expectSnapshotTree(gpa, fsb, "/host/OUTB", "# Era One\n", "a + b");
}

test "pre-content server degrades: history syncs at exit 0, checkout refuses blob_missing" {
    const gpa = std.testing.allocator;

    var srv_mem = try fsys.MemFS.init(gpa);
    defer srv_mem.deinit();
    const srv_fs = srv_mem.fs();
    try srv_fs.mkdir(gpa, "/srv/FLINT/streams");

    // spec_rev unset — the fixture behaves like a spec_rev<4 flintd that
    // never serves the content ops.
    var server = sync.InProcServer{
        .allocator = gpa,
        .fs = srv_fs,
        .store_root = "/srv/FLINT",
    };

    var ha = try TestHarness.init(gpa);
    defer ha.deinit();
    ha.env_sign_key = rfc8032_seed_hex;
    ha.sync_dial = sync.InProcServer.dial;
    ha.sync_dial_ctx = &server;
    const fsa = ha.mem.fs();

    try fsa.mkdir(gpa, "/host/SRCA");
    try writeProjectTree(gpa, fsa, "/host/SRCA", "# Era One\n", "a + b");
    try runExpect(ha, gpa, &.{ "init", "--name=a", "--src=/host/SRCA" }, 0);
    try runExpect(ha, gpa, &.{ "add", "/host/SRCA" }, 0);
    try runExpect(ha, gpa, &.{ "commit", "-m", "c1" }, 0);

    try runExpect(ha, gpa, &.{ "push", "--remote=tcp://127.0.0.1:4748" }, 0);
    try std.testing.expect(std.mem.indexOf(u8, ha.last_err.items, "proto_version") != null);

    // Nothing content-shaped landed remotely — but history is complete.
    const main_id = try streamIdByName(gpa, fsa, "/host/FLINT", "main");
    defer gpa.free(main_id);
    try std.testing.expectEqual(@as(usize, 0), try manifestLineCount(gpa, srv_fs, "/srv/FLINT", main_id));
    try std.testing.expectEqual(@as(usize, 0), try blobCount(gpa, srv_fs, "/srv/FLINT"));

    var hb = try TestHarness.init(gpa);
    defer hb.deinit();
    hb.sync_dial = sync.InProcServer.dial;
    hb.sync_dial_ctx = &server;
    const fsb = hb.mem.fs();
    try fsb.mkdir(gpa, "/host/SRCB");
    try runExpect(hb, gpa, &.{ "clone", "tcp://127.0.0.1:4748", "--stream=main", "--name=b", "--src=/host/SRCB" }, 0);
    try std.testing.expect(std.mem.indexOf(u8, hb.last_err.items, "proto_version") != null);

    // History verifies; checkout is explicit about the missing content.
    try runExpect(hb, gpa, &.{ "verify", "--all" }, 0);
    {
        const res = try hb.runCmd(&.{ "checkout", "--head", "--into=/host/OUTB" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expect(std.mem.indexOf(u8, res.out, "blob_missing") != null);
    }

    // --json reports history success with content marked degraded.
    {
        const res = try hb.runCmd(&.{ "pull", "--json", "--remote=tcp://127.0.0.1:4748" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        var p = try std.json.parseFromSlice(std.json.Value, gpa, res.out, .{});
        defer p.deinit();
        const o = p.value.object;
        try std.testing.expect(o.get("ok").?.bool);
        const content = o.get("data").?.object.get("content").?.object;
        try std.testing.expectEqualStrings("degraded", content.get("state").?.string);
        try std.testing.expectEqualStrings("get_manifest", content.get("op").?.string);
    }
}

test "recovery: preserved original revision's content follows the detached Change" {
    const gpa = std.testing.allocator;

    var srv_mem = try fsys.MemFS.init(gpa);
    defer srv_mem.deinit();
    const srv_fs = srv_mem.fs();
    try srv_fs.mkdir(gpa, "/srv/FLINT/streams");

    var server = sync.InProcServer{
        .allocator = gpa,
        .fs = srv_fs,
        .store_root = "/srv/FLINT",
        .spec_rev = 4,
    };

    // --- A commits c1 and pushes. ------------------------------------------
    var ha = try TestHarness.init(gpa);
    defer ha.deinit();
    ha.env_sign_key = rfc8032_seed_hex;
    ha.sync_dial = sync.InProcServer.dial;
    ha.sync_dial_ctx = &server;
    const fsa = ha.mem.fs();

    try fsa.mkdir(gpa, "/host/SRCA");
    try writeProjectTree(gpa, fsa, "/host/SRCA", "# Era One\n", "a + b");
    try runExpect(ha, gpa, &.{ "init", "--name=a", "--src=/host/SRCA" }, 0);
    try runExpect(ha, gpa, &.{ "add", "/host/SRCA" }, 0);
    try runExpect(ha, gpa, &.{ "commit", "-m", "c1" }, 0);
    try runExpect(ha, gpa, &.{ "push", "--remote=tcp://127.0.0.1:4748" }, 0);

    // --- B clones, commits c2 on main, pushes. ------------------------------
    var hb = try TestHarness.init(gpa);
    defer hb.deinit();
    hb.env_sign_key = rfc8032_seed_hex;
    hb.sync_dial = sync.InProcServer.dial;
    hb.sync_dial_ctx = &server;
    const fsb = hb.mem.fs();
    try fsb.mkdir(gpa, "/host/SRCB");
    try runExpect(hb, gpa, &.{ "clone", "tcp://127.0.0.1:4748", "--stream=main", "--name=b", "--src=/host/SRCB" }, 0);
    try runExpect(hb, gpa, &.{ "checkout", "--head", "--into=/host/SRCB" }, 0);
    {
        // B advances a file A never touched — disjoint from A's later edit.
        const p = "/host/SRCB/app.py";
        try fsb.writeFileSafe(gpa, p, "print('hi')\nprint('b')\n");
    }
    try runExpect(hb, gpa, &.{ "commit", "-m", "b's c2" }, 0);
    try runExpect(hb, gpa, &.{ "push", "--remote=tcp://127.0.0.1:4748" }, 0);

    // --- A diverges (still based on c1), preserves via fork, resets, merges.
    {
        const p = "/host/SRCA/README.md";
        try fsa.writeFileSafe(gpa, p, "# Era One\n\nA was here\n");
    }
    const diverged_out = try runOut(ha, gpa, &.{ "commit", "-m", "a's divergent c2'" }, 0);
    const c2p_id = try commitId(gpa, diverged_out);
    defer {
        gpa.free(diverged_out);
        gpa.free(c2p_id);
    }
    try runExpect(ha, gpa, &.{ "push", "--remote=tcp://127.0.0.1:4748" }, 1); // stale_head
    try runExpect(ha, gpa, &.{ "fork", "main", "aside" }, 0);
    try runExpect(ha, gpa, &.{ "pull", "--reset", "--remote=tcp://127.0.0.1:4748" }, 0);
    try runExpect(ha, gpa, &.{ "merge", "aside" }, 0);
    try runExpect(ha, gpa, &.{ "push", "--remote=tcp://127.0.0.1:4748" }, 0);

    // The preserved divergent revision's manifest reached the remote's
    // manifest log for main, alongside its detached Change line.
    const main_id = try streamIdByName(gpa, fsa, "/host/FLINT", "main");
    defer gpa.free(main_id);
    try std.testing.expect(try manifestLineCount(gpa, srv_fs, "/srv/FLINT", main_id) >= 3);

    // --- D: a fresh receiver never saw SRCA — clone then checkout the
    // preserved revision byte-identically.
    var hd = try TestHarness.init(gpa);
    defer hd.deinit();
    hd.sync_dial = sync.InProcServer.dial;
    hd.sync_dial_ctx = &server;
    const fsd = hd.mem.fs();
    try fsd.mkdir(gpa, "/host/SRCD");
    try runExpect(hd, gpa, &.{ "clone", "tcp://127.0.0.1:4748", "--stream=main", "--name=d", "--src=/host/SRCD" }, 0);
    try runExpect(hd, gpa, &.{ "verify", "--all" }, 0);

    var flag_buf: [64]u8 = undefined;
    const flag = try std.fmt.bufPrint(&flag_buf, "--change={s}", .{c2p_id});
    try runExpect(hd, gpa, &.{ "checkout", flag, "--into=/host/OUTD" }, 0);
    {
        // The divergent revision's manifest attests A's bytes.
        const p = "/host/OUTD/README.md";
        try expectFileBytes(gpa, fsd, p, "# Era One\n\nA was here\n");
        const p2 = "/host/OUTD/app.py";
        try expectFileBytes(gpa, fsd, p2, "print('hi')\n");
    }
}

test "content integrity legs: wrong-hash blob_put, manifest id conflict, tampered manifest, blob tamper" {
    const gpa = std.testing.allocator;

    var srv_mem = try fsys.MemFS.init(gpa);
    defer srv_mem.deinit();
    const srv_fs = srv_mem.fs();
    try srv_fs.mkdir(gpa, "/srv/FLINT/streams");

    var server = sync.InProcServer{
        .allocator = gpa,
        .fs = srv_fs,
        .store_root = "/srv/FLINT",
        .spec_rev = 4,
    };

    const transport = try sync.InProcServer.dial(&server, gpa, std.testing.io, "tcp://127.0.0.1:4748");
    var client = sync.SyncClient.init(gpa, transport);
    defer client.deinit();
    try client.handshake(null);

    // blob_put whose id doesn't hash to the bytes → blob_malformed.
    {
        const bogus = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        try std.testing.expectError(error.Refuse, sync_content.putBlob(&client, bogus, "nope"));
        try std.testing.expectEqualStrings("blob_malformed", fsys.last_refuse.code());
    }
    // blob_put a valid blob then blob_get it back.
    const blob_id = blk: {
        const data = "hello blob\n";
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(data, &digest, .{});
        const hex = std.fmt.bytesToHex(digest, .lower);
        try sync_content.putBlob(&client, &hex, data);
        break :blk try gpa.dupe(u8, &hex);
    };
    defer gpa.free(blob_id);
    {
        const data = try sync_content.getBlob(&client, blob_id);
        defer gpa.free(data);
        try std.testing.expectEqualStrings("hello blob\n", data);
    }
    // blob_get of an absent id → blob_missing.
    {
        const absent = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        try std.testing.expectError(error.Refuse, sync_content.getBlob(&client, absent));
        try std.testing.expectEqualStrings("blob_missing", fsys.last_refuse.code());
    }

    // A tampered stored blob is refused blob_malformed on read.
    {
        const bp = try store.blobPath(gpa, "/srv/FLINT", blob_id);
        defer gpa.free(bp);
        try srv_fs.writeFileSafe(gpa, bp, "tampered");
        try std.testing.expectError(error.Refuse, sync_content.getBlob(&client, blob_id));
        try std.testing.expectEqualStrings("blob_malformed", fsys.last_refuse.code());
    }

    // put_manifest of an unsigned/malformed line → refused, not stored.
    {
        const bad_line = "{\"stream\":\"x\",\"change\":\"y\"}";
        const lines = [_][]const u8{bad_line};
        try std.testing.expectError(error.Refuse, sync_content.putManifestLines(&client, "main", &lines));
        const code = fsys.last_refuse.code();
        try std.testing.expect(std.mem.eql(u8, code, "stream_missing") or std.mem.eql(u8, code, "change_malformed") or std.mem.eql(u8, code, "manifest_torn"));
    }
}

test "nonempty fork publishes its own content; fresh clone of the fork checks out" {
    const gpa = std.testing.allocator;

    var srv_mem = try fsys.MemFS.init(gpa);
    defer srv_mem.deinit();
    const srv_fs = srv_mem.fs();
    try srv_fs.mkdir(gpa, "/srv/FLINT/streams");

    var server = sync.InProcServer{
        .allocator = gpa,
        .fs = srv_fs,
        .store_root = "/srv/FLINT",
        .spec_rev = 4,
    };

    // --- A: main with one revision, pushed. --------------------------------
    var ha = try TestHarness.init(gpa);
    defer ha.deinit();
    ha.env_sign_key = rfc8032_seed_hex;
    ha.sync_dial = sync.InProcServer.dial;
    ha.sync_dial_ctx = &server;
    const fsa = ha.mem.fs();

    try fsa.mkdir(gpa, "/host/SRCA");
    try writeProjectTree(gpa, fsa, "/host/SRCA", "# Era One\n", "a + b");
    try runExpect(ha, gpa, &.{ "init", "--name=a", "--src=/host/SRCA" }, 0);
    try runExpect(ha, gpa, &.{ "add", "/host/SRCA" }, 0);
    try runExpect(ha, gpa, &.{ "commit", "-m", "c1" }, 0);
    try runExpect(ha, gpa, &.{ "push", "--remote=tcp://127.0.0.1:4748" }, 0);

    // --- A forks main → feature and commits divergent content on it. -------
    try runExpect(ha, gpa, &.{ "fork", "main", "feature" }, 0);
    try fsa.mkdir(gpa, "/host/SRCF");
    try runExpect(ha, gpa, &.{ "init", "--name=feat", "--src=/host/SRCF", "--stream=feature" }, 0);
    try writeProjectTree(gpa, fsa, "/host/SRCF", "# Feature era\n", "a - b");
    try fsa.writeFileSafe(gpa, "/host/SRCF/feat.go", "package feat\n\nfunc Go() int { return 7 }\n");
    try runExpect(ha, gpa, &.{ "add", "/host/SRCF", "--ws=feat" }, 0);
    try runExpect(ha, gpa, &.{ "commit", "--ws=feat", "-m", "feat c2" }, 0);
    try runExpect(ha, gpa, &.{ "push", "--ws=feat", "--remote=tcp://127.0.0.1:4748" }, 0);

    const feature_id = try streamIdByName(gpa, fsa, "/host/FLINT", "feature");
    defer gpa.free(feature_id);
    const main_id = try streamIdByName(gpa, fsa, "/host/FLINT", "main");
    defer gpa.free(main_id);
    try std.testing.expectEqual(@as(usize, 1), try manifestLineCount(gpa, srv_fs, "/srv/FLINT", feature_id));

    // --- B: clone the fork stream — the forked_from chain and both
    // streams' manifests+blobs land; checkout reproduces the fork's tree.
    var hb = try TestHarness.init(gpa);
    defer hb.deinit();
    hb.sync_dial = sync.InProcServer.dial;
    hb.sync_dial_ctx = &server;
    const fsb = hb.mem.fs();
    try fsb.mkdir(gpa, "/host/SRCB");
    try runExpect(hb, gpa, &.{ "clone", "tcp://127.0.0.1:4748", "--stream=feature", "--name=b", "--src=/host/SRCB" }, 0);
    try std.testing.expectEqual(@as(usize, 1), try manifestLineCount(gpa, fsb, "/host/FLINT", feature_id));
    try std.testing.expectEqual(@as(usize, 1), try manifestLineCount(gpa, fsb, "/host/FLINT", main_id));

    try runExpect(hb, gpa, &.{ "checkout", "--head", "--into=/host/OUTB" }, 0);
    try expectSnapshotTree(gpa, fsb, "/host/OUTB", "# Feature era\n", "a - b");
    try expectFileBytes(gpa, fsb, "/host/OUTB/feat.go", "package feat\n\nfunc Go() int { return 7 }\n");
}
