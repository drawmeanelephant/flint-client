const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const store = @import("store.zig");
const fsys = @import("fsys.zig");
const sync = @import("sync.zig");
const json = @import("json.zig");

const main = @import("main.zig");
const TestHarness = main.TestHarness;
const rfc8032_seed_hex = main.rfc8032_seed_hex;

/// Wraps `InProcServer.dial` and rewrites `read` replies — truncating them to
/// a signed prefix, or padding the raw change lines past the 4 MiB log bound —
/// so tests can exercise pull/clone behavior against a lying peer.
const MutatingDial = struct {
    server: *sync.InProcServer,
    mode: Mode,

    const Mode = enum { short_prefix, pad_pages };
    const PAD_TO: usize = 900_000;

    fn dial(dial_ctx: ?*anyopaque, allocator: Allocator, io: Io, remote_url: []const u8) anyerror!sync.Transport {
        const self: *MutatingDial = @ptrCast(@alignCast(dial_ctx.?));
        const inner = try sync.InProcServer.dial(self.server, allocator, io, remote_url);
        const t = try allocator.create(Inner);
        t.* = .{ .inner = inner, .mode = self.mode };
        return .{
            .ptr = t,
            .vtable = &.{
                .requestLine = Inner.requestLineImpl,
                .close = Inner.closeImpl,
            },
        };
    }

    const Inner = struct {
        inner: sync.Transport,
        mode: Mode,
        read_calls: usize = 0,

        /// Splits the `changes` array of a `read` reply into its quoted-string
        /// elements (raw escaped bytes preserved). Caller frees `elems`.
        fn readElements(allocator: Allocator, resp: []const u8) !struct { prefix: []const u8, elems: [][]const u8 } {
            const marker = "\"changes\":[";
            const at = std.mem.indexOf(u8, resp, marker) orelse return error.BadReply;
            var elems: std.ArrayList([]const u8) = .empty;
            errdefer elems.deinit(allocator);
            var i = at + marker.len;
            while (i < resp.len and resp[i] != ']') {
                if (resp[i] != '"') return error.BadReply;
                const start = i;
                i += 1;
                while (i < resp.len) {
                    if (resp[i] == '\\') {
                        i += 2;
                    } else if (resp[i] == '"') {
                        i += 1;
                        break;
                    } else i += 1;
                }
                try elems.append(allocator, resp[start..i]);
                if (i < resp.len and resp[i] == ',') i += 1;
            }
            return .{ .prefix = resp[0 .. at + marker.len], .elems = try elems.toOwnedSlice(allocator) };
        }

        fn rewrite(
            resp: []const u8,
            keep: usize,
            more: bool,
            pad_to: usize,
            allocator: Allocator,
        ) ![]u8 {
            const r = try readElements(allocator, resp);
            defer allocator.free(r.elems);
            var out: std.ArrayList(u8) = .empty;
            errdefer out.deinit(allocator);
            try out.appendSlice(allocator, r.prefix);
            for (r.elems[0..@min(keep, r.elems.len)], 0..) |e, i_e| {
                if (i_e > 0) try out.append(allocator, ',');
                if (pad_to == 0 or e.len >= pad_to + 2) {
                    try out.appendSlice(allocator, e);
                } else {
                    // Pad the line *content* with trailing spaces: the JSON
                    // string stays valid and the signature still verifies.
                    try out.append(allocator, '"');
                    try out.appendSlice(allocator, e[1 .. e.len - 1]);
                    try out.appendNTimes(allocator, ' ', pad_to - e.len);
                    try out.append(allocator, '"');
                }
            }
            try out.print(allocator, "],\"more\":{s}}}", .{if (more) "true" else "false"});
            return out.toOwnedSlice(allocator);
        }

        fn requestLineImpl(ptr: *anyopaque, allocator: Allocator, req_line: []const u8) anyerror![]u8 {
            const self: *Inner = @ptrCast(@alignCast(ptr));
            const resp = try self.inner.requestLine(allocator, req_line);
            if (std.mem.indexOf(u8, req_line, "\"op\":\"read\"") == null) return resp;
            defer allocator.free(resp);
            self.read_calls += 1;
            switch (self.mode) {
                // Reply holds only the first fetched change and lies `more:false`.
                .short_prefix => return rewrite(resp, 1, false, 0, allocator),
                // First page: 3 changes at ~900KB each, more:true. Later
                // pages: all remaining changes, ~900KB each — every reply
                // and line stays under its own bound, but the total append
                // exceeds the 4 MiB log bound.
                .pad_pages => {
                    if (self.read_calls == 1) return rewrite(resp, 3, true, PAD_TO, allocator);
                    return rewrite(resp, std.math.maxInt(usize), false, PAD_TO, allocator);
                },
            }
        }

        fn closeImpl(ptr: *anyopaque, allocator: Allocator) void {
            const self: *Inner = @ptrCast(@alignCast(ptr));
            self.inner.close(allocator);
            allocator.destroy(self);
        }
    };
};

test "pull refuses an incomplete signed prefix that does not reach the remote head (#58)" {
    const gpa = std.testing.allocator;

    var srv_mem = try fsys.MemFS.init(gpa);
    defer srv_mem.deinit();
    const srv_fs = srv_mem.fs();
    try srv_fs.mkdir(gpa, "/srv/FLINT/streams");

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

    try fsa.writeFileSafe(gpa, "/host/SRCA/calc.go", "package calc\n\nfunc X() int {\n\treturn 1\n}\n");
    for ([_][]const []const u8{
        &.{ "init", "--name=a", "--src=/host/SRCA" },
        &.{ "add", "/host/SRCA" },
        &.{ "commit", "-m", "c1" },
        &.{ "push", "--remote=tcp://127.0.0.1:4748" },
    }) |cmd| {
        const res = try ha.runCmd(cmd);
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }

    var hb = try TestHarness.init(gpa);
    defer hb.deinit();
    hb.sync_dial = sync.InProcServer.dial;
    hb.sync_dial_ctx = &server;
    const fsb = hb.mem.fs();

    {
        const res = try hb.runCmd(&.{
            "clone",
            "tcp://127.0.0.1:4748",
            "--stream=main",
            "--name=b",
            "--src=/host/SRCB",
        });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }

    // The remote advances by two signed changes.
    for ([_][]const u8{ "2", "3" }) |ret| {
        const src = try std.fmt.allocPrint(gpa, "package calc\n\nfunc X() int {{\n\treturn {s}\n}}\n", .{ret});
        defer gpa.free(src);
        try fsa.writeFileSafe(gpa, "/host/SRCA/calc.go", src);
        ha.now += 5;
        for ([_][]const []const u8{
            &.{ "add", "/host/SRCA" },
            &.{ "commit", "-m", "next" },
            &.{"push"},
        }) |cmd| {
            const res = try ha.runCmd(cmd);
            defer gpa.free(res.out);
            try std.testing.expectEqual(@as(u8, 0), res.rc);
        }
    }

    var idx = try store.loadStoreIndex(gpa, fsb, hb.root);
    defer idx.deinit();
    const log_path = try store.streamLogPath(gpa, hb.root, idx.streamByName("main").?.id);
    defer gpa.free(log_path);
    const log_before = try fsb.readFile(gpa, log_path, store.MaxFileReadBytes);
    defer gpa.free(log_before);

    // The peer returns a signed proper prefix claiming `more:false`; pull must
    // refuse stream_malformed instead of publishing an incomplete head.
    var md = MutatingDial{ .server = &server, .mode = .short_prefix };
    hb.sync_dial = MutatingDial.dial;
    hb.sync_dial_ctx = &md;
    {
        const res = try hb.runCmd(&.{"pull"});
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse stream_malformed head mismatch\n", res.out);
    }

    const log_after = try fsb.readFile(gpa, log_path, store.MaxFileReadBytes);
    defer gpa.free(log_after);
    try std.testing.expectEqualStrings(log_before, log_after);
}

test "pull refuses when the fetched suffix would push the log past 4 MiB (#59)" {
    const gpa = std.testing.allocator;

    var srv_mem = try fsys.MemFS.init(gpa);
    defer srv_mem.deinit();
    const srv_fs = srv_mem.fs();
    try srv_fs.mkdir(gpa, "/srv/FLINT/streams");

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

    try fsa.writeFileSafe(gpa, "/host/SRCA/calc.go", "package calc\n\nfunc X() int {\n\treturn 1\n}\n");
    for ([_][]const []const u8{
        &.{ "init", "--name=a", "--src=/host/SRCA" },
        &.{ "add", "/host/SRCA" },
        &.{ "commit", "-m", "c1" },
        &.{ "push", "--remote=tcp://127.0.0.1:4748" },
    }) |cmd| {
        const res = try ha.runCmd(cmd);
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }

    var hb = try TestHarness.init(gpa);
    defer hb.deinit();
    hb.sync_dial = sync.InProcServer.dial;
    hb.sync_dial_ctx = &server;
    const fsb = hb.mem.fs();

    {
        const res = try hb.runCmd(&.{
            "clone",
            "tcp://127.0.0.1:4748",
            "--stream=main",
            "--name=b",
            "--src=/host/SRCB",
        });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }

    for ([_][]const u8{ "2", "3", "4", "5", "6" }) |ret| {
        const src = try std.fmt.allocPrint(gpa, "package calc\n\nfunc X() int {{\n\treturn {s}\n}}\n", .{ret});
        defer gpa.free(src);
        try fsa.writeFileSafe(gpa, "/host/SRCA/calc.go", src);
        ha.now += 5;
        for ([_][]const []const u8{
            &.{ "add", "/host/SRCA" },
            &.{ "commit", "-m", "next" },
            &.{"push"},
        }) |cmd| {
            const res = try ha.runCmd(cmd);
            defer gpa.free(res.out);
            try std.testing.expectEqual(@as(u8, 0), res.rc);
        }
    }

    var idx = try store.loadStoreIndex(gpa, fsb, hb.root);
    defer idx.deinit();
    const log_path = try store.streamLogPath(gpa, hb.root, idx.streamByName("main").?.id);
    defer gpa.free(log_path);
    const log_before = try fsb.readFile(gpa, log_path, store.MaxFileReadBytes);
    defer gpa.free(log_before);

    // Each reply line and page stays under its own bound, but the padded
    // changes would push the log file past MaxFileReadBytes — refuse before
    // writing so `verify --all` still passes on an unchanged store.
    var md = MutatingDial{ .server = &server, .mode = .pad_pages };
    hb.sync_dial = MutatingDial.dial;
    hb.sync_dial_ctx = &md;
    {
        const res = try hb.runCmd(&.{"pull"});
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse store_too_large file\n", res.out);
    }

    const log_after = try fsb.readFile(gpa, log_path, store.MaxFileReadBytes);
    defer gpa.free(log_after);
    try std.testing.expectEqualStrings(log_before, log_after);
}

test "push --stream publishes a saved fork re-anchored to its incorporating merge (#65)" {
    const gpa = std.testing.allocator;

    var srv_mem = try fsys.MemFS.init(gpa);
    defer srv_mem.deinit();
    const srv_fs = srv_mem.fs();
    try srv_fs.mkdir(gpa, "/srv/FLINT/streams");

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

    const base_src = "package calc\n\nfunc X() int {\n\treturn 1\n}\n\nfunc Y() int {\n\treturn 2\n}\n";
    try fsa.writeFileSafe(gpa, "/host/SRCA/calc.go", base_src);

    // A: init, commit c1 (base), push -> server main = [c1].
    for ([_][]const []const u8{
        &.{ "init", "--name=a", "--src=/host/SRCA" },
        &.{ "add", "/host/SRCA" },
        &.{ "commit", "-m", "c1" },
        &.{ "push", "--remote=tcp://127.0.0.1:4748" },
    }) |cmd| {
        const res = try ha.runCmd(cmd);
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }

    // B: clone main, then commit divergent d1 signed by B's own key.
    var hb = try TestHarness.init(gpa);
    defer hb.deinit();
    hb.sync_dial = sync.InProcServer.dial;
    hb.sync_dial_ctx = &server;
    const fsb = hb.mem.fs();
    try fsb.writeFileSafe(gpa, "/host/SRCB/calc.go", base_src);
    for ([_][]const []const u8{
        &.{ "clone", "tcp://127.0.0.1:4748", "--stream=main", "--name=b", "--src=/host/SRCB" },
        &.{ "keygen", "--name=bkey" },
    }) |cmd| {
        const res = try hb.runCmd(cmd);
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }

    var idx_b = try store.loadStoreIndex(gpa, fsb, hb.root);
    defer idx_b.deinit();
    const main_id = try gpa.dupe(u8, idx_b.streamByName("main").?.id);
    defer gpa.free(main_id);

    // A: modify X, commit c2, push -> server main = [c1, c2].
    try fsa.writeFileSafe(
        gpa,
        "/host/SRCA/calc.go",
        "package calc\n\nfunc X() int {\n\treturn 10\n}\n\nfunc Y() int {\n\treturn 2\n}\n",
    );
    ha.now += 5;
    for ([_][]const []const u8{
        &.{ "add", "/host/SRCA" },
        &.{ "commit", "-m", "c2" },
        &.{"push"},
    }) |cmd| {
        const res = try ha.runCmd(cmd);
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }

    // B: modify Y, commit divergent d1 -> local main = [c1, c2, d1].
    try fsb.writeFileSafe(
        gpa,
        "/host/SRCB/calc.go",
        "package calc\n\nfunc X() int {\n\treturn 1\n}\n\nfunc Y() int {\n\treturn 999\n}\n",
    );
    hb.now += 10;
    for ([_][]const []const u8{
        &.{ "add", "--ws=b", "/host/SRCB" },
        &.{ "commit", "--ws=b", "-m", "d1" },
    }) |cmd| {
        const res = try hb.runCmd(cmd);
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }
    const d1_id = blk: {
        const loaded = try store.loadStream(gpa, fsb, hb.root, main_id);
        defer loaded.deinit(gpa);
        break :blk try gpa.dupe(u8, loaded.stream.head.?);
    };
    defer gpa.free(d1_id);
    const d1_author = blk: {
        const loaded = try store.loadStream(gpa, fsb, hb.root, main_id);
        defer loaded.deinit(gpa);
        break :blk try gpa.dupe(u8, loaded.changes[loaded.changes.len - 1].author);
    };
    defer gpa.free(d1_author);

    // The documented stale-writer recovery: fork -> pull --reset -> merge -> push.
    {
        const res = try hb.runCmd(&.{ "fork", "main", "saved-b" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        const want = try std.fmt.allocPrint(gpa, "flint: fork ok stream=saved-b head={s}\n", .{d1_id});
        defer gpa.free(want);
        try std.testing.expectEqualStrings(want, res.out);
    }
    const saved_id = blk: {
        var idx2 = try store.loadStoreIndex(gpa, fsb, hb.root);
        defer idx2.deinit();
        break :blk try gpa.dupe(u8, idx2.streamByName("saved-b").?.id);
    };
    defer gpa.free(saved_id);
    {
        const res = try hb.runCmd(&.{ "pull", "--ws=b", "--reset" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expect(std.mem.startsWith(u8, res.out, "flint: pull reset stream=main"));
    }
    {
        const res = try hb.runCmd(&.{ "merge", "--ws=b", "saved-b" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expect(std.mem.startsWith(u8, res.out, "flint: merge ok conflicts=0"));
    }
    const merge_id = blk: {
        const loaded = try store.loadStream(gpa, fsb, hb.root, main_id);
        defer loaded.deinit(gpa);
        break :blk try gpa.dupe(u8, loaded.stream.head.?);
    };
    defer gpa.free(merge_id);
    {
        const res = try hb.runCmd(&.{ "push", "--ws=b" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expectEqualStrings("flint: push ok stream=main changes=1\n", res.out);
    }

    // Issue #65: the saved fork's origin (d1) exists only as an unreachable
    // sibling line and can never join a remote log. The push must re-anchor
    // saved-b to the merge Change that incorporated d1 — previously this
    // refused `change_missing`.
    {
        const res = try hb.runCmd(&.{ "push", "--stream=saved-b", "--remote=tcp://127.0.0.1:4748" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expectEqualStrings("flint: push ok stream=saved-b changes=0\n", res.out);
    }

    // The fork record was re-anchored to the merge, locally and remotely.
    {
        const loaded = try store.loadStream(gpa, fsb, hb.root, saved_id);
        defer loaded.deinit(gpa);
        try std.testing.expectEqualStrings(merge_id, loaded.stream.head.?);
        try std.testing.expectEqualStrings(merge_id, loaded.stream.forked_from.?.change);
        try std.testing.expectEqualStrings(main_id, loaded.stream.forked_from.?.stream);
    }
    {
        const s_rec_p = try store.streamRecordPath(gpa, server.store_root, saved_id);
        defer gpa.free(s_rec_p);
        const s_rec_raw = try srv_fs.readFile(gpa, s_rec_p, store.MaxFileReadBytes);
        defer gpa.free(s_rec_raw);
        var s_rec = try json.parseStream(gpa, s_rec_raw);
        defer s_rec.deinit(gpa);
        try std.testing.expectEqualStrings(merge_id, s_rec.head.?);
        try std.testing.expectEqualStrings(merge_id, s_rec.forked_from.?.change);
    }

    // Idempotent: pushing again is a no-op.
    {
        const res = try hb.runCmd(&.{ "push", "--stream=saved-b", "--remote=tcp://127.0.0.1:4748" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expectEqualStrings("flint: push up to date\n", res.out);
    }

    // A fresh client clones saved-b, follows the forked_from chain, and gets
    // the merge Change — signed by B's key — whose `merged` link names the
    // original divergent Change id.
    var hc = try TestHarness.init(gpa);
    defer hc.deinit();
    hc.sync_dial = sync.InProcServer.dial;
    hc.sync_dial_ctx = &server;
    const fsc = hc.mem.fs();
    try fsc.mkdir(gpa, "/host/SRCC");
    {
        const res = try hc.runCmd(&.{
            "clone",
            "tcp://127.0.0.1:4748",
            "--stream=saved-b",
            "--name=c",
            "--src=/host/SRCC",
        });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expect(std.mem.startsWith(u8, res.out, "flint: clone ok stream=saved-b"));
    }
    {
        const res = try hc.runCmd(&.{ "verify", "--all" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }
    {
        const c_log_p = try store.streamLogPath(gpa, hc.root, main_id);
        defer gpa.free(c_log_p);
        const c_log = try fsc.readFile(gpa, c_log_p, store.MaxFileReadBytes);
        defer gpa.free(c_log);
        const c_lines = try store.readJSONLLines(gpa, c_log);
        defer gpa.free(c_lines);
        try std.testing.expectEqual(@as(usize, 3), c_lines.len);
        var mc = try json.parseChange(gpa, c_lines[2]);
        defer mc.deinit(gpa);
        try std.testing.expectEqualStrings(merge_id, mc.id);
        try std.testing.expectEqualStrings(d1_id, mc.merged.?);
        try std.testing.expectEqualStrings(d1_author, mc.author);
    }

    // Pushing the same post-reset history to a *fresh* remote sends only the
    // first-parent chain — the unreachable sibling line (d1) is never sent.
    var srv_mem2 = try fsys.MemFS.init(gpa);
    defer srv_mem2.deinit();
    const srv_fs2 = srv_mem2.fs();
    try srv_fs2.mkdir(gpa, "/srv/FLINT2/streams");
    var server2 = sync.InProcServer{
        .allocator = gpa,
        .fs = srv_fs2,
        .store_root = "/srv/FLINT2",
    };
    hb.sync_dial_ctx = &server2;
    {
        const res = try hb.runCmd(&.{ "push", "--stream=saved-b", "--remote=tcp://127.0.0.1:4749" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expectEqualStrings("flint: push ok stream=saved-b changes=0\n", res.out);
    }
    {
        const s2_log_p = try store.streamLogPath(gpa, server2.store_root, main_id);
        defer gpa.free(s2_log_p);
        const s2_log = try srv_fs2.readFile(gpa, s2_log_p, store.MaxFileReadBytes);
        defer gpa.free(s2_log);
        const s2_lines = try store.readJSONLLines(gpa, s2_log);
        defer gpa.free(s2_lines);
        try std.testing.expectEqual(@as(usize, 3), s2_lines.len);
        for (s2_lines) |line| {
            var c = try json.parseChange(gpa, line);
            defer c.deinit(gpa);
            try std.testing.expect(!std.mem.eql(u8, c.id, d1_id));
        }
    }
}
