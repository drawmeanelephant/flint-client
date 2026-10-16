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

test "maximum-atom commit pushes and clones: >1 MiB change under the 4 MiB line bound (#60)" {
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

    // 4096 consts sits at the documented 4096-Atom bound; the signed Change
    // lands above the old 1 MiB receive clamp but under the 4 MiB line bound.
    var src: std.ArrayList(u8) = .empty;
    defer src.deinit(gpa);
    try src.appendSlice(gpa, "pub const alpha: u32 = 1;\npub const beta: u32 = 10;\n");
    for (0..4094) |i| {
        try src.print(gpa, "pub const item_{d:0>4}: u32 = {d};\n", .{ i, i });
    }
    try fsa.writeFileSafe(gpa, "/host/SRCA/main.zig", src.items);

    for ([_][]const []const u8{
        &.{ "init", "--name=a", "--src=/host/SRCA" },
        &.{ "add", "/host/SRCA" },
        &.{ "commit", "-m", "maximum-atoms" },
        &.{ "push", "--remote=tcp://127.0.0.1:4748" },
    }) |cmd| {
        const res = try ha.runCmd(cmd);
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }

    // Guard the premise: the pushed Change really exceeds the old 1 MiB clamp.
    var idx_a = try store.loadStoreIndex(gpa, fsa, ha.root);
    defer idx_a.deinit();
    const main_id = idx_a.streamByName("main").?.id;
    const log_p = try store.streamLogPath(gpa, ha.root, main_id);
    defer gpa.free(log_p);
    const log_bytes = try fsa.readFile(gpa, log_p, store.MaxFileReadBytes);
    defer gpa.free(log_bytes);
    try std.testing.expect(std.mem.endsWith(u8, log_bytes, "\n"));
    try std.testing.expect(log_bytes.len - 1 > 1024 * 1024);
    try std.testing.expect(log_bytes.len <= sync.MaxChangeBytes);

    var hb = try TestHarness.init(gpa);
    defer hb.deinit();
    hb.env_sign_key = rfc8032_seed_hex;
    hb.sync_dial = sync.InProcServer.dial;
    hb.sync_dial_ctx = &server;

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
        try std.testing.expectEqualStrings("flint: clone ok stream=main changes=1\n", res.out);
    }
    {
        const vres = try hb.runCmd(&.{ "verify", "--all" });
        defer gpa.free(vres.out);
        try std.testing.expectEqual(@as(u8, 0), vres.rc);
        try std.testing.expect(std.mem.indexOf(u8, vres.out, "sig: verified\n") != null);
    }
}
test "clean merge after pull --reset rebuilds the workspace Atom table from history (#64)" {
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

    const base_src = "pub const alpha: u32 = 1;\npub const beta: u32 = 10;\n";
    try fsa.writeFileSafe(gpa, "/host/SRCA/main.zig", base_src);
    for ([_][]const []const u8{
        &.{ "init", "--name=a", "--src=/host/SRCA" },
        &.{ "add", "/host/SRCA" },
        &.{ "commit", "-m", "base" },
        &.{ "push", "--remote=tcp://127.0.0.1:4748" },
    }) |cmd| {
        const res = try ha.runCmd(cmd);
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }

    var hb = try TestHarness.init(gpa);
    defer hb.deinit();
    hb.env_sign_key = rfc8032_seed_hex;
    hb.rng_seed = 77;
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

    // A commits alpha=2 and pushes; B commits beta=20 locally — divergent.
    try fsa.writeFileSafe(gpa, "/host/SRCA/main.zig", "pub const alpha: u32 = 2;\npub const beta: u32 = 10;\n");
    ha.now += 5;
    for ([_][]const []const u8{
        &.{ "add", "/host/SRCA" },
        &.{ "commit", "-m", "alpha=2" },
        &.{"push"},
    }) |cmd| {
        const res = try ha.runCmd(cmd);
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }

    try fsb.writeFileSafe(gpa, "/host/SRCB/main.zig", "pub const alpha: u32 = 1;\npub const beta: u32 = 20;\n");
    hb.now += 3;
    for ([_][]const []const u8{
        &.{ "add", "/host/SRCB" },
        &.{ "commit", "-m", "beta=20" },
    }) |cmd| {
        const res = try hb.runCmd(cmd);
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }

    // Documented recovery: fork aside, reset main to remote, merge the fork
    // back, push. The merge is clean (disjoint atoms).
    for ([_][]const []const u8{
        &.{ "fork", "main", "saved-b" },
        &.{ "pull", "--reset", "--remote=tcp://127.0.0.1:4748" },
        &.{ "merge", "saved-b" },
        &.{"push"},
    }) |cmd| {
        const res = try hb.runCmd(cmd);
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }

    // The workspace Atom table must match the merged head's replayed state,
    // not the pre-reset divergent head — both edits present.
    var idx = try store.loadStoreIndex(gpa, fsb, hb.root);
    defer idx.deinit();
    // `loadAllStreamChanges` reloads and frees the index's Stream records —
    // copy the head before calling it.
    const merged_head = try gpa.dupe(u8, idx.streamByName("main").?.head.?);
    defer gpa.free(merged_head);

    const ws_atoms = try store.loadWorkspaceAtoms(gpa, fsb, hb.root, "b");
    defer store.freeStoredAtoms(gpa, ws_atoms);
    const all_changes = try store.loadAllStreamChanges(gpa, fsb, hb.root, &idx);
    defer store.freeChanges(gpa, all_changes);
    const replayed = try store.replayStreamAtoms(gpa, merged_head, all_changes);
    defer store.freeStoredAtoms(gpa, replayed.atoms);

    const S = struct {
        fn map(allocator: Allocator, atoms: []const store.StoredAtom) !std.StringHashMap([]const u8) {
            var m = std.StringHashMap([]const u8).init(allocator);
            for (atoms) |a| try m.put(a.name, a.hash);
            return m;
        }
    };
    var ws_map = try S.map(gpa, ws_atoms);
    defer ws_map.deinit();
    var rp_map = try S.map(gpa, replayed.atoms);
    defer rp_map.deinit();

    try std.testing.expectEqual(rp_map.count(), ws_map.count());
    var it = rp_map.iterator();
    while (it.next()) |kv| {
        const wv = ws_map.get(kv.key_ptr.*) orelse {
            std.debug.print("missing atom in ws table: {s}\n", .{kv.key_ptr.*});
            return error.TestUnexpectedResult;
        };
        try std.testing.expectEqualStrings(kv.value_ptr.*, wv);
    }
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
    // A server that predates `deposit` refuses the op with `usage`; push then
    // falls back to the spec_rev 2 re-anchor covered by this test (#73).
    server.force_refuse_op = "deposit";
    server.force_refuse_code = "usage";

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
    server2.force_refuse_op = "deposit";
    server2.force_refuse_code = "usage";
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

test "push deposits the original saved-fork origin so a fresh clone verifies it (#73)" {
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

    // A: init, commit c1, push -> server main = [c1].
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

    // B: clone main, commit divergent d1 signed by B's own key.
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

    // B: modify Y, commit divergent d1.
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

    // The documented recovery: fork -> pull --reset -> merge -> push.
    for ([_][]const []const u8{
        &.{ "fork", "main", "saved-b" },
        &.{ "pull", "--ws=b", "--reset" },
        &.{ "merge", "--ws=b", "saved-b" },
        &.{ "push", "--ws=b" },
    }) |cmd| {
        const res = try hb.runCmd(cmd);
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }

    const saved_id = blk: {
        var idx2 = try store.loadStoreIndex(gpa, fsb, hb.root);
        defer idx2.deinit();
        break :blk try gpa.dupe(u8, idx2.streamByName("saved-b").?.id);
    };
    defer gpa.free(saved_id);

    // The merge's `merged` link named d1, so push deposited d1's original
    // signed bytes onto main's remote log as a detached tail line.
    {
        const s_log_p = try store.streamLogPath(gpa, server.store_root, main_id);
        defer gpa.free(s_log_p);
        const s_log = try srv_fs.readFile(gpa, s_log_p, store.MaxFileReadBytes);
        defer gpa.free(s_log);
        const s_lines = try store.readJSONLLines(gpa, s_log);
        defer gpa.free(s_lines);
        try std.testing.expectEqual(@as(usize, 4), s_lines.len);
        var dc = try json.parseChange(gpa, s_lines[3]);
        defer dc.deinit(gpa);
        try std.testing.expectEqualStrings(d1_id, dc.id);

        // Byte-identical to the local original — nothing was re-signed.
        const b_log_p = try store.streamLogPath(gpa, hb.root, main_id);
        defer gpa.free(b_log_p);
        const b_log = try fsb.readFile(gpa, b_log_p, store.MaxFileReadBytes);
        defer gpa.free(b_log);
        const b_lines = try store.readJSONLLines(gpa, b_log);
        defer gpa.free(b_lines);
        try std.testing.expectEqual(@as(usize, 4), b_lines.len);
        try std.testing.expectEqualStrings(b_lines[1], s_lines[3]);
    }

    // Issue #73: on a deposit-capable server the saved fork keeps its
    // ORIGINAL forked_from — the origin Change is now present remotely, so
    // `create` succeeds without any re-anchor.
    {
        const res = try hb.runCmd(&.{ "push", "--stream=saved-b", "--remote=tcp://127.0.0.1:4748" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expectEqualStrings("flint: push ok stream=saved-b changes=0\n", res.out);
    }
    {
        const loaded = try store.loadStream(gpa, fsb, hb.root, saved_id);
        defer loaded.deinit(gpa);
        try std.testing.expectEqualStrings(d1_id, loaded.stream.head.?);
        try std.testing.expectEqualStrings(d1_id, loaded.stream.forked_from.?.change);
        try std.testing.expectEqualStrings(main_id, loaded.stream.forked_from.?.stream);
    }
    {
        const s_rec_p = try store.streamRecordPath(gpa, server.store_root, saved_id);
        defer gpa.free(s_rec_p);
        const s_rec_raw = try srv_fs.readFile(gpa, s_rec_p, store.MaxFileReadBytes);
        defer gpa.free(s_rec_raw);
        var s_rec = try json.parseStream(gpa, s_rec_raw);
        defer s_rec.deinit(gpa);
        try std.testing.expectEqualStrings(d1_id, s_rec.head.?);
        try std.testing.expectEqualStrings(d1_id, s_rec.forked_from.?.change);
    }

    // A fresh agent clones saved-b and can fetch + verify the ORIGINAL
    // signed Change — the exact capability #73 requires.
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
        const res = try hc.runCmd(&.{ "verify", d1_id });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        const want = try std.fmt.allocPrint(gpa, "flint: verify {s} sig: verified\n", .{d1_id});
        defer gpa.free(want);
        try std.testing.expectEqualStrings(want, res.out);
    }
}

test "push publishes a nonempty saved fork with original forked_from (#73)" {
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

    // B: clone main — sees the server's current [c1] chain.
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

    // A advances main again -> server main = [c1, c2, c3].
    try fsa.writeFileSafe(
        gpa,
        "/host/SRCA/calc.go",
        "package calc\n\nfunc X() int {\n\treturn 20\n}\n\nfunc Y() int {\n\treturn 2\n}\n",
    );
    ha.now += 5;
    for ([_][]const []const u8{
        &.{ "add", "/host/SRCA" },
        &.{ "commit", "-m", "c3" },
        &.{"push"},
    }) |cmd| {
        const res = try ha.runCmd(cmd);
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }

    // B: divergent commit d1, fork it aside, then commit s2 ON saved-b so
    // the fork carries its own Changes — the case that cannot re-anchor.
    try fsb.writeFileSafe(
        gpa,
        "/host/SRCB/calc.go",
        "package calc\n\nfunc X() int {\n\treturn 1\n}\n\nfunc Y() int {\n\treturn 999\n}\n",
    );
    hb.now += 10;
    for ([_][]const []const u8{
        &.{ "add", "--ws=b", "/host/SRCB" },
        &.{ "commit", "--ws=b", "-m", "d1" },
        &.{ "fork", "main", "saved-b" },
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

    // Attach a workspace to saved-b and commit s2 there (parent = d1).
    try fsb.mkdir(gpa, "/host/SRCW");
    {
        const res = try hb.runCmd(&.{ "init", "--name=wbs", "--src=/host/SRCW", "--stream=saved-b" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }
    try fsb.writeFileSafe(
        gpa,
        "/host/SRCW/calc.go",
        "package calc\n\nfunc X() int {\n\treturn 1\n}\n\nfunc Y() int {\n\treturn 999\n}\n\nfunc Z() int {\n\treturn 7\n}\n",
    );
    for ([_][]const []const u8{
        &.{ "add", "--ws=wbs", "/host/SRCW" },
        &.{ "commit", "--ws=wbs", "-m", "s2" },
    }) |cmd| {
        const res = try hb.runCmd(cmd);
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }
    const s2_id = blk: {
        var idx2 = try store.loadStoreIndex(gpa, fsb, hb.root);
        defer idx2.deinit();
        break :blk try gpa.dupe(u8, idx2.streamByName("saved-b").?.head.?);
    };
    defer gpa.free(s2_id);

    // Recover: reset main to the remote head, merge saved-b back, push.
    for ([_][]const []const u8{
        &.{ "pull", "--ws=b", "--reset" },
        &.{ "merge", "--ws=b", "saved-b" },
        &.{ "push", "--ws=b" },
    }) |cmd| {
        const res = try hb.runCmd(cmd);
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }

    // saved-b keeps its original forked_from — the deposit path publishes
    // d1 onto main, the record is created with the real origin, and the
    // ordinary append then publishes s2.
    {
        const res = try hb.runCmd(&.{ "push", "--stream=saved-b", "--remote=tcp://127.0.0.1:4748" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expectEqualStrings("flint: push ok stream=saved-b changes=1\n", res.out);
    }
    const saved_id = blk: {
        var idx2 = try store.loadStoreIndex(gpa, fsb, hb.root);
        defer idx2.deinit();
        break :blk try gpa.dupe(u8, idx2.streamByName("saved-b").?.id);
    };
    defer gpa.free(saved_id);
    {
        const s_rec_p = try store.streamRecordPath(gpa, server.store_root, saved_id);
        defer gpa.free(s_rec_p);
        const s_rec_raw = try srv_fs.readFile(gpa, s_rec_p, store.MaxFileReadBytes);
        defer gpa.free(s_rec_raw);
        var s_rec = try json.parseStream(gpa, s_rec_raw);
        defer s_rec.deinit(gpa);
        try std.testing.expectEqualStrings(s2_id, s_rec.head.?);
        try std.testing.expectEqualStrings(d1_id, s_rec.forked_from.?.change);
        try std.testing.expectEqualStrings(main_id, s_rec.forked_from.?.stream);
    }
    {
        const s_log_p = try store.streamLogPath(gpa, server.store_root, main_id);
        defer gpa.free(s_log_p);
        const s_log = try srv_fs.readFile(gpa, s_log_p, store.MaxFileReadBytes);
        defer gpa.free(s_log);
        const s_lines = try store.readJSONLLines(gpa, s_log);
        defer gpa.free(s_lines);
        var found_d1 = false;
        for (s_lines) |line| {
            var c = try json.parseChange(gpa, line);
            defer c.deinit(gpa);
            if (std.mem.eql(u8, c.id, d1_id)) found_d1 = true;
        }
        try std.testing.expect(found_d1);
    }

    // A fresh agent clones saved-b and verifies both the original origin
    // and the fork's own signed Change.
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
    }
    for ([_][]const u8{ d1_id, s2_id }) |cid| {
        const res = try hc.runCmd(&.{ "verify", cid });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        const want = try std.fmt.allocPrint(gpa, "flint: verify {s} sig: verified\n", .{cid});
        defer gpa.free(want);
        try std.testing.expectEqualStrings(want, res.out);
    }
}

test "commit refuses stage_stale for a stage predating a pulled head; re-add restages (#67)" {
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

    // Shared base on `main`: alpha=1, beta=10 (#67 repro shape).
    try fsa.writeFileSafe(
        gpa,
        "/host/SRCA/main.zig",
        "pub const alpha: u32 = 1;\npub const beta: u32 = 10;\n",
    );
    for ([_][]const []const u8{
        &.{ "init", "--name=a", "--src=/host/SRCA" },
        &.{ "add", "/host/SRCA" },
        &.{ "commit", "-m", "base" },
        &.{ "push", "--remote=tcp://127.0.0.1:4748" },
    }) |cmd| {
        const res = try ha.runCmd(cmd);
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }

    var idx_a = try store.loadStoreIndex(gpa, fsa, ha.root);
    defer idx_a.deinit();
    const h0 = try gpa.dupe(u8, idx_a.streamByName("main").?.head.?);
    defer gpa.free(h0);

    // B clones `main`, stages alpha=3 against h0, and does not commit.
    var hb = try TestHarness.init(gpa);
    defer hb.deinit();
    hb.env_sign_key = rfc8032_seed_hex;
    hb.sync_dial = sync.InProcServer.dial;
    hb.sync_dial_ctx = &server;
    const fsb = hb.mem.fs();
    {
        const res = try hb.runCmd(&.{
            "clone", "tcp://127.0.0.1:4748", "--stream=main", "--name=b", "--src=/host/SRCB",
        });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }
    try fsb.writeFileSafe(
        gpa,
        "/host/SRCB/main.zig",
        "pub const alpha: u32 = 3;\npub const beta: u32 = 10;\n",
    );
    {
        const res = try hb.runCmd(&.{ "add", "--ws=b", "/host/SRCB" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }
    const stage_path = try store.workspaceStagePath(gpa, hb.root, "b");
    defer gpa.free(stage_path);
    const staged = try fsb.readFile(gpa, stage_path, store.MaxFileReadBytes);
    defer gpa.free(staged);

    // A commits+pushes alpha=2: the shared head advances to h1.
    try fsa.writeFileSafe(
        gpa,
        "/host/SRCA/main.zig",
        "pub const alpha: u32 = 2;\npub const beta: u32 = 10;\n",
    );
    ha.now += 5;
    for ([_][]const []const u8{
        &.{ "add", "/host/SRCA" },
        &.{ "commit", "-m", "alpha=2" },
        &.{"push"},
    }) |cmd| {
        const res = try ha.runCmd(cmd);
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }
    const loaded_a = try store.loadStream(gpa, fsa, ha.root, idx_a.streamByName("main").?.id);
    defer loaded_a.deinit(gpa);
    const h1 = try gpa.dupe(u8, loaded_a.stream.head.?);
    defer gpa.free(h1);

    // B's ordinary pull succeeds: the local head moves to h1 while the
    // STAGE bytes (diffed against h0) stay untouched.
    {
        const res = try hb.runCmd(&.{"pull"});
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expectEqualStrings("flint: pull ok stream=main changes=1\n", res.out);
        const staged_now = try fsb.readFile(gpa, stage_path, store.MaxFileReadBytes);
        defer gpa.free(staged_now);
        try std.testing.expectEqualStrings(staged, staged_now);
    }

    // Committing the pre-pull stage must refuse `stage_stale` instead of
    // silently reparenting alpha=3 over A's alpha=2.
    {
        const res = try hb.runCmd(&.{ "commit", "-m", "staged-before-pull" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        const want = try std.fmt.allocPrint(
            gpa,
            "flint: refuse stage_stale staged against {s}; stream head is now {s}; re-run add to restage\n",
            .{ h0, h1 },
        );
        defer gpa.free(want);
        try std.testing.expectEqualStrings(want, res.out);
        // The refusal preserves the staged intent byte-for-byte.
        const staged_kept = try fsb.readFile(gpa, stage_path, store.MaxFileReadBytes);
        defer gpa.free(staged_kept);
        try std.testing.expectEqualStrings(staged, staged_kept);
    }

    // Unknown provenance (a stage written before BASE.json existed) refuses
    // the same way rather than silently assuming the latest head.
    const base_path = try store.workspaceBasePath(gpa, hb.root, "b");
    defer gpa.free(base_path);
    try fsb.remove(gpa, base_path);
    {
        const res = try hb.runCmd(&.{ "commit", "-m", "staged-before-pull" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings(
            "flint: refuse stage_stale stage base unknown; re-run add to restage\n",
            res.out,
        );
    }

    // Explicit restage: re-running `add` re-stamps BASE.json at h1.
    {
        const res = try hb.runCmd(&.{ "add", "--ws=b", "/host/SRCB" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }
    {
        const res = try hb.runCmd(&.{ "commit", "-m", "restaged" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        const want_suffix = try std.fmt.allocPrint(gpa, " parent={s}\n", .{h1});
        defer gpa.free(want_suffix);
        try std.testing.expect(std.mem.endsWith(u8, res.out, want_suffix));
    }
    {
        const res = try hb.runCmd(&.{"push"});
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expect(!fsb.exists(gpa, stage_path));
        try std.testing.expect(!fsb.exists(gpa, base_path));
    }

    // A fresh observer replays the same workspace table as B: alpha=3 wins,
    // but only because B re-staged it against h1 after the refusal.
    var hc = try TestHarness.init(gpa);
    defer hc.deinit();
    hc.sync_dial = sync.InProcServer.dial;
    hc.sync_dial_ctx = &server;
    const fsc = hc.mem.fs();
    {
        const res = try hc.runCmd(&.{
            "clone", "tcp://127.0.0.1:4748", "--stream=main", "--name=c", "--src=/host/SRCC",
        });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }
    const atoms_b = try fsb.readFile(gpa, "/host/FLINT/ws/b/ATOMS.jsonl", store.MaxFileReadBytes);
    defer gpa.free(atoms_b);
    const atoms_c = try fsc.readFile(gpa, "/host/FLINT/ws/c/ATOMS.jsonl", store.MaxFileReadBytes);
    defer gpa.free(atoms_c);
    try std.testing.expectEqualStrings(atoms_b, atoms_c);
    for ([_]*TestHarness{ hb, hc }) |hx| {
        const res = try hx.runCmd(&.{ "verify", "--all" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }
}

test "commit refuses stage_stale when a sibling workspace advances the head (#67)" {
    const gpa = std.testing.allocator;

    var h = try TestHarness.init(gpa);
    defer h.deinit();
    h.env_sign_key = rfc8032_seed_hex;
    const mfs = h.mem.fs();

    try mfs.writeFileSafe(gpa, "/host/S1/calc.go", "package calc\n\nfunc X() int {\n\treturn 1\n}\n");
    try mfs.writeFileSafe(gpa, "/host/S2/calc.go", "package calc\n\nfunc X() int {\n\treturn 7\n}\n");

    // w1 commits c1 on `main`; w2 attaches to `main` and stages X=7 on top.
    for ([_][]const []const u8{
        &.{ "init", "--name=w1", "--src=/host/S1" },
        &.{ "add", "--ws=w1", "/host/S1" },
        &.{ "commit", "--ws=w1", "-m", "c1" },
        &.{ "init", "--name=w2", "--src=/host/S2", "--stream=main" },
        &.{ "add", "--ws=w2", "/host/S2" },
    }) |cmd| {
        const res = try h.runCmd(cmd);
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }

    // w1 advances the same stream's head to c2 — no pull involved.
    try mfs.writeFileSafe(gpa, "/host/S1/calc.go", "package calc\n\nfunc X() int {\n\treturn 2\n}\n");
    h.now += 5;
    for ([_][]const []const u8{
        &.{ "add", "--ws=w1", "/host/S1" },
        &.{ "commit", "--ws=w1", "-m", "c2" },
    }) |cmd| {
        const res = try h.runCmd(cmd);
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }

    // w2's stage was diffed against c1; committing onto c2 must refuse.
    {
        const res = try h.runCmd(&.{ "commit", "--ws=w2", "-m", "stale-stage" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expect(
            std.mem.startsWith(u8, res.out, "flint: refuse stage_stale staged against "),
        );
    }

    // Re-running `add` restages against c2; the commit then lands.
    {
        const res = try h.runCmd(&.{ "add", "--ws=w2", "/host/S2" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }
    {
        const res = try h.runCmd(&.{ "commit", "--ws=w2", "-m", "restaged" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expect(std.mem.startsWith(u8, res.out, "flint: commit ok id="));
    }
}
