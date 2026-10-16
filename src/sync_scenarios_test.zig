const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const store = @import("store.zig");
const fsys = @import("fsys.zig");
const sync = @import("sync.zig");

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
