const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const fsys = @import("fsys.zig");
pub const uuid = @import("uuid.zig");
pub const store = @import("store.zig");
pub const json = @import("json.zig");
pub const ed25519 = @import("ed25519.zig");
pub const canon = @import("canon.zig");
pub const parser = @import("parser/parser.zig");
pub const render = @import("parser/render.zig");
pub const workspace = @import("workspace.zig");

/// Runtime context for executing a `flint` command.
/// Allows injecting an in-memory filesystem, custom writers, clock/RNG, and environment in tests.
pub const Context = struct {
    allocator: Allocator,
    io: Io,
    fs: fsys.FS,
    stdout: *Io.Writer,
    stderr: *Io.Writer,
    cwd: []const u8 = ".",
    uuid_gen: ?*uuid.UUIDGen = null,
    env_flint_store: ?[]const u8 = null,
    env_flint_sign_key: ?[]const u8 = null,
    env_flint_remote: ?[]const u8 = null,
};

pub fn main(init: std.process.Init) u8 {
    const arena = init.arena.allocator();
    const args = init.minimal.args.toSlice(arena) catch return 1;
    const argv = if (args.len > 1) args[1..] else &[_][]const u8{};

    var stdout_buf: [4096]u8 = undefined;
    var stdout_fw: Io.File.Writer = .init(.stdout(), init.io, &stdout_buf);
    const stdout_w = &stdout_fw.interface;

    var stderr_buf: [4096]u8 = undefined;
    var stderr_fw: Io.File.Writer = .init(.stderr(), init.io, &stderr_buf);
    const stderr_w = &stderr_fw.interface;

    var host_fs = fsys.HostFS.init(init.io);
    var host_uuid = uuid.UUIDGen.initHost(init.io);
    const cwd = std.process.currentPathAlloc(init.io, arena) catch ".";

    const ctx = Context{
        .allocator = init.gpa,
        .io = init.io,
        .fs = host_fs.fs(),
        .stdout = stdout_w,
        .stderr = stderr_w,
        .cwd = cwd,
        .uuid_gen = &host_uuid,
        .env_flint_store = init.environ_map.get("FLINT_STORE"),
        .env_flint_sign_key = init.environ_map.get("FLINT_SIGN_KEY"),
        .env_flint_remote = init.environ_map.get("FLINT_REMOTE"),
    };

    const rc = runWithContext(ctx, argv);
    stdout_w.flush() catch {};
    stderr_w.flush() catch {};
    return rc;
}

fn printUsage(w: *Io.Writer) void {
    w.writeAll("flint: usage\n") catch {};
}

fn printHelp(w: *Io.Writer) void {
    w.writeAll(
        \\usage: flint [--store <dir>] <verb> [args...]
        \\
        \\verbs:
        \\  init --name=<n> --src=<dir> [--stream=<s>]
        \\  add [--ws=<n>] [file ...]
        \\  status [--ws=<n>]
        \\  commit [-m=<msg> | --message=<msg> | -m <msg>] [--ws=<n>] [--key=<k>]
        \\  log [--stream=<s>] [--ws=<n>]
        \\  verify <id> | --all | --file=<log>
        \\  fork <from> <to>
        \\  merge <from> [--ws=<n>]
        \\  parse-corpus <dir>
        \\  keygen [--name=<n>]
        \\
        \\note: passing a 64-hex seed literal via --key or FLINT_SIGN_KEY exposes
        \\it in /proc/<pid>/environ, ps output, and shell history; prefer key names
        \\stored under <store>/keys/<name>.
        \\
    ) catch {};
}

pub fn handleErr(err: anyerror, out: *Io.Writer) u8 {
    if (err == error.Refuse) {
        fsys.writeRefuseLine(out);
        if (std.mem.eql(u8, fsys.last_refuse.code(), "usage")) {
            return 2;
        }
        return 1;
    }
    out.print("flint: error {s}\n", .{@errorName(err)}) catch {};
    return 1;
}

/// Extracts `--store <dir>` or `--store=<dir>` from anywhere in `args`,
/// returning the remaining arguments in order.
fn extractGlobalArgs(
    allocator: Allocator,
    args: []const []const u8,
) !struct { store_flag: []const u8, help: bool, rest: [][]const u8 } {
    var store_flag: []const u8 = "";
    var has_store = false;
    var help = false;
    var rest: std.ArrayList([]const u8) = .empty;
    errdefer rest.deinit(allocator);

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.startsWith(u8, a, "--store=")) {
            if (has_store) return fsys.refuse("usage", "");
            store_flag = a["--store=".len..];
            if (store_flag.len == 0) return fsys.refuse("usage", "");
            has_store = true;
        } else if (std.mem.eql(u8, a, "--store")) {
            if (has_store or i + 1 >= args.len or args[i + 1].len == 0) {
                return fsys.refuse("usage", "");
            }
            i += 1;
            store_flag = args[i];
            has_store = true;
        } else if (std.mem.eql(u8, a, "-h") or std.mem.eql(u8, a, "--help")) {
            help = true;
        } else {
            try rest.append(allocator, a);
        }
    }

    return .{
        .store_flag = store_flag,
        .help = help,
        .rest = try rest.toOwnedSlice(allocator),
    };
}

pub fn runWithContext(ctx: Context, args: []const []const u8) u8 {
    var default_uuid = uuid.UUIDGen.initHost(ctx.io);
    const uuid_gen = ctx.uuid_gen orelse &default_uuid;

    const extracted = extractGlobalArgs(ctx.allocator, args) catch |err| {
        return handleErr(err, ctx.stdout);
    };
    defer ctx.allocator.free(extracted.rest);

    if (extracted.help) {
        printHelp(ctx.stdout);
        return 0;
    }

    if (extracted.rest.len == 0) {
        printUsage(ctx.stdout);
        return 2;
    }

    const verb = extracted.rest[0];
    const sub = extracted.rest[1..];

    // Verbs that do not require a store root:
    if (std.mem.eql(u8, verb, "verify") and ed25519.verifyFileArg(sub) != null) {
        return ed25519.cmdVerify(ctx.allocator, ctx.fs, null, sub, ctx.stdout) catch |err| {
            return handleErr(err, ctx.stdout);
        };
    }

    if (std.mem.eql(u8, verb, "parse-corpus")) {
        render.cmdParseCorpus(ctx.allocator, ctx.fs, sub, ctx.stdout) catch |err| {
            return handleErr(err, ctx.stdout);
        };
        return 0;
    }

    const is_known_store_verb = std.mem.eql(u8, verb, "keygen") or
        std.mem.eql(u8, verb, "verify") or
        std.mem.eql(u8, verb, "init") or
        std.mem.eql(u8, verb, "add") or
        std.mem.eql(u8, verb, "status") or
        std.mem.eql(u8, verb, "commit") or
        std.mem.eql(u8, verb, "log") or
        std.mem.eql(u8, verb, "fork") or
        std.mem.eql(u8, verb, "merge") or
        std.mem.eql(u8, verb, "clone") or
        std.mem.eql(u8, verb, "push") or
        std.mem.eql(u8, verb, "pull");

    if (!is_known_store_verb) {
        printUsage(ctx.stdout);
        return 2;
    }

    const root = store.resolveStoreRoot(
        ctx.allocator,
        ctx.fs,
        extracted.store_flag,
        ctx.env_flint_store,
        ctx.cwd,
    ) catch |err| blk: {
        if (err == error.Refuse and (std.mem.eql(u8, verb, "init") or std.mem.eql(u8, verb, "clone"))) {
            const clean_cwd = fsys.cleanPath(ctx.allocator, if (ctx.cwd.len > 0) ctx.cwd else ".") catch |e| return handleErr(e, ctx.stdout);
            defer ctx.allocator.free(clean_cwd);
            break :blk fsys.joinPath(ctx.allocator, &.{ clean_cwd, ".flint" }) catch |e| return handleErr(e, ctx.stdout);
        }
        return handleErr(err, ctx.stdout);
    };
    defer ctx.allocator.free(root);

    if (std.mem.eql(u8, verb, "init")) {
        workspace.cmdInit(ctx.allocator, ctx.fs, root, uuid_gen, ctx.stdout, sub) catch |err| {
            return handleErr(err, ctx.stdout);
        };
        return 0;
    }

    if (std.mem.eql(u8, verb, "add")) {
        workspace.cmdAdd(ctx.allocator, ctx.fs, root, uuid_gen, ctx.stdout, sub) catch |err| {
            return handleErr(err, ctx.stdout);
        };
        return 0;
    }

    if (std.mem.eql(u8, verb, "status")) {
        workspace.cmdStatus(ctx.allocator, ctx.fs, root, ctx.stdout, sub) catch |err| {
            return handleErr(err, ctx.stdout);
        };
        return 0;
    }

    if (std.mem.eql(u8, verb, "keygen")) {
        ed25519.cmdKeygen(ctx.allocator, ctx.fs, root, uuid_gen, sub, ctx.stdout) catch |err| {
            return handleErr(err, ctx.stdout);
        };
        return 0;
    }

    if (std.mem.eql(u8, verb, "verify")) {
        return ed25519.cmdVerify(ctx.allocator, ctx.fs, root, sub, ctx.stdout) catch |err| {
            return handleErr(err, ctx.stdout);
        };
    }

    return handleErr(fsys.refuse("usage", ""), ctx.stdout);
}

test {
    _ = fsys;
    _ = uuid;
    _ = store;
    _ = json;
    _ = ed25519;
    _ = canon;
    _ = parser;
    _ = render;
    _ = workspace;
}

const TestHarness = struct {
    allocator: Allocator,
    mem: fsys.MemFS,
    uuid_gen: uuid.UUIDGen,
    now: i64 = 1760000000,
    rng_seed: u8 = 1,
    root: []const u8 = "/host/FLINT",
    cwd: []const u8 = "/host",

    fn init(allocator: Allocator) !*TestHarness {
        const h = try allocator.create(TestHarness);
        h.* = .{
            .allocator = allocator,
            .mem = try fsys.MemFS.init(allocator),
            .uuid_gen = undefined,
        };
        h.uuid_gen = uuid.UUIDGen.initCustom(h, getNow, h, fillRand);
        return h;
    }

    fn deinit(self: *TestHarness) void {
        self.mem.deinit();
        self.allocator.destroy(self);
    }

    fn getNow(ptr: ?*anyopaque) i64 {
        const self: *TestHarness = @ptrCast(@alignCast(ptr.?));
        return self.now;
    }

    fn fillRand(ptr: ?*anyopaque, buf: []u8) void {
        const self: *TestHarness = @ptrCast(@alignCast(ptr.?));
        for (buf) |*b| {
            b.* = self.rng_seed;
            self.rng_seed = self.rng_seed *% 31 +% 17;
        }
    }

    fn runCmd(self: *TestHarness, args: []const []const u8) !struct { rc: u8, out: []u8 } {
        var out_w: Io.Writer.Allocating = .init(self.allocator);
        errdefer out_w.deinit();
        var err_w: Io.Writer.Allocating = .init(self.allocator);
        defer err_w.deinit();

        const ctx = Context{
            .allocator = self.allocator,
            .io = std.testing.io,
            .fs = self.mem.fs(),
            .stdout = &out_w.writer,
            .stderr = &err_w.writer,
            .cwd = self.cwd,
            .uuid_gen = &self.uuid_gen,
            .env_flint_store = self.root,
        };
        const rc = runWithContext(ctx, args);
        return .{
            .rc = rc,
            .out = try out_w.toOwnedSlice(),
        };
    }
};

test "CLI verify --file on testdata/sig/{good,bad}.jsonl" {
    const gpa = std.testing.allocator;
    var host_fs = fsys.HostFS.init(std.testing.io);
    const fs = host_fs.fs();

    const good_raw = try fs.readFile(gpa, "testdata/sig/good.jsonl", store.MaxFileReadBytes);
    defer gpa.free(good_raw);
    const bad_raw = try fs.readFile(gpa, "testdata/sig/bad.jsonl", store.MaxFileReadBytes);
    defer gpa.free(bad_raw);

    var h = try TestHarness.init(gpa);
    defer h.deinit();
    const mfs = h.mem.fs();

    try mfs.writeFileSafe(gpa, "/host/FLINTV/good.jsonl", good_raw);
    try mfs.writeFileSafe(gpa, "/host/FLINTV/bad.jsonl", bad_raw);

    {
        const res = try h.runCmd(&.{ "verify", "--file=/host/FLINTV/good.jsonl" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expectEqualStrings(
            "flint: verify 0199de2d-dc00-7000-8000-000000000100 sig: verified\n",
            res.out,
        );
    }
    {
        const res = try h.runCmd(&.{ "verify", "--file=/host/FLINTV/bad.jsonl" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings(
            "flint: verify 0199de2d-dc00-7000-8000-000000000100 sig_invalid\n",
            res.out,
        );
    }
}

test "Flip any single field fails verify (sig_invalid, exit 1)" {
    const gpa = std.testing.allocator;
    var host_fs = fsys.HostFS.init(std.testing.io);
    const fs = host_fs.fs();

    const good_raw = try fs.readFile(gpa, "testdata/sig/good.jsonl", store.MaxFileReadBytes);
    defer gpa.free(good_raw);
    const good_lines = try store.readJSONLLines(gpa, good_raw);
    defer gpa.free(good_lines);
    const base = try json.parseChange(gpa, good_lines[0]);
    defer base.deinit(gpa);

    const other_uuid = "0199de2d-dc00-7000-8000-000000000999";
    const other_hash = "ff11111111111111111111111111111111111111111111111111111111111111";
    const other_author = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";

    var h = try TestHarness.init(gpa);
    defer h.deinit();
    const mfs = h.mem.fs();

    const Case = enum {
        id,
        parent,
        stream,
        ts,
        author,
        message,
        merged,
        op0_type,
        op0_atom_id,
        op0_kind,
        op0_new_name,
        op0_new_span_file,
        op0_new_span_start,
        op0_new_span_end,
        op0_new_hash,
        op0_new_sig_hash,
        op1_old_hash,
        op2_old_hash,
    };

    const cases = [_]Case{
        .id,
        .parent,
        .stream,
        .ts,
        .author,
        .message,
        .merged,
        .op0_type,
        .op0_atom_id,
        .op0_kind,
        .op0_new_name,
        .op0_new_span_file,
        .op0_new_span_start,
        .op0_new_span_end,
        .op0_new_hash,
        .op0_new_sig_hash,
        .op1_old_hash,
        .op2_old_hash,
    };

    for (cases) |tc| {
        var m = try base.clone(gpa);
        defer m.deinit(gpa);
        const ops_mut = @constCast(m.ops);

        switch (tc) {
            .id => {
                gpa.free(m.id);
                m.id = try gpa.dupe(u8, other_uuid);
            },
            .parent => {
                if (m.parent) |p| gpa.free(p);
                m.parent = try gpa.dupe(u8, other_uuid);
            },
            .stream => {
                gpa.free(m.stream);
                m.stream = try gpa.dupe(u8, other_uuid);
            },
            .ts => {
                m.ts += 1;
            },
            .author => {
                gpa.free(m.author);
                m.author = try gpa.dupe(u8, other_author);
            },
            .message => {
                gpa.free(m.message);
                m.message = try gpa.dupe(u8, "pinned vector changX");
            },
            .merged => {
                if (m.merged) |mg| gpa.free(mg);
                m.merged = try gpa.dupe(u8, other_uuid);
            },
            .op0_type => {
                gpa.free(ops_mut[0].type);
                ops_mut[0].type = try gpa.dupe(u8, "modify");
            },
            .op0_atom_id => {
                gpa.free(ops_mut[0].atom_id);
                ops_mut[0].atom_id = try gpa.dupe(u8, other_uuid);
            },
            .op0_kind => {
                gpa.free(ops_mut[0].kind);
                ops_mut[0].kind = try gpa.dupe(u8, "const");
            },
            .op0_new_name => {
                gpa.free(ops_mut[0].new_name);
                ops_mut[0].new_name = try gpa.dupe(u8, "sample.Sub");
            },
            .op0_new_span_file => {
                gpa.free(ops_mut[0].new_span.?.file);
                ops_mut[0].new_span.?.file = try gpa.dupe(u8, "go/other.go");
            },
            .op0_new_span_start => {
                ops_mut[0].new_span.?.start += 1;
            },
            .op0_new_span_end => {
                ops_mut[0].new_span.?.end += 1;
            },
            .op0_new_hash => {
                gpa.free(ops_mut[0].new_hash);
                ops_mut[0].new_hash = try gpa.dupe(u8, other_hash);
            },
            .op0_new_sig_hash => {
                gpa.free(ops_mut[0].new_sig_hash);
                ops_mut[0].new_sig_hash = try gpa.dupe(u8, other_hash);
            },
            .op1_old_hash => {
                gpa.free(ops_mut[1].old_hash);
                ops_mut[1].old_hash = try gpa.dupe(u8, other_hash);
            },
            .op2_old_hash => {
                gpa.free(ops_mut[2].old_hash);
                ops_mut[2].old_hash = try gpa.dupe(u8, other_hash);
            },
        }

        const line = try json.marshalChangeLine(gpa, m);
        defer gpa.free(line);
        try mfs.writeFileSafe(gpa, "/host/FLINTV/mut.jsonl", line);

        const res = try h.runCmd(&.{ "verify", "--file=/host/FLINTV/mut.jsonl" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        const want = try std.fmt.allocPrint(gpa, "flint: verify {s} sig_invalid\n", .{m.id});
        defer gpa.free(want);
        try std.testing.expectEqualStrings(want, res.out);
    }
}

test "JSON key order and whitespace invariance" {
    const gpa = std.testing.allocator;
    var host_fs = fsys.HostFS.init(std.testing.io);
    const fs = host_fs.fs();

    const good_raw = try fs.readFile(gpa, "testdata/sig/good.jsonl", store.MaxFileReadBytes);
    defer gpa.free(good_raw);
    const good_lines = try store.readJSONLLines(gpa, good_raw);
    defer gpa.free(good_lines);
    const c = try json.parseChange(gpa, good_lines[0]);
    defer c.deinit(gpa);

    const reordered = try std.fmt.allocPrint(
        gpa,
        "{{  \"sig\" : \"{s}\" , \"merged\" : null , \"message\" : \"{s}\" , " ++
            "\"author\" : \"{s}\" , \"ts\" : 1760000000000 , \"stream\" : \"{s}\" , " ++
            "\"parent\" : null , \"id\" : \"{s}\" , \"ops\" : [ " ++
            "{{ \"old_hash\" : \"{s}\" , \"atom_id\" : \"{s}\" , \"type\" : \"delete\" }} , " ++
            "{{ \"old_hash\" : \"{s}\" , \"new_sig_hash\" : \"{s}\" , \"new_hash\" : \"{s}\" , \"atom_id\" : \"{s}\" , \"type\" : \"modify\" }} , " ++
            "{{ \"new_sig_hash\" : \"{s}\" , \"new_hash\" : \"{s}\" , \"new_span\" : {{ \"end\" : 85 , \"start\" : 40 , \"file\" : \"go/sample.go\" }} , \"new_name\" : \"sample.Add\" , \"kind\" : \"fn\" , \"atom_id\" : \"{s}\" , \"type\" : \"add\" }} " ++
            "] }}\n",
        .{
            c.sig,
            c.message,
            c.author,
            c.stream,
            c.id,
            c.ops[2].old_hash,
            c.ops[2].atom_id,
            c.ops[1].old_hash,
            c.ops[1].new_sig_hash,
            c.ops[1].new_hash,
            c.ops[1].atom_id,
            c.ops[0].new_sig_hash,
            c.ops[0].new_hash,
            c.ops[0].atom_id,
        },
    );
    defer gpa.free(reordered);

    var h = try TestHarness.init(gpa);
    defer h.deinit();
    const mfs = h.mem.fs();
    try mfs.writeFileSafe(gpa, "/host/FLINTV/reordered.jsonl", reordered);

    const res = try h.runCmd(&.{ "verify", "--file=/host/FLINTV/reordered.jsonl" });
    defer gpa.free(res.out);
    try std.testing.expectEqual(@as(u8, 0), res.rc);
    try std.testing.expectEqualStrings(
        "flint: verify 0199de2d-dc00-7000-8000-000000000100 sig: verified\n",
        res.out,
    );
}

test "keygen, key resolution, sign, verify --all and verify <id>" {
    const gpa = std.testing.allocator;
    var h = try TestHarness.init(gpa);
    defer h.deinit();
    const mfs = h.mem.fs();

    // 1. `flint keygen --name=alice` writes `<store>/keys/alice` (64 hex + '\n', mode 0600)
    {
        const res = try h.runCmd(&.{ "keygen", "--name=alice" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expect(std.mem.startsWith(u8, res.out, "flint: keygen "));
        try std.testing.expectEqual(@as(usize, "flint: keygen ".len + 64 + 1), res.out.len);

        const key_bytes = try mfs.readFile(gpa, "/host/FLINT/keys/alice", store.MaxFileReadBytes);
        defer gpa.free(key_bytes);
        try std.testing.expectEqual(@as(usize, 65), key_bytes.len);
        try std.testing.expectEqual(@as(u8, '\n'), key_bytes[64]);
        try std.testing.expect(ed25519.parseHex32Lower(key_bytes[0..64]) != null);
        try std.testing.expectEqual(@as(?u32, 0o600), h.mem.getMode("/host/FLINT/keys/alice"));

        // Seed must never appear in stdout
        try std.testing.expect(std.mem.indexOf(u8, res.out, key_bytes[0..64]) == null);
    }

    // 2. Duplicate keygen refuses `key_exists`
    {
        const res = try h.runCmd(&.{ "keygen", "--name=alice" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse key_exists\n", res.out);
    }

    // 3. Load sole key and sign a Change into a store stream, then verify <id> and verify --all
    var seed = try ed25519.loadSigningSeed(gpa, mfs, h.root, "", null);
    const stream_id = "0199de2d-dc00-7000-8000-000000000000";
    const change_id = "0199de2d-dc00-7000-8000-000000000002";

    const st = store.Stream{
        .id = stream_id,
        .name = "main",
        .head = change_id,
        .created = 1760000000000,
        .forked_from = null,
    };
    try store.writeStreamRecord(gpa, mfs, h.root, st);

    var c = store.Change{
        .id = try gpa.dupe(u8, change_id),
        .parent = null,
        .stream = try gpa.dupe(u8, stream_id),
        .ts = 1760000000000,
        .author = try gpa.dupe(u8, ""),
        .message = try gpa.dupe(u8, "signed with alice key"),
        .ops = try gpa.alloc(store.Op, 0),
        .merged = null,
        .sig = try gpa.dupe(u8, ""),
    };
    defer c.deinit(gpa);

    try ed25519.signChangeWithSeed(gpa, &c, &seed);
    // Verify seed was wiped
    try std.testing.expectEqual(@as([32]u8, @splat(0)), seed);

    const line = try json.marshalChangeLine(gpa, c);
    defer gpa.free(line);
    const log_path = try store.streamLogPath(gpa, h.root, stream_id);
    defer gpa.free(log_path);
    try mfs.appendSync(gpa, log_path, line);

    {
        const res = try h.runCmd(&.{ "verify", change_id });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expectEqualStrings(
            "flint: verify 0199de2d-dc00-7000-8000-000000000002 sig: verified\n",
            res.out,
        );
    }
    {
        const res = try h.runCmd(&.{ "verify", "--all" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expectEqualStrings(
            "flint: verify 0199de2d-dc00-7000-8000-000000000002 sig: verified\n",
            res.out,
        );
    }
    {
        const res = try h.runCmd(&.{ "verify", "0199de2d-dc00-7000-8000-000000000999" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings(
            "flint: refuse change_missing 0199de2d-dc00-7000-8000-000000000999\n",
            res.out,
        );
    }
}

test "store root resolution order (--store -> FLINT_STORE -> walk up .flint/ or FLINT/ -> store_not_found)" {
    const gpa = std.testing.allocator;
    var mem = try fsys.MemFS.init(gpa);
    defer mem.deinit();
    const mfs = mem.fs();

    try mfs.mkdir(gpa, "/repo/.flint/streams");
    try mfs.mkdir(gpa, "/repo/sub/deep");
    try mfs.mkdir(gpa, "/guest/FLINT/streams");
    try mfs.mkdir(gpa, "/guest/work/inner");

    // 1. --store flag wins
    {
        const r = try store.resolveStoreRoot(gpa, mfs, "/explicit/store", "/env/store", "/repo/sub/deep");
        defer gpa.free(r);
        try std.testing.expectEqualStrings("/explicit/store", r);
    }
    // 2. FLINT_STORE env wins over walk-up
    {
        const r = try store.resolveStoreRoot(gpa, mfs, "", "/env/store", "/repo/sub/deep");
        defer gpa.free(r);
        try std.testing.expectEqualStrings("/env/store", r);
    }
    // 3. Walk-up finds .flint
    {
        const r = try store.resolveStoreRoot(gpa, mfs, "", null, "/repo/sub/deep");
        defer gpa.free(r);
        try std.testing.expectEqualStrings("/repo/.flint", r);
    }
    // 4. Walk-up finds uppercase FLINT (guest-copied store)
    {
        const r = try store.resolveStoreRoot(gpa, mfs, "", null, "/guest/work/inner");
        defer gpa.free(r);
        try std.testing.expectEqualStrings("/guest/FLINT", r);
    }
    // 5. Missing store refuses store_not_found naming cwd
    {
        try std.testing.expectError(
            error.Refuse,
            store.resolveStoreRoot(gpa, mfs, "", null, "/nowhere/dir"),
        );
        try std.testing.expectEqualStrings("store_not_found", fsys.last_refuse.code());
        try std.testing.expectEqualStrings("/nowhere/dir", fsys.last_refuse.detail());
    }
}

const ManifestAtom = struct {
    file: []const u8,
    kind: []const u8,
    name: []const u8,
    start: u32,
    end: u32,
    hash: []const u8,
    sig_hash: []const u8,
};

const ManifestDoc = struct {
    version: i64,
    files: i64,
    atoms: []ManifestAtom,
};

fn parseSingleTestAtom(allocator: Allocator, fs: fsys.FS, rel_file: []const u8) !parser.Atom {
    const path = try std.fmt.allocPrint(allocator, "testdata/corpus/{s}", .{rel_file});
    defer allocator.free(path);
    const src = try fs.readFile(allocator, path, store.MaxFileReadBytes);
    defer allocator.free(src);
    var perr: ?parser.ParseErrorInfo = null;
    const atoms = try parser.parseFile(allocator, rel_file, src, null, &perr);
    errdefer parser.freeAtoms(allocator, atoms);
    try std.testing.expectEqual(@as(usize, 1), atoms.len);
    const a = atoms[0];
    allocator.free(atoms);
    return a;
}

test "Full corpus (50 .go + 50 .zig = 100 files, 245 atoms) matches MANIFEST.json and parse-corpus" {
    const gpa = std.testing.allocator;
    var host_fs = fsys.HostFS.init(std.testing.io);
    const fs = host_fs.fs();

    var go_files: usize = 0;
    var zig_files: usize = 0;
    var got_atoms: std.ArrayList(parser.Atom) = .empty;
    defer {
        for (got_atoms.items) |*a| a.deinit(gpa);
        got_atoms.deinit(gpa);
    }

    const subs = [_][]const u8{ "go", "zig" };
    for (subs) |sub| {
        const dir = try std.fmt.allocPrint(gpa, "testdata/corpus/{s}", .{sub});
        defer gpa.free(dir);
        const entries = try fs.list(gpa, dir);
        defer fsys.FS.freeDirEntries(gpa, entries);

        for (entries) |e| {
            if (e.is_dir) continue;
            const rel = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ sub, e.name });
            defer gpa.free(rel);
            if (parser.forPath(rel) == null) continue;
            if (std.mem.eql(u8, sub, "go")) go_files += 1 else zig_files += 1;

            const full = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ dir, e.name });
            defer gpa.free(full);
            const src = try fs.readFile(gpa, full, store.MaxFileReadBytes);
            defer gpa.free(src);

            var perr: ?parser.ParseErrorInfo = null;
            const atoms = try parser.parseFile(gpa, rel, src, null, &perr);
            defer gpa.free(atoms);
            for (atoms) |a| {
                try got_atoms.append(gpa, a);
            }
        }
    }

    try std.testing.expectEqual(@as(usize, 50), go_files);
    try std.testing.expectEqual(@as(usize, 50), zig_files);

    const manifest_raw = try fs.readFile(gpa, "testdata/corpus/MANIFEST.json", store.MaxFileReadBytes);
    defer gpa.free(manifest_raw);
    const parsed_manifest = try std.json.parseFromSlice(ManifestDoc, gpa, manifest_raw, .{ .ignore_unknown_fields = true });
    defer parsed_manifest.deinit();

    try std.testing.expectEqual(@as(i64, 1), parsed_manifest.value.version);
    try std.testing.expectEqual(@as(i64, 100), parsed_manifest.value.files);
    try std.testing.expectEqual(@as(usize, 245), parsed_manifest.value.atoms.len);
    try std.testing.expectEqual(parsed_manifest.value.atoms.len, got_atoms.items.len);

    var go_sample_fn: usize = 0;
    var go_sample_struct: usize = 0;
    var go_sample_const: usize = 0;
    var zig_sample_fn: usize = 0;
    var zig_sample_struct: usize = 0;
    var zig_sample_const: usize = 0;
    var zig_sample_test: usize = 0;
    var has_receiver_meta: usize = 0;

    var go_kinds = std.StringHashMap(usize).init(gpa);
    defer go_kinds.deinit();
    var zig_kinds = std.StringHashMap(usize).init(gpa);
    defer zig_kinds.deinit();

    var want_rendered: std.ArrayList(u8) = .empty;
    defer want_rendered.deinit(gpa);

    for (got_atoms.items, 0..) |a, idx| {
        const m = parsed_manifest.value.atoms[idx];
        const got_hash = std.fmt.bytesToHex(a.hash, .lower);
        const got_sig = std.fmt.bytesToHex(a.sig_hash, .lower);
        try std.testing.expectEqualStrings(m.file, a.file);
        try std.testing.expectEqualStrings(m.kind, a.kind);
        try std.testing.expectEqualStrings(m.name, a.name);
        try std.testing.expectEqual(m.start, a.start);
        try std.testing.expectEqual(m.end, a.end);
        try std.testing.expectEqualStrings(m.hash, &got_hash);
        try std.testing.expectEqualStrings(m.sig_hash, &got_sig);

        const row = try std.fmt.allocPrint(
            gpa,
            "{s}\t{s}\t{s}\t{d}\t{d}\t{s}\t{s}\n",
            .{ m.file, m.kind, m.name, m.start, m.end, m.hash, m.sig_hash },
        );
        defer gpa.free(row);
        try want_rendered.appendSlice(gpa, row);

        if (std.mem.startsWith(u8, a.file, "go/")) {
            const gop = try go_kinds.getOrPut(m.kind);
            if (!gop.found_existing) gop.value_ptr.* = 0;
            gop.value_ptr.* += 1;
            if (std.mem.eql(u8, a.file, "go/sample.go")) {
                if (std.mem.eql(u8, a.kind, "fn")) go_sample_fn += 1;
                if (std.mem.eql(u8, a.kind, "struct")) go_sample_struct += 1;
                if (std.mem.eql(u8, a.kind, "const")) go_sample_const += 1;
            }
            if (std.mem.eql(u8, a.kind, "method")) {
                try std.testing.expect(std.mem.indexOfScalar(u8, a.name, '*') == null);
                try std.testing.expect(a.meta.len == 1);
                try std.testing.expectEqualStrings("receiver", a.meta[0].key);
                try std.testing.expect(a.meta[0].value.len > 0);
                has_receiver_meta += 1;
            }
        } else {
            const gop = try zig_kinds.getOrPut(m.kind);
            if (!gop.found_existing) gop.value_ptr.* = 0;
            gop.value_ptr.* += 1;
            if (std.mem.eql(u8, a.file, "zig/sample.zig")) {
                if (std.mem.eql(u8, a.kind, "fn")) zig_sample_fn += 1;
                if (std.mem.eql(u8, a.kind, "struct")) zig_sample_struct += 1;
                if (std.mem.eql(u8, a.kind, "const")) zig_sample_const += 1;
                if (std.mem.eql(u8, a.kind, "test")) zig_sample_test += 1;
            }
        }
    }

    try std.testing.expectEqual(@as(usize, 2), go_sample_fn);
    try std.testing.expectEqual(@as(usize, 1), go_sample_struct);
    try std.testing.expectEqual(@as(usize, 1), go_sample_const);
    try std.testing.expectEqual(@as(usize, 3), zig_sample_fn);
    try std.testing.expectEqual(@as(usize, 1), zig_sample_struct);
    try std.testing.expectEqual(@as(usize, 1), zig_sample_const);
    try std.testing.expectEqual(@as(usize, 1), zig_sample_test);
    try std.testing.expect(has_receiver_meta >= 3);

    for ([_][]const u8{ "fn", "method", "test", "struct", "interface", "type", "type_alias", "const", "var" }) |k| {
        try std.testing.expect((go_kinds.get(k) orelse 0) >= 3);
    }
    for ([_][]const u8{ "fn", "test", "struct", "enum", "union", "const", "var" }) |k| {
        try std.testing.expect((zig_kinds.get(k) orelse 0) >= 3);
    }

    // Verify `flint parse-corpus testdata/corpus` matches MANIFEST.json byte-for-byte
    var out_w: Io.Writer.Allocating = .init(gpa);
    defer out_w.deinit();
    var err_w: Io.Writer.Allocating = .init(gpa);
    defer err_w.deinit();
    const ctx = Context{
        .allocator = gpa,
        .io = std.testing.io,
        .fs = fs,
        .stdout = &out_w.writer,
        .stderr = &err_w.writer,
    };
    const rc = runWithContext(ctx, &.{ "parse-corpus", "testdata/corpus" });
    try std.testing.expectEqual(@as(u8, 0), rc);
    try std.testing.expectEqualStrings(want_rendered.items, out_w.written());
}

test "Canonical token streams match all 6 testdata/canon/*.txt fixtures and scientific notation" {
    const gpa = std.testing.allocator;
    var host_fs = fsys.HostFS.init(std.testing.io);
    const fs = host_fs.fs();

    const CanonCase = struct {
        fixture: []const u8,
        rel_file: []const u8,
        atom_name: []const u8,
        kind: []const u8,
    };
    const cases = [_]CanonCase{
        .{ .fixture = "go_sample_Add.txt", .rel_file = "go/sample.go", .atom_name = "sample.Add", .kind = "fn" },
        .{ .fixture = "go_methods_Scale.txt", .rel_file = "go/methods.go", .atom_name = "shapes.Rect.Scale", .kind = "method" },
        .{ .fixture = "go_iota_Green.txt", .rel_file = "go/iota.go", .atom_name = "flags.Green", .kind = "const" },
        .{ .fixture = "zig_sample_add.txt", .rel_file = "zig/sample.zig", .atom_name = "sample.add", .kind = "fn" },
        .{ .fixture = "zig_containers_Packed.txt", .rel_file = "zig/containers.zig", .atom_name = "containers.Packed", .kind = "struct" },
        .{ .fixture = "zig_sample_test.txt", .rel_file = "zig/sample.zig", .atom_name = "sample.test:add works", .kind = "test" },
    };

    for (cases) |cc| {
        const fix_path = try std.fmt.allocPrint(gpa, "testdata/canon/{s}", .{cc.fixture});
        defer gpa.free(fix_path);
        const want_bytes = try fs.readFile(gpa, fix_path, store.MaxFileReadBytes);
        defer gpa.free(want_bytes);
        const want = std.mem.trimEnd(u8, want_bytes, "\r\n");

        const src_path = try std.fmt.allocPrint(gpa, "testdata/corpus/{s}", .{cc.rel_file});
        defer gpa.free(src_path);
        const src = try fs.readFile(gpa, src_path, store.MaxFileReadBytes);
        defer gpa.free(src);

        var perr: ?parser.ParseErrorInfo = null;
        var cmap = try parser.canonMap(gpa, cc.rel_file, src, &perr);
        defer parser.freeCanonMap(gpa, &cmap);

        const got = cmap.get(cc.atom_name) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings(want, got);

        const atoms = try parser.parseFile(gpa, cc.rel_file, src, null, &perr);
        defer parser.freeAtoms(gpa, atoms);
        var found_hash: ?[32]u8 = null;
        for (atoms) |a| {
            if (std.mem.eql(u8, a.name, cc.atom_name)) {
                found_hash = a.hash;
                break;
            }
        }
        const expect_hash = canon.hashDomainBody(canon.atom_domain, cc.kind, want);
        try std.testing.expectEqual(expect_hash, found_hash.?);
    }

    // Scientific notation literals stay a single token in canonMap
    var perr: ?parser.ParseErrorInfo = null;
    var sci_map = try parser.canonMap(gpa, "sci.zig", "const eps: f64 = 1e-5;\nconst hexp: f64 = 0x1p-4;\n", &perr);
    defer parser.freeCanonMap(gpa, &sci_map);
    try std.testing.expectEqualStrings("const _ : f64 = 1e-5 ;", sci_map.get("sci.eps").?);
    try std.testing.expectEqualStrings("const _ : f64 = 0x1p-4 ;", sci_map.get("sci.hexp").?);
}

test "Go and Zig pair hash-movement properties (rename, body, ws, param, field)" {
    const gpa = std.testing.allocator;
    var host_fs = fsys.HostFS.init(std.testing.io);
    const fs = host_fs.fs();

    const Lang = struct { dir: []const u8, ext: []const u8 };
    for ([_]Lang{ .{ .dir = "go", .ext = ".go" }, .{ .dir = "zig", .ext = ".zig" } }) |lang| {
        const ren_a_path = try std.fmt.allocPrint(gpa, "{s}/pair_rename_a{s}", .{ lang.dir, lang.ext });
        defer gpa.free(ren_a_path);
        const ren_b_path = try std.fmt.allocPrint(gpa, "{s}/pair_rename_b{s}", .{ lang.dir, lang.ext });
        defer gpa.free(ren_b_path);
        var ren_a = try parseSingleTestAtom(gpa, fs, ren_a_path);
        defer ren_a.deinit(gpa);
        var ren_b = try parseSingleTestAtom(gpa, fs, ren_b_path);
        defer ren_b.deinit(gpa);
        try std.testing.expect(std.mem.endsWith(u8, ren_a.name, ".fn_a"));
        try std.testing.expect(std.mem.endsWith(u8, ren_b.name, ".fn_a_renamed"));
        try std.testing.expectEqual(ren_a.hash, ren_b.hash);
        try std.testing.expectEqual(ren_a.sig_hash, ren_b.sig_hash);

        const body_a_path = try std.fmt.allocPrint(gpa, "{s}/pair_body_a{s}", .{ lang.dir, lang.ext });
        defer gpa.free(body_a_path);
        const body_b_path = try std.fmt.allocPrint(gpa, "{s}/pair_body_b{s}", .{ lang.dir, lang.ext });
        defer gpa.free(body_b_path);
        var body_a = try parseSingleTestAtom(gpa, fs, body_a_path);
        defer body_a.deinit(gpa);
        var body_b = try parseSingleTestAtom(gpa, fs, body_b_path);
        defer body_b.deinit(gpa);
        try std.testing.expect(!std.mem.eql(u8, &body_a.hash, &body_b.hash));
        try std.testing.expectEqual(body_a.sig_hash, body_b.sig_hash);

        const ws_a_path = try std.fmt.allocPrint(gpa, "{s}/pair_ws_a{s}", .{ lang.dir, lang.ext });
        defer gpa.free(ws_a_path);
        const ws_b_path = try std.fmt.allocPrint(gpa, "{s}/pair_ws_b{s}", .{ lang.dir, lang.ext });
        defer gpa.free(ws_b_path);
        var ws_a = try parseSingleTestAtom(gpa, fs, ws_a_path);
        defer ws_a.deinit(gpa);
        var ws_b = try parseSingleTestAtom(gpa, fs, ws_b_path);
        defer ws_b.deinit(gpa);
        try std.testing.expectEqual(ws_a.hash, ws_b.hash);
        try std.testing.expectEqual(ws_a.sig_hash, ws_b.sig_hash);

        const param_a_path = try std.fmt.allocPrint(gpa, "{s}/pair_param_a{s}", .{ lang.dir, lang.ext });
        defer gpa.free(param_a_path);
        const param_b_path = try std.fmt.allocPrint(gpa, "{s}/pair_param_b{s}", .{ lang.dir, lang.ext });
        defer gpa.free(param_b_path);
        var param_a = try parseSingleTestAtom(gpa, fs, param_a_path);
        defer param_a.deinit(gpa);
        var param_b = try parseSingleTestAtom(gpa, fs, param_b_path);
        defer param_b.deinit(gpa);
        try std.testing.expect(!std.mem.eql(u8, &param_a.hash, &param_b.hash));
        try std.testing.expect(!std.mem.eql(u8, &param_a.sig_hash, &param_b.sig_hash));

        const field_a_path = try std.fmt.allocPrint(gpa, "{s}/pair_field_a{s}", .{ lang.dir, lang.ext });
        defer gpa.free(field_a_path);
        const field_b_path = try std.fmt.allocPrint(gpa, "{s}/pair_field_b{s}", .{ lang.dir, lang.ext });
        defer gpa.free(field_b_path);
        var field_a = try parseSingleTestAtom(gpa, fs, field_a_path);
        defer field_a.deinit(gpa);
        var field_b = try parseSingleTestAtom(gpa, fs, field_b_path);
        defer field_b.deinit(gpa);
        try std.testing.expect(!std.mem.eql(u8, &field_a.hash, &field_b.hash));
    }
}

test "Refusals (anon_ret.zig offset 14, bad.go offset 29) and usingnamespace ignore" {
    const gpa = std.testing.allocator;
    var host_fs = fsys.HostFS.init(std.testing.io);
    const fs = host_fs.fs();

    const RefuseCase = struct { file: []const u8, code: []const u8, off: usize };
    const cases = [_]RefuseCase{
        .{ .file = "anon_ret.zig", .code = "parse_unsupported", .off = 14 },
        .{ .file = "bad.go", .code = "syntax", .off = 29 },
    };
    for (cases) |tc| {
        const path = try std.fmt.allocPrint(gpa, "testdata/corpus/refuse/{s}", .{tc.file});
        defer gpa.free(path);
        const src = try fs.readFile(gpa, path, store.MaxFileReadBytes);
        defer gpa.free(src);

        var perr: ?parser.ParseErrorInfo = null;
        try std.testing.expectError(
            error.ParseFailed,
            parser.parseFile(gpa, tc.file, src, null, &perr),
        );
        try std.testing.expect(perr != null);
        try std.testing.expectEqualStrings(tc.code, perr.?.code);
        try std.testing.expectEqual(tc.off, perr.?.offset);
    }

    var perr: ?parser.ParseErrorInfo = null;
    const atoms = try parser.parseFile(
        gpa,
        "legacy.zig",
        "pub usingnamespace @import(\"other.zig\");\npub fn kept() void {}\n",
        null,
        &perr,
    );
    defer parser.freeAtoms(gpa, atoms);
    try std.testing.expectEqual(@as(usize, 1), atoms.len);
    try std.testing.expectEqualStrings("legacy.kept", atoms[0].name);
}

test "CLI parse-corpus on Zig files" {
    const gpa = std.testing.allocator;
    var host_fs = fsys.HostFS.init(std.testing.io);
    const fs = host_fs.fs();
    const sample_src = try fs.readFile(gpa, "testdata/corpus/zig/sample.zig", store.MaxFileReadBytes);
    defer gpa.free(sample_src);

    var h = try TestHarness.init(gpa);
    defer h.deinit();
    const mfs = h.mem.fs();
    try mfs.writeFileSafe(gpa, "/corpus/zig/sample.zig", sample_src);

    const res = try h.runCmd(&.{ "parse-corpus", "/corpus" });
    defer gpa.free(res.out);
    try std.testing.expectEqual(@as(u8, 0), res.rc);

    var line_count: usize = 0;
    var it = std.mem.splitScalar(u8, std.mem.trimEnd(u8, res.out, "\n"), '\n');
    while (it.next()) |line| {
        if (line.len == 0) continue;
        line_count += 1;
        try std.testing.expect(std.mem.startsWith(u8, line, "zig/sample.zig\t"));
    }
    try std.testing.expectEqual(@as(usize, 6), line_count);
}

test "init layout and refusals" {
    const gpa = std.testing.allocator;
    var h = try TestHarness.init(gpa);
    defer h.deinit();
    const mfs = h.mem.fs();
    try mfs.mkdir(gpa, "/host/src");

    // 1. Fresh init creates streams/<id>.json, ws/w/WORKSPACE.json, and empty ws/w/ATOMS.jsonl.
    {
        const res = try h.runCmd(&.{ "init", "--name=w", "--src=/host/src" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expectEqualStrings("flint: init ok ws=w stream=main\n", res.out);
    }

    var idx = try store.loadStoreIndex(gpa, mfs, h.root);
    defer idx.deinit();
    try std.testing.expectEqual(@as(usize, 1), idx.streams.items.len);
    const st = idx.streams.items[0];
    try std.testing.expectEqualStrings("main", st.name);
    try std.testing.expect(st.head == null);
    try std.testing.expectEqual(h.now * 1000, st.created);

    try std.testing.expectEqual(@as(usize, 1), idx.workspaces.items.len);
    const ws = idx.workspaces.items[0];
    try std.testing.expectEqualStrings("w", ws.name);
    try std.testing.expectEqualStrings("/host/src", ws.src);
    try std.testing.expectEqualStrings(st.id, ws.stream);

    const atoms_data = try mfs.readFile(gpa, "/host/FLINT/ws/w/ATOMS.jsonl", store.MaxFileReadBytes);
    defer gpa.free(atoms_data);
    try std.testing.expectEqual(@as(usize, 0), atoms_data.len);

    // 2. Re-init same workspace -> refuse ws_exists.
    {
        const res = try h.runCmd(&.{ "init", "--name=w", "--src=/host/src" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse ws_exists\n", res.out);
    }

    // 3. Init different workspace while `main` stream exists -> refuse stream_exists main.
    {
        const res = try h.runCmd(&.{ "init", "--name=w2", "--src=/host/src" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse stream_exists main\n", res.out);
    }

    // 4. Missing src -> refuse src_missing.
    {
        const res = try h.runCmd(&.{ "init", "--name=w3", "--src=/host/missing" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse src_missing\n", res.out);
    }

    // 5. Invalid workspace name -> refuse usage (exit 2).
    {
        const res = try h.runCmd(&.{ "init", "--name=Bad_Name", "--src=/host/src" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 2), res.rc);
        try std.testing.expectEqualStrings("flint: refuse usage\n", res.out);
    }

    // 6. Clock unset -> refuse clock_unset on init.
    {
        var h2 = try TestHarness.init(gpa);
        defer h2.deinit();
        try h2.mem.fs().mkdir(gpa, "/host/src");
        h2.now = 0;
        const res = try h2.runCmd(&.{ "init", "--name=w", "--src=/host/src" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse clock_unset\n", res.out);
    }
}

test "add idempotent, edits, and full 245-atom corpus" {
    const gpa = std.testing.allocator;
    var host_fs = fsys.HostFS.init(std.testing.io);
    const hfs = host_fs.fs();

    const sample_go = try hfs.readFile(gpa, "testdata/corpus/go/sample.go", store.MaxFileReadBytes);
    defer gpa.free(sample_go);
    const sample_zig = try hfs.readFile(gpa, "testdata/corpus/zig/sample.zig", store.MaxFileReadBytes);
    defer gpa.free(sample_zig);

    var h = try TestHarness.init(gpa);
    defer h.deinit();
    const mfs = h.mem.fs();
    try mfs.writeFileSafe(gpa, "/host/src/go/sample.go", sample_go);
    try mfs.writeFileSafe(gpa, "/host/src/zig/sample.zig", sample_zig);

    {
        const res = try h.runCmd(&.{ "init", "--name=w", "--src=/host/src" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }

    // 1. Add go/sample.go -> 4 new Atoms.
    {
        const res = try h.runCmd(&.{ "add", "/host/src/go/sample.go" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expectEqualStrings("flint: add files=1 new=4 modified=0 deleted=0 unchanged=0\n", res.out);
    }

    const atoms1 = try store.loadWorkspaceAtoms(gpa, mfs, h.root, "w");
    defer store.freeStoredAtoms(gpa, atoms1);
    try std.testing.expectEqual(@as(usize, 4), atoms1.len);

    var id_by_name = std.StringHashMap([]u8).init(gpa);
    defer {
        var it = id_by_name.iterator();
        while (it.next()) |kv| gpa.free(kv.value_ptr.*);
        id_by_name.deinit();
    }
    var orig_add_hash: []u8 = &.{};
    defer if (orig_add_hash.len > 0) gpa.free(orig_add_hash);
    var orig_add_sig_hash: []u8 = &.{};
    defer if (orig_add_sig_hash.len > 0) gpa.free(orig_add_sig_hash);

    for (atoms1) |a| {
        try id_by_name.put(a.name, try gpa.dupe(u8, a.id));
        if (std.mem.eql(u8, a.name, "sample.Add")) {
            orig_add_hash = try gpa.dupe(u8, a.hash);
            orig_add_sig_hash = try gpa.dupe(u8, a.sig_hash);
        }
    }

    const stage1 = try mfs.readFile(gpa, "/host/FLINT/ws/w/STAGE.jsonl", store.MaxFileReadBytes);
    defer gpa.free(stage1);

    // 2. Re-add go/sample.go -> 0 new, 4 unchanged; Atom IDs and STAGE.jsonl byte-identical.
    {
        const res = try h.runCmd(&.{ "add", "/host/src/go/sample.go" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expectEqualStrings("flint: add files=1 new=0 modified=0 deleted=0 unchanged=4\n", res.out);
    }

    const atoms2 = try store.loadWorkspaceAtoms(gpa, mfs, h.root, "w");
    defer store.freeStoredAtoms(gpa, atoms2);
    for (atoms2) |a| {
        try std.testing.expectEqualStrings(id_by_name.get(a.name).?, a.id);
    }
    const stage2 = try mfs.readFile(gpa, "/host/FLINT/ws/w/STAGE.jsonl", store.MaxFileReadBytes);
    defer gpa.free(stage2);
    try std.testing.expectEqualStrings(stage1, stage2);

    // 3. Add zig/sample.zig -> 6 new Atoms (total 10 in ATOMS.jsonl).
    {
        const res = try h.runCmd(&.{ "add", "/host/src/zig/sample.zig" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expectEqualStrings("flint: add files=1 new=6 modified=0 deleted=0 unchanged=0\n", res.out);
    }

    // Simulate a commit having cleared STAGE.jsonl so subsequent edits produce modify + delete ops.
    try mfs.remove(gpa, "/host/FLINT/ws/w/STAGE.jsonl");

    // 4. Edit sample.go (`Add` body changed, `Answer` removed) and sample.zig (comment/whitespace only).
    try mfs.writeFileSafe(
        gpa,
        "/host/src/go/sample.go",
        "package sample\n\ntype Point struct {\n\tX, Y int\n}\n\nfunc Add(a, b int) int {\n\treturn a + b + 1\n}\n\nfunc Mul(a, b int) int {\n\treturn a * b\n}\n",
    );
    const zig_with_comment = try std.fmt.allocPrint(gpa, "// formatting-only edit\n\n{s}\n", .{sample_zig});
    defer gpa.free(zig_with_comment);
    try mfs.writeFileSafe(gpa, "/host/src/zig/sample.zig", zig_with_comment);

    {
        const res = try h.runCmd(&.{"add"});
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expectEqualStrings("flint: add files=2 new=0 modified=1 deleted=1 unchanged=8\n", res.out);
    }

    const stage_ops = try store.loadWorkspaceStage(gpa, mfs, h.root, "w");
    defer store.freeOps(gpa, stage_ops);
    try std.testing.expectEqual(@as(usize, 2), stage_ops.len);

    var saw_mod = false;
    var saw_del = false;
    for (stage_ops) |op| {
        if (std.mem.eql(u8, op.type, "modify")) {
            saw_mod = true;
            try std.testing.expectEqualStrings(id_by_name.get("sample.Add").?, op.atom_id);
            try std.testing.expectEqualStrings(orig_add_hash, op.old_hash);
            try std.testing.expect(!std.mem.eql(u8, orig_add_hash, op.new_hash));
            try std.testing.expectEqualStrings(orig_add_sig_hash, op.new_sig_hash);
        } else if (std.mem.eql(u8, op.type, "delete")) {
            saw_del = true;
            try std.testing.expectEqualStrings(id_by_name.get("sample.Answer").?, op.atom_id);
            try std.testing.expect(op.old_hash.len > 0);
        }
    }
    try std.testing.expect(saw_mod and saw_del);

    // 5. Full 100-file / 245-atom corpus add + idempotent re-add on HostFS + MemFS.
    var h_full = try TestHarness.init(gpa);
    defer h_full.deinit();
    const mfs_full = h_full.mem.fs();

    for ([_][]const u8{ "go", "zig" }) |sub| {
        const dir = try std.fmt.allocPrint(gpa, "testdata/corpus/{s}", .{sub});
        defer gpa.free(dir);
        const entries = try hfs.list(gpa, dir);
        defer fsys.FS.freeDirEntries(gpa, entries);
        for (entries) |e| {
            if (e.is_dir) continue;
            const disk_path = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ dir, e.name });
            defer gpa.free(disk_path);
            const content = try hfs.readFile(gpa, disk_path, store.MaxFileReadBytes);
            defer gpa.free(content);
            const mem_path = try std.fmt.allocPrint(gpa, "/host/corpus/{s}/{s}", .{ sub, e.name });
            defer gpa.free(mem_path);
            try mfs_full.writeFileSafe(gpa, mem_path, content);
        }
    }

    {
        const res = try h_full.runCmd(&.{ "init", "--name=c", "--src=/host/corpus" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }
    {
        const res = try h_full.runCmd(&.{ "add", "--ws=c" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expectEqualStrings("flint: add files=100 new=245 modified=0 deleted=0 unchanged=0\n", res.out);
    }
    {
        const res = try h_full.runCmd(&.{ "add", "--ws=c" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expectEqualStrings("flint: add files=100 new=0 modified=0 deleted=0 unchanged=245\n", res.out);
    }
    {
        const res = try h_full.runCmd(&.{ "status", "--ws=c" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expect(std.mem.indexOf(
            u8,
            res.out,
            "flint: status ws=c stream=main atoms=245 staged=245 add=245 modify=0 delete=0 duplicates=0\n",
        ) != null);
        try std.testing.expect(std.mem.indexOf(u8, res.out, "flint: stage … +181\n") != null);
    }
}

test "stage fold rules and status" {
    const gpa = std.testing.allocator;
    var host_fs = fsys.HostFS.init(std.testing.io);
    const hfs = host_fs.fs();
    const sample_go = try hfs.readFile(gpa, "testdata/corpus/go/sample.go", store.MaxFileReadBytes);
    defer gpa.free(sample_go);
    const sample_zig = try hfs.readFile(gpa, "testdata/corpus/zig/sample.zig", store.MaxFileReadBytes);
    defer gpa.free(sample_zig);

    var h = try TestHarness.init(gpa);
    defer h.deinit();
    const mfs = h.mem.fs();
    try mfs.writeFileSafe(gpa, "/host/src/go/sample.go", sample_go);
    try mfs.writeFileSafe(gpa, "/host/src/zig/sample.zig", sample_zig);

    {
        const res = try h.runCmd(&.{ "init", "--name=w", "--src=/host/src" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }
    {
        const res = try h.runCmd(&.{ "add", "/host/src/go/sample.go" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }

    // Rule 1 & 2: add + modify -> add (with updated hash); add + delete -> nothing (vanishes).
    try mfs.writeFileSafe(
        gpa,
        "/host/src/go/sample.go",
        "package sample\n\ntype Point struct {\n\tX, Y int\n}\n\nfunc Add(a, b int) int {\n\treturn a + b + 99\n}\n\nfunc Mul(a, b int) int {\n\treturn a * b\n}\n",
    );
    {
        const res = try h.runCmd(&.{ "add", "/host/src/go/sample.go" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expectEqualStrings("flint: add files=1 new=0 modified=1 deleted=1 unchanged=2\n", res.out);
    }

    const stage = try store.loadWorkspaceStage(gpa, mfs, h.root, "w");
    defer store.freeOps(gpa, stage);
    try std.testing.expectEqual(@as(usize, 3), stage.len);
    for (stage) |op| {
        try std.testing.expectEqualStrings("add", op.type);
        try std.testing.expect(!std.mem.eql(u8, op.new_name, "sample.Answer"));
    }

    // Status reflects 3 atoms, 3 staged (all add).
    {
        const res = try h.runCmd(&.{"status"});
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expect(std.mem.indexOf(
            u8,
            res.out,
            "flint: status ws=w stream=main atoms=3 staged=3 add=3 modify=0 delete=0 duplicates=0\n",
        ) != null);
        try std.testing.expect(std.mem.indexOf(u8, res.out, "flint: stage add sample.Add\n") != null);
    }

    // Rule 3 & 4: clear stage (as if committed), then modify + modify -> single modify with original old_hash;
    // then modify + delete -> single delete with original old_hash.
    try mfs.remove(gpa, "/host/FLINT/ws/w/STAGE.jsonl");
    const atoms_before = try store.loadWorkspaceAtoms(gpa, mfs, h.root, "w");
    defer store.freeStoredAtoms(gpa, atoms_before);
    var add_before_hash: []u8 = &.{};
    defer if (add_before_hash.len > 0) gpa.free(add_before_hash);
    for (atoms_before) |a| {
        if (std.mem.eql(u8, a.name, "sample.Add")) {
            add_before_hash = try gpa.dupe(u8, a.hash);
        }
    }

    try mfs.writeFileSafe(
        gpa,
        "/host/src/go/sample.go",
        "package sample\n\ntype Point struct {\n\tX, Y int\n}\n\nfunc Add(a, b int) int {\n\treturn a + b + 200\n}\n\nfunc Mul(a, b int) int {\n\treturn a * b\n}\n",
    );
    {
        const res = try h.runCmd(&.{ "add", "/host/src/go/sample.go" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }

    try mfs.writeFileSafe(
        gpa,
        "/host/src/go/sample.go",
        "package sample\n\ntype Point struct {\n\tX, Y int\n}\n\nfunc Add(a, b int) int {\n\treturn a + b + 300\n}\n\nfunc Mul(a, b int) int {\n\treturn a * b\n}\n",
    );
    {
        const res = try h.runCmd(&.{ "add", "/host/src/go/sample.go" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }

    const stage_mod = try store.loadWorkspaceStage(gpa, mfs, h.root, "w");
    defer store.freeOps(gpa, stage_mod);
    try std.testing.expectEqual(@as(usize, 1), stage_mod.len);
    try std.testing.expectEqualStrings("modify", stage_mod[0].type);
    try std.testing.expectEqualStrings(add_before_hash, stage_mod[0].old_hash);

    // Now delete Add -> modify + delete folds to delete with original old_hash.
    try mfs.writeFileSafe(
        gpa,
        "/host/src/go/sample.go",
        "package sample\n\ntype Point struct {\n\tX, Y int\n}\n\nfunc Mul(a, b int) int {\n\treturn a * b\n}\n",
    );
    {
        const res = try h.runCmd(&.{ "add", "/host/src/go/sample.go" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }

    const stage_del = try store.loadWorkspaceStage(gpa, mfs, h.root, "w");
    defer store.freeOps(gpa, stage_del);
    try std.testing.expectEqual(@as(usize, 1), stage_del.len);
    try std.testing.expectEqualStrings("delete", stage_del[0].type);
    try std.testing.expectEqualStrings(add_before_hash, stage_del[0].old_hash);

    // Also test disappeared file from directory: add zig/sample.zig, clear stage, remove zig/sample.zig, run add.
    {
        const res = try h.runCmd(&.{ "add", "/host/src/zig/sample.zig" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }
    try mfs.remove(gpa, "/host/FLINT/ws/w/STAGE.jsonl");
    try mfs.remove(gpa, "/host/src/zig/sample.zig");
    {
        const res = try h.runCmd(&.{"add"});
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expectEqualStrings("flint: add files=1 new=0 modified=0 deleted=6 unchanged=2\n", res.out);
    }
}

test "parse error and duplicate decl all-or-nothing" {
    const gpa = std.testing.allocator;
    var host_fs = fsys.HostFS.init(std.testing.io);
    const hfs = host_fs.fs();
    const sample_go = try hfs.readFile(gpa, "testdata/corpus/go/sample.go", store.MaxFileReadBytes);
    defer gpa.free(sample_go);
    const sample_zig = try hfs.readFile(gpa, "testdata/corpus/zig/sample.zig", store.MaxFileReadBytes);
    defer gpa.free(sample_zig);
    const bad_go = try hfs.readFile(gpa, "testdata/corpus/refuse/bad.go", store.MaxFileReadBytes);
    defer gpa.free(bad_go);

    var h = try TestHarness.init(gpa);
    defer h.deinit();
    const mfs = h.mem.fs();
    try mfs.writeFileSafe(gpa, "/host/src/go/a.go", sample_go);
    try mfs.writeFileSafe(gpa, "/host/src/go/b.go", bad_go);
    try mfs.writeFileSafe(gpa, "/host/src/zig/c.zig", sample_zig);

    {
        const res = try h.runCmd(&.{ "init", "--name=w", "--src=/host/src" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }

    // 1 of 3 files has a syntax error -> must refuse and stage 0 ops.
    {
        const res = try h.runCmd(&.{"add"});
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expect(std.mem.indexOf(u8, res.out, "flint: refuse syntax") != null);
        try std.testing.expect(std.mem.indexOf(u8, res.out, "go/b.go") != null);
    }
    try std.testing.expect(!mfs.exists(gpa, "/host/FLINT/ws/w/STAGE.jsonl"));
    const atoms = try store.loadWorkspaceAtoms(gpa, mfs, h.root, "w");
    defer store.freeStoredAtoms(gpa, atoms);
    try std.testing.expectEqual(@as(usize, 0), atoms.len);

    // Duplicate declaration in a file -> refuse duplicate_decl and stage 0 ops.
    try mfs.remove(gpa, "/host/src/go/b.go");
    try mfs.writeFileSafe(gpa, "/host/src/zig/dup.zig", "pub fn foo() void {}\npub fn foo() void {}\n");
    {
        const res = try h.runCmd(&.{"add"});
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expect(std.mem.indexOf(u8, res.out, "flint: refuse duplicate_decl zig/dup.zig") != null);
    }
    try std.testing.expect(!mfs.exists(gpa, "/host/FLINT/ws/w/STAGE.jsonl"));
}

test "torn line, store bounds, stale head, and guest store portability" {
    const gpa = std.testing.allocator;
    var h = try TestHarness.init(gpa);
    defer h.deinit();
    const mfs = h.mem.fs();
    try mfs.mkdir(gpa, "/host/src");

    {
        const res = try h.runCmd(&.{ "init", "--name=w", "--src=/host/src" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }

    // 1. Torn final line in ATOMS.jsonl -> refuse stream_torn.
    try mfs.writeFileSafe(gpa, "/host/FLINT/ws/w/ATOMS.jsonl", "{\"id\":\"x\",\"kind\":\"fn\",\"name\":\"p.F\"");
    {
        const res = try h.runCmd(&.{"status"});
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expect(std.mem.indexOf(u8, res.out, "flint: refuse stream_torn") != null);
    }

    // 2. File size bound (> 4 MiB) -> refuse store_too_large file.
    const big = try gpa.alloc(u8, store.MaxFileReadBytes + 16);
    defer gpa.free(big);
    @memset(big, 'a');
    try mfs.writeFileSafe(gpa, "/host/FLINT/ws/w/ATOMS.jsonl", big);
    {
        const res = try h.runCmd(&.{"status"});
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse store_too_large file\n", res.out);
    }

    // 3. Atoms bound (> 4096 Atoms) -> refuse store_too_large atoms.
    var many_atoms: Io.Writer.Allocating = .init(gpa);
    defer many_atoms.deinit();
    const line = "{\"id\":\"01950000-0000-7000-8000-000000000001\",\"kind\":\"fn\",\"name\":\"p.F\",\"hash\":\"00\",\"sig_hash\":\"00\",\"span\":{\"file\":\"a.go\",\"start\":0,\"end\":1}}\n";
    var k: usize = 0;
    while (k < store.MaxAtoms + 1) : (k += 1) {
        try many_atoms.writer.writeAll(line);
    }
    try mfs.writeFileSafe(gpa, "/host/FLINT/ws/w/ATOMS.jsonl", many_atoms.written());
    {
        const res = try h.runCmd(&.{"status"});
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse store_too_large atoms\n", res.out);
    }

    // 4. Stale head guard -> refuse stale_head.
    try mfs.writeFileSafe(gpa, "/host/FLINT/ws/w/ATOMS.jsonl", "");
    var idx = try store.loadStoreIndex(gpa, mfs, h.root);
    defer idx.deinit();
    const st = idx.streams.items[0];
    try std.testing.expectError(
        error.Refuse,
        store.checkStaleHead(gpa, mfs, h.root, st.id, "01950000-0000-7000-8000-ffffffffffff"),
    );
    try std.testing.expectEqualStrings("stale_head", fsys.last_refuse.code());

    // 5. Guest store portability: a workspace pointing to non-existent `/host/guest-only-src`
    // does not prevent `init --name=hostws --src=/host/src --stream=main` from replaying `main`.
    try store.writeWorkspaceConfig(gpa, mfs, h.root, .{
        .name = "w",
        .src = "/host/guest-only-src",
        .stream = st.id,
        .created = 1760000000000,
    });
    {
        const res = try h.runCmd(&.{ "init", "--name=hostws", "--src=/host/src", "--stream=main" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expectEqualStrings("flint: init ok ws=hostws stream=main atoms=0 replayed=0\n", res.out);
    }
}

test "HostFS writeFileSafe and appendSync crash-safe file operations" {
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_abs = try tmp.dir.realPathFileAlloc(std.testing.io, ".", gpa);
    defer gpa.free(tmp_abs);

    var host_fs = fsys.HostFS.init(std.testing.io);
    const fs = host_fs.fs();

    const target = try std.fmt.allocPrint(gpa, "{s}/nested/ATOMS.jsonl", .{tmp_abs});
    defer gpa.free(target);

    try fs.writeFileSafe(gpa, target, "line1\n");
    try fs.appendSync(gpa, target, "line2\n");

    const data = try fs.readFile(gpa, target, store.MaxFileReadBytes);
    defer gpa.free(data);
    try std.testing.expectEqualStrings("line1\nline2\n", data);

    // Ensure no leftover `.tmp-*` file remains in `nested/`.
    const nested_dir = try std.fmt.allocPrint(gpa, "{s}/nested", .{tmp_abs});
    defer gpa.free(nested_dir);
    const entries = try fs.list(gpa, nested_dir);
    defer fsys.FS.freeDirEntries(gpa, entries);
    try std.testing.expectEqual(@as(usize, 1), entries.len);
    try std.testing.expectEqualStrings("ATOMS.jsonl", entries[0].name);
}

