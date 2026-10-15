const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const fsys = @import("fsys.zig");
pub const uuid = @import("uuid.zig");
pub const store = @import("store.zig");
pub const json = @import("json.zig");
pub const ed25519 = @import("ed25519.zig");

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
        if (sub.len != 1 or sub[0].len == 0) {
            printUsage(ctx.stdout);
            return 2;
        }
        return handleErr(fsys.refuse("usage", ""), ctx.stdout);
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
    ) catch |err| {
        return handleErr(err, ctx.stdout);
    };
    defer ctx.allocator.free(root);

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
