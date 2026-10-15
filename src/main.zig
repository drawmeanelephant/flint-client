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
pub const sign = @import("sign.zig");
pub const merge = @import("merge.zig");
pub const sync = @import("sync.zig");

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
    env_flint_auth_key: ?[]const u8 = null,
    sync_dial: ?sync.DialFn = null,
    sync_dial_ctx: ?*anyopaque = null,
};

/// Returns the shell's logical cwd ($PWD) when it resolves to the same
/// directory as getcwd, else the physical path. Messages that name the cwd
/// (`store_not_found`) then show the path the user typed rather than a
/// canonicalized one (`/private/var/...` on macOS).
fn logicalCwd(io: Io, arena: Allocator, pwd: ?[]const u8) []const u8 {
    const phys = std.process.currentPathAlloc(io, arena) catch return ".";
    const p = pwd orelse return phys;
    if (p.len == 0 or p[0] != '/') return phys;
    const clean_p = fsys.cleanPath(arena, p) catch return phys;
    const phys_st = Io.Dir.statFile(.cwd(), io, phys, .{}) catch return phys;
    const pwd_st = Io.Dir.statFile(.cwd(), io, clean_p, .{}) catch return phys;
    if (pwd_st.kind != .directory or pwd_st.inode != phys_st.inode) return phys;
    return clean_p;
}

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
    const cwd = logicalCwd(init.io, arena, init.environ_map.get("PWD"));

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
        .env_flint_auth_key = init.environ_map.get("FLINT_AUTH_KEY"),
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
        \\  clone <remote> --stream=<s> --name=<n> --src=<dir> [--auth-key=<file>]
        \\  push [--remote=<url>] [--stream=<s>] [--ws=<n>] [--auth-key=<file>]
        \\  pull [--remote=<url>] [--stream=<s>] [--ws=<n>] [--auth-key=<file>] [--reset]
        \\  parse-corpus <dir>
        \\  keygen [--name=<n>]
        \\
        \\note: passing a 64-hex seed literal via --key or FLINT_SIGN_KEY exposes
        \\it in /proc/<pid>/environ, ps output, and shell history; prefer key names
        \\stored under <store>/keys/<name>.
        \\
    ) catch {};
}

/// Maps common host/transport error names to lowercase phrases so `flint:
/// error` lines read like the Go implementation's console messages instead
/// of leaking raw Zig error names. Unmapped names print verbatim.
fn friendlyErrorName(err: anyerror) []const u8 {
    return switch (err) {
        error.ConnectionRefused => "connection refused",
        error.ConnectionResetByPeer => "connection reset by peer",
        error.ConnectionTimedOut => "connection timed out",
        error.UnknownHostName => "unknown host",
        error.NameServerFailure => "name resolution failed",
        error.HostUnreachable => "host unreachable",
        error.NetworkUnreachable => "network unreachable",
        error.NetworkDown => "network down",
        error.EndOfStream => "connection closed",
        error.BrokenPipe => "broken pipe",
        error.AddressNotAvailable => "address not available",
        error.AddressInUse => "address already in use",
        error.AccessDenied => "access denied",
        error.FileNotFound => "file not found",
        error.NotDir => "not a directory",
        error.IsDir => "is a directory",
        error.OutOfMemory => "out of memory",
        else => @errorName(err),
    };
}

pub fn handleErr(err: anyerror, out: *Io.Writer) u8 {
    if (err == error.Refuse) {
        fsys.writeRefuseLine(out);
        if (std.mem.eql(u8, fsys.last_refuse.code(), "usage")) {
            return 2;
        }
        return 1;
    }
    if (fsys.err_context) |*ec| {
        out.print("flint: error {s} {s}: {s}\n", .{ ec.verb(), ec.remote(), friendlyErrorName(err) }) catch {};
    } else {
        out.print("flint: error {s}\n", .{friendlyErrorName(err)}) catch {};
    }
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
    fsys.clearErrContext();
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
        return render.cmdParseCorpus(ctx.allocator, ctx.fs, sub, ctx.stdout) catch |err| {
            return handleErr(err, ctx.stdout);
        };
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

    if (std.mem.eql(u8, verb, "commit")) {
        sign.cmdCommit(ctx.allocator, ctx.fs, root, uuid_gen, ctx.env_flint_sign_key, ctx.stdout, sub) catch |err| {
            return handleErr(err, ctx.stdout);
        };
        return 0;
    }

    if (std.mem.eql(u8, verb, "log")) {
        sign.cmdLog(ctx.allocator, ctx.fs, root, ctx.stdout, sub) catch |err| {
            return handleErr(err, ctx.stdout);
        };
        return 0;
    }

    if (std.mem.eql(u8, verb, "fork")) {
        merge.cmdFork(ctx.allocator, ctx.fs, root, uuid_gen, ctx.stdout, sub) catch |err| {
            return handleErr(err, ctx.stdout);
        };
        return 0;
    }

    if (std.mem.eql(u8, verb, "merge")) {
        return merge.cmdMerge(ctx.allocator, ctx.fs, root, uuid_gen, ctx.env_flint_sign_key, ctx.stdout, sub) catch |err| {
            return handleErr(err, ctx.stdout);
        };
    }

    const dial_fn = ctx.sync_dial orelse sync.defaultTcpDial;

    if (std.mem.eql(u8, verb, "clone")) {
        sync.cmdClone(
            ctx.allocator,
            ctx.io,
            ctx.fs,
            root,
            ctx.env_flint_remote,
            ctx.env_flint_auth_key,
            dial_fn,
            ctx.sync_dial_ctx,
            ctx.stdout,
            sub,
        ) catch |err| {
            return handleErr(err, ctx.stdout);
        };
        return 0;
    }

    if (std.mem.eql(u8, verb, "push")) {
        sync.cmdPush(
            ctx.allocator,
            ctx.io,
            ctx.fs,
            root,
            ctx.env_flint_remote,
            ctx.env_flint_auth_key,
            dial_fn,
            ctx.sync_dial_ctx,
            ctx.stdout,
            sub,
        ) catch |err| {
            return handleErr(err, ctx.stdout);
        };
        return 0;
    }

    if (std.mem.eql(u8, verb, "pull")) {
        sync.cmdPull(
            ctx.allocator,
            ctx.io,
            ctx.fs,
            root,
            ctx.env_flint_remote,
            ctx.env_flint_auth_key,
            dial_fn,
            ctx.sync_dial_ctx,
            ctx.stdout,
            sub,
        ) catch |err| {
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
    _ = sign;
    _ = merge;
    _ = sync;
}

const TestHarness = struct {
    allocator: Allocator,
    mem: fsys.MemFS,
    uuid_gen: uuid.UUIDGen,
    now: i64 = 1760000000,
    rng_seed: u8 = 1,
    root: []const u8 = "/host/FLINT",
    cwd: []const u8 = "/host",
    env_sign_key: ?[]const u8 = null,
    env_remote: ?[]const u8 = null,
    env_auth_key: ?[]const u8 = null,
    sync_dial: ?sync.DialFn = null,
    sync_dial_ctx: ?*anyopaque = null,

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
            .env_flint_sign_key = self.env_sign_key,
            .env_flint_remote = self.env_remote,
            .env_flint_auth_key = self.env_auth_key,
            .sync_dial = self.sync_dial,
            .sync_dial_ctx = self.sync_dial_ctx,
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

    // Verify `flint parse-corpus testdata/corpus` writes testdata/corpus.OUT matching MANIFEST.json byte-for-byte
    // and prints the spec summary line.
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
    defer std.Io.Dir.cwd().deleteFile(std.testing.io, "testdata/corpus.OUT") catch {};
    const rc = runWithContext(ctx, &.{ "parse-corpus", "testdata/corpus" });
    try std.testing.expectEqual(@as(u8, 0), rc);
    try std.testing.expectEqualStrings("flint: parse files=100 atoms=245 parse_errors=0\n", out_w.written());
    const out_bytes = try fs.readFile(gpa, "testdata/corpus.OUT", store.MaxFileReadBytes);
    defer gpa.free(out_bytes);
    try std.testing.expectEqualStrings(want_rendered.items, out_bytes);

    // Verify `flint parse-corpus testdata/corpus/refuse` counts parse_errors without aborting
    // and returns non-zero exit code.
    var refuse_out_w: Io.Writer.Allocating = .init(gpa);
    defer refuse_out_w.deinit();
    const refuse_ctx = Context{
        .allocator = gpa,
        .io = std.testing.io,
        .fs = fs,
        .stdout = &refuse_out_w.writer,
        .stderr = &err_w.writer,
    };
    defer std.Io.Dir.cwd().deleteFile(std.testing.io, "testdata/corpus/refuse.OUT") catch {};
    const refuse_rc = runWithContext(refuse_ctx, &.{ "parse-corpus", "testdata/corpus/refuse" });
    try std.testing.expectEqual(@as(u8, 1), refuse_rc);
    try std.testing.expectEqualStrings("flint: parse files=2 atoms=0 parse_errors=2\n", refuse_out_w.written());

    // Verify missing/extra args refuse with `usage` (exit code 2).
    var bad_out_w: Io.Writer.Allocating = .init(gpa);
    defer bad_out_w.deinit();
    const bad_ctx = Context{
        .allocator = gpa,
        .io = std.testing.io,
        .fs = fs,
        .stdout = &bad_out_w.writer,
        .stderr = &err_w.writer,
    };
    const bad_rc = runWithContext(bad_ctx, &.{"parse-corpus"});
    try std.testing.expectEqual(@as(u8, 2), bad_rc);
    try std.testing.expectEqualStrings("flint: refuse usage\n", bad_out_w.written());
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

    // Go ungrouped `const x int` (missing `= value`) refuses `syntax`.
    var const_perr: ?parser.ParseErrorInfo = null;
    try std.testing.expectError(
        error.ParseFailed,
        parser.parseFile(gpa, "bad_const.go", "package p\nconst x int\n", null, &const_perr),
    );
    try std.testing.expect(const_perr != null);
    try std.testing.expectEqualStrings("syntax", const_perr.?.code);

    // Go `func Testabc(t *testing.T)` (lowercase after `Test`) is `fn`, while `TestAbc` is `test`.
    var test_perr: ?parser.ParseErrorInfo = null;
    const test_atoms = try parser.parseFile(
        gpa,
        "t_test.go",
        "package p\nimport \"testing\"\nfunc Testabc(t *testing.T) {}\nfunc TestAbc(t *testing.T) {}\n",
        null,
        &test_perr,
    );
    defer parser.freeAtoms(gpa, test_atoms);
    try std.testing.expectEqual(@as(usize, 2), test_atoms.len);
    try std.testing.expectEqualStrings("fn", test_atoms[0].kind);
    try std.testing.expectEqualStrings("p.Testabc", test_atoms[0].name);
    try std.testing.expectEqualStrings("test", test_atoms[1].kind);
    try std.testing.expectEqualStrings("p.test:TestAbc", test_atoms[1].name);

    // Zig function with inline error set in return type `error{Bad}!i32` parses as `fn`.
    var zig_err_perr: ?parser.ParseErrorInfo = null;
    const zig_err_atoms = try parser.parseFile(
        gpa,
        "err_ret.zig",
        "pub fn f() error{Bad}!i32 { return 0; }\n",
        null,
        &zig_err_perr,
    );
    defer parser.freeAtoms(gpa, zig_err_atoms);
    try std.testing.expectEqual(@as(usize, 1), zig_err_atoms.len);
    try std.testing.expectEqualStrings("fn", zig_err_atoms[0].kind);
    try std.testing.expectEqualStrings("err_ret.f", zig_err_atoms[0].name);
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
    try std.testing.expectEqualStrings("flint: parse files=1 atoms=6 parse_errors=0\n", res.out);

    const out_bytes = try mfs.readFile(gpa, "/corpus.OUT", store.MaxFileReadBytes);
    defer gpa.free(out_bytes);

    var line_count: usize = 0;
    var it = std.mem.splitScalar(u8, std.mem.trimEnd(u8, out_bytes, "\n"), '\n');
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

    // 4. Missing src or non-directory src -> refuse src_missing.
    {
        const res = try h.runCmd(&.{ "init", "--name=w3", "--src=/host/missing" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse src_missing\n", res.out);
    }
    try mfs.writeFileSafe(gpa, "/host/not_a_dir.go", "package p\n");
    {
        const res = try h.runCmd(&.{ "init", "--name=w3", "--src=/host/not_a_dir.go" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse src_missing\n", res.out);
    }

    // 4b. Store-root discovery ignores regular files named `.flint` or `FLINT`.
    try mfs.writeFileSafe(gpa, "/host/src/sub/.flint", "not a dir\n");
    try mfs.writeFileSafe(gpa, "/host/src/sub/FLINT", "not a dir\n");
    {
        const resolved = try store.resolveStoreRoot(gpa, mfs, "", null, "/host/src/sub");
        defer gpa.free(resolved);
        try std.testing.expectEqualStrings("/host/FLINT", resolved);
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

    // Untracked nonexistent directory/extensionless arg -> refuse src_missing.
    {
        const res = try h.runCmd(&.{ "add", "/host/src/nonexistent_dir" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse src_missing /host/src/nonexistent_dir\n", res.out);
    }

    // Disappeared directory arg with tracked files -> stages deletes for its tracked files.
    try mfs.writeFileSafe(gpa, "/host/src/sub/mod.zig", sample_zig);
    {
        const res = try h.runCmd(&.{ "add", "/host/src/sub" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expectEqualStrings("flint: add files=1 new=6 modified=0 deleted=0 unchanged=0\n", res.out);
    }
    try mfs.remove(gpa, "/host/FLINT/ws/w/STAGE.jsonl");
    try mfs.remove(gpa, "/host/src/sub/mod.zig");
    try mfs.remove(gpa, "/host/src/sub");
    {
        const res = try h.runCmd(&.{ "add", "/host/src/sub" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expectEqualStrings("flint: add files=0 new=0 modified=0 deleted=6 unchanged=0\n", res.out);
    }

    // Missing ws.src root (when entire src tree vanishes) -> flint add (no args) stages deletes
    // for the remaining tracked files instead of silently printing 0s.
    try mfs.remove(gpa, "/host/FLINT/ws/w/STAGE.jsonl");
    try mfs.remove(gpa, "/host/src/go/sample.go");
    try mfs.remove(gpa, "/host/src/go");
    try mfs.remove(gpa, "/host/src/zig");
    try mfs.remove(gpa, "/host/src");
    {
        const res = try h.runCmd(&.{"add"});
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expectEqualStrings("flint: add files=0 new=0 modified=0 deleted=2 unchanged=0\n", res.out);
    }
    // Once no atoms remain tracked and ws.src is still missing, flint add refuses src_missing.
    {
        const res = try h.runCmd(&.{"add"});
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse src_missing /host/src\n", res.out);
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
    const anon_ret_zig = try hfs.readFile(gpa, "testdata/corpus/refuse/anon_ret.zig", store.MaxFileReadBytes);
    defer gpa.free(anon_ret_zig);

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

    // 1 of 3 files has a syntax error -> must refuse with :<offset> and stage 0 ops.
    {
        const res = try h.runCmd(&.{"add"});
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse syntax go/b.go:29\n", res.out);
    }
    try std.testing.expect(!mfs.exists(gpa, "/host/FLINT/ws/w/STAGE.jsonl"));
    const atoms = try store.loadWorkspaceAtoms(gpa, mfs, h.root, "w");
    defer store.freeStoredAtoms(gpa, atoms);
    try std.testing.expectEqual(@as(usize, 0), atoms.len);

    // parse_unsupported refusal also includes :<offset> suffix.
    try mfs.remove(gpa, "/host/src/go/b.go");
    try mfs.writeFileSafe(gpa, "/host/src/zig/anon_ret.zig", anon_ret_zig);
    {
        const res = try h.runCmd(&.{"add"});
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse parse_unsupported zig/anon_ret.zig:14\n", res.out);
    }
    try mfs.remove(gpa, "/host/src/zig/anon_ret.zig");

    // Duplicate declaration in a file -> refuse duplicate_decl and stage 0 ops.
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

    // 1b. Empty line in ATOMS.jsonl -> refuse atom_malformed; empty line in STAGE.jsonl -> refuse stage_malformed.
    try mfs.writeFileSafe(gpa, "/host/FLINT/ws/w/ATOMS.jsonl", "\n");
    {
        const res = try h.runCmd(&.{"status"});
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse atom_malformed\n", res.out);
    }
    try mfs.writeFileSafe(gpa, "/host/FLINT/ws/w/ATOMS.jsonl", "");
    try mfs.writeFileSafe(gpa, "/host/FLINT/ws/w/STAGE.jsonl", "\n");
    {
        const res = try h.runCmd(&.{"status"});
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse stage_malformed\n", res.out);
    }
    try mfs.remove(gpa, "/host/FLINT/ws/w/STAGE.jsonl");

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

const rfc8032_seed_hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const rfc8032_pub_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

test "commit, log, verify, and roll-forward" {
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
    {
        const res = try h.runCmd(&.{ "add", "/host/src" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }

    var idx = try store.loadStoreIndex(gpa, mfs, h.root);
    defer idx.deinit();
    const ws = idx.workspaces.items[0];
    const rec_path = try store.streamRecordPath(gpa, h.root, ws.stream);
    defer gpa.free(rec_path);
    const log_path = try store.streamLogPath(gpa, h.root, ws.stream);
    defer gpa.free(log_path);

    // 1. Inject a fault AFTER the append to streams/<id>.jsonl and BEFORE rewriting streams/<id>.json.
    const FaultCtx = struct {
        rec_path: []const u8,
        fn beforeWrite(ctx: ?*anyopaque, op: []const u8, path: []const u8) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            if (std.mem.eql(u8, op, "write") and std.mem.eql(u8, path, self.rec_path)) {
                return error.SimulatedCrashBeforeRecordRewrite;
            }
        }
    };
    var fctx = FaultCtx{ .rec_path = rec_path };
    h.mem.before_write_ctx = &fctx;
    h.mem.before_write = FaultCtx.beforeWrite;

    {
        const res = try h.runCmd(&.{ "commit", "-m", "first commit\nextra detail" });
        defer gpa.free(res.out);
        h.mem.before_write = null;
        try std.testing.expectEqual(@as(u8, 1), res.rc);
    }

    // Verify the stream log was written, while the stream record still has head == null.
    try std.testing.expect(mfs.exists(gpa, log_path));
    const raw_rec = try mfs.readFile(gpa, rec_path, store.MaxFileReadBytes);
    defer gpa.free(raw_rec);
    const stale_st = try json.parseStream(gpa, raw_rec);
    defer stale_st.deinit(gpa);
    try std.testing.expect(stale_st.head == null);

    // Next `flint log` rolls the stale record forward and prints the first line of the message!
    var first_id: []u8 = &.{};
    defer if (first_id.len > 0) gpa.free(first_id);
    {
        const res = try h.runCmd(&.{"log"});
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);

        const loaded = try store.loadStream(gpa, mfs, h.root, ws.stream);
        defer loaded.deinit(gpa);
        try std.testing.expectEqual(@as(usize, 1), loaded.changes.len);
        try std.testing.expect(loaded.stream.head != null);
        try std.testing.expectEqualStrings(loaded.changes[0].id, loaded.stream.head.?);
        first_id = try gpa.dupe(u8, loaded.changes[0].id);

        const want_log0 = try std.fmt.allocPrint(
            gpa,
            "flint: change {s} parent=none ops=4 author={s} msg=first commit\n",
            .{ first_id, rfc8032_pub_hex[0..8] },
        );
        defer gpa.free(want_log0);
        try std.testing.expectEqualStrings(want_log0, res.out);
    }

    // Clean up STAGE.jsonl left from the simulated crash and perform a second linear commit.
    const stage_path = try store.workspaceStagePath(gpa, h.root, "w");
    defer gpa.free(stage_path);
    try mfs.remove(gpa, stage_path);

    try mfs.writeFileSafe(
        gpa,
        "/host/src/go/sample.go",
        "package sample\n\ntype Point struct { X, Y int }\nfunc Add(a, b int) int { return a - b }\nfunc Mul(a, b int) int { return a * b }\n",
    );
    h.now += 5;
    {
        const res = try h.runCmd(&.{ "add", "/host/src" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }
    {
        const res = try h.runCmd(&.{ "commit", "-m", "second commit" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expect(std.mem.startsWith(u8, res.out, "flint: commit ok id="));
        const want_suffix = try std.fmt.allocPrint(gpa, " ops=2 parent={s}\n", .{first_id});
        defer gpa.free(want_suffix);
        try std.testing.expect(std.mem.endsWith(u8, res.out, want_suffix));
    }
    try std.testing.expect(!mfs.exists(gpa, stage_path));

    // `flint log --stream=main` prints newest first (2 lines).
    var second_id: []u8 = &.{};
    defer if (second_id.len > 0) gpa.free(second_id);
    {
        const loaded = try store.loadStream(gpa, mfs, h.root, ws.stream);
        defer loaded.deinit(gpa);
        try std.testing.expectEqual(@as(usize, 2), loaded.changes.len);
        second_id = try gpa.dupe(u8, loaded.changes[1].id);

        const res = try h.runCmd(&.{ "log", "--stream=main" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        const want_log = try std.fmt.allocPrint(
            gpa,
            "flint: change {s} parent={s} ops=2 author={s} msg=second commit\nflint: change {s} parent=none ops=4 author={s} msg=first commit\n",
            .{ second_id, first_id, rfc8032_pub_hex[0..8], first_id, rfc8032_pub_hex[0..8] },
        );
        defer gpa.free(want_log);
        try std.testing.expectEqualStrings(want_log, res.out);
    }

    // `flint verify --all` and `flint verify <id>` both verify.
    {
        const res = try h.runCmd(&.{ "verify", "--all" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        const want = try std.fmt.allocPrint(
            gpa,
            "flint: verify {s} sig: verified\nflint: verify {s} sig: verified\n",
            .{ first_id, second_id },
        );
        defer gpa.free(want);
        try std.testing.expectEqualStrings(want, res.out);
    }
    {
        const res = try h.runCmd(&.{ "verify", second_id });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        const want = try std.fmt.allocPrint(gpa, "flint: verify {s} sig: verified\n", .{second_id});
        defer gpa.free(want);
        try std.testing.expectEqualStrings(want, res.out);
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

    // 1. nothing_to_commit when stage is empty.
    {
        const res = try h.runCmd(&.{ "commit", "-m", "empty" });
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
    const stage_before = try mfs.readFile(gpa, stage_path, store.MaxFileReadBytes);
    defer gpa.free(stage_before);

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
    try std.testing.expect(!mfs.exists(gpa, log_path));
    try std.testing.expect(mfs.exists(gpa, stage_path));
    const stage_after = try mfs.readFile(gpa, stage_path, store.MaxFileReadBytes);
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
    try std.testing.expect(!mfs.exists(gpa, log_path));

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

fn opsSliceEqual(a: []const store.Op, b: []const store.Op) bool {
    if (a.len != b.len) return false;
    for (a, b) |oa, ob| {
        if (!std.mem.eql(u8, oa.type, ob.type) or
            !std.mem.eql(u8, oa.atom_id, ob.atom_id) or
            !std.mem.eql(u8, oa.kind, ob.kind) or
            !std.mem.eql(u8, oa.new_name, ob.new_name) or
            !merge.spansEqual(oa.new_span, ob.new_span) or
            !std.mem.eql(u8, oa.new_hash, ob.new_hash) or
            !std.mem.eql(u8, oa.new_sig_hash, ob.new_sig_hash) or
            !std.mem.eql(u8, oa.old_hash, ob.old_hash))
        {
            return false;
        }
    }
    return true;
}

fn parseStoredAtomValue(allocator: Allocator, val: std.json.Value) !store.StoredAtom {
    if (val != .object) return error.InvalidJson;
    const obj = val.object;
    const id = try allocator.dupe(u8, obj.get("id").?.string);
    errdefer allocator.free(id);
    const kind = try allocator.dupe(u8, obj.get("kind").?.string);
    errdefer allocator.free(kind);
    const name = try allocator.dupe(u8, obj.get("name").?.string);
    errdefer allocator.free(name);
    const hash = try allocator.dupe(u8, obj.get("hash").?.string);
    errdefer allocator.free(hash);
    const sig_hash = if (obj.get("sig_hash")) |sh|
        (if (sh == .string) try allocator.dupe(u8, sh.string) else "")
    else
        "";
    errdefer if (sig_hash.len > 0) allocator.free(sig_hash);
    const sp = try json.parseSpanValue(allocator, obj.get("span").?);
    errdefer sp.deinit(allocator);
    return .{
        .id = id,
        .kind = kind,
        .name = name,
        .hash = hash,
        .sig_hash = sig_hash,
        .span = sp,
        .origin = "",
    };
}

test "merge scenarios (20 fixtures) and into<->from symmetry" {
    const gpa = std.testing.allocator;
    var host_fs = fsys.HostFS.init(std.testing.io);
    const hfs = host_fs.fs();

    const entries = try hfs.list(gpa, "testdata/merge");
    defer fsys.FS.freeDirEntries(gpa, entries);

    var scenario_count: usize = 0;
    for (entries) |e| {
        if (e.is_dir or !std.mem.endsWith(u8, e.name, ".json")) continue;
        scenario_count += 1;

        const path = try std.fmt.allocPrint(gpa, "testdata/merge/{s}", .{e.name});
        defer gpa.free(path);
        const raw = try hfs.readFile(gpa, path, store.MaxFileReadBytes);
        defer gpa.free(raw);

        var parsed = try std.json.parseFromSlice(std.json.Value, gpa, raw, .{});
        defer parsed.deinit();
        const root = parsed.value.object;
        const sc_name = root.get("name").?.string;

        const base_arr = root.get("base_atoms").?.array.items;
        var base_atoms: std.ArrayList(store.StoredAtom) = .empty;
        defer {
            for (base_atoms.items) |a| a.deinit(gpa);
            base_atoms.deinit(gpa);
        }
        for (base_arr) |item| {
            try base_atoms.append(gpa, try parseStoredAtomValue(gpa, item));
        }

        const into_arr = root.get("into").?.array.items;
        var into_changes: std.ArrayList([]store.Op) = .empty;
        defer {
            for (into_changes.items) |ops| store.freeOps(gpa, ops);
            into_changes.deinit(gpa);
        }
        for (into_arr) |ch_val| {
            var ops_list: std.ArrayList(store.Op) = .empty;
            errdefer {
                for (ops_list.items) |op| op.deinit(gpa);
                ops_list.deinit(gpa);
            }
            for (ch_val.array.items) |op_val| {
                try ops_list.append(gpa, try json.parseOpValue(gpa, op_val));
            }
            try into_changes.append(gpa, try ops_list.toOwnedSlice(gpa));
        }

        const from_arr = root.get("from").?.array.items;
        var from_changes: std.ArrayList([]store.Op) = .empty;
        defer {
            for (from_changes.items) |ops| store.freeOps(gpa, ops);
            from_changes.deinit(gpa);
        }
        for (from_arr) |ch_val| {
            var ops_list: std.ArrayList(store.Op) = .empty;
            errdefer {
                for (ops_list.items) |op| op.deinit(gpa);
                ops_list.deinit(gpa);
            }
            for (ch_val.array.items) |op_val| {
                try ops_list.append(gpa, try json.parseOpValue(gpa, op_val));
            }
            try from_changes.append(gpa, try ops_list.toOwnedSlice(gpa));
        }

        const want_obj = root.get("want").?.object;
        const want_clean = want_obj.get("clean").?.bool;
        var want_ops: std.ArrayList(store.Op) = .empty;
        defer {
            for (want_ops.items) |op| op.deinit(gpa);
            want_ops.deinit(gpa);
        }
        for (want_obj.get("ops").?.array.items) |op_val| {
            try want_ops.append(gpa, try json.parseOpValue(gpa, op_val));
        }
        store.sortOps(want_ops.items);

        const want_conflicts = want_obj.get("conflicts").?.array.items;

        const res = try merge.mergeOps(gpa, base_atoms.items, into_changes.items, from_changes.items);
        defer res.deinit(gpa);

        try std.testing.expectEqual(want_clean, res.clean);
        try std.testing.expect(opsSliceEqual(res.ops, want_ops.items));
        try std.testing.expectEqual(want_conflicts.len, res.conflicts.len);
        for (res.conflicts, 0..) |c, idx| {
            const wc = want_conflicts[idx].object;
            try std.testing.expectEqualStrings(wc.get("name").?.string, c.name);
            try std.testing.expectEqualStrings(wc.get("type").?.string, c.type);
        }

        // Equal add: verify `into`'s Atom ID is kept when `into`'s changes + merge ops are applied.
        if (std.mem.eql(u8, sc_name, "equal_add")) {
            var atoms_by_id = std.StringHashMap(store.StoredAtom).init(gpa);
            defer {
                var it = atoms_by_id.iterator();
                while (it.next()) |kv| {
                    gpa.free(kv.key_ptr.*);
                    kv.value_ptr.deinit(gpa);
                }
                atoms_by_id.deinit();
            }
            for (into_changes.items) |ops| {
                try store.applyOpsToAtomMap(gpa, &atoms_by_id, ops, false);
            }
            try store.applyOpsToAtomMap(gpa, &atoms_by_id, res.ops, true);
            try std.testing.expectEqual(@as(usize, 1), atoms_by_id.count());
            const into_add_id = into_changes.items[0][0].atom_id;
            try std.testing.expect(atoms_by_id.contains(into_add_id));
        }

        // Symmetry: swapping `into` and `from` must give the exact same set of conflict (name, type) pairs.
        const rev = try merge.mergeOps(gpa, base_atoms.items, from_changes.items, into_changes.items);
        defer rev.deinit(gpa);
        try std.testing.expectEqual(res.clean, rev.clean);
        try std.testing.expectEqual(res.conflicts.len, rev.conflicts.len);
        for (res.conflicts, rev.conflicts) |cf, cr| {
            try std.testing.expectEqualStrings(cf.name, cr.name);
            try std.testing.expectEqualStrings(cf.type, cr.type);
        }
    }
    try std.testing.expectEqual(@as(usize, 20), scenario_count);
}

test "fork, init --stream replay, clean merge, re-merge, verify --all, and src_behind guard" {
    const gpa = std.testing.allocator;
    var h = try TestHarness.init(gpa);
    defer h.deinit();
    h.env_sign_key = rfc8032_seed_hex;
    const mfs = h.mem.fs();

    const base_src = "package calc\n\nfunc X() int {\n\treturn 1\n}\n\nfunc Y() int {\n\treturn 2\n}\n";
    try mfs.writeFileSafe(gpa, "/host/SRCA/calc.go", base_src);
    try mfs.writeFileSafe(gpa, "/host/SRCB/calc.go", base_src);

    // 1. Init workspace `a` on stream `main`.
    {
        const res = try h.runCmd(&.{ "init", "--name=a", "--src=/host/SRCA" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }

    // Refusal: `fork_empty` when `main` has no head yet.
    {
        const res = try h.runCmd(&.{ "fork", "main", "feature" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse fork_empty\n", res.out);
    }

    // Refusal: `stream_missing` on fork.
    {
        const res = try h.runCmd(&.{ "fork", "nope", "feature" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse stream_missing nope\n", res.out);
    }

    // Stage and commit base on `a` (`main`).
    {
        const res = try h.runCmd(&.{ "add", "/host/SRCA" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }
    {
        const res = try h.runCmd(&.{ "commit", "-m", "base" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }

    var base_head: []u8 = &.{};
    defer if (base_head.len > 0) gpa.free(base_head);
    var main_id: []u8 = &.{};
    defer if (main_id.len > 0) gpa.free(main_id);
    {
        var idx = try store.loadStoreIndex(gpa, mfs, h.root);
        defer idx.deinit();
        const main_st = idx.streamByName("main").?;
        base_head = try gpa.dupe(u8, main_st.head.?);
        main_id = try gpa.dupe(u8, main_st.id);
    }

    // 2. Fork `main` -> `feature`.
    h.now += 5;
    {
        const res = try h.runCmd(&.{ "fork", "main", "feature" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        const want = try std.fmt.allocPrint(gpa, "flint: fork ok stream=feature head={s}\n", .{base_head});
        defer gpa.free(want);
        try std.testing.expectEqualStrings(want, res.out);
    }

    // Refusal: `stream_exists` when forking to an existing stream name.
    {
        const res = try h.runCmd(&.{ "fork", "main", "feature" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse stream_exists feature\n", res.out);
    }

    // Verify `forked_from` in `feature`'s stream record.
    {
        var idx = try store.loadStoreIndex(gpa, mfs, h.root);
        defer idx.deinit();
        const feat_st = idx.streamByName("feature").?;
        try std.testing.expectEqualStrings(base_head, feat_st.head.?);
        try std.testing.expect(feat_st.forked_from != null);
        try std.testing.expectEqualStrings(main_id, feat_st.forked_from.?.stream);
        try std.testing.expectEqualStrings(base_head, feat_st.forked_from.?.change);
    }

    // 3. `init --name=b --src=/host/SRCB --stream=feature` replays Ops and matches `a`'s Atom table.
    h.now += 5;
    {
        const res = try h.runCmd(&.{ "init", "--name=b", "--src=/host/SRCB", "--stream=feature" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expectEqualStrings("flint: init ok ws=b stream=feature atoms=2 replayed=1\n", res.out);
    }

    {
        const atoms_a = try store.loadWorkspaceAtoms(gpa, mfs, h.root, "a");
        defer store.freeStoredAtoms(gpa, atoms_a);
        const atoms_b = try store.loadWorkspaceAtoms(gpa, mfs, h.root, "b");
        defer store.freeStoredAtoms(gpa, atoms_b);
        try std.testing.expectEqual(@as(usize, 2), atoms_a.len);
        try std.testing.expectEqual(@as(usize, 2), atoms_b.len);
        for (atoms_a, atoms_b) |aa, ab| {
            try std.testing.expectEqualStrings(aa.id, ab.id);
            try std.testing.expectEqualStrings(aa.kind, ab.kind);
            try std.testing.expectEqualStrings(aa.name, ab.name);
            try std.testing.expectEqualStrings(aa.hash, ab.hash);
            try std.testing.expectEqualStrings(aa.sig_hash, ab.sig_hash);
            try std.testing.expect(merge.spansEqual(aa.span, ab.span));
        }
    }

    // 4. Machine B edits `X` and commits on `feature`.
    try mfs.writeFileSafe(
        gpa,
        "/host/SRCB/calc.go",
        "package calc\n\nfunc X() int {\n\treturn 10\n}\n\nfunc Y() int {\n\treturn 2\n}\n",
    );
    h.now += 5;
    {
        const res = try h.runCmd(&.{ "add", "/host/SRCB" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }
    {
        const res = try h.runCmd(&.{ "commit", "--ws=b", "-m", "feat" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }

    // 5. Machine A edits `Y`. Before committing, test `stage_dirty` refusal on `merge`.
    try mfs.writeFileSafe(
        gpa,
        "/host/SRCA/calc.go",
        "package calc\n\nfunc X() int {\n\treturn 1\n}\n\nfunc Y() int {\n\treturn 20\n}\n",
    );
    h.now += 5;
    {
        const res = try h.runCmd(&.{ "add", "/host/SRCA" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }
    {
        const res = try h.runCmd(&.{ "merge", "feature" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse stage_dirty\n", res.out);
    }
    {
        const res = try h.runCmd(&.{ "commit", "--ws=a", "-m", "main" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }

    // Refusal: `stream_missing` on merge.
    {
        const res = try h.runCmd(&.{ "merge", "--ws=a", "no-such-stream" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse stream_missing no-such-stream\n", res.out);
    }

    var pre_merge_main_head: []u8 = &.{};
    defer if (pre_merge_main_head.len > 0) gpa.free(pre_merge_main_head);
    var feat_head: []u8 = &.{};
    defer if (feat_head.len > 0) gpa.free(feat_head);
    {
        var idx = try store.loadStoreIndex(gpa, mfs, h.root);
        defer idx.deinit();
        pre_merge_main_head = try gpa.dupe(u8, idx.streamByName("main").?.head.?);
        feat_head = try gpa.dupe(u8, idx.streamByName("feature").?.head.?);
    }

    // 6. Clean merge of `feature` into `main` (workspace `a` resolved unambiguously without `--ws`).
    h.now += 5;
    {
        const res = try h.runCmd(&.{ "merge", "feature" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expect(std.mem.startsWith(u8, res.out, "flint: merge ok conflicts=0 ops=1 id="));
        try std.testing.expect(std.mem.endsWith(u8, res.out, "\nflint: merge src not materialized files=1\n"));
    }

    // Verify the signed merge Change on `main` (`parent == pre_merge_main_head`, `merged == feat_head`).
    {
        const loaded = try store.loadStream(gpa, mfs, h.root, main_id);
        defer loaded.deinit(gpa);
        try std.testing.expectEqual(@as(usize, 3), loaded.changes.len);
        const merge_change = loaded.changes[2];
        try std.testing.expectEqualStrings(merge_change.id, loaded.stream.head.?);
        try std.testing.expectEqualStrings(pre_merge_main_head, merge_change.parent.?);
        try std.testing.expectEqualStrings(feat_head, merge_change.merged.?);
        try std.testing.expect(try ed25519.verifyChange(gpa, &merge_change));
    }

    // Re-merge `feature` -> `flint: merge up to date`, nothing written.
    const main_log_path = try store.streamLogPath(gpa, h.root, main_id);
    defer gpa.free(main_log_path);
    const main_log_before = try mfs.readFile(gpa, main_log_path, store.MaxFileReadBytes);
    defer gpa.free(main_log_before);
    {
        const res = try h.runCmd(&.{ "merge", "feature" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expectEqualStrings("flint: merge up to date\n", res.out);
    }
    const main_log_after = try mfs.readFile(gpa, main_log_path, store.MaxFileReadBytes);
    defer gpa.free(main_log_after);
    try std.testing.expectEqualStrings(main_log_before, main_log_after);

    // `verify --all` verifies all 4 Changes across `main` and `feature`.
    {
        const res = try h.runCmd(&.{ "verify", "--all" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        var line_count: usize = 0;
        var it = std.mem.splitScalar(u8, std.mem.trimEnd(u8, res.out, "\n"), '\n');
        while (it.next()) |line| {
            line_count += 1;
            try std.testing.expect(std.mem.endsWith(u8, line, " sig: verified"));
        }
        try std.testing.expectEqual(@as(usize, 4), line_count);
    }

    // 7. `src_behind` guard: `calc.X` in workspace `a` is marked `origin: merge`,
    // while `/host/SRCA/calc.go` still has the old `X() { return 1 }` on disk.
    {
        const atoms_after_merge = try store.loadWorkspaceAtoms(gpa, mfs, h.root, "a");
        defer store.freeStoredAtoms(gpa, atoms_after_merge);
        var found_merge_origin = false;
        for (atoms_after_merge) |a| {
            if (std.mem.eql(u8, a.name, "calc.X") and std.mem.eql(u8, a.origin, "merge")) {
                found_merge_origin = true;
            }
        }
        try std.testing.expect(found_merge_origin);
    }

    {
        const res = try h.runCmd(&.{ "add", "/host/SRCA" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse src_behind calc.go\n", res.out);
    }
    const stage_a = try store.workspaceStagePath(gpa, h.root, "a");
    defer gpa.free(stage_a);
    try std.testing.expect(!mfs.exists(gpa, stage_a));

    // Once `/host/SRCA/calc.go` is updated on disk so `X` matches the merged hash,
    // `add` succeeds and clears `origin: merge`!
    try mfs.writeFileSafe(
        gpa,
        "/host/SRCA/calc.go",
        "package calc\n\nfunc X() int {\n\treturn 10\n}\n\nfunc Y() int {\n\treturn 20\n}\n",
    );
    {
        const res = try h.runCmd(&.{ "add", "/host/SRCA" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expectEqualStrings("flint: add files=1 new=0 modified=0 deleted=0 unchanged=2\n", res.out);
    }
    {
        const atoms_cleared = try store.loadWorkspaceAtoms(gpa, mfs, h.root, "a");
        defer store.freeStoredAtoms(gpa, atoms_cleared);
        for (atoms_cleared) |a| {
            try std.testing.expectEqualStrings("", a.origin);
        }
    }
}

test "conflicting merge writes MERGE.json and leaves history and ATOMS.jsonl byte-identical" {
    const gpa = std.testing.allocator;
    var h = try TestHarness.init(gpa);
    defer h.deinit();
    h.env_sign_key = rfc8032_seed_hex;
    const mfs = h.mem.fs();

    const base_src = "package calc\n\nfunc X() int {\n\treturn 1\n}\n\nfunc Y() int {\n\treturn 2\n}\n";
    try mfs.writeFileSafe(gpa, "/host/SRCA/calc.go", base_src);
    try mfs.writeFileSafe(gpa, "/host/SRCB/calc.go", base_src);

    for ([_][]const []const u8{
        &.{ "init", "--name=a", "--src=/host/SRCA" },
        &.{ "add", "/host/SRCA" },
        &.{ "commit", "-m", "base" },
        &.{ "fork", "main", "feature" },
        &.{ "init", "--name=b", "--src=/host/SRCB", "--stream=feature" },
    }) |cmd| {
        const res = try h.runCmd(cmd);
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }

    // Machine B edits `X` to return 10.
    try mfs.writeFileSafe(
        gpa,
        "/host/SRCB/calc.go",
        "package calc\n\nfunc X() int {\n\treturn 10\n}\n\nfunc Y() int {\n\treturn 2\n}\n",
    );
    h.now += 5;
    for ([_][]const []const u8{
        &.{ "add", "/host/SRCB" },
        &.{ "commit", "--ws=b", "-m", "feat" },
    }) |cmd| {
        const res = try h.runCmd(cmd);
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }

    // Machine A edits `X` to return 99.
    try mfs.writeFileSafe(
        gpa,
        "/host/SRCA/calc.go",
        "package calc\n\nfunc X() int {\n\treturn 99\n}\n\nfunc Y() int {\n\treturn 2\n}\n",
    );
    h.now += 5;
    for ([_][]const []const u8{
        &.{ "add", "/host/SRCA" },
        &.{ "commit", "--ws=a", "-m", "main" },
    }) |cmd| {
        const res = try h.runCmd(cmd);
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }

    var idx = try store.loadStoreIndex(gpa, mfs, h.root);
    defer idx.deinit();
    const main_id = idx.streamByName("main").?.id;
    const rec_path = try store.streamRecordPath(gpa, h.root, main_id);
    defer gpa.free(rec_path);
    const log_path = try store.streamLogPath(gpa, h.root, main_id);
    defer gpa.free(log_path);
    const atoms_path = try store.workspaceAtomsPath(gpa, h.root, "a");
    defer gpa.free(atoms_path);

    const rec_before = try mfs.readFile(gpa, rec_path, store.MaxFileReadBytes);
    defer gpa.free(rec_before);
    const log_before = try mfs.readFile(gpa, log_path, store.MaxFileReadBytes);
    defer gpa.free(log_before);
    const atoms_before = try mfs.readFile(gpa, atoms_path, store.MaxFileReadBytes);
    defer gpa.free(atoms_before);

    {
        const res = try h.runCmd(&.{ "merge", "feature" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 2), res.rc);
        try std.testing.expectEqualStrings(
            "flint: merge conflict atom=calc.X type=concurrent_modify\nflint: merge conflicts=1\n",
            res.out,
        );
    }

    const rec_after = try mfs.readFile(gpa, rec_path, store.MaxFileReadBytes);
    defer gpa.free(rec_after);
    const log_after = try mfs.readFile(gpa, log_path, store.MaxFileReadBytes);
    defer gpa.free(log_after);
    const atoms_after = try mfs.readFile(gpa, atoms_path, store.MaxFileReadBytes);
    defer gpa.free(atoms_after);

    try std.testing.expectEqualStrings(rec_before, rec_after);
    try std.testing.expectEqualStrings(log_before, log_after);
    try std.testing.expectEqualStrings(atoms_before, atoms_after);

    const merge_path = try store.workspaceMergePath(gpa, h.root, "a");
    defer gpa.free(merge_path);
    const merge_bytes = try mfs.readFile(gpa, merge_path, store.MaxFileReadBytes);
    defer gpa.free(merge_bytes);

    var parsed = try std.json.parseFromSlice(std.json.Value, gpa, merge_bytes, .{});
    defer parsed.deinit();
    const conflicts = parsed.value.object.get("conflicts").?.array.items;
    try std.testing.expectEqual(@as(usize, 1), conflicts.len);
    try std.testing.expectEqualStrings("calc.X", conflicts[0].object.get("name").?.string);
    try std.testing.expectEqualStrings("concurrent_modify", conflicts[0].object.get("type").?.string);
}

test "M106e remote verbs: push, clone, pull, fork_needed, tampered sig_invalid, and REMOTE.json" {
    const gpa = std.testing.allocator;

    // Server store in its own MemFS.
    var srv_mem = try fsys.MemFS.init(gpa);
    defer srv_mem.deinit();
    const srv_fs = srv_mem.fs();
    try srv_fs.mkdir(gpa, "/srv/FLINT/streams");

    var server = sync.InProcServer{
        .allocator = gpa,
        .fs = srv_fs,
        .store_root = "/srv/FLINT",
    };

    // Client A store.
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
        &.{ "commit", "-m", "initial" },
    }) |cmd| {
        const res = try ha.runCmd(cmd);
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }

    // 1. Push without any remote configured refuses `remote_missing`.
    {
        const res = try ha.runCmd(&.{"push"});
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse remote_missing\n", res.out);
    }

    // 2. Push with `--remote=tcp://127.0.0.1:4748` creates `main` on server, appends Change,
    //    and persists `ws/a/REMOTE.json`.
    {
        const res = try ha.runCmd(&.{ "push", "--remote=tcp://127.0.0.1:4748" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expectEqualStrings("flint: push ok stream=main changes=1\n", res.out);
    }

    // Verify `ws/a/REMOTE.json` was written and subsequent `push` with no `--remote` flag
    // resolves from `REMOTE.json` and reports `up to date`.
    {
        const rc_opt = try store.loadWorkspaceRemote(gpa, fsa, ha.root, "a");
        try std.testing.expect(rc_opt != null);
        defer rc_opt.?.deinit(gpa);
        try std.testing.expectEqualStrings("tcp://127.0.0.1:4748", rc_opt.?.remote);

        const res = try ha.runCmd(&.{"push"});
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expectEqualStrings("flint: push up to date\n", res.out);
    }

    // Verify server log and stream record are byte-identical to Client A's.
    var idx_a = try store.loadStoreIndex(gpa, fsa, ha.root);
    defer idx_a.deinit();
    const main_id = idx_a.streamByName("main").?.id;
    {
        const a_log_p = try store.streamLogPath(gpa, ha.root, main_id);
        defer gpa.free(a_log_p);
        const s_log_p = try store.streamLogPath(gpa, server.store_root, main_id);
        defer gpa.free(s_log_p);

        const a_log = try fsa.readFile(gpa, a_log_p, store.MaxFileReadBytes);
        defer gpa.free(a_log);
        const s_log = try srv_fs.readFile(gpa, s_log_p, store.MaxFileReadBytes);
        defer gpa.free(s_log);
        try std.testing.expectEqualStrings(a_log, s_log);
    }

    // 3. Client B clones `main` from the server, replays atoms byte-verbatim, and passes `verify --all`.
    var hb = try TestHarness.init(gpa);
    defer hb.deinit();
    hb.env_sign_key = rfc8032_seed_hex;
    hb.sync_dial = sync.InProcServer.dial;
    hb.sync_dial_ctx = &server;
    const fsb = hb.mem.fs();
    try fsb.writeFileSafe(gpa, "/host/SRCB/calc.go", base_src);

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

        // Compare Client B's stream log and ATOMS.jsonl byte-for-byte with Client A's.
        const a_log_p = try store.streamLogPath(gpa, ha.root, main_id);
        defer gpa.free(a_log_p);
        const b_log_p = try store.streamLogPath(gpa, hb.root, main_id);
        defer gpa.free(b_log_p);
        const a_log = try fsa.readFile(gpa, a_log_p, store.MaxFileReadBytes);
        defer gpa.free(a_log);
        const b_log = try fsb.readFile(gpa, b_log_p, store.MaxFileReadBytes);
        defer gpa.free(b_log);
        try std.testing.expectEqualStrings(a_log, b_log);

        const a_atoms_p = try store.workspaceAtomsPath(gpa, ha.root, "a");
        defer gpa.free(a_atoms_p);
        const b_atoms_p = try store.workspaceAtomsPath(gpa, hb.root, "b");
        defer gpa.free(b_atoms_p);
        const a_atoms = try fsa.readFile(gpa, a_atoms_p, store.MaxFileReadBytes);
        defer gpa.free(a_atoms);
        const b_atoms = try fsb.readFile(gpa, b_atoms_p, store.MaxFileReadBytes);
        defer gpa.free(b_atoms);
        try std.testing.expectEqualStrings(a_atoms, b_atoms);
    }

    // 4. Client A makes a second commit and pushes it to the server.
    try fsa.writeFileSafe(
        gpa,
        "/host/SRCA/calc.go",
        "package calc\n\nfunc X() int {\n\treturn 10\n}\n\nfunc Y() int {\n\treturn 2\n}\n",
    );
    ha.now += 5;
    for ([_][]const []const u8{
        &.{ "add", "/host/SRCA" },
        &.{ "commit", "-m", "second" },
        &.{"push"},
    }) |cmd| {
        const res = try ha.runCmd(cmd);
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }

    // 5. Tampered pull line on Client B aborts with `sig_invalid` and writes nothing!
    {
        const b_log_p = try store.streamLogPath(gpa, hb.root, main_id);
        defer gpa.free(b_log_p);
        const b_rec_p = try store.streamRecordPath(gpa, hb.root, main_id);
        defer gpa.free(b_rec_p);
        const log_before = try fsb.readFile(gpa, b_log_p, store.MaxFileReadBytes);
        defer gpa.free(log_before);
        const rec_before = try fsb.readFile(gpa, b_rec_p, store.MaxFileReadBytes);
        defer gpa.free(rec_before);

        server.tamper_read_sig = true;
        defer server.tamper_read_sig = false;

        const res = try hb.runCmd(&.{"pull"});
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse sig_invalid\n", res.out);

        const log_after = try fsb.readFile(gpa, b_log_p, store.MaxFileReadBytes);
        defer gpa.free(log_after);
        const rec_after = try fsb.readFile(gpa, b_rec_p, store.MaxFileReadBytes);
        defer gpa.free(rec_after);
        try std.testing.expectEqualStrings(log_before, log_after);
        try std.testing.expectEqualStrings(rec_before, rec_after);
    }

    // 6. Clean `pull` on Client B advances head and appends the second Change byte-verbatim.
    {
        const res = try hb.runCmd(&.{"pull"});
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expectEqualStrings("flint: pull ok stream=main changes=1\n", res.out);

        const res2 = try hb.runCmd(&.{"pull"});
        defer gpa.free(res2.out);
        try std.testing.expectEqual(@as(u8, 0), res2.rc);
        try std.testing.expectEqualStrings("flint: pull up to date\n", res2.out);

        const vres = try hb.runCmd(&.{ "verify", "--all" });
        defer gpa.free(vres.out);
        try std.testing.expectEqual(@as(u8, 0), vres.rc);
    }

    // 7. Divergence test: Client A commits+pushes Change 3; Client B (before pulling Change 3)
    //    syncs its local ATOMS, commits a divergent Change 3b locally, and tries `push` (`stale_head`)
    //    then `pull` (`fork_needed`).
    try fsa.writeFileSafe(
        gpa,
        "/host/SRCA/calc.go",
        "package calc\n\nfunc X() int {\n\treturn 10\n}\n\nfunc Y() int {\n\treturn 20\n}\n",
    );
    ha.now += 5;
    for ([_][]const []const u8{
        &.{ "add", "/host/SRCA" },
        &.{ "commit", "-m", "server-ahead" },
        &.{"push"},
    }) |cmd| {
        const res = try ha.runCmd(cmd);
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }

    // Client B edits calc.go and commits locally on `main` (diverging from server's `main`).
    try fsb.writeFileSafe(
        gpa,
        "/host/SRCB/calc.go",
        "package calc\n\nfunc X() int {\n\treturn 1\n}\n\nfunc Y() int {\n\treturn 999\n}\n",
    );
    hb.now += 10;
    for ([_][]const []const u8{
        &.{ "add", "/host/SRCB" },
        &.{ "commit", "-m", "diverged-local" },
    }) |cmd| {
        const res = try hb.runCmd(cmd);
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }

    // Client B `push` refuses `stale_head`.
    {
        const res = try hb.runCmd(&.{"push"});
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse stale_head\n", res.out);
    }

    // Client B `pull` refuses `fork_needed` because local and remote heads have diverged.
    {
        const res = try hb.runCmd(&.{"pull"});
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse fork_needed\n", res.out);
    }
}

test "M106e auth challenge, allow-author, forked stream clone/push, and loopback TCP" {
    const gpa = std.testing.allocator;

    var srv_mem = try fsys.MemFS.init(gpa);
    defer srv_mem.deinit();
    const srv_fs = srv_mem.fs();
    try srv_fs.mkdir(gpa, "/srv/FLINT/streams");

    const auth_secret_hex = "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5";
    var auth_key_bytes: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&auth_key_bytes, auth_secret_hex);

    var server = sync.InProcServer{
        .allocator = gpa,
        .fs = srv_fs,
        .store_root = "/srv/FLINT",
        .auth_key = auth_key_bytes,
    };

    var ha = try TestHarness.init(gpa);
    defer ha.deinit();
    ha.env_sign_key = rfc8032_seed_hex;
    ha.sync_dial = sync.InProcServer.dial;
    ha.sync_dial_ctx = &server;
    const fsa = ha.mem.fs();

    try fsa.writeFileSafe(gpa, "/host/auth.key", auth_secret_hex ++ "\n");
    try fsa.writeFileSafe(gpa, "/host/wrong.key", "0000000000000000000000000000000000000000000000000000000000000000\n");
    try fsa.writeFileSafe(gpa, "/host/SRCA/calc.go", "package calc\n\nfunc X() int {\n\treturn 1\n}\n");

    for ([_][]const []const u8{
        &.{ "init", "--name=a", "--src=/host/SRCA" },
        &.{ "add", "/host/SRCA" },
        &.{ "commit", "-m", "c1" },
        &.{ "fork", "main", "feature" },
        &.{ "init", "--name=feat", "--src=/host/SRCA", "--stream=feature" },
    }) |cmd| {
        const res = try ha.runCmd(cmd);
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }

    try fsa.writeFileSafe(gpa, "/host/SRCA/calc.go", "package calc\n\nfunc X() int {\n\treturn 2\n}\n");
    ha.now += 5;
    for ([_][]const []const u8{
        &.{ "add", "--ws=feat", "/host/SRCA" },
        &.{ "commit", "--ws=feat", "-m", "c2-on-feature" },
    }) |cmd| {
        const res = try ha.runCmd(cmd);
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }

    // 1. Unauthenticated push to `--auth-key` server refuses `auth_required`.
    {
        const res = try ha.runCmd(&.{ "push", "--ws=feat", "--remote=tcp://127.0.0.1:4748" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse auth_required\n", res.out);
    }

    // 2. Wrong `--auth-key` refuses `auth_failed`.
    {
        const res = try ha.runCmd(&.{ "push", "--ws=feat", "--remote=tcp://127.0.0.1:4748", "--auth-key=/host/wrong.key" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse auth_failed\n", res.out);
    }

    // 3. Author allowlist gate: unlisted author refuses `author_not_allowed`.
    const other_author = [_][]const u8{"0000000000000000000000000000000000000000000000000000000000000000"};
    server.allow_authors = &other_author;
    {
        const res = try ha.runCmd(&.{ "push", "--ws=feat", "--remote=tcp://127.0.0.1:4748", "--auth-key=/host/auth.key" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse author_not_allowed\n", res.out);
    }
    const allowed_author = [_][]const u8{rfc8032_pub_hex};
    server.allow_authors = &allowed_author;

    // 4. Correct `--auth-key` + listed author succeeds and pushes both `main` (ancestor) and `feature`!
    {
        const res = try ha.runCmd(&.{ "push", "--ws=feat", "--remote=tcp://127.0.0.1:4748", "--auth-key=/host/auth.key" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expectEqualStrings("flint: push ok stream=feature changes=1\n", res.out);
    }

    // 5. Real loopback TCP test (`defaultTcpDial` over `127.0.0.1:<ephemeral_port>`):
    //    Client C clones `feature` (following `forked_from` chain `main` -> `feature`) over a live TCP socket!
    var listen_addr = Io.net.IpAddress{ .ip4 = Io.net.Ip4Address.loopback(0) };
    var tcp_srv = try listen_addr.listen(std.testing.io, .{ .reuse_address = true });
    defer tcp_srv.deinit(std.testing.io);
    const port = tcp_srv.socket.address.getPort();
    const tcp_url = try std.fmt.allocPrint(gpa, "tcp://127.0.0.1:{d}", .{port});
    defer gpa.free(tcp_url);

    const ServerAcceptTask = struct {
        fn run(srv: *sync.InProcServer, tcp_listener: *Io.net.Server, io: Io) void {
            const conn = tcp_listener.accept(io) catch return;
            srv.serveNetStream( std.heap.page_allocator, io, conn);
        }
    };
    const thr = try std.Thread.spawn(.{}, ServerAcceptTask.run, .{ &server, &tcp_srv, std.testing.io });
    defer thr.join();

    var hc = try TestHarness.init(gpa);
    defer hc.deinit();
    hc.env_auth_key = auth_secret_hex;
    // Leave `hc.sync_dial = null` so `runWithContext` uses `sync.defaultTcpDial` over real TCP!
    const fsc = hc.mem.fs();
    try fsc.mkdir(gpa, "/host/SRCC");

    {
        const res = try hc.runCmd(&.{
            "clone",
            tcp_url,
            "--stream=feature",
            "--name=c",
            "--src=/host/SRCC",
        });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expectEqualStrings("flint: clone ok stream=feature changes=2\n", res.out);
    }

    {
        const vres = try hc.runCmd(&.{ "verify", "--all" });
        defer gpa.free(vres.out);
        try std.testing.expectEqual(@as(u8, 0), vres.rc);
    }
}

const FailDial = struct {
    err: anyerror,

    fn dial(ctx: ?*anyopaque, _: Allocator, _: Io, _: []const u8) anyerror!sync.Transport {
        const self: *FailDial = @ptrCast(@alignCast(ctx.?));
        return self.err;
    }
};

test "transport errors print verb + remote context, not raw error names (#31)" {
    const gpa = std.testing.allocator;

    var h = try TestHarness.init(gpa);
    defer h.deinit();
    const fs = h.mem.fs();
    try fs.mkdir(gpa, "/host/SRCA");
    try fs.mkdir(gpa, "/host/SRCB");
    {
        const res = try h.runCmd(&.{ "init", "--name=a", "--src=/host/SRCA" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }

    var fd = FailDial{ .err = error.ConnectionRefused };
    h.sync_dial = FailDial.dial;
    h.sync_dial_ctx = &fd;

    {
        const res = try h.runCmd(&.{ "pull", "--remote=tcp://127.0.0.1:1", "--ws=a" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: error pull tcp://127.0.0.1:1: connection refused\n", res.out);
    }
    fd.err = error.UnknownHostName;
    {
        const res = try h.runCmd(&.{ "push", "--remote=tcp://nohost.invalid:9", "--ws=a" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: error push tcp://nohost.invalid:9: unknown host\n", res.out);
    }
    fd.err = error.ConnectionRefused;
    {
        const res = try h.runCmd(&.{ "clone", "tcp://127.0.0.1:1", "--stream=main", "--name=b", "--src=/host/SRCB" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: error clone tcp://127.0.0.1:1: connection refused\n", res.out);
    }

    // The context must not leak into the next command: `push` with no remote
    // configured still refuses `remote_missing` in the plain refusal form.
    {
        const res = try h.runCmd(&.{"push"});
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse remote_missing\n", res.out);
    }
}

test "re-clone never overwrites a divergent stream (#28); fork + pull --reset + merge + push recovers (#29)" {
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

    // B: clone main -> [c1].
    var hb = try TestHarness.init(gpa);
    defer hb.deinit();
    hb.env_sign_key = rfc8032_seed_hex;
    hb.sync_dial = sync.InProcServer.dial;
    hb.sync_dial_ctx = &server;
    const fsb = hb.mem.fs();
    try fsb.writeFileSafe(gpa, "/host/SRCB/calc.go", base_src);
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

    var idx_b = try store.loadStoreIndex(gpa, fsb, hb.root);
    defer idx_b.deinit();
    const main_id = try gpa.dupe(u8, idx_b.streamByName("main").?.id);
    defer gpa.free(main_id);
    const b_rec_p = try store.streamRecordPath(gpa, hb.root, main_id);
    defer gpa.free(b_rec_p);
    const b_log_p = try store.streamLogPath(gpa, hb.root, main_id);
    defer gpa.free(b_log_p);

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

    // Re-clone while local is strictly behind is a fast-forward and is allowed:
    // the existing log is a verified prefix, so only the missing suffix appends.
    try fsb.mkdir(gpa, "/host/SRCB2");
    {
        const res = try hb.runCmd(&.{
            "clone",
            "tcp://127.0.0.1:4748",
            "--stream=main",
            "--name=b2",
            "--src=/host/SRCB2",
        });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expectEqualStrings("flint: clone ok stream=main changes=2\n", res.out);
    }
    {
        const b_log = try fsb.readFile(gpa, b_log_p, store.MaxFileReadBytes);
        defer gpa.free(b_log);
        const b_lines = try store.readJSONLLines(gpa, b_log);
        defer gpa.free(b_lines);
        try std.testing.expectEqual(@as(usize, 2), b_lines.len);
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

    // A: modify X again, commit c3, push -> server main = [c1, c2, c3].
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
    const c3_id = blk: {
        var idx_a = try store.loadStoreIndex(gpa, fsa, ha.root);
        defer idx_a.deinit();
        const a_main = idx_a.streamByName("main").?;
        break :blk try gpa.dupe(u8, a_main.head.?);
    };
    defer gpa.free(c3_id);

    // Issue #28: re-clone over a divergent local stream refuses and destroys nothing.
    const rec_before = try fsb.readFile(gpa, b_rec_p, store.MaxFileReadBytes);
    defer gpa.free(rec_before);
    const log_before = try fsb.readFile(gpa, b_log_p, store.MaxFileReadBytes);
    defer gpa.free(log_before);
    try fsb.mkdir(gpa, "/host/SRCB3");
    {
        const res = try hb.runCmd(&.{
            "clone",
            "tcp://127.0.0.1:4748",
            "--stream=main",
            "--name=b3",
            "--src=/host/SRCB3",
        });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse fork_needed\n", res.out);

        const rec_after = try fsb.readFile(gpa, b_rec_p, store.MaxFileReadBytes);
        defer gpa.free(rec_after);
        const log_after = try fsb.readFile(gpa, b_log_p, store.MaxFileReadBytes);
        defer gpa.free(log_after);
        try std.testing.expectEqualStrings(rec_before, rec_after);
        try std.testing.expectEqualStrings(log_before, log_after);

        const ws3_cfg = try store.workspaceConfigPath(gpa, hb.root, "b3");
        defer gpa.free(ws3_cfg);
        try std.testing.expect(!fsb.exists(gpa, ws3_cfg));
    }

    // Issue #29: pull refuses fork_needed; --reset refuses until d1 is forked aside.
    {
        const res = try hb.runCmd(&.{ "pull", "--ws=b" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse fork_needed\n", res.out);
    }
    {
        const res = try hb.runCmd(&.{ "pull", "--ws=b", "--reset" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse fork_needed\n", res.out);
        const log_now = try fsb.readFile(gpa, b_log_p, store.MaxFileReadBytes);
        defer gpa.free(log_now);
        try std.testing.expectEqualStrings(log_before, log_now);
    }
    {
        const res = try hb.runCmd(&.{ "fork", "main", "b-work" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        const want = try std.fmt.allocPrint(gpa, "flint: fork ok stream=b-work head={s}\n", .{d1_id});
        defer gpa.free(want);
        try std.testing.expectEqualStrings(want, res.out);
    }
    {
        const res = try hb.runCmd(&.{ "pull", "--ws=b", "--reset" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        const want = try std.fmt.allocPrint(gpa, "flint: pull reset stream=main changes=1 head={s}\n", .{c3_id});
        defer gpa.free(want);
        try std.testing.expectEqualStrings(want, res.out);

        // Local log now holds the remote suffix; d1 survives as a sibling line
        // reachable through b-work's fork point.
        const loaded = try store.loadStream(gpa, fsb, hb.root, main_id);
        defer loaded.deinit(gpa);
        try std.testing.expectEqualStrings(c3_id, loaded.stream.head.?);
        try std.testing.expectEqual(@as(usize, 4), loaded.changes.len);
        try std.testing.expectEqualStrings(d1_id, loaded.changes[2].id);
        try std.testing.expectEqualStrings(c3_id, loaded.changes[3].id);
    }

    // merge b-work into main: clean (d1 touched Y, c3 touched X); merge Change's
    // parent is the remote head so push fast-forwards the server.
    {
        const res = try hb.runCmd(&.{ "merge", "--ws=b", "b-work" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expect(std.mem.startsWith(u8, res.out, "flint: merge ok conflicts=0 ops=1 id="));
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

    // A pulls the merge Change; every store verifies green.
    {
        const res = try ha.runCmd(&.{ "pull", "--ws=a" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expectEqualStrings("flint: pull ok stream=main changes=1\n", res.out);
    }
    for ([_]*TestHarness{ ha, hb }) |h| {
        const res = try h.runCmd(&.{ "verify", "--all" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }
    {
        var vout: Io.Writer.Allocating = .init(gpa);
        defer vout.deinit();
        const vrc = try ed25519.cmdVerify(gpa, srv_fs, server.store_root, &.{"--all"}, &vout.writer);
        try std.testing.expectEqual(@as(u8, 0), vrc);
    }

    // Server log is [c1, c2, c3, M]; M parents the remote head and merges d1.
    {
        const s_log_p = try store.streamLogPath(gpa, server.store_root, main_id);
        defer gpa.free(s_log_p);
        const s_log = try srv_fs.readFile(gpa, s_log_p, store.MaxFileReadBytes);
        defer gpa.free(s_log);
        const s_lines = try store.readJSONLLines(gpa, s_log);
        defer gpa.free(s_lines);
        try std.testing.expectEqual(@as(usize, 4), s_lines.len);
        var mc = try json.parseChange(gpa, s_lines[3]);
        defer mc.deinit(gpa);
        try std.testing.expectEqualStrings(merge_id, mc.id);
        try std.testing.expectEqualStrings(c3_id, mc.parent.?);
        try std.testing.expectEqualStrings(d1_id, mc.merged.?);
    }
}



test "clone creates a missing --src dir; a file path still refuses src_missing (#32)" {
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

    // --src does not exist yet: clone creates it, including parent dirs.
    {
        const res = try hb.runCmd(&.{
            "clone",
            "tcp://127.0.0.1:4748",
            "--stream=main",
            "--name=b",
            "--src=/host/SRCB/fresh",
        });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expectEqualStrings("flint: clone ok stream=main changes=1\n", res.out);
        try std.testing.expect(fsb.isDir(gpa, "/host/SRCB/fresh"));
    }

    // --src that exists but is not a directory still refuses src_missing.
    try fsb.writeFileSafe(gpa, "/host/SRCC", "not a dir");
    {
        const res = try hb.runCmd(&.{
            "clone",
            "tcp://127.0.0.1:4748",
            "--stream=main",
            "--name=c",
            "--src=/host/SRCC",
        });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse src_missing /host/SRCC\n", res.out);
    }
}
