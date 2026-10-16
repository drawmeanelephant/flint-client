//! `--json` envelope plumbing and the store-verb dispatch table — see
//! docs/flint-json-results-spec.md. Lives outside main.zig to keep the
//! dispatcher under the 4000-line policy bound.
const std = @import("std");
const Io = std.Io;
const fsys = @import("fsys.zig");
const report = @import("report.zig");
const workspace = @import("workspace.zig");
const sign = @import("sign.zig");
const merge = @import("merge.zig");
const content = @import("content.zig");
const handoff = @import("handoff.zig");
const sync = @import("sync.zig");
const ed25519 = @import("ed25519.zig");
const uuid = @import("uuid.zig");
const main = @import("main.zig");

/// True when argv carried the `--json` flag — used to answer with an
/// envelope even when argument extraction itself refused.
pub fn wantJson(args: []const []const u8) bool {
    for (args) |a| {
        if (std.mem.eql(u8, a, "--json")) return true;
    }
    return false;
}

/// Writes the marshaled envelope to `ctx.stdout`. Falls back to a minimal
/// error envelope when serialization itself fails (out of memory, or the
/// result exceeded the 64 KiB bound).
pub fn writeResult(r: *report.Report, ctx: *const main.Context) void {
    const line = r.marshal(ctx.allocator) catch |e| {
        var fr = report.Report.init(ctx.allocator, r.verb);
        defer fr.deinit();
        fr.setError(main.friendlyErrorName(e)) catch {};
        fr.local = .unknown;
        fr.exit_code = 1;
        const fl = fr.marshal(ctx.allocator) catch {
            ctx.stdout.writeAll(
                "{\"v\":1,\"verb\":\"\",\"ok\":false,\"exit\":1,\"kind\":\"error\",\"workspace\":null,\"stream\":null,\"heads\":null,\"changes\":null,\"conflicts\":null,\"refusal\":null,\"error\":{\"name\":\"serialization failed\"},\"local\":\"unknown\",\"remote\":null,\"data\":{}}\n",
            ) catch {};
            return;
        };
        defer ctx.allocator.free(fl);
        ctx.stdout.writeAll(fl) catch {};
        return;
    };
    defer ctx.allocator.free(line);
    ctx.stdout.writeAll(line) catch {};
}

/// Ends a `--json` invocation that produced a result: serializes the report
/// populated by the verb and returns the verb's exit code.
pub fn ok(rep: ?*report.Report, rc: u8, ctx: *const main.Context) u8 {
    const r = rep orelse return rc;
    r.exit_code = rc;
    writeResult(r, ctx);
    return rc;
}

/// Ends a `--json` invocation that refused or errored: the legacy
/// `flint:` diagnostic goes to stderr (diagnostics never share the result
/// stream), and the envelope carries the structured refusal/error.
pub fn fail(rep: ?*report.Report, err: anyerror, ctx: *const main.Context) u8 {
    const r = rep orelse return main.handleErr(err, ctx.stdout);
    const rc = main.handleErr(err, ctx.stderr);
    if (err == error.Refuse) {
        r.setRefusal(fsys.last_refuse.code(), fsys.last_refuse.detail()) catch {};
    } else {
        r.setError(main.friendlyErrorName(err)) catch {};
    }
    r.exit_code = rc;
    writeResult(r, ctx);
    return rc;
}

/// Dispatches a known store verb. `out_w` is the sink writer in `--json`
/// mode (text discarded; the report carries the result) or real stdout in
/// text mode. `rep` is non-null iff `--json`.
pub fn dispatchStoreVerb(
    ctx: *const main.Context,
    rep: ?*report.Report,
    out_w: *Io.Writer,
    uuid_gen: *uuid.UUIDGen,
    root: []const u8,
    verb: []const u8,
    sub: []const []const u8,
) u8 {
    if (std.mem.eql(u8, verb, "init")) {
        workspace.cmdInit(ctx.allocator, ctx.fs, root, uuid_gen, out_w, sub) catch |err| {
            return fail(rep, err, ctx);
        };
        return ok(rep, 0, ctx);
    }

    if (std.mem.eql(u8, verb, "add")) {
        workspace.cmdAdd(ctx.allocator, ctx.fs, root, uuid_gen, out_w, sub) catch |err| {
            return fail(rep, err, ctx);
        };
        return ok(rep, 0, ctx);
    }

    if (std.mem.eql(u8, verb, "status")) {
        workspace.cmdStatus(ctx.allocator, ctx.fs, root, out_w, sub) catch |err| {
            return fail(rep, err, ctx);
        };
        return ok(rep, 0, ctx);
    }

    if (std.mem.eql(u8, verb, "commit")) {
        sign.cmdCommit(ctx.allocator, ctx.fs, root, ctx.cwd, uuid_gen, ctx.env_flint_sign_key, out_w, sub) catch |err| {
            return fail(rep, err, ctx);
        };
        return ok(rep, 0, ctx);
    }

    if (std.mem.eql(u8, verb, "log")) {
        sign.cmdLog(ctx.allocator, ctx.fs, root, out_w, sub) catch |err| {
            return fail(rep, err, ctx);
        };
        return ok(rep, 0, ctx);
    }

    if (std.mem.eql(u8, verb, "fork")) {
        merge.cmdFork(ctx.allocator, ctx.fs, root, uuid_gen, out_w, sub) catch |err| {
            return fail(rep, err, ctx);
        };
        return ok(rep, 0, ctx);
    }

    if (std.mem.eql(u8, verb, "merge")) {
        const rc = merge.cmdMerge(ctx.allocator, ctx.fs, root, ctx.cwd, uuid_gen, ctx.env_flint_sign_key, out_w, sub) catch |err| {
            return fail(rep, err, ctx);
        };
        return ok(rep, rc, ctx);
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
            out_w,
            ctx.stderr,
            sub,
        ) catch |err| {
            return fail(rep, err, ctx);
        };
        return ok(rep, 0, ctx);
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
            out_w,
            ctx.stderr,
            sub,
        ) catch |err| {
            return fail(rep, err, ctx);
        };
        return ok(rep, 0, ctx);
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
            out_w,
            ctx.stderr,
            sub,
        ) catch |err| {
            return fail(rep, err, ctx);
        };
        return ok(rep, 0, ctx);
    }

    if (std.mem.eql(u8, verb, "handoff")) {
        handoff.cmdHandoff(ctx.allocator, ctx.fs, root, uuid_gen, ctx.env_flint_sign_key, out_w, sub) catch |err| {
            return fail(rep, err, ctx);
        };
        return ok(rep, 0, ctx);
    }

    if (std.mem.eql(u8, verb, "checkout")) {
        content.cmdCheckout(ctx.allocator, ctx.fs, root, ctx.cwd, out_w, sub) catch |err| {
            return fail(rep, err, ctx);
        };
        return ok(rep, 0, ctx);
    }

    if (std.mem.eql(u8, verb, "keygen")) {
        ed25519.cmdKeygen(ctx.allocator, ctx.fs, root, uuid_gen, sub, out_w) catch |err| {
            return fail(rep, err, ctx);
        };
        return ok(rep, 0, ctx);
    }

    if (std.mem.eql(u8, verb, "verify")) {
        const rc = ed25519.cmdVerify(ctx.allocator, ctx.fs, root, sub, out_w) catch |err| {
            return fail(rep, err, ctx);
        };
        return ok(rep, rc, ctx);
    }

    return fail(rep, fsys.refuse("usage", ""), ctx);
}
