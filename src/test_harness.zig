const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const main = @import("main.zig");
const fsys = @import("fsys.zig");
const uuid = @import("uuid.zig");
const sync = @import("sync.zig");

/// In-memory CLI driver for unit and scenario tests: MemFS store, deterministic
/// UUID/clock, injectable FLINT_* environment and sync dial. Re-exported as
/// `main.TestHarness` for the existing call sites.
pub const TestHarness = struct {
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
    /// stderr captured by the most recent `runCmd` — refusals still land on
    /// `out` in text mode; notes like the content-degraded line live here.
    last_err: std.ArrayList(u8) = .empty,

    pub fn init(allocator: Allocator) !*TestHarness {
        const h = try allocator.create(TestHarness);
        h.* = .{
            .allocator = allocator,
            .mem = try fsys.MemFS.init(allocator),
            .uuid_gen = undefined,
        };
        h.uuid_gen = uuid.UUIDGen.initCustom(h, getNow, h, fillRand);
        return h;
    }

    pub fn deinit(self: *TestHarness) void {
        self.last_err.deinit(self.allocator);
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

    pub fn runCmd(self: *TestHarness, args: []const []const u8) !struct { rc: u8, out: []u8 } {
        var out_w: Io.Writer.Allocating = .init(self.allocator);
        errdefer out_w.deinit();
        var err_w: Io.Writer.Allocating = .init(self.allocator);
        defer err_w.deinit();

        const ctx = main.Context{
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
        const rc = main.runWithContext(ctx, args);
        self.last_err.clearRetainingCapacity();
        try self.last_err.appendSlice(self.allocator, err_w.written());
        return .{
            .rc = rc,
            .out = try out_w.toOwnedSlice(),
        };
    }
};
