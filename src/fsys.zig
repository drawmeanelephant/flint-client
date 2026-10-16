const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const MaxFileReadBytes: usize = 4 * 1024 * 1024;

pub const RefuseInfo = struct {
    code_buf: [64]u8 = undefined,
    code_len: usize = 0,
    detail_buf: [512]u8 = undefined,
    detail_len: usize = 0,

    pub fn code(self: *const RefuseInfo) []const u8 {
        return self.code_buf[0..self.code_len];
    }

    pub fn detail(self: *const RefuseInfo) []const u8 {
        return self.detail_buf[0..self.detail_len];
    }
};

pub threadlocal var last_refuse: RefuseInfo = .{};

/// Records a FLINT refusal code and optional detail and returns `error.Refuse`.
pub fn refuse(code_str: []const u8, detail_str: []const u8) error{Refuse} {
    const clen = @min(code_str.len, last_refuse.code_buf.len);
    @memcpy(last_refuse.code_buf[0..clen], code_str[0..clen]);
    last_refuse.code_len = clen;

    const dlen = @min(detail_str.len, last_refuse.detail_buf.len);
    @memcpy(last_refuse.detail_buf[0..dlen], detail_str[0..dlen]);
    last_refuse.detail_len = dlen;

    return error.Refuse;
}

pub fn writeRefuseLine(w: *Io.Writer) void {
    const c = last_refuse.code();
    const d = last_refuse.detail();
    if (d.len == 0) {
        w.print("flint: refuse {s}\n", .{c}) catch {};
    } else {
        w.print("flint: refuse {s} {s}\n", .{ c, d }) catch {};
    }
}

/// Context attached to non-refusal errors so `handleErr` can say which verb
/// and remote URL failed instead of printing a bare error name. The sync
/// verbs set it once the remote is resolved; `runWithContext` clears it
/// before dispatch so a stale context never leaks into the next command.
pub const ErrContext = struct {
    verb_buf: [16]u8 = undefined,
    verb_len: usize = 0,
    remote_buf: [512]u8 = undefined,
    remote_len: usize = 0,

    pub fn verb(self: *const ErrContext) []const u8 {
        return self.verb_buf[0..self.verb_len];
    }

    pub fn remote(self: *const ErrContext) []const u8 {
        return self.remote_buf[0..self.remote_len];
    }
};

pub threadlocal var err_context: ?ErrContext = null;

pub fn setErrContext(verb_str: []const u8, remote_str: []const u8) void {
    var ctx: ErrContext = .{};
    ctx.verb_len = @min(verb_str.len, ctx.verb_buf.len);
    @memcpy(ctx.verb_buf[0..ctx.verb_len], verb_str[0..ctx.verb_len]);
    ctx.remote_len = @min(remote_str.len, ctx.remote_buf.len);
    @memcpy(ctx.remote_buf[0..ctx.remote_len], remote_str[0..ctx.remote_len]);
    err_context = ctx;
}

pub fn clearErrContext() void {
    err_context = null;
}

/// EntryKind classifies a directory entry or stat result for the content
/// layer: regular files are tracked, directories are walked, links and any
/// other non-regular entries are recorded but never followed.
pub const EntryKind = enum { file, dir, link, other };

pub const DirEntry = struct {
    name: []const u8,
    is_dir: bool,
    kind: EntryKind = .file,
};

pub const Stat = struct {
    kind: EntryKind,
    mode: u32,
    size: u64,
};

pub fn entryKindFromIo(k: Io.File.Kind) EntryKind {
    return switch (k) {
        .file => .file,
        .directory => .dir,
        .sym_link => .link,
        else => .other,
    };
}

/// Permissions bits (0o777 mask) where the platform exposes them, else 0.
pub fn permissionsMode(p: Io.File.Permissions) u32 {
    if (@hasDecl(Io.File.Permissions, "toMode")) {
        return @as(u32, @intCast(p.toMode() & 0o777));
    }
    return 0;
}

pub const FS = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        readFile: *const fn (ptr: *anyopaque, allocator: Allocator, path: []const u8, max_bytes: usize) anyerror![]u8,
        writeFileSafe: *const fn (ptr: *anyopaque, allocator: Allocator, path: []const u8, data: []const u8) anyerror!void,
        writeKeyFile: *const fn (ptr: *anyopaque, allocator: Allocator, path: []const u8, data: []const u8) anyerror!void,
        appendSync: *const fn (ptr: *anyopaque, allocator: Allocator, path: []const u8, data: []const u8) anyerror!void,
        mkdir: *const fn (ptr: *anyopaque, allocator: Allocator, path: []const u8) anyerror!void,
        list: *const fn (ptr: *anyopaque, allocator: Allocator, path: []const u8) anyerror![]DirEntry,
        remove: *const fn (ptr: *anyopaque, allocator: Allocator, path: []const u8) anyerror!void,
        exists: *const fn (ptr: *anyopaque, allocator: Allocator, path: []const u8) bool,
        isDir: *const fn (ptr: *anyopaque, allocator: Allocator, path: []const u8) bool,
        stat: *const fn (ptr: *anyopaque, allocator: Allocator, path: []const u8) anyerror!Stat,
        setMode: *const fn (ptr: *anyopaque, path: []const u8, mode: u32) anyerror!void,
    };

    pub fn readFile(self: FS, allocator: Allocator, path: []const u8, max_bytes: usize) ![]u8 {
        const limit = if (max_bytes == 0) MaxFileReadBytes else max_bytes;
        return self.vtable.readFile(self.ptr, allocator, path, limit);
    }

    pub fn writeFileSafe(self: FS, allocator: Allocator, path: []const u8, data: []const u8) !void {
        return self.vtable.writeFileSafe(self.ptr, allocator, path, data);
    }

    pub fn writeKeyFile(self: FS, allocator: Allocator, path: []const u8, data: []const u8) !void {
        return self.vtable.writeKeyFile(self.ptr, allocator, path, data);
    }

    pub fn appendSync(self: FS, allocator: Allocator, path: []const u8, data: []const u8) !void {
        return self.vtable.appendSync(self.ptr, allocator, path, data);
    }

    pub fn mkdir(self: FS, allocator: Allocator, path: []const u8) !void {
        return self.vtable.mkdir(self.ptr, allocator, path);
    }

    pub fn list(self: FS, allocator: Allocator, path: []const u8) ![]DirEntry {
        return self.vtable.list(self.ptr, allocator, path);
    }

    pub fn remove(self: FS, allocator: Allocator, path: []const u8) !void {
        return self.vtable.remove(self.ptr, allocator, path);
    }

    pub fn exists(self: FS, allocator: Allocator, path: []const u8) bool {
        return self.vtable.exists(self.ptr, allocator, path);
    }

    pub fn isDir(self: FS, allocator: Allocator, path: []const u8) bool {
        return self.vtable.isDir(self.ptr, allocator, path);
    }

    /// Lstat-style metadata: the final path component is never followed
    /// through a symlink, so callers can classify links safely.
    pub fn stat(self: FS, allocator: Allocator, path: []const u8) !Stat {
        return self.vtable.stat(self.ptr, allocator, path);
    }

    /// Applies POSIX permission bits (masked to 0o777); a no-op where the
    /// platform does not expose mode bits.
    pub fn setMode(self: FS, path: []const u8, mode: u32) !void {
        return self.vtable.setMode(self.ptr, path, mode);
    }

    pub fn freeDirEntries(allocator: Allocator, entries: []DirEntry) void {
        for (entries) |e| allocator.free(e.name);
        allocator.free(entries);
    }
};

pub fn cleanMemPath(p: []const u8) []const u8 {
    if (p.len == 0) return "";
    var out = p;
    while (out.len > 1 and out[out.len - 1] == '/') {
        out = out[0 .. out.len - 1];
    }
    return out;
}

pub fn cleanPath(allocator: Allocator, p: []const u8) ![]u8 {
    if (p.len == 0) return allocator.dupe(u8, ".");
    const is_abs = p[0] == '/';
    var parts: std.ArrayList([]const u8) = .empty;
    defer parts.deinit(allocator);

    var it = std.mem.splitScalar(u8, p, '/');
    while (it.next()) |seg| {
        if (seg.len == 0 or std.mem.eql(u8, seg, ".")) continue;
        if (std.mem.eql(u8, seg, "..")) {
            if (parts.items.len > 0 and !std.mem.eql(u8, parts.items[parts.items.len - 1], "..")) {
                _ = parts.pop();
            } else if (!is_abs) {
                try parts.append(allocator, "..");
            }
            continue;
        }
        try parts.append(allocator, seg);
    }

    if (parts.items.len == 0) {
        return allocator.dupe(u8, if (is_abs) "/" else ".");
    }

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    for (parts.items, 0..) |seg, i| {
        if (is_abs or i > 0) try out.append(allocator, '/');
        try out.appendSlice(allocator, seg);
    }
    return out.toOwnedSlice(allocator);
}

pub fn joinPath(allocator: Allocator, parts: []const []const u8) ![]u8 {
    var raw: std.ArrayList(u8) = .empty;
    defer raw.deinit(allocator);
    for (parts) |part| {
        if (part.len == 0) continue;
        if (part[0] == '/') {
            raw.clearRetainingCapacity();
            try raw.appendSlice(allocator, part);
        } else {
            if (raw.items.len > 0 and raw.items[raw.items.len - 1] != '/') {
                try raw.append(allocator, '/');
            }
            try raw.appendSlice(allocator, part);
        }
    }
    return cleanPath(allocator, raw.items);
}

pub fn dirName(p: []const u8) []const u8 {
    const trimmed = cleanMemPath(p);
    if (std.mem.lastIndexOfScalar(u8, trimmed, '/')) |idx| {
        if (idx == 0) return "/";
        return trimmed[0..idx];
    }
    return ".";
}

pub fn baseName(p: []const u8) []const u8 {
    const trimmed = cleanMemPath(p);
    if (std.mem.lastIndexOfScalar(u8, trimmed, '/')) |idx| {
        return trimmed[idx + 1 ..];
    }
    return trimmed;
}

fn dirEntryLessThan(_: void, a: DirEntry, b: DirEntry) bool {
    return std.mem.lessThan(u8, a.name, b.name);
}

fn currentPid() u32 {
    if (builtin.os.tag == .linux) {
        return @intCast(@as(u32, @bitCast(std.os.linux.getpid())));
    }
    if (builtin.link_libc) {
        return @intCast(std.c.getpid());
    }
    return 0;
}

fn syncParentDir(io: Io, path: []const u8) void {
    const parent = dirName(path);
    const dir_file = Io.Dir.openFile(.cwd(), io, parent, .{
        .mode = .read_only,
        .allow_directory = true,
        .path_only = false,
    }) catch return;
    defer dir_file.close(io);
    dir_file.sync(io) catch {};
}

/// Host filesystem implementation backed by `std.Io.Dir`.
pub const HostFS = struct {
    io: Io,

    pub fn init(io: Io) HostFS {
        return .{ .io = io };
    }

    pub fn fs(self: *HostFS) FS {
        return .{
            .ptr = self,
            .vtable = &.{
                .readFile = readFileImpl,
                .writeFileSafe = writeFileSafeImpl,
                .writeKeyFile = writeKeyFileImpl,
                .appendSync = appendSyncImpl,
                .mkdir = mkdirImpl,
                .list = listImpl,
                .remove = removeImpl,
                .exists = existsImpl,
                .isDir = isDirImpl,
                .stat = statImpl,
                .setMode = setModeImpl,
            },
        };
    }

    fn readFileImpl(ptr: *anyopaque, allocator: Allocator, path: []const u8, max_bytes: usize) anyerror![]u8 {
        const self: *HostFS = @ptrCast(@alignCast(ptr));
        const file = try Io.Dir.openFile(.cwd(), self.io, path, .{ .mode = .read_only });
        defer file.close(self.io);

        var rbuf: [4096]u8 = undefined;
        var reader = file.reader(self.io, &rbuf);
        const data = reader.interface.allocRemaining(allocator, .limited(max_bytes + 1)) catch |err| switch (err) {
            error.StreamTooLong => return refuse("store_too_large", "file"),
            else => return err,
        };
        if (data.len > max_bytes) {
            allocator.free(data);
            return refuse("store_too_large", "file");
        }
        return data;
    }

    /// Ensures `path`'s parent directory exists, skipping `createDirPath`
    /// when it already resolves to one — its not-following stat reports
    /// NotDir on a symlinked leaf (e.g. /tmp -> /private/tmp on macOS).
    fn ensureParentDir(ptr: *anyopaque, allocator: Allocator, path: []const u8) anyerror!void {
        const self: *HostFS = @ptrCast(@alignCast(ptr));
        const parent = dirName(path);
        if (parent.len == 0 or std.mem.eql(u8, parent, ".") or std.mem.eql(u8, parent, "/")) return;
        if (!isDirImpl(ptr, allocator, parent)) {
            try Io.Dir.createDirPath(.cwd(), self.io, parent);
        }
    }

    fn writeFileSafeImpl(ptr: *anyopaque, allocator: Allocator, path: []const u8, data: []const u8) anyerror!void {
        const self: *HostFS = @ptrCast(@alignCast(ptr));
        try ensureParentDir(ptr, allocator, path);

        var rand_u64: u64 = 0;
        self.io.random(std.mem.asBytes(&rand_u64));
        const rand_hex = std.fmt.hex(rand_u64);
        const pid = currentPid();

        const tmp_path = try std.fmt.allocPrint(allocator, "{s}.tmp-{d}-{s}", .{ path, pid, &rand_hex });
        defer allocator.free(tmp_path);

        {
            const tmp_file = try Io.Dir.createFile(.cwd(), self.io, tmp_path, .{ .truncate = true });
            errdefer {
                tmp_file.close(self.io);
                Io.Dir.deleteFile(.cwd(), self.io, tmp_path) catch {};
            }
            try tmp_file.writeStreamingAll(self.io, data);
            try tmp_file.sync(self.io);
            tmp_file.close(self.io);
        }

        errdefer Io.Dir.deleteFile(.cwd(), self.io, tmp_path) catch {};
        try Io.Dir.rename(.cwd(), tmp_path, .cwd(), path, self.io);
        syncParentDir(self.io, path);
    }

    fn writeKeyFileImpl(ptr: *anyopaque, allocator: Allocator, path: []const u8, data: []const u8) anyerror!void {
        const self: *HostFS = @ptrCast(@alignCast(ptr));
        if (existsImpl(ptr, allocator, path)) {
            return refuse("key_exists", "");
        }
        try ensureParentDir(ptr, allocator, path);

        const file = Io.Dir.createFile(.cwd(), self.io, path, .{
            .exclusive = true,
            .permissions = Io.File.Permissions.fromMode(0o600),
        }) catch |err| switch (err) {
            error.PathAlreadyExists => return refuse("key_exists", ""),
            else => return err,
        };
        errdefer {
            file.close(self.io);
            Io.Dir.deleteFile(.cwd(), self.io, path) catch {};
        }
        try file.writeStreamingAll(self.io, data);
        try file.sync(self.io);
        file.close(self.io);
        syncParentDir(self.io, path);
    }

    fn appendSyncImpl(ptr: *anyopaque, allocator: Allocator, path: []const u8, data: []const u8) anyerror!void {
        const self: *HostFS = @ptrCast(@alignCast(ptr));
        try ensureParentDir(ptr, allocator, path);

        const file = try Io.Dir.createFile(.cwd(), self.io, path, .{
            .truncate = false,
            .read = true,
        });
        defer file.close(self.io);

        const end_pos = try file.length(self.io);
        try file.writePositionalAll(self.io, data, end_pos);
        try file.sync(self.io);
    }

    fn mkdirImpl(ptr: *anyopaque, allocator: Allocator, path: []const u8) anyerror!void {
        const self: *HostFS = @ptrCast(@alignCast(ptr));
        const clean = cleanMemPath(path);
        if (clean.len == 0 or std.mem.eql(u8, clean, ".") or std.mem.eql(u8, clean, "/")) return;
        if (!isDirImpl(ptr, allocator, clean)) {
            try Io.Dir.createDirPath(.cwd(), self.io, clean);
        }
    }

    fn listImpl(ptr: *anyopaque, allocator: Allocator, path: []const u8) anyerror![]DirEntry {
        const self: *HostFS = @ptrCast(@alignCast(ptr));
        var dir = try Io.Dir.openDir(.cwd(), self.io, path, .{ .iterate = true });
        defer dir.close(self.io);

        var list_out: std.ArrayList(DirEntry) = .empty;
        errdefer {
            for (list_out.items) |e| allocator.free(e.name);
            list_out.deinit(allocator);
        }

        var it = dir.iterate();
        while (try it.next(self.io)) |entry| {
            const name_copy = try allocator.dupe(u8, entry.name);
            errdefer allocator.free(name_copy);
            try list_out.append(allocator, .{
                .name = name_copy,
                .is_dir = entry.kind == .directory,
                .kind = entryKindFromIo(entry.kind),
            });
        }

        const slice = try list_out.toOwnedSlice(allocator);
        std.mem.sort(DirEntry, slice, {}, dirEntryLessThan);
        return slice;
    }

    fn removeImpl(ptr: *anyopaque, allocator: Allocator, path: []const u8) anyerror!void {
        _ = allocator;
        const self: *HostFS = @ptrCast(@alignCast(ptr));
        try Io.Dir.deleteFile(.cwd(), self.io, path);
    }

    fn existsImpl(ptr: *anyopaque, allocator: Allocator, path: []const u8) bool {
        _ = allocator;
        const self: *HostFS = @ptrCast(@alignCast(ptr));
        _ = Io.Dir.statFile(.cwd(), self.io, path, .{}) catch return false;
        return true;
    }

    fn isDirImpl(ptr: *anyopaque, allocator: Allocator, path: []const u8) bool {
        _ = allocator;
        const self: *HostFS = @ptrCast(@alignCast(ptr));
        const st = Io.Dir.statFile(.cwd(), self.io, path, .{}) catch return false;
        return st.kind == .directory;
    }

    fn statImpl(ptr: *anyopaque, allocator: Allocator, path: []const u8) anyerror!Stat {
        _ = allocator;
        const self: *HostFS = @ptrCast(@alignCast(ptr));
        const st = try Io.Dir.statFile(.cwd(), self.io, path, .{ .follow_symlinks = false });
        return .{
            .kind = entryKindFromIo(st.kind),
            .mode = permissionsMode(st.permissions),
            .size = st.size,
        };
    }

    fn setModeImpl(ptr: *anyopaque, path: []const u8, mode: u32) anyerror!void {
        const self: *HostFS = @ptrCast(@alignCast(ptr));
        if (@hasDecl(Io.File.Permissions, "fromMode")) {
            const perms = Io.File.Permissions.fromMode(@intCast(mode & 0o777));
            try Io.Dir.setFilePermissions(.cwd(), self.io, path, perms, .{});
        }
    }
};

/// In-memory filesystem for deterministic unit and conformance tests,
/// mirroring Go's `memFS` (including the `before_write` fault-injection hook).
pub const MemFS = struct {
    allocator: Allocator,
    files: std.StringHashMap([]u8),
    dirs: std.StringHashMap(void),
    modes: std.StringHashMap(u32),
    links: std.StringHashMap([]u8),
    before_write_ctx: ?*anyopaque = null,
    before_write: ?*const fn (ctx: ?*anyopaque, op: []const u8, path: []const u8) anyerror!void = null,

    pub fn init(allocator: Allocator) !MemFS {
        var self = MemFS{
            .allocator = allocator,
            .files = std.StringHashMap([]u8).init(allocator),
            .dirs = std.StringHashMap(void).init(allocator),
            .modes = std.StringHashMap(u32).init(allocator),
            .links = std.StringHashMap([]u8).init(allocator),
        };
        try self.putDir("/host");
        return self;
    }

    pub fn deinit(self: *MemFS) void {
        var fit = self.files.iterator();
        while (fit.next()) |kv| {
            self.allocator.free(kv.key_ptr.*);
            self.allocator.free(kv.value_ptr.*);
        }
        self.files.deinit();

        var dit = self.dirs.iterator();
        while (dit.next()) |kv| {
            self.allocator.free(kv.key_ptr.*);
        }
        self.dirs.deinit();

        var mit = self.modes.iterator();
        while (mit.next()) |kv| {
            self.allocator.free(kv.key_ptr.*);
        }
        self.modes.deinit();

        var lit = self.links.iterator();
        while (lit.next()) |kv| {
            self.allocator.free(kv.key_ptr.*);
            self.allocator.free(kv.value_ptr.*);
        }
        self.links.deinit();
    }

    pub fn fs(self: *MemFS) FS {
        return .{
            .ptr = self,
            .vtable = &.{
                .readFile = readFileImpl,
                .writeFileSafe = writeFileSafeImpl,
                .writeKeyFile = writeKeyFileImpl,
                .appendSync = appendSyncImpl,
                .mkdir = mkdirImpl,
                .list = listImpl,
                .remove = removeImpl,
                .exists = existsImpl,
                .isDir = isDirImpl,
                .stat = statImpl,
                .setMode = setModeImpl,
            },
        };
    }

    pub fn getMode(self: *const MemFS, path: []const u8) ?u32 {
        return self.modes.get(cleanMemPath(path));
    }

    /// Adds a symlink entry at `path` pointing at `target` for tests that need
    /// non-regular directory entries. Links are classified, never resolved.
    pub fn addSymlink(self: *MemFS, path: []const u8, target: []const u8) !void {
        const p = cleanMemPath(path);
        try self.markParents(p);
        const k = try self.allocator.dupe(u8, p);
        errdefer self.allocator.free(k);
        const v = try self.allocator.dupe(u8, target);
        errdefer self.allocator.free(v);
        try self.links.put(k, v);
    }

    fn putDir(self: *MemFS, p: []const u8) !void {
        const clean = cleanMemPath(p);
        if (clean.len == 0) return;
        if (!self.dirs.contains(clean)) {
            const k = try self.allocator.dupe(u8, clean);
            errdefer self.allocator.free(k);
            try self.dirs.put(k, {});
        }
    }

    fn markParents(self: *MemFS, p: []const u8) !void {
        var cur = cleanMemPath(p);
        while (true) {
            const idx = std.mem.lastIndexOfScalar(u8, cur, '/') orelse break;
            if (idx == 0) {
                try self.putDir("/");
                break;
            }
            cur = cur[0..idx];
            try self.putDir(cur);
        }
    }

    fn putMode(self: *MemFS, p: []const u8, mode: u32) !void {
        if (self.modes.getPtr(p)) |m| {
            m.* = mode;
        } else {
            const k = try self.allocator.dupe(u8, p);
            errdefer self.allocator.free(k);
            try self.modes.put(k, mode);
        }
    }

    fn readFileImpl(ptr: *anyopaque, allocator: Allocator, path: []const u8, max_bytes: usize) anyerror![]u8 {
        const self: *MemFS = @ptrCast(@alignCast(ptr));
        const p = cleanMemPath(path);
        if (self.dirs.contains(p)) return error.IsDir;
        const data = self.files.get(p) orelse return error.FileNotFound;
        if (data.len > max_bytes) return refuse("store_too_large", "file");
        return allocator.dupe(u8, data);
    }

    fn writeFileSafeImpl(ptr: *anyopaque, allocator: Allocator, path: []const u8, data: []const u8) anyerror!void {
        _ = allocator;
        const self: *MemFS = @ptrCast(@alignCast(ptr));
        const p = cleanMemPath(path);
        if (p.len == 0) return error.InvalidArgument;
        if (self.before_write) |hook| {
            try hook(self.before_write_ctx, "write", p);
        }
        if (self.dirs.contains(p)) return error.IsDir;
        try self.markParents(p);

        const copy = try self.allocator.dupe(u8, data);
        errdefer self.allocator.free(copy);

        if (self.files.getPtr(p)) |existing| {
            self.allocator.free(existing.*);
            existing.* = copy;
        } else {
            const k = try self.allocator.dupe(u8, p);
            errdefer self.allocator.free(k);
            try self.files.put(k, copy);
        }
        try self.putMode(p, 0o644);
    }

    fn writeKeyFileImpl(ptr: *anyopaque, allocator: Allocator, path: []const u8, data: []const u8) anyerror!void {
        const self: *MemFS = @ptrCast(@alignCast(ptr));
        const p = cleanMemPath(path);
        if (p.len == 0) return error.InvalidArgument;
        if (self.before_write) |hook| {
            try hook(self.before_write_ctx, "write", p);
        }
        if (existsImpl(ptr, allocator, p)) {
            return refuse("key_exists", "");
        }
        try self.markParents(p);

        const copy = try self.allocator.dupe(u8, data);
        errdefer self.allocator.free(copy);
        const k = try self.allocator.dupe(u8, p);
        errdefer self.allocator.free(k);
        try self.files.put(k, copy);
        try self.putMode(p, 0o600);
    }

    fn appendSyncImpl(ptr: *anyopaque, allocator: Allocator, path: []const u8, data: []const u8) anyerror!void {
        _ = allocator;
        const self: *MemFS = @ptrCast(@alignCast(ptr));
        const p = cleanMemPath(path);
        if (p.len == 0) return error.InvalidArgument;
        if (self.before_write) |hook| {
            try hook(self.before_write_ctx, "append", p);
        }
        if (self.dirs.contains(p)) return error.IsDir;
        try self.markParents(p);

        if (self.files.getPtr(p)) |existing| {
            const combined = try self.allocator.alloc(u8, existing.*.len + data.len);
            @memcpy(combined[0..existing.*.len], existing.*);
            @memcpy(combined[existing.*.len..], data);
            self.allocator.free(existing.*);
            existing.* = combined;
        } else {
            const copy = try self.allocator.dupe(u8, data);
            errdefer self.allocator.free(copy);
            const k = try self.allocator.dupe(u8, p);
            errdefer self.allocator.free(k);
            try self.files.put(k, copy);
        }
    }

    fn mkdirImpl(ptr: *anyopaque, allocator: Allocator, path: []const u8) anyerror!void {
        _ = allocator;
        const self: *MemFS = @ptrCast(@alignCast(ptr));
        const p = cleanMemPath(path);
        if (p.len == 0) return error.InvalidArgument;
        if (self.before_write) |hook| {
            try hook(self.before_write_ctx, "mkdir", p);
        }
        if (self.files.contains(p)) return error.PathAlreadyExists;
        try self.markParents(p);
        try self.putDir(p);
    }

    fn listImpl(ptr: *anyopaque, allocator: Allocator, path: []const u8) anyerror![]DirEntry {
        const self: *MemFS = @ptrCast(@alignCast(ptr));
        const dir = cleanMemPath(path);
        if (self.files.contains(dir)) return error.NotDir;

        const prefix = if (std.mem.eql(u8, dir, "/"))
            try allocator.dupe(u8, "/")
        else
            try std.fmt.allocPrint(allocator, "{s}/", .{dir});
        defer allocator.free(prefix);

        var children = std.StringHashMap(EntryKind).init(allocator);
        defer children.deinit();

        var found_dir = self.dirs.contains(dir);

        var dit = self.dirs.iterator();
        while (dit.next()) |kv| {
            const p = kv.key_ptr.*;
            if (std.mem.startsWith(u8, p, prefix)) {
                found_dir = true;
                const rest = p[prefix.len..];
                if (rest.len == 0) continue;
                const child_name = if (std.mem.indexOfScalar(u8, rest, '/')) |i| rest[0..i] else rest;
                try children.put(child_name, .dir);
            }
        }

        var fit = self.files.iterator();
        while (fit.next()) |kv| {
            const p = kv.key_ptr.*;
            if (std.mem.startsWith(u8, p, prefix)) {
                found_dir = true;
                const rest = p[prefix.len..];
                if (rest.len == 0) continue;
                if (std.mem.indexOfScalar(u8, rest, '/')) |i| {
                    try children.put(rest[0..i], .dir);
                } else if (!children.contains(rest)) {
                    try children.put(rest, .file);
                }
            }
        }

        var lit = self.links.iterator();
        while (lit.next()) |kv| {
            const p = kv.key_ptr.*;
            if (std.mem.startsWith(u8, p, prefix)) {
                found_dir = true;
                const rest = p[prefix.len..];
                if (rest.len == 0) continue;
                const child_name = if (std.mem.indexOfScalar(u8, rest, '/')) |i| rest[0..i] else rest;
                if (std.mem.indexOfScalar(u8, rest, '/') == null and !children.contains(child_name)) {
                    try children.put(child_name, .link);
                }
            }
        }

        if (!found_dir) return error.FileNotFound;

        var out: std.ArrayList(DirEntry) = .empty;
        errdefer {
            for (out.items) |e| allocator.free(e.name);
            out.deinit(allocator);
        }

        var cit = children.iterator();
        while (cit.next()) |kv| {
            const name_copy = try allocator.dupe(u8, kv.key_ptr.*);
            errdefer allocator.free(name_copy);
            try out.append(allocator, .{
                .name = name_copy,
                .is_dir = kv.value_ptr.* == .dir,
                .kind = kv.value_ptr.*,
            });
        }

        const slice = try out.toOwnedSlice(allocator);
        std.mem.sort(DirEntry, slice, {}, dirEntryLessThan);
        return slice;
    }

    fn removeImpl(ptr: *anyopaque, allocator: Allocator, path: []const u8) anyerror!void {
        _ = allocator;
        const self: *MemFS = @ptrCast(@alignCast(ptr));
        const p = cleanMemPath(path);
        if (self.before_write) |hook| {
            try hook(self.before_write_ctx, "remove", p);
        }
        if (self.links.fetchRemove(p)) |lkv| {
            self.allocator.free(lkv.key);
            self.allocator.free(lkv.value);
            return;
        }
        if (self.files.fetchRemove(p)) |kv| {
            self.allocator.free(kv.key);
            self.allocator.free(kv.value);
            if (self.modes.fetchRemove(p)) |mkv| {
                self.allocator.free(mkv.key);
            }
            return;
        }
        if (self.dirs.fetchRemove(p)) |dkv| {
            self.allocator.free(dkv.key);
            return;
        }
        return error.FileNotFound;
    }

    fn existsImpl(ptr: *anyopaque, allocator: Allocator, path: []const u8) bool {
        const self: *MemFS = @ptrCast(@alignCast(ptr));
        const p = cleanMemPath(path);
        if (self.files.contains(p) or self.dirs.contains(p) or self.links.contains(p)) return true;
        const prefix = std.fmt.allocPrint(allocator, "{s}/", .{p}) catch return false;
        defer allocator.free(prefix);

        var fit = self.files.iterator();
        while (fit.next()) |kv| {
            if (std.mem.startsWith(u8, kv.key_ptr.*, prefix)) return true;
        }
        var dit = self.dirs.iterator();
        while (dit.next()) |kv| {
            if (std.mem.startsWith(u8, kv.key_ptr.*, prefix)) return true;
        }
        return false;
    }

    fn isDirImpl(ptr: *anyopaque, allocator: Allocator, path: []const u8) bool {
        const self: *MemFS = @ptrCast(@alignCast(ptr));
        const p = cleanMemPath(path);
        if (self.files.contains(p)) return false;
        if (self.dirs.contains(p)) return true;
        const prefix = std.fmt.allocPrint(allocator, "{s}/", .{p}) catch return false;
        defer allocator.free(prefix);

        var fit = self.files.iterator();
        while (fit.next()) |kv| {
            if (std.mem.startsWith(u8, kv.key_ptr.*, prefix)) return true;
        }
        var dit = self.dirs.iterator();
        while (dit.next()) |kv| {
            if (std.mem.startsWith(u8, kv.key_ptr.*, prefix)) return true;
        }
        return false;
    }

    fn statImpl(ptr: *anyopaque, allocator: Allocator, path: []const u8) anyerror!Stat {
        const self: *MemFS = @ptrCast(@alignCast(ptr));
        const p = cleanMemPath(path);
        if (self.files.get(p)) |data| {
            return .{
                .kind = .file,
                .mode = self.modes.get(p) orelse 0o644,
                .size = data.len,
            };
        }
        if (self.links.get(p)) |target| {
            return .{ .kind = .link, .mode = 0o777, .size = target.len };
        }
        if (isDirImpl(ptr, allocator, p)) {
            return .{ .kind = .dir, .mode = 0o755, .size = 0 };
        }
        return error.FileNotFound;
    }

    fn setModeImpl(ptr: *anyopaque, path: []const u8, mode: u32) anyerror!void {
        const self: *MemFS = @ptrCast(@alignCast(ptr));
        const p = cleanMemPath(path);
        if (!self.files.contains(p)) return error.FileNotFound;
        try self.putMode(p, mode & 0o777);
    }
};
