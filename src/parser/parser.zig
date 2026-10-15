const std = @import("std");
const store = @import("../store.zig");
const zig_parser = @import("zig.zig");

pub const Atom = struct {
    kind: []const u8,
    name: []const u8,
    file: []const u8,
    start: u32,
    end: u32,
    hash: [32]u8,
    sig_hash: [32]u8,
    meta: []store.MetaEntry = &.{},

    pub fn deinit(self: *Atom, allocator: std.mem.Allocator) void {
        allocator.free(self.kind);
        allocator.free(self.name);
        allocator.free(self.file);
        for (self.meta) |m| {
            m.deinit(allocator);
        }
        if (self.meta.len > 0) allocator.free(self.meta);
    }
};

pub fn freeAtoms(allocator: std.mem.Allocator, atoms: []Atom) void {
    for (atoms) |*a| a.deinit(allocator);
    allocator.free(atoms);
}

pub const ParseErrorInfo = struct {
    file: []const u8,
    offset: usize,
    code: []const u8,

    pub fn formatAlloc(self: ParseErrorInfo, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "flint: {s} {s}:{d}", .{ self.code, self.file, self.offset });
    }
};

pub const Language = enum {
    go,
    zig,
};

pub fn forPath(file: []const u8) ?Language {
    if (std.mem.endsWith(u8, file, ".go")) return .go;
    if (std.mem.endsWith(u8, file, ".zig")) return .zig;
    return null;
}

pub fn parseFile(
    allocator: std.mem.Allocator,
    file: []const u8,
    src: []const u8,
    sink: ?*std.StringHashMap([]const u8),
    err_info: *?ParseErrorInfo,
) ![]Atom {
    const lang = forPath(file) orelse {
        err_info.* = .{ .file = file, .offset = 0, .code = "parse_unsupported" };
        return error.ParseFailed;
    };
    return switch (lang) {
        .zig => zig_parser.parse(allocator, file, src, sink, err_info),
        .go => {
            err_info.* = .{ .file = file, .offset = 0, .code = "parse_unsupported" };
            return error.ParseFailed;
        },
    };
}

pub fn canonMap(
    allocator: std.mem.Allocator,
    file: []const u8,
    src: []const u8,
    err_info: *?ParseErrorInfo,
) !std.StringHashMap([]const u8) {
    var map = std.StringHashMap([]const u8).init(allocator);
    errdefer freeCanonMap(allocator, &map);

    const atoms = try parseFile(allocator, file, src, &map, err_info);
    freeAtoms(allocator, atoms);
    return map;
}

pub fn freeCanonMap(allocator: std.mem.Allocator, map: *std.StringHashMap([]const u8)) void {
    var it = map.iterator();
    while (it.next()) |entry| {
        allocator.free(entry.key_ptr.*);
        allocator.free(entry.value_ptr.*);
    }
    map.deinit();
}
