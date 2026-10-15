const std = @import("std");
const fsys = @import("../fsys.zig");
const parser = @import("parser.zig");

const Atom = parser.Atom;

fn atomLess(_: void, a: Atom, b: Atom) bool {
    const cmp = std.mem.order(u8, a.file, b.file);
    if (cmp != .eq) return cmp == .lt;
    return a.start < b.start;
}

pub fn render(allocator: std.mem.Allocator, atoms: []const Atom) ![]u8 {
    const sorted = try allocator.dupe(Atom, atoms);
    defer allocator.free(sorted);
    std.mem.sort(Atom, sorted, {}, atomLess);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    for (sorted) |a| {
        const hash_hex = std.fmt.bytesToHex(a.hash, .lower);
        const sig_hex = std.fmt.bytesToHex(a.sig_hash, .lower);
        const line = try std.fmt.allocPrint(
            allocator,
            "{s}\t{s}\t{s}\t{d}\t{d}\t{s}\t{s}\n",
            .{ a.file, a.kind, a.name, a.start, a.end, &hash_hex, &sig_hex },
        );
        defer allocator.free(line);
        try out.appendSlice(allocator, line);
    }

    return out.toOwnedSlice(allocator);
}

pub fn cmdParseCorpus(
    allocator: std.mem.Allocator,
    fs: fsys.FS,
    args: []const []const u8,
    out_w: *std.Io.Writer,
) !void {
    if (args.len == 0) {
        return fsys.refuse("bad_args", "parse-corpus <dir>");
    }
    const root = fsys.cleanMemPath(args[0]);

    var all: std.ArrayList(Atom) = .empty;
    defer {
        for (all.items) |*a| a.deinit(allocator);
        all.deinit(allocator);
    }

    const subs = [_][]const u8{ "go", "zig" };
    for (subs) |sub| {
        const dir = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ root, sub });
        defer allocator.free(dir);
        const entries = fs.list(allocator, dir) catch continue;
        defer fsys.FS.freeDirEntries(allocator, entries);

        for (entries) |e| {
            if (e.is_dir) continue;
            const rel = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ sub, e.name });
            defer allocator.free(rel);
            if (parser.forPath(rel) == null) continue;

            const full = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ dir, e.name });
            defer allocator.free(full);
            const src = try fs.readFile(allocator, full, fsys.MaxFileReadBytes);
            defer allocator.free(src);

            var perr: ?parser.ParseErrorInfo = null;
            const atoms = parser.parseFile(allocator, rel, src, null, &perr) catch |err| {
                if (err == error.ParseFailed) {
                    if (perr) |pe| {
                        return fsys.refuse(pe.code, pe.file);
                    }
                    return fsys.refuse("syntax", rel);
                }
                return err;
            };
            defer allocator.free(atoms);

            for (atoms) |a| {
                try all.append(allocator, a);
            }
        }
    }

    const out = try render(allocator, all.items);
    defer allocator.free(out);

    var it = std.mem.splitScalar(u8, out, '\n');
    while (it.next()) |line| {
        if (line.len == 0) continue;
        try out_w.print("{s}\n", .{line});
    }
}
