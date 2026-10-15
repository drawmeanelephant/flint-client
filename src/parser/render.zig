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

fn dirEntryLess(_: void, a: fsys.DirEntry, b: fsys.DirEntry) bool {
    return std.mem.lessThan(u8, a.name, b.name);
}

pub fn cmdParseCorpus(
    allocator: std.mem.Allocator,
    fs: fsys.FS,
    args: []const []const u8,
    out_w: *std.Io.Writer,
) !u8 {
    if (args.len != 1 or args[0].len == 0) {
        return fsys.refuse("usage", "");
    }
    const root = std.mem.trimEnd(u8, args[0], "/");
    if (root.len == 0) {
        return fsys.refuse("usage", "");
    }

    var all: std.ArrayList(Atom) = .empty;
    defer {
        for (all.items) |*a| a.deinit(allocator);
        all.deinit(allocator);
    }

    var files: usize = 0;
    var parse_errors: usize = 0;

    const go_dir = try std.fmt.allocPrint(allocator, "{s}/go", .{root});
    defer allocator.free(go_dir);
    const zig_dir = try std.fmt.allocPrint(allocator, "{s}/zig", .{root});
    defer allocator.free(zig_dir);

    const has_split_dirs = (fs.exists(allocator, go_dir) and fs.isDir(allocator, go_dir)) or
        (fs.exists(allocator, zig_dir) and fs.isDir(allocator, zig_dir));

    if (!fs.exists(allocator, root)) {
        parse_errors += 1;
    } else if (has_split_dirs) {
        const subs = [_][]const u8{ "go", "zig" };
        for (subs) |sub| {
            const dir = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ root, sub });
            defer allocator.free(dir);
            if (!fs.exists(allocator, dir)) continue;
            const entries = fs.list(allocator, dir) catch {
                parse_errors += 1;
                continue;
            };
            defer fsys.FS.freeDirEntries(allocator, entries);
            std.mem.sort(fsys.DirEntry, entries, {}, dirEntryLess);

            for (entries) |e| {
                if (e.is_dir) continue;
                const rel = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ sub, e.name });
                defer allocator.free(rel);
                if (parser.forPath(rel) == null) continue;

                files += 1;
                const full = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ dir, e.name });
                defer allocator.free(full);
                const src = fs.readFile(allocator, full, fsys.MaxFileReadBytes) catch {
                    parse_errors += 1;
                    continue;
                };
                defer allocator.free(src);

                var perr: ?parser.ParseErrorInfo = null;
                const atoms = parser.parseFile(allocator, rel, src, null, &perr) catch {
                    parse_errors += 1;
                    continue;
                };
                defer allocator.free(atoms);

                for (atoms) |a| {
                    try all.append(allocator, a);
                }
            }
        }
    } else {
        if (fs.list(allocator, root)) |entries| {
            defer fsys.FS.freeDirEntries(allocator, entries);
            std.mem.sort(fsys.DirEntry, entries, {}, dirEntryLess);

            for (entries) |e| {
                if (e.is_dir) continue;
                if (parser.forPath(e.name) == null) continue;

                files += 1;
                const full = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ root, e.name });
                defer allocator.free(full);
                const src = fs.readFile(allocator, full, fsys.MaxFileReadBytes) catch {
                    parse_errors += 1;
                    continue;
                };
                defer allocator.free(src);

                var perr: ?parser.ParseErrorInfo = null;
                const atoms = parser.parseFile(allocator, e.name, src, null, &perr) catch {
                    parse_errors += 1;
                    continue;
                };
                defer allocator.free(atoms);

                for (atoms) |a| {
                    try all.append(allocator, a);
                }
            }
        } else |_| {
            parse_errors += 1;
        }
    }

    const out = try render(allocator, all.items);
    defer allocator.free(out);

    const out_path = try std.fmt.allocPrint(allocator, "{s}.OUT", .{root});
    defer allocator.free(out_path);

    var write_failed = false;
    fs.writeFileSafe(allocator, out_path, out) catch {
        write_failed = true;
    };

    try out_w.print(
        "flint: parse files={d} atoms={d} parse_errors={d}\n",
        .{ files, all.items.len, parse_errors },
    );

    if (parse_errors != 0 or write_failed) {
        return 1;
    }
    return 0;
}
