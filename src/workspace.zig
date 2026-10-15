const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const fsys = @import("fsys.zig");
const FS = fsys.FS;
const store = @import("store.zig");
const uuid = @import("uuid.zig");
const parser = @import("parser/parser.zig");

pub fn storedAtomFromParser(allocator: Allocator, id: []const u8, a: parser.Atom) !store.StoredAtom {
    const id_dup = try allocator.dupe(u8, id);
    errdefer allocator.free(id_dup);
    const kind_dup = try allocator.dupe(u8, a.kind);
    errdefer allocator.free(kind_dup);
    const name_dup = try allocator.dupe(u8, a.name);
    errdefer allocator.free(name_dup);

    const hash_hex = std.fmt.bytesToHex(a.hash, .lower);
    const hash_dup = try allocator.dupe(u8, &hash_hex);
    errdefer allocator.free(hash_dup);

    const sig_hex = std.fmt.bytesToHex(a.sig_hash, .lower);
    const sig_dup = try allocator.dupe(u8, &sig_hex);
    errdefer allocator.free(sig_dup);

    const file_dup = try allocator.dupe(u8, a.file);
    errdefer allocator.free(file_dup);

    var meta: []store.MetaEntry = &.{};
    if (a.meta.len > 0) {
        meta = try allocator.alloc(store.MetaEntry, a.meta.len);
        var i: usize = 0;
        errdefer {
            for (meta[0..i]) |m| m.deinit(allocator);
            allocator.free(meta);
        }
        while (i < a.meta.len) : (i += 1) {
            meta[i] = try a.meta[i].clone(allocator);
        }
    }

    return .{
        .id = id_dup,
        .kind = kind_dup,
        .name = name_dup,
        .hash = hash_dup,
        .sig_hash = sig_dup,
        .span = .{
            .file = file_dup,
            .start = a.start,
            .end = a.end,
        },
        .metadata = meta,
        .origin = "",
    };
}

/// Implements `flint init --name=<ws> --src=<dir> [--stream=<name>]`.
pub fn cmdInit(
    allocator: Allocator,
    fs: FS,
    root: []const u8,
    uuid_gen: *uuid.UUIDGen,
    out: *Io.Writer,
    args: []const []const u8,
) !void {
    var ws_name: []const u8 = "";
    var raw_src: []const u8 = "";
    var stream_flag: []const u8 = "";
    var has_stream_flag = false;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.startsWith(u8, a, "--name=")) {
            ws_name = a["--name=".len..];
        } else if (std.mem.eql(u8, a, "--name") and i + 1 < args.len) {
            i += 1;
            ws_name = args[i];
        } else if (std.mem.startsWith(u8, a, "--src=")) {
            raw_src = a["--src=".len..];
        } else if (std.mem.eql(u8, a, "--src") and i + 1 < args.len) {
            i += 1;
            raw_src = args[i];
        } else if (std.mem.startsWith(u8, a, "--stream=")) {
            stream_flag = a["--stream=".len..];
            has_stream_flag = true;
        } else if (std.mem.eql(u8, a, "--stream") and i + 1 < args.len) {
            i += 1;
            stream_flag = args[i];
            has_stream_flag = true;
        } else {
            return fsys.refuse("usage", "");
        }
    }

    if (!store.validWorkspaceName(ws_name) or raw_src.len == 0 or (has_stream_flag and stream_flag.len == 0)) {
        return fsys.refuse("usage", "");
    }

    const src_dir = try fsys.cleanPath(allocator, raw_src);
    defer allocator.free(src_dir);
    if (!fs.exists(allocator, src_dir)) {
        return fsys.refuse("src_missing", "");
    }

    var idx = try store.loadStoreIndex(allocator, fs, root);
    defer idx.deinit();

    const cfg_path = try store.workspaceConfigPath(allocator, root, ws_name);
    defer allocator.free(cfg_path);
    if (idx.workspaceByName(ws_name) != null or fs.exists(allocator, cfg_path)) {
        return fsys.refuse("ws_exists", "");
    }

    const created_ms = try uuid_gen.nowMs();

    if (has_stream_flag) {
        const st_init = idx.streamByName(stream_flag) orelse {
            return fsys.refuse("stream_missing", stream_flag);
        };
        const stream_id = try allocator.dupe(u8, st_init.id);
        defer allocator.free(stream_id);

        const all_changes = try store.loadAllStreamChanges(allocator, fs, root, &idx);
        defer store.freeChanges(allocator, all_changes);

        const st = idx.streamByID(stream_id) orelse {
            return fsys.refuse("stream_missing", stream_flag);
        };

        const replay = try store.replayStreamAtoms(allocator, st.head, all_changes);
        defer store.freeStoredAtoms(allocator, replay.atoms);

        if (replay.atoms.len > store.MaxAtoms) {
            return fsys.refuse("store_too_large", "atoms");
        }

        const ws_dir = try store.workspaceDir(allocator, root, ws_name);
        defer allocator.free(ws_dir);
        try fs.mkdir(allocator, ws_dir);

        const ws = store.Workspace{
            .name = ws_name,
            .src = src_dir,
            .stream = st.id,
            .created = created_ms,
        };
        try store.writeWorkspaceConfig(allocator, fs, root, ws);
        try store.writeWorkspaceAtoms(allocator, fs, root, ws_name, replay.atoms);

        try out.print(
            "flint: init ok ws={s} stream={s} atoms={d} replayed={d}\n",
            .{ ws_name, st.name, replay.atoms.len, replay.replayed },
        );
        return;
    }

    if (idx.streamByName("main") != null) {
        return fsys.refuse("stream_exists", "main");
    }

    const stream_id = try uuid_gen.new();

    const s_dir = try store.streamsDir(allocator, root);
    defer allocator.free(s_dir);
    try fs.mkdir(allocator, s_dir);

    const ws_dir = try store.workspaceDir(allocator, root, ws_name);
    defer allocator.free(ws_dir);
    try fs.mkdir(allocator, ws_dir);

    const st = store.Stream{
        .id = &stream_id,
        .name = "main",
        .head = null,
        .created = created_ms,
        .forked_from = null,
    };
    try store.writeStreamRecord(allocator, fs, root, st);

    const ws = store.Workspace{
        .name = ws_name,
        .src = src_dir,
        .stream = &stream_id,
        .created = created_ms,
    };
    try store.writeWorkspaceConfig(allocator, fs, root, ws);

    const atoms_path = try store.workspaceAtomsPath(allocator, root, ws_name);
    defer allocator.free(atoms_path);
    try fs.writeFileSafe(allocator, atoms_path, "");

    try out.print("flint: init ok ws={s} stream=main\n", .{ws_name});
}

const AddTarget = struct {
    rel_prefix: []const u8,
    is_dir: bool,
};

fn relToSrc(src_root: []const u8, p: []const u8) ?[]const u8 {
    const clean_root = fsys.cleanMemPath(src_root);
    const clean_p = fsys.cleanMemPath(p);
    if (std.mem.eql(u8, clean_p, clean_root)) {
        return "";
    }
    if (std.mem.startsWith(u8, clean_p, clean_root) and
        clean_p.len > clean_root.len and
        clean_p[clean_root.len] == '/')
    {
        return clean_p[clean_root.len + 1 ..];
    }
    return null;
}

fn inTargets(rel: []const u8, targets: []const AddTarget) bool {
    for (targets) |t| {
        if (!t.is_dir) {
            if (std.mem.eql(u8, rel, t.rel_prefix)) return true;
            continue;
        }
        if (t.rel_prefix.len == 0 or std.mem.eql(u8, rel, t.rel_prefix)) {
            return true;
        }
        if (std.mem.startsWith(u8, rel, t.rel_prefix) and
            rel.len > t.rel_prefix.len and
            rel[t.rel_prefix.len] == '/')
        {
            return true;
        }
    }
    return false;
}

fn walkSourceFiles(
    allocator: Allocator,
    fs: FS,
    src_root: []const u8,
    dir: []const u8,
    entries: []const fsys.DirEntry,
    out_map: *std.StringHashMap(void),
) !void {
    for (entries) |e| {
        const child = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ fsys.cleanMemPath(dir), e.name });
        defer allocator.free(child);
        if (e.is_dir) {
            const sub_entries = try fs.list(allocator, child);
            defer FS.freeDirEntries(allocator, sub_entries);
            try walkSourceFiles(allocator, fs, src_root, child, sub_entries, out_map);
            continue;
        }
        const rel = relToSrc(src_root, child) orelse continue;
        if (parser.forPath(rel) != null) {
            if (!out_map.contains(rel)) {
                const rel_dup = try allocator.dupe(u8, rel);
                errdefer allocator.free(rel_dup);
                try out_map.put(rel_dup, {});
            }
        }
    }
}

fn strLessThan(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

/// Implements `flint add [--ws=<name>] [PATH...]`.
pub fn cmdAdd(
    allocator: Allocator,
    fs: FS,
    root: []const u8,
    uuid_gen: *uuid.UUIDGen,
    out: *Io.Writer,
    args: []const []const u8,
) !void {
    var ws_flag: []const u8 = "";
    var paths: std.ArrayList([]u8) = .empty;
    defer {
        for (paths.items) |p| allocator.free(p);
        paths.deinit(allocator);
    }

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.startsWith(u8, a, "--ws=")) {
            ws_flag = a["--ws=".len..];
            continue;
        }
        if (std.mem.eql(u8, a, "--ws") and i + 1 < args.len) {
            i += 1;
            ws_flag = args[i];
            continue;
        }
        const cleaned = try fsys.cleanPath(allocator, a);
        errdefer allocator.free(cleaned);
        try paths.append(allocator, cleaned);
    }

    var idx = try store.loadStoreIndex(allocator, fs, root);
    defer idx.deinit();

    const ws = try store.resolveWorkspace(allocator, fs, &idx, ws_flag, paths.items);
    if (paths.items.len == 0) {
        const ws_src_dup = try allocator.dupe(u8, ws.src);
        errdefer allocator.free(ws_src_dup);
        try paths.append(allocator, ws_src_dup);
    }

    const existing_atoms = try store.loadWorkspaceAtoms(allocator, fs, root, ws.name);
    defer store.freeStoredAtoms(allocator, existing_atoms);

    const existing_stage = try store.loadWorkspaceStage(allocator, fs, root, ws.name);
    defer store.freeOps(allocator, existing_stage);

    var atoms_by_file = std.StringHashMap(std.ArrayList(store.StoredAtom)).init(allocator);
    defer {
        var it = atoms_by_file.iterator();
        while (it.next()) |kv| {
            kv.value_ptr.deinit(allocator);
        }
        atoms_by_file.deinit();
    }
    for (existing_atoms) |a| {
        const gop = try atoms_by_file.getOrPut(a.span.file);
        if (!gop.found_existing) {
            gop.value_ptr.* = .empty;
        }
        try gop.value_ptr.append(allocator, a);
    }

    var targets: std.ArrayList(AddTarget) = .empty;
    defer targets.deinit(allocator);

    var disk_files_map = std.StringHashMap(void).init(allocator);
    defer {
        var it = disk_files_map.iterator();
        while (it.next()) |kv| allocator.free(kv.key_ptr.*);
        disk_files_map.deinit();
    }

    for (paths.items) |p| {
        const rel = relToSrc(ws.src, p) orelse {
            return fsys.refuse("src_missing", p);
        };
        if (fs.list(allocator, p)) |entries| {
            defer FS.freeDirEntries(allocator, entries);
            try targets.append(allocator, .{ .rel_prefix = rel, .is_dir = true });
            try walkSourceFiles(allocator, fs, ws.src, p, entries, &disk_files_map);
            continue;
        } else |_| {}

        if (parser.forPath(rel) == null) {
            continue;
        }
        if (fs.exists(allocator, p)) {
            try targets.append(allocator, .{ .rel_prefix = rel, .is_dir = false });
            if (!disk_files_map.contains(rel)) {
                const rel_dup = try allocator.dupe(u8, rel);
                errdefer allocator.free(rel_dup);
                try disk_files_map.put(rel_dup, {});
            }
            continue;
        }
        // A disappeared single file that was tracked in ATOMS.jsonl deletes its Atoms.
        if (atoms_by_file.get(rel)) |list| {
            if (list.items.len > 0) {
                try targets.append(allocator, .{ .rel_prefix = rel, .is_dir = false });
                continue;
            }
        }
        return fsys.refuse("src_missing", p);
    }

    var disk_files: std.ArrayList([]const u8) = .empty;
    defer disk_files.deinit(allocator);
    {
        var it = disk_files_map.iterator();
        while (it.next()) |kv| {
            try disk_files.append(allocator, kv.key_ptr.*);
        }
    }
    std.mem.sort([]const u8, disk_files.items, {}, strLessThan);

    // Step 1: Parse every file on disk first (all-or-nothing: any syntax,
    // parse_unsupported, or duplicate_decl error refuses before staging).
    var parsed_by_file = std.StringHashMap([]parser.Atom).init(allocator);
    defer {
        var it = parsed_by_file.iterator();
        while (it.next()) |kv| {
            parser.freeAtoms(allocator, kv.value_ptr.*);
        }
        parsed_by_file.deinit();
    }

    for (disk_files.items) |rel| {
        const full = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ ws.src, rel });
        defer allocator.free(full);

        const src = try fs.readFile(allocator, full, store.MaxFileReadBytes);
        defer allocator.free(src);

        if (parser.forPath(rel) == null) continue;

        var perr: ?parser.ParseErrorInfo = null;
        const decls = parser.parseFile(allocator, rel, src, null, &perr) catch |err| switch (err) {
            error.ParseFailed => {
                if (perr) |pe| {
                    const detail = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ pe.file, pe.offset });
                    defer allocator.free(detail);
                    return fsys.refuse(pe.code, detail);
                }
                return fsys.refuse("syntax", rel);
            },
            else => return err,
        };
        errdefer parser.freeAtoms(allocator, decls);

        var seen_in_file = std.HashMap(
            store.AtomKey,
            void,
            store.AtomKeyContext,
            std.hash_map.default_max_load_percentage,
        ).init(allocator);
        defer seen_in_file.deinit();

        for (decls) |d| {
            const k = store.AtomKey{ .file = rel, .kind = d.kind, .name = d.name };
            if (seen_in_file.contains(k)) {
                const detail = try std.fmt.allocPrint(allocator, "{s} {s} {s}", .{ rel, d.kind, d.name });
                defer allocator.free(detail);
                return fsys.refuse("duplicate_decl", detail);
            }
            try seen_in_file.put(k, {});
        }

        try parsed_by_file.put(rel, decls);
    }

    // Collect all affected relative files (files on disk + tracked files under
    // any added target that disappeared from disk).
    var affected_map = std.StringHashMap(void).init(allocator);
    defer affected_map.deinit();

    for (disk_files.items) |rel| {
        try affected_map.put(rel, {});
    }
    {
        var it = atoms_by_file.iterator();
        while (it.next()) |kv| {
            const rel = kv.key_ptr.*;
            if (inTargets(rel, targets.items)) {
                try affected_map.put(rel, {});
            }
        }
    }

    var affected_files: std.ArrayList([]const u8) = .empty;
    defer affected_files.deinit(allocator);
    {
        var it = affected_map.iterator();
        while (it.next()) |kv| {
            try affected_files.append(allocator, kv.key_ptr.*);
        }
    }
    std.mem.sort([]const u8, affected_files.items, {}, strLessThan);

    // Step 1b: Enforce M103d `src_behind` guard before staging anything:
    // if any Atom marked `origin: merge` in an affected file is missing on disk
    // or has a different hash, refuse `src_behind <file>` and stage nothing.
    for (affected_files.items) |rel| {
        const old_list_opt = atoms_by_file.get(rel);
        if (old_list_opt == null) continue;
        const old_list = old_list_opt.?.items;

        var has_merge_origin = false;
        for (old_list) |old| {
            if (std.mem.eql(u8, old.origin, "merge")) {
                has_merge_origin = true;
                break;
            }
        }
        if (!has_merge_origin) continue;

        const decls = parsed_by_file.get(rel) orelse &[_]parser.Atom{};
        var decl_hash_by_key = std.HashMap(
            store.AtomKey,
            [64]u8,
            store.AtomKeyContext,
            std.hash_map.default_max_load_percentage,
        ).init(allocator);
        defer decl_hash_by_key.deinit();

        for (decls) |d| {
            const k = store.AtomKey{ .file = rel, .kind = d.kind, .name = d.name };
            try decl_hash_by_key.put(k, std.fmt.bytesToHex(d.hash, .lower));
        }

        for (old_list) |old| {
            if (!std.mem.eql(u8, old.origin, "merge")) continue;
            const k = store.AtomKey{ .file = rel, .kind = old.kind, .name = old.name };
            const disk_hash = decl_hash_by_key.get(k) orelse {
                return fsys.refuse("src_behind", rel);
            };
            if (!std.mem.eql(u8, &disk_hash, old.hash)) {
                return fsys.refuse("src_behind", rel);
            }
        }
    }

    // Step 2: Diff per file against ATOMS.jsonl (ADR 0049 §1).
    var new_atoms: std.ArrayList(store.StoredAtom) = .empty;
    defer {
        for (new_atoms.items) |a| a.deinit(allocator);
        new_atoms.deinit(allocator);
    }

    for (existing_atoms) |a| {
        if (!affected_map.contains(a.span.file)) {
            const cloned = try a.clone(allocator);
            errdefer cloned.deinit(allocator);
            try new_atoms.append(allocator, cloned);
        }
    }

    var diff_ops: std.ArrayList(store.Op) = .empty;
    defer {
        for (diff_ops.items) |op| op.deinit(allocator);
        diff_ops.deinit(allocator);
    }

    var count_new: usize = 0;
    var count_mod: usize = 0;
    var count_del: usize = 0;
    var count_unchanged: usize = 0;

    for (affected_files.items) |rel| {
        const old_list: []const store.StoredAtom = if (atoms_by_file.get(rel)) |l| l.items else &.{};

        var old_by_key = std.HashMap(
            store.AtomKey,
            store.StoredAtom,
            store.AtomKeyContext,
            std.hash_map.default_max_load_percentage,
        ).init(allocator);
        defer old_by_key.deinit();

        for (old_list) |old| {
            const k = store.AtomKey{ .file = old.span.file, .kind = old.kind, .name = old.name };
            try old_by_key.put(k, old);
        }

        var matched_old = std.StringHashMap(void).init(allocator);
        defer matched_old.deinit();

        const decls = parsed_by_file.get(rel) orelse &[_]parser.Atom{};
        for (decls) |d| {
            const key = store.AtomKey{ .file = rel, .kind = d.kind, .name = d.name };
            const new_hash_arr = std.fmt.bytesToHex(d.hash, .lower);
            const new_sig_arr = std.fmt.bytesToHex(d.sig_hash, .lower);
            const new_hash = new_hash_arr[0..];
            const new_sig_hash = new_sig_arr[0..];

            if (old_by_key.get(key)) |old| {
                try matched_old.put(old.id, {});
                const updated = try storedAtomFromParser(allocator, old.id, d);
                errdefer updated.deinit(allocator);

                if (!std.mem.eql(u8, old.hash, new_hash)) {
                    count_mod += 1;
                    const t_mod = try allocator.dupe(u8, "modify");
                    errdefer allocator.free(t_mod);
                    const aid = try allocator.dupe(u8, old.id);
                    errdefer allocator.free(aid);
                    const nh = try allocator.dupe(u8, new_hash);
                    errdefer allocator.free(nh);
                    const nsh = try allocator.dupe(u8, new_sig_hash);
                    errdefer allocator.free(nsh);
                    const oh = try allocator.dupe(u8, old.hash);
                    errdefer allocator.free(oh);

                    try diff_ops.append(allocator, .{
                        .type = t_mod,
                        .atom_id = aid,
                        .new_hash = nh,
                        .new_sig_hash = nsh,
                        .old_hash = oh,
                    });
                } else {
                    count_unchanged += 1;
                }
                try new_atoms.append(allocator, updated);
            } else {
                const id_buf = try uuid_gen.new();
                const added = try storedAtomFromParser(allocator, &id_buf, d);
                errdefer added.deinit(allocator);

                const t_add = try allocator.dupe(u8, "add");
                errdefer allocator.free(t_add);
                const aid = try allocator.dupe(u8, &id_buf);
                errdefer allocator.free(aid);
                const kind_dup = try allocator.dupe(u8, added.kind);
                errdefer allocator.free(kind_dup);
                const name_dup = try allocator.dupe(u8, added.name);
                errdefer allocator.free(name_dup);
                const span_copy = try added.span.clone(allocator);
                errdefer span_copy.deinit(allocator);
                const nh = try allocator.dupe(u8, added.hash);
                errdefer allocator.free(nh);
                const nsh = try allocator.dupe(u8, added.sig_hash);
                errdefer allocator.free(nsh);

                count_new += 1;
                try diff_ops.append(allocator, .{
                    .type = t_add,
                    .atom_id = aid,
                    .kind = kind_dup,
                    .new_name = name_dup,
                    .new_span = span_copy,
                    .new_hash = nh,
                    .new_sig_hash = nsh,
                });
                try new_atoms.append(allocator, added);
            }
        }

        for (old_list) |old| {
            if (!matched_old.contains(old.id)) {
                count_del += 1;
                const t_del = try allocator.dupe(u8, "delete");
                errdefer allocator.free(t_del);
                const aid = try allocator.dupe(u8, old.id);
                errdefer allocator.free(aid);
                const oh = try allocator.dupe(u8, old.hash);
                errdefer allocator.free(oh);

                try diff_ops.append(allocator, .{
                    .type = t_del,
                    .atom_id = aid,
                    .old_hash = oh,
                });
            }
        }
    }

    if (new_atoms.items.len > store.MaxAtoms) {
        return fsys.refuse("store_too_large", "atoms");
    }

    // Step 3: Fold diff_ops into STAGE.jsonl and write both files safely.
    const folded_stage = try store.foldStageOps(allocator, existing_stage, diff_ops.items, new_atoms.items);
    defer store.freeOps(allocator, folded_stage);

    if (folded_stage.len > store.MaxAtoms) {
        return fsys.refuse("store_too_large", "atoms");
    }

    try store.writeWorkspaceAtoms(allocator, fs, root, ws.name, new_atoms.items);
    try store.writeWorkspaceStage(allocator, fs, root, ws.name, folded_stage);

    try out.print(
        "flint: add files={d} new={d} modified={d} deleted={d} unchanged={d}\n",
        .{ disk_files.items.len, count_new, count_mod, count_del, count_unchanged },
    );
}

fn opQualifiedName(op: store.Op, atoms_by_id: *const std.StringHashMap(store.StoredAtom)) []const u8 {
    if (op.new_name.len > 0) return op.new_name;
    if (atoms_by_id.get(op.atom_id)) |a| {
        if (a.name.len > 0) return a.name;
    }
    return op.atom_id;
}

/// Implements `flint status [--ws=<name>]`.
pub fn cmdStatus(
    allocator: Allocator,
    fs: FS,
    root: []const u8,
    out: *Io.Writer,
    args: []const []const u8,
) !void {
    var ws_flag: []const u8 = "";
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.startsWith(u8, a, "--ws=")) {
            ws_flag = a["--ws=".len..];
            continue;
        }
        if (std.mem.eql(u8, a, "--ws") and i + 1 < args.len) {
            i += 1;
            ws_flag = args[i];
            continue;
        }
        return fsys.refuse("usage", "");
    }

    var idx = try store.loadStoreIndex(allocator, fs, root);
    defer idx.deinit();

    const ws = try store.resolveWorkspace(allocator, fs, &idx, ws_flag, &.{});

    const atoms = try store.loadWorkspaceAtoms(allocator, fs, root, ws.name);
    defer store.freeStoredAtoms(allocator, atoms);

    const stage = try store.loadWorkspaceStage(allocator, fs, root, ws.name);
    defer store.freeOps(allocator, stage);

    var atoms_by_id = std.StringHashMap(store.StoredAtom).init(allocator);
    defer atoms_by_id.deinit();

    var seen_keys = std.HashMap(
        store.AtomKey,
        void,
        store.AtomKeyContext,
        std.hash_map.default_max_load_percentage,
    ).init(allocator);
    defer seen_keys.deinit();

    var duplicates: usize = 0;
    for (atoms) |a| {
        try atoms_by_id.put(a.id, a);
        const k = store.AtomKey{ .file = a.span.file, .kind = a.kind, .name = a.name };
        if (seen_keys.contains(k)) {
            duplicates += 1;
        }
        try seen_keys.put(k, {});
    }

    const stream_name = if (idx.streamByID(ws.stream)) |st| st.name else ws.stream;

    var count_add: usize = 0;
    var count_mod: usize = 0;
    var count_del: usize = 0;
    for (stage) |op| {
        if (std.mem.eql(u8, op.type, "add")) {
            count_add += 1;
        } else if (std.mem.eql(u8, op.type, "modify")) {
            count_mod += 1;
        } else if (std.mem.eql(u8, op.type, "delete")) {
            count_del += 1;
        }
    }

    try out.print(
        "flint: status ws={s} stream={s} atoms={d} staged={d} add={d} modify={d} delete={d} duplicates={d}\n",
        .{ ws.name, stream_name, atoms.len, stage.len, count_add, count_mod, count_del, duplicates },
    );

    store.sortOps(stage);
    const stage_cap: usize = 64;
    const limit = @min(stage.len, stage_cap);
    for (stage[0..limit]) |op| {
        const name = opQualifiedName(op, &atoms_by_id);
        try out.print("flint: stage {s} {s}\n", .{ op.type, name });
    }
    if (stage.len > stage_cap) {
        try out.print("flint: stage … +{d}\n", .{stage.len - stage_cap});
    }
}
