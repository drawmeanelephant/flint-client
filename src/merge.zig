const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const fsys = @import("fsys.zig");
const FS = fsys.FS;
const store = @import("store.zig");
const json = @import("json.zig");
const uuid = @import("uuid.zig");
const ed25519 = @import("ed25519.zig");

pub const ConflictDeleteVsModify = "delete_vs_modify";
pub const ConflictDeleteVsMove = "delete_vs_move";
pub const ConflictDeleteVsRename = "delete_vs_rename";
pub const ConflictConcurrentAdd = "concurrent_add";
pub const ConflictConcurrentModify = "concurrent_modify";
pub const ConflictConcurrentMove = "concurrent_move";
pub const ConflictConcurrentRename = "concurrent_rename";
pub const ConflictModifyVsMove = "modify_vs_move";
pub const ConflictModifyVsRename = "modify_vs_rename";
pub const ConflictMoveVsRename = "move_vs_rename";

pub fn conflictPriority(conflict_type: []const u8) u8 {
    if (std.mem.eql(u8, conflict_type, ConflictDeleteVsModify)) return 1;
    if (std.mem.eql(u8, conflict_type, ConflictDeleteVsMove)) return 2;
    if (std.mem.eql(u8, conflict_type, ConflictDeleteVsRename)) return 3;
    if (std.mem.eql(u8, conflict_type, ConflictConcurrentAdd)) return 4;
    if (std.mem.eql(u8, conflict_type, ConflictConcurrentModify)) return 5;
    if (std.mem.eql(u8, conflict_type, ConflictConcurrentMove)) return 6;
    if (std.mem.eql(u8, conflict_type, ConflictConcurrentRename)) return 7;
    if (std.mem.eql(u8, conflict_type, ConflictModifyVsMove)) return 8;
    if (std.mem.eql(u8, conflict_type, ConflictModifyVsRename)) return 9;
    if (std.mem.eql(u8, conflict_type, ConflictMoveVsRename)) return 10;
    return 99;
}

pub fn crossFieldConflict(a: []const u8, b: []const u8) []const u8 {
    const first = if (std.mem.order(u8, a, b) == .gt) b else a;
    const second = if (std.mem.order(u8, a, b) == .gt) a else b;
    if (std.mem.eql(u8, first, "modify") and std.mem.eql(u8, second, "move")) return ConflictModifyVsMove;
    if (std.mem.eql(u8, first, "modify") and std.mem.eql(u8, second, "rename")) return ConflictModifyVsRename;
    if (std.mem.eql(u8, first, "move") and std.mem.eql(u8, second, "rename")) return ConflictMoveVsRename;
    return ConflictConcurrentModify;
}

pub fn pickHighestPriorityConflict(candidates: []const []const u8) []const u8 {
    if (candidates.len == 0) return "";
    var best = candidates[0];
    for (candidates[1..]) |c| {
        if (conflictPriority(c) < conflictPriority(best)) {
            best = c;
        }
    }
    return best;
}

fn conflictLessThan(_: void, a: store.MergeConflict, b: store.MergeConflict) bool {
    const cmp_name = std.mem.order(u8, a.name, b.name);
    if (cmp_name != .eq) return cmp_name == .lt;
    const cmp_type = std.mem.order(u8, a.type, b.type);
    if (cmp_type != .eq) return cmp_type == .lt;
    return std.mem.order(u8, a.atom_id, b.atom_id) == .lt;
}

pub fn sortMergeConflicts(conflicts: []store.MergeConflict) void {
    std.mem.sort(store.MergeConflict, conflicts, {}, conflictLessThan);
}

pub fn spansEqual(a: ?store.Span, b: ?store.Span) bool {
    if (a == null and b == null) return true;
    if (a == null or b == null) return false;
    return std.mem.eql(u8, a.?.file, b.?.file) and a.?.start == b.?.start and a.?.end == b.?.end;
}

/// Borrowed net effect on a single Atom across a sequence of Changes from the
/// common ancestor (exclusive) to a Stream head (ADR 0049 §2 step 2).
pub const AtomEffect = struct {
    atom_id: []const u8,
    added: bool = false,
    deleted: bool = false,
    modified: bool = false,
    renamed: bool = false,
    moved: bool = false,
    kind: []const u8 = "",
    name: []const u8 = "",
    span: ?store.Span = null,
    hash: []const u8 = "",
    sig_hash: []const u8 = "",
    old_hash: []const u8 = "",
};

const AddKey = struct {
    kind: []const u8,
    name: []const u8,
};

const AddKeyContext = struct {
    pub fn hash(_: @This(), k: AddKey) u64 {
        var h = std.hash.Wyhash.init(0);
        h.update(k.kind);
        h.update("\x00");
        h.update(k.name);
        return h.final();
    }
    pub fn eql(_: @This(), a: AddKey, b: AddKey) bool {
        return std.mem.eql(u8, a.kind, b.kind) and std.mem.eql(u8, a.name, b.name);
    }
};

pub const MergeResult = struct {
    clean: bool,
    ops: []store.Op,
    conflicts: []store.MergeConflict,

    pub fn deinit(self: MergeResult, allocator: Allocator) void {
        store.freeOps(allocator, self.ops);
        for (self.conflicts) |c| c.deinit(allocator);
        allocator.free(self.conflicts);
    }
};

pub fn foldSideEffects(
    allocator: Allocator,
    base_by_id: *const std.StringHashMap(store.StoredAtom),
    changes: []const []const store.Op,
) !std.StringHashMap(AtomEffect) {
    var effects = std.StringHashMap(AtomEffect).init(allocator);
    errdefer effects.deinit();

    for (changes) |ops| {
        const sorted = try allocator.dupe(store.Op, ops);
        defer allocator.free(sorted);
        store.sortOps(sorted);

        for (sorted) |op| {
            const gop = try effects.getOrPut(op.atom_id);
            if (!gop.found_existing) {
                var init_eff = AtomEffect{ .atom_id = op.atom_id };
                if (base_by_id.get(op.atom_id)) |base| {
                    init_eff.old_hash = base.hash;
                } else if (op.old_hash.len > 0) {
                    init_eff.old_hash = op.old_hash;
                }
                gop.value_ptr.* = init_eff;
            }
            const eff = gop.value_ptr;

            if (eff.added) {
                if (std.mem.eql(u8, op.type, "modify")) {
                    eff.hash = op.new_hash;
                    if (op.new_sig_hash.len > 0) {
                        eff.sig_hash = op.new_sig_hash;
                    }
                    if (op.new_span) |sp| {
                        eff.span = sp;
                    }
                } else if (std.mem.eql(u8, op.type, "rename")) {
                    eff.name = op.new_name;
                } else if (std.mem.eql(u8, op.type, "move")) {
                    eff.span = op.new_span;
                } else if (std.mem.eql(u8, op.type, "delete")) {
                    _ = effects.remove(op.atom_id);
                }
                continue;
            }

            if (std.mem.eql(u8, op.type, "add")) {
                eff.added = true;
                eff.deleted = false;
                eff.modified = false;
                eff.renamed = false;
                eff.moved = false;
                eff.kind = op.kind;
                eff.name = op.new_name;
                eff.span = op.new_span;
                eff.hash = op.new_hash;
                eff.sig_hash = op.new_sig_hash;
            } else if (std.mem.eql(u8, op.type, "modify")) {
                if (eff.old_hash.len == 0 and op.old_hash.len > 0) {
                    eff.old_hash = op.old_hash;
                }
                eff.modified = true;
                eff.hash = op.new_hash;
                eff.sig_hash = op.new_sig_hash;
            } else if (std.mem.eql(u8, op.type, "rename")) {
                if (eff.old_hash.len == 0 and op.old_hash.len > 0) {
                    eff.old_hash = op.old_hash;
                }
                eff.renamed = true;
                eff.name = op.new_name;
            } else if (std.mem.eql(u8, op.type, "move")) {
                if (eff.old_hash.len == 0 and op.old_hash.len > 0) {
                    eff.old_hash = op.old_hash;
                }
                eff.moved = true;
                eff.span = op.new_span;
            } else if (std.mem.eql(u8, op.type, "delete")) {
                if (eff.old_hash.len == 0 and op.old_hash.len > 0) {
                    eff.old_hash = op.old_hash;
                }
                eff.deleted = true;
                eff.modified = false;
                eff.renamed = false;
                eff.moved = false;
                eff.hash = "";
                eff.sig_hash = "";
                eff.name = "";
                eff.span = null;
            }
        }
    }

    return effects;
}

const ActiveKinds = struct {
    buf: [3][]const u8 = undefined,
    len: usize = 0,

    fn slice(self: *const ActiveKinds) []const []const u8 {
        return self.buf[0..self.len];
    }
};

fn activeEffectKinds(eff_opt: ?AtomEffect) ActiveKinds {
    var out = ActiveKinds{};
    const eff = eff_opt orelse return out;
    if (eff.added) return out;
    if (eff.deleted) {
        out.buf[0] = "delete";
        out.len = 1;
        return out;
    }
    if (eff.modified) {
        out.buf[out.len] = "modify";
        out.len += 1;
    }
    if (eff.moved) {
        out.buf[out.len] = "move";
        out.len += 1;
    }
    if (eff.renamed) {
        out.buf[out.len] = "rename";
        out.len += 1;
    }
    return out;
}

fn appendFromEffectOps(
    allocator: Allocator,
    merge_ops: *std.ArrayList(store.Op),
    atom_id: []const u8,
    into_pre_hash: []const u8,
    i_eff_opt: ?AtomEffect,
    f_eff: AtomEffect,
) !void {
    if (f_eff.deleted) {
        if (i_eff_opt) |i_eff| {
            if (i_eff.deleted) return;
        }
        const op = try (store.Op{
            .type = "delete",
            .atom_id = atom_id,
            .old_hash = into_pre_hash,
        }).clone(allocator);
        errdefer op.deinit(allocator);
        try merge_ops.append(allocator, op);
        return;
    }
    if (f_eff.modified) {
        const same = if (i_eff_opt) |i_eff| (i_eff.modified and std.mem.eql(u8, i_eff.hash, f_eff.hash)) else false;
        if (!same) {
            const op = try (store.Op{
                .type = "modify",
                .atom_id = atom_id,
                .new_hash = f_eff.hash,
                .new_sig_hash = f_eff.sig_hash,
                .old_hash = into_pre_hash,
            }).clone(allocator);
            errdefer op.deinit(allocator);
            try merge_ops.append(allocator, op);
        }
    }
    if (f_eff.moved) {
        const same = if (i_eff_opt) |i_eff| (i_eff.moved and spansEqual(i_eff.span, f_eff.span)) else false;
        if (!same) {
            const op = try (store.Op{
                .type = "move",
                .atom_id = atom_id,
                .new_span = f_eff.span,
                .old_hash = into_pre_hash,
            }).clone(allocator);
            errdefer op.deinit(allocator);
            try merge_ops.append(allocator, op);
        }
    }
    if (f_eff.renamed) {
        const same = if (i_eff_opt) |i_eff| (i_eff.renamed and std.mem.eql(u8, i_eff.name, f_eff.name)) else false;
        if (!same) {
            const op = try (store.Op{
                .type = "rename",
                .atom_id = atom_id,
                .new_name = f_eff.name,
                .old_hash = into_pre_hash,
            }).clone(allocator);
            errdefer op.deinit(allocator);
            try merge_ops.append(allocator, op);
        }
    }
}

/// Runs the ADR 0049 §2 step 2 & 3 semantic merge on Ops given the ancestor
/// Atom table and each side's Change op-lists since the ancestor.
pub fn mergeOps(
    allocator: Allocator,
    base_atoms: []const store.StoredAtom,
    into_changes: []const []const store.Op,
    from_changes: []const []const store.Op,
) !MergeResult {
    var base_by_id = std.StringHashMap(store.StoredAtom).init(allocator);
    defer base_by_id.deinit();
    for (base_atoms) |a| {
        try base_by_id.put(a.id, a);
    }

    var into_effs = try foldSideEffects(allocator, &base_by_id, into_changes);
    defer into_effs.deinit();
    var from_effs = try foldSideEffects(allocator, &base_by_id, from_changes);
    defer from_effs.deinit();

    var into_adds = std.HashMap(AddKey, AtomEffect, AddKeyContext, std.hash_map.default_max_load_percentage).init(allocator);
    defer into_adds.deinit();
    {
        var it = into_effs.iterator();
        while (it.next()) |kv| {
            const eff = kv.value_ptr.*;
            if (eff.added) {
                try into_adds.put(.{ .kind = eff.kind, .name = eff.name }, eff);
            }
        }
    }

    var from_adds = std.HashMap(AddKey, AtomEffect, AddKeyContext, std.hash_map.default_max_load_percentage).init(allocator);
    defer from_adds.deinit();
    {
        var it = from_effs.iterator();
        while (it.next()) |kv| {
            const eff = kv.value_ptr.*;
            if (eff.added) {
                try from_adds.put(.{ .kind = eff.kind, .name = eff.name }, eff);
            }
        }
    }

    var conflicts: std.ArrayList(store.MergeConflict) = .empty;
    errdefer {
        for (conflicts.items) |c| c.deinit(allocator);
        conflicts.deinit(allocator);
    }
    var merge_ops: std.ArrayList(store.Op) = .empty;
    errdefer {
        for (merge_ops.items) |op| op.deinit(allocator);
        merge_ops.deinit(allocator);
    }

    // 1. Handle added Atoms (keyed by (kind, name)).
    {
        var fit = from_adds.iterator();
        while (fit.next()) |kv| {
            const key = kv.key_ptr.*;
            const f_eff = kv.value_ptr.*;
            if (into_adds.get(key)) |i_eff| {
                if (std.mem.eql(u8, i_eff.hash, f_eff.hash)) {
                    // Equal hash -> clean, keeps `into`'s id, nothing emitted.
                    continue;
                }
                const c = store.MergeConflict{
                    .atom_id = try allocator.dupe(u8, i_eff.atom_id),
                    .name = try allocator.dupe(u8, f_eff.name),
                    .type = try allocator.dupe(u8, ConflictConcurrentAdd),
                };
                errdefer c.deinit(allocator);
                try conflicts.append(allocator, c);
            } else {
                const op = try (store.Op{
                    .type = "add",
                    .atom_id = f_eff.atom_id,
                    .kind = f_eff.kind,
                    .new_name = f_eff.name,
                    .new_span = f_eff.span,
                    .new_hash = f_eff.hash,
                    .new_sig_hash = f_eff.sig_hash,
                }).clone(allocator);
                errdefer op.deinit(allocator);
                try merge_ops.append(allocator, op);
            }
        }
    }

    // 2. Handle existing Atoms (keyed by AtomID).
    var seen_atom_ids = std.StringHashMap(void).init(allocator);
    defer seen_atom_ids.deinit();
    {
        var it = into_effs.iterator();
        while (it.next()) |kv| {
            if (!kv.value_ptr.added) {
                try seen_atom_ids.put(kv.key_ptr.*, {});
            }
        }
    }
    {
        var it = from_effs.iterator();
        while (it.next()) |kv| {
            if (!kv.value_ptr.added) {
                try seen_atom_ids.put(kv.key_ptr.*, {});
            }
        }
    }

    var atom_ids: std.ArrayList([]const u8) = .empty;
    defer atom_ids.deinit(allocator);
    {
        var it = seen_atom_ids.iterator();
        while (it.next()) |kv| {
            try atom_ids.append(allocator, kv.key_ptr.*);
        }
    }
    std.mem.sort([]const u8, atom_ids.items, {}, struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lessThan);

    for (atom_ids.items) |id| {
        const i_eff_opt = into_effs.get(id);
        const f_eff_opt = from_effs.get(id);
        const i_kinds_arr = activeEffectKinds(i_eff_opt);
        const f_kinds_arr = activeEffectKinds(f_eff_opt);
        const i_kinds = i_kinds_arr.slice();
        const f_kinds = f_kinds_arr.slice();

        // Untouched on `from` -> clean, nothing to apply on `into`.
        if (f_kinds.len == 0) continue;
        const f_eff = f_eff_opt.?;

        const base_opt = base_by_id.get(id);
        var atom_name: []const u8 = if (base_opt) |b| b.name else "";
        if (atom_name.len == 0) {
            if (i_eff_opt) |ie| {
                if (ie.name.len > 0) atom_name = ie.name;
            }
            if (atom_name.len == 0 and f_eff.name.len > 0) {
                atom_name = f_eff.name;
            }
            if (atom_name.len == 0) {
                atom_name = id;
            }
        }

        var into_pre_hash: []const u8 = if (base_opt) |b| b.hash else "";
        if (into_pre_hash.len == 0) {
            if (i_eff_opt) |ie| {
                if (ie.old_hash.len > 0) into_pre_hash = ie.old_hash;
            }
            if (into_pre_hash.len == 0 and f_eff.old_hash.len > 0) {
                into_pre_hash = f_eff.old_hash;
            }
        }
        if (i_eff_opt) |ie| {
            if (ie.modified) {
                into_pre_hash = ie.hash;
            }
        }

        // Untouched on `into` -> clean (including multi-field refactor on `from`).
        if (i_kinds.len == 0) {
            try appendFromEffectOps(allocator, &merge_ops, id, into_pre_hash, null, f_eff);
            continue;
        }

        const i_eff = i_eff_opt.?;

        // Both sides touched this Atom: evaluate pairwise table across active fields.
        var cand_conflicts: [9][]const u8 = undefined;
        var cand_len: usize = 0;

        for (i_kinds) |ik| {
            for (f_kinds) |fk| {
                if (std.mem.eql(u8, ik, "delete") and std.mem.eql(u8, fk, "delete")) {
                    // delete vs delete -> clean
                } else if ((std.mem.eql(u8, ik, "delete") and std.mem.eql(u8, fk, "modify")) or
                    (std.mem.eql(u8, ik, "modify") and std.mem.eql(u8, fk, "delete")))
                {
                    cand_conflicts[cand_len] = ConflictDeleteVsModify;
                    cand_len += 1;
                } else if ((std.mem.eql(u8, ik, "delete") and std.mem.eql(u8, fk, "move")) or
                    (std.mem.eql(u8, ik, "move") and std.mem.eql(u8, fk, "delete")))
                {
                    cand_conflicts[cand_len] = ConflictDeleteVsMove;
                    cand_len += 1;
                } else if ((std.mem.eql(u8, ik, "delete") and std.mem.eql(u8, fk, "rename")) or
                    (std.mem.eql(u8, ik, "rename") and std.mem.eql(u8, fk, "delete")))
                {
                    cand_conflicts[cand_len] = ConflictDeleteVsRename;
                    cand_len += 1;
                } else if (std.mem.eql(u8, ik, "modify") and std.mem.eql(u8, fk, "modify")) {
                    if (!std.mem.eql(u8, i_eff.hash, f_eff.hash)) {
                        cand_conflicts[cand_len] = ConflictConcurrentModify;
                        cand_len += 1;
                    }
                } else if (std.mem.eql(u8, ik, "move") and std.mem.eql(u8, fk, "move")) {
                    if (!spansEqual(i_eff.span, f_eff.span)) {
                        cand_conflicts[cand_len] = ConflictConcurrentMove;
                        cand_len += 1;
                    }
                } else if (std.mem.eql(u8, ik, "rename") and std.mem.eql(u8, fk, "rename")) {
                    if (!std.mem.eql(u8, i_eff.name, f_eff.name)) {
                        cand_conflicts[cand_len] = ConflictConcurrentRename;
                        cand_len += 1;
                    }
                } else {
                    cand_conflicts[cand_len] = crossFieldConflict(ik, fk);
                    cand_len += 1;
                }
            }
        }

        if (cand_len > 0) {
            const winning = pickHighestPriorityConflict(cand_conflicts[0..cand_len]);
            const c = store.MergeConflict{
                .atom_id = try allocator.dupe(u8, id),
                .name = try allocator.dupe(u8, atom_name),
                .type = try allocator.dupe(u8, winning),
            };
            errdefer c.deinit(allocator);
            try conflicts.append(allocator, c);
            continue;
        }

        // Clean when both sides touched the Atom (e.g. equal modify/move/rename/delete).
        try appendFromEffectOps(allocator, &merge_ops, id, into_pre_hash, i_eff, f_eff);
    }

    if (conflicts.items.len > 0) {
        for (merge_ops.items) |op| op.deinit(allocator);
        merge_ops.deinit(allocator);

        const conf_slice = try conflicts.toOwnedSlice(allocator);
        sortMergeConflicts(conf_slice);
        return .{
            .clean = false,
            .ops = try allocator.alloc(store.Op, 0),
            .conflicts = conf_slice,
        };
    }

    conflicts.deinit(allocator);
    const ops_slice = try merge_ops.toOwnedSlice(allocator);
    store.sortOps(ops_slice);
    return .{
        .clean = true,
        .ops = ops_slice,
        .conflicts = try allocator.alloc(store.MergeConflict, 0),
    };
}

/// Returns X plus everything reachable from X through `parent` and `merged`
/// links (ADR 0049 §2 step 1).
pub fn ancestorSet(
    allocator: Allocator,
    head_id: ?[]const u8,
    changes_by_id: *const std.StringHashMap(store.Change),
) !std.StringHashMap(void) {
    var anc = std.StringHashMap(void).init(allocator);
    errdefer anc.deinit();

    const start = head_id orelse return anc;
    if (start.len == 0) return anc;

    var queue: std.ArrayList([]const u8) = .empty;
    defer queue.deinit(allocator);
    try queue.append(allocator, start);

    var q_idx: usize = 0;
    while (q_idx < queue.items.len) : (q_idx += 1) {
        const cur = queue.items[q_idx];
        if (cur.len == 0 or anc.contains(cur)) continue;
        try anc.put(cur, {});
        const c = changes_by_id.get(cur) orelse continue;
        if (c.parent) |p| {
            if (p.len > 0 and !anc.contains(p)) {
                try queue.append(allocator, p);
            }
        }
        if (c.merged) |m| {
            if (m.len > 0 and !anc.contains(m)) {
                try queue.append(allocator, m);
            }
        }
    }

    return anc;
}

/// Finds the first Change on `from_head`'s parent chain that is in `anc(into_head)`.
/// Returns `up_to_date = true` if `from_head` itself is already in `anc(into_head)`.
pub fn findCommonAncestor(
    allocator: Allocator,
    into_head: ?[]const u8,
    from_head: ?[]const u8,
    changes_by_id: *const std.StringHashMap(store.Change),
) !struct { ancestor_id: []const u8, up_to_date: bool } {
    const fh = from_head orelse return .{ .ancestor_id = "", .up_to_date = true };
    if (fh.len == 0) return .{ .ancestor_id = "", .up_to_date = true };

    var into_anc = try ancestorSet(allocator, into_head, changes_by_id);
    defer into_anc.deinit();

    if (into_anc.contains(fh)) {
        return .{ .ancestor_id = fh, .up_to_date = true };
    }

    var seen = std.StringHashMap(void).init(allocator);
    defer seen.deinit();

    var cur: []const u8 = fh;
    while (cur.len > 0) {
        if (seen.contains(cur)) {
            return fsys.refuse("change_malformed", cur);
        }
        try seen.put(cur, {});
        if (into_anc.contains(cur)) {
            return .{ .ancestor_id = cur, .up_to_date = false };
        }
        const c = changes_by_id.get(cur) orelse {
            return fsys.refuse("change_missing", cur);
        };
        cur = c.parent orelse break;
    }

    return fsys.refuse("change_missing", "");
}

/// Collects the chronological sequence of Change op-lists (`[]const []const store.Op`)
/// along `head_id`'s parent chain from `ancestor_id` (exclusive) to `head_id` (inclusive).
pub fn changesSinceAncestor(
    allocator: Allocator,
    head_id: []const u8,
    ancestor_id: []const u8,
    changes_by_id: *const std.StringHashMap(store.Change),
) ![]const []const store.Op {
    var rev: std.ArrayList([]const store.Op) = .empty;
    errdefer rev.deinit(allocator);

    var seen = std.StringHashMap(void).init(allocator);
    defer seen.deinit();

    var cur = head_id;
    while (cur.len > 0 and !std.mem.eql(u8, cur, ancestor_id)) {
        if (seen.contains(cur)) {
            return fsys.refuse("change_malformed", cur);
        }
        try seen.put(cur, {});
        const c = changes_by_id.get(cur) orelse {
            return fsys.refuse("change_missing", cur);
        };
        try rev.append(allocator, c.ops);
        cur = c.parent orelse {
            return fsys.refuse("change_missing", ancestor_id);
        };
    }

    std.mem.reverse([]const store.Op, rev.items);
    return rev.toOwnedSlice(allocator);
}

fn resolveMergeWorkspace(
    allocator: Allocator,
    fs: FS,
    idx: *const store.StoreIndex,
    ws_flag: []const u8,
    from_name: []const u8,
    from_stream_id: []const u8,
) !*const store.Workspace {
    if (ws_flag.len > 0 or idx.workspaces.items.len <= 1) {
        return store.resolveWorkspace(allocator, fs, idx, ws_flag, &.{});
    }
    if (from_stream_id.len > 0) {
        var candidate: ?*const store.Workspace = null;
        var count: usize = 0;
        for (idx.workspaces.items) |*ws| {
            if (!std.mem.eql(u8, ws.stream, from_stream_id)) {
                candidate = ws;
                count += 1;
            }
        }
        if (count == 1) {
            return candidate.?;
        }
    }
    return store.resolveWorkspace(allocator, fs, idx, ws_flag, &.{}) catch |err| {
        if (from_stream_id.len == 0) {
            return fsys.refuse("stream_missing", from_name);
        }
        return err;
    };
}

/// Implements `flint fork <from> <new>`.
pub fn cmdFork(
    allocator: Allocator,
    fs: FS,
    root: []const u8,
    uuid_gen: *uuid.UUIDGen,
    out: *Io.Writer,
    args: []const []const u8,
) !void {
    if (args.len != 2 or args[0].len == 0 or !store.validWorkspaceName(args[1])) {
        return fsys.refuse("usage", "");
    }
    const from_name = args[0];
    const new_name = args[1];

    var idx = try store.loadStoreIndex(allocator, fs, root);
    defer idx.deinit();

    const from_rec = idx.streamByName(from_name) orelse {
        return fsys.refuse("stream_missing", from_name);
    };
    const from_id = try allocator.dupe(u8, from_rec.id);
    defer allocator.free(from_id);

    const loaded = try store.loadStream(allocator, fs, root, from_id);
    defer loaded.deinit(allocator);

    if (idx.streamByName(new_name) != null) {
        return fsys.refuse("stream_exists", new_name);
    }
    const head = loaded.stream.head orelse {
        return fsys.refuse("fork_empty", "");
    };
    if (head.len == 0) {
        return fsys.refuse("fork_empty", "");
    }

    const created_ms = try uuid_gen.nowMs();
    const new_id = try uuid_gen.new();

    try store.writeStreamRecord(allocator, fs, root, .{
        .id = &new_id,
        .name = new_name,
        .head = head,
        .created = created_ms,
        .forked_from = .{
            .stream = loaded.stream.id,
            .change = head,
        },
    });

    try out.print("flint: fork ok stream={s} head={s}\n", .{ new_name, head });
}

/// Implements `flint merge [--ws=<name>] <from>`.
/// Returns exit code 0 on clean/up-to-date merge, 2 on conflicts, or `error.Refuse`.
pub fn cmdMerge(
    allocator: Allocator,
    fs: FS,
    root: []const u8,
    uuid_gen: *uuid.UUIDGen,
    env_sign_key: ?[]const u8,
    out: *Io.Writer,
    args: []const []const u8,
) !u8 {
    var ws_flag: []const u8 = "";
    var from_name: []const u8 = "";

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.startsWith(u8, a, "--ws=")) {
            ws_flag = a["--ws=".len..];
        } else if (std.mem.eql(u8, a, "--ws") and i + 1 < args.len) {
            i += 1;
            ws_flag = args[i];
        } else if (std.mem.startsWith(u8, a, "-")) {
            return fsys.refuse("usage", "");
        } else {
            if (from_name.len > 0) {
                return fsys.refuse("usage", "");
            }
            from_name = a;
        }
    }
    if (from_name.len == 0) {
        return fsys.refuse("usage", "");
    }

    var idx = try store.loadStoreIndex(allocator, fs, root);
    defer idx.deinit();

    const from_rec_opt = idx.streamByName(from_name);
    const from_stream_id = if (from_rec_opt) |st| st.id else "";

    const ws = try resolveMergeWorkspace(allocator, fs, &idx, ws_flag, from_name, from_stream_id);

    const stage = try store.loadWorkspaceStage(allocator, fs, root, ws.name);
    defer store.freeOps(allocator, stage);
    if (stage.len > 0) {
        return fsys.refuse("stage_dirty", "");
    }

    if (from_rec_opt == null) {
        return fsys.refuse("stream_missing", from_name);
    }

    const into_stream_id = try allocator.dupe(u8, ws.stream);
    defer allocator.free(into_stream_id);
    const from_id_copy = try allocator.dupe(u8, from_stream_id);
    defer allocator.free(from_id_copy);

    const into_loaded = try store.loadStream(allocator, fs, root, into_stream_id);
    defer into_loaded.deinit(allocator);
    const from_loaded = try store.loadStream(allocator, fs, root, from_id_copy);
    defer from_loaded.deinit(allocator);

    const all_changes = try store.loadAllStreamChanges(allocator, fs, root, &idx);
    defer store.freeChanges(allocator, all_changes);

    var changes_by_id = std.StringHashMap(store.Change).init(allocator);
    defer changes_by_id.deinit();
    for (all_changes) |c| {
        try changes_by_id.put(c.id, c);
    }

    const anc = try findCommonAncestor(allocator, into_loaded.stream.head, from_loaded.stream.head, &changes_by_id);
    if (anc.up_to_date) {
        try out.writeAll("flint: merge up to date\n");
        return 0;
    }

    const into_head = into_loaded.stream.head orelse return fsys.refuse("change_missing", "");
    const from_head = from_loaded.stream.head orelse return fsys.refuse("change_missing", "");

    const replayed = try store.replayStreamAtoms(allocator, anc.ancestor_id, all_changes);
    defer store.freeStoredAtoms(allocator, replayed.atoms);

    const into_ops = try changesSinceAncestor(allocator, into_head, anc.ancestor_id, &changes_by_id);
    defer allocator.free(into_ops);
    const from_ops = try changesSinceAncestor(allocator, from_head, anc.ancestor_id, &changes_by_id);
    defer allocator.free(from_ops);

    const res = try mergeOps(allocator, replayed.atoms, into_ops, from_ops);
    defer res.deinit(allocator);

    const merge_path = try store.workspaceMergePath(allocator, root, ws.name);
    defer allocator.free(merge_path);

    if (!res.clean) {
        const report_line = try json.marshalMergeReportLine(allocator, .{
            .into = into_head,
            .from = from_head,
            .ancestor = anc.ancestor_id,
            .conflicts = res.conflicts,
        });
        defer allocator.free(report_line);
        try fs.writeFileSafe(allocator, merge_path, report_line);

        for (res.conflicts) |c| {
            try out.print("flint: merge conflict atom={s} type={s}\n", .{ c.name, c.type });
        }
        try out.print("flint: merge conflicts={d}\n", .{res.conflicts.len});
        return 2;
    }

    if (idx.change_count + 1 > store.MaxChanges) {
        return fsys.refuse("store_too_large", "changes");
    }

    // Clean merge: load signing seed BEFORE writing any file.
    var seed = try ed25519.loadSigningSeed(allocator, fs, root, "", env_sign_key);
    defer std.crypto.secureZero(u8, &seed);

    const ts = try uuid_gen.nowMs();
    const change_id = try uuid_gen.new();
    const msg = try std.fmt.allocPrint(allocator, "merge {s}", .{from_loaded.stream.name});
    defer allocator.free(msg);

    var c = store.Change{
        .id = &change_id,
        .parent = into_head,
        .stream = into_loaded.stream.id,
        .ts = ts,
        .author = "",
        .message = msg,
        .ops = res.ops,
        .merged = from_head,
        .sig = "",
    };
    defer {
        if (c.author.len > 0) allocator.free(c.author);
        if (c.sig.len > 0) allocator.free(c.sig);
    }

    try ed25519.signChangeWithSeed(allocator, &c, &seed);

    const existing_atoms = try store.loadWorkspaceAtoms(allocator, fs, root, ws.name);
    defer store.freeStoredAtoms(allocator, existing_atoms);

    var atoms_by_id = std.StringHashMap(store.StoredAtom).init(allocator);
    defer {
        var it = atoms_by_id.iterator();
        while (it.next()) |kv| {
            allocator.free(kv.key_ptr.*);
            kv.value_ptr.deinit(allocator);
        }
        atoms_by_id.deinit();
    }
    for (existing_atoms) |a| {
        const cloned = try a.clone(allocator);
        errdefer cloned.deinit(allocator);
        const k = try allocator.dupe(u8, cloned.id);
        errdefer allocator.free(k);
        try atoms_by_id.put(k, cloned);
    }

    // Count distinct files affected by the merged Ops before/after applying them.
    var unmaterialized_files = std.StringHashMap(void).init(allocator);
    defer unmaterialized_files.deinit();
    for (c.ops) |op| {
        if (atoms_by_id.get(op.atom_id)) |a| {
            if (a.span.file.len > 0) {
                try unmaterialized_files.put(a.span.file, {});
            }
        }
        if (op.new_span) |sp| {
            if (sp.file.len > 0) {
                try unmaterialized_files.put(sp.file, {});
            }
        }
    }
    const unmaterialized_count = unmaterialized_files.count();

    try store.applyOpsToAtomMap(allocator, &atoms_by_id, c.ops, true);
    if (atoms_by_id.count() > store.MaxAtoms) {
        return fsys.refuse("store_too_large", "atoms");
    }

    var updated_atoms: std.ArrayList(store.StoredAtom) = .empty;
    defer updated_atoms.deinit(allocator);
    {
        var it = atoms_by_id.iterator();
        while (it.next()) |kv| {
            try updated_atoms.append(allocator, kv.value_ptr.*);
        }
    }

    var updated_st = try store.appendStreamChange(allocator, fs, root, into_loaded.stream.id, into_head, c);
    updated_st.deinit(allocator);

    try store.writeWorkspaceAtoms(allocator, fs, root, ws.name, updated_atoms.items);
    if (fs.exists(allocator, merge_path)) {
        fs.remove(allocator, merge_path) catch {};
    }

    try out.print("flint: merge ok conflicts=0 ops={d} id={s}\n", .{ c.ops.len, c.id });
    try out.print("flint: merge src not materialized files={d}\n", .{unmaterialized_count});
    return 0;
}
