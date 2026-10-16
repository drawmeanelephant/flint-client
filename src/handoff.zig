//! FLINT-HANDOFF/1 — revision-bound agent handoffs and proposals
//! (docs/flint-handoffs-spec.md). Record parse/emit lives in `json.zig`, the
//! `handoff_msg` preimage and Ed25519 glue in `ed25519.zig`, record types and
//! the `handoffs/<stream>.jsonl` log bounds in `store.zig`. This module owns
//! the lazy log reader, the lifecycle fold, computed verdicts, and the
//! `flint handoff` verb family.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const fsys = @import("fsys.zig");
const FS = fsys.FS;
const store = @import("store.zig");
const json = @import("json.zig");
const uuid = @import("uuid.zig");
const ed25519 = @import("ed25519.zig");
const merge = @import("merge.zig");
const report = @import("report.zig");
const content = @import("content.zig");

const packet_format = "FLINT-HANDOFF-PACKET/1";

/// One line of a handoffs log after read-time classification (§6): a valid
/// `FLINT-HANDOFF/1` record, a `/1` line failing §1.5 rules 1–3 (`invalid`),
/// or a JSON object carrying another `format` (`unknown_version`). Non-JSON
/// and non-object lines refuse `handoff_malformed` before classification.
pub const LogEntry = struct {
    line: []const u8,
    /// Best-effort `handoff` attribution — set even for invalid lines.
    handoff: ?[]const u8,
    status: enum { ok, invalid, unknown_version },
    record: ?store.HandoffRecord = null,
    // Display fields for `invalid` lines (records print `sig=invalid`).
    id: ?[]const u8 = null,
    kind: ?[]const u8 = null,
    author: ?[]const u8 = null,

    pub fn deinit(self: LogEntry, allocator: Allocator) void {
        allocator.free(self.line);
        if (self.handoff) |v| allocator.free(v);
        if (self.record) |r| r.deinit(allocator);
        if (self.id) |v| allocator.free(v);
        if (self.kind) |v| allocator.free(v);
        if (self.author) |v| allocator.free(v);
    }
};

/// Log is one `handoffs/<stream-id>.jsonl` file, loaded lazily by the handoff
/// verbs — never by the every-invocation store index (§2).
pub const Log = struct {
    allocator: Allocator,
    stream_id: []u8,
    entries: []LogEntry,

    pub fn deinit(self: Log) void {
        self.allocator.free(self.stream_id);
        for (self.entries) |e| e.deinit(self.allocator);
        self.allocator.free(self.entries);
    }

    /// Byte content of a stored valid record's line (no trailing newline).
    pub fn lineFor(self: *const Log, record_id: []const u8) ?[]const u8 {
        for (self.entries) |e| {
            if (e.record) |r| {
                if (std.mem.eql(u8, r.id, record_id)) return e.line;
            }
        }
        return null;
    }
};

/// LoadLog reads `handoffs/<stream_id>.jsonl` (absent → empty), enforcing the
/// §2 bounds and torn/empty-line refusals.
pub fn loadLog(allocator: Allocator, fs: FS, root: []const u8, stream_id: []const u8) !Log {
    const sid = try allocator.dupe(u8, stream_id);
    errdefer allocator.free(sid);

    var entries: std.ArrayList(LogEntry) = .empty;
    errdefer {
        for (entries.items) |e| e.deinit(allocator);
        entries.deinit(allocator);
    }

    const path = try store.handoffLogPath(allocator, root, stream_id);
    defer allocator.free(path);
    if (fs.exists(allocator, path)) {
        const data = try fs.readFile(allocator, path, store.MaxFileReadBytes);
        defer allocator.free(data);
        const lines = try store.readHandoffLines(allocator, data);
        defer allocator.free(lines);
        if (lines.len > store.MaxHandoffRecords) {
            return fsys.refuse("store_too_large", "handoffs");
        }

        for (lines) |line| {
            const owned = try allocator.dupe(u8, line);
            var entry = LogEntry{
                .line = owned,
                .handoff = json.peekHandoffField(allocator, line, "handoff") catch null,
                .status = .unknown_version,
            };
            errdefer entry.deinit(allocator);

            const format = json.peekHandoffFormat(allocator, line) catch {
                // Not a JSON object at all — a malformed log line (§6).
                return fsys.refuse("handoff_malformed", "");
            };
            if (format) |f| {
                defer allocator.free(f);
                if (std.mem.eql(u8, f, json.handoff_format)) {
                    if (json.parseHandoffRecord(allocator, line)) |rec| {
                        entry.status = .ok;
                        entry.record = rec;
                    } else |_| {
                        entry.status = .invalid;
                        entry.id = json.peekHandoffField(allocator, line, "id") catch null;
                        entry.kind = json.peekHandoffField(allocator, line, "kind") catch null;
                        entry.author = json.peekHandoffField(allocator, line, "author") catch null;
                    }
                }
            }
            try entries.append(allocator, entry);
        }
    }

    return .{ .allocator = allocator, .stream_id = sid, .entries = try entries.toOwnedSlice(allocator) };
}

pub fn freeEntries(allocator: Allocator, entries: []LogEntry) void {
    for (entries) |e| e.deinit(allocator);
    allocator.free(entries);
}

/// Finds every log entry naming `handoff_id` across all `handoffs/*.jsonl`
/// logs. `owner_stream` receives the id of the log holding them (the propose
/// record's `stream`); multiple logs claiming the same id keep the first.
pub fn findEntries(
    allocator: Allocator,
    fs: FS,
    root: []const u8,
    handoff_id: []const u8,
    stream_filter: ?[]const u8,
) !struct { stream_id: ?[]u8, entries: []LogEntry } {
    var out: std.ArrayList(LogEntry) = .empty;
    errdefer freeEntries(allocator, out.items);
    var owner: ?[]u8 = null;
    errdefer if (owner) |o| allocator.free(o);

    const dir = try store.handoffsDir(allocator, root);
    defer allocator.free(dir);
    if (!fs.isDir(allocator, dir)) {
        return .{ .stream_id = null, .entries = try out.toOwnedSlice(allocator) };
    }
    const files = try fs.list(allocator, dir);
    defer FS.freeDirEntries(allocator, files);

    for (files) |f| {
        if (f.is_dir or !std.mem.endsWith(u8, f.name, ".jsonl")) continue;
        const sid = f.name[0 .. f.name.len - ".jsonl".len];
        if (uuid.parseUUID(sid) == null) continue;
        if (stream_filter) |sf| {
            if (!std.mem.eql(u8, sf, sid)) continue;
        }
        const log = try loadLog(allocator, fs, root, sid);
        for (log.entries) |e| {
            const hit = if (e.handoff) |h| std.mem.eql(u8, h, handoff_id) else false;
            if (hit) {
                if (owner == null and e.record != null) {
                    owner = try allocator.dupe(u8, e.record.?.stream);
                }
                try out.append(allocator, e);
            } else {
                e.deinit(allocator);
            }
        }
        allocator.free(log.entries);
        allocator.free(log.stream_id);
    }
    return .{ .stream_id = owner, .entries = try out.toOwnedSlice(allocator) };
}

pub const ProposalState = enum { none, proposed, accepted, superseded, withdrawn };

/// Fold is the §3 lifecycle fold of one proposal's entries in append order:
/// the first terminal record fixes the state; later records count into
/// `extra_records`; `attest` validations accumulate regardless.
pub const Fold = struct {
    state: ProposalState = .none,
    propose: ?*const store.HandoffRecord = null,
    terminal: ?*const store.HandoffRecord = null,
    extra_records: usize = 0,
    invalid_count: usize = 0,
    unknown_count: usize = 0,
    lifecycle_invalid: bool = false,
    attests: std.ArrayList(*const store.HandoffRecord) = .empty,

    pub fn deinit(self: *Fold, allocator: Allocator) void {
        self.attests.deinit(allocator);
    }
};

pub fn foldEntries(allocator: Allocator, entries: []const LogEntry) !Fold {
    var fold = Fold{};
    errdefer fold.deinit(allocator);

    for (entries) |*e| {
        switch (e.status) {
            .invalid => fold.invalid_count += 1,
            .unknown_version => fold.unknown_count += 1,
            .ok => {
                const r = &e.record.?;
                const is_propose = std.mem.eql(u8, r.kind, "propose");
                if (is_propose) {
                    if (fold.propose != null) {
                        // A second propose under the same handoff id reuses
                        // the record id — a §1.5 `id conflict` violation.
                        fold.lifecycle_invalid = true;
                    } else {
                        fold.propose = r;
                        if (fold.state == .none) fold.state = .proposed;
                    }
                    continue;
                }
                if (std.mem.eql(u8, r.kind, "attest")) {
                    try fold.attests.append(allocator, r);
                    if (fold.state == .accepted or fold.state == .superseded or
                        fold.state == .withdrawn)
                    {
                        fold.extra_records += 1;
                    }
                    continue;
                }
                if (fold.propose == null) {
                    // An event record ahead of the proposal's `propose` in
                    // append order can never have passed lifecycle checks.
                    fold.lifecycle_invalid = true;
                    continue;
                }
                if (fold.terminal != null) {
                    fold.extra_records += 1;
                    continue;
                }
                if (std.mem.eql(u8, r.kind, "accept")) {
                    fold.state = .accepted;
                    fold.terminal = r;
                } else if (std.mem.eql(u8, r.kind, "supersede")) {
                    fold.state = .superseded;
                    fold.terminal = r;
                } else {
                    fold.state = .withdrawn;
                    fold.terminal = r;
                }
            },
        }
    }
    return fold;
}

/// Verifies every `ok` record's signature (§5: inspect re-verifies rules 1–4).
/// Returns the count of signature failures.
fn countBadSigs(allocator: Allocator, entries: []const LogEntry) !usize {
    var bad: usize = 0;
    for (entries) |*e| {
        if (e.record) |*r| {
            const ok = ed25519.verifyHandoff(allocator, r) catch false;
            if (!ok) bad += 1;
        }
    }
    return bad;
}

/// Reports whether every Change reachable from `start` through `parent` and
/// `merged` links resolves in `changes_by_id` (§5 completeness).
fn ancestryComplete(
    allocator: Allocator,
    start: []const u8,
    changes_by_id: *const std.StringHashMap(store.Change),
) !bool {
    var seen = std.StringHashMap(void).init(allocator);
    defer seen.deinit();
    var queue: std.ArrayList([]const u8) = .empty;
    defer queue.deinit(allocator);
    try queue.append(allocator, start);

    var i: usize = 0;
    while (i < queue.items.len) : (i += 1) {
        const cur = queue.items[i];
        if (cur.len == 0 or seen.contains(cur)) continue;
        try seen.put(cur, {});
        const c = changes_by_id.get(cur) orelse return false;
        if (c.parent) |p| try queue.append(allocator, p);
        if (c.merged) |m| try queue.append(allocator, m);
    }
    return true;
}

/// Collects the Ops union of the Changes reachable from `candidate` but not
/// from `base` — the delta the proposal claims to carry (§4).
fn candidateDeltaOps(
    allocator: Allocator,
    base: ?[]const u8,
    candidate: []const u8,
    changes_by_id: *const std.StringHashMap(store.Change),
) ![]const store.Op {
    var base_anc = try merge.ancestorSet(allocator, base, changes_by_id);
    defer base_anc.deinit();
    var cand_anc = try merge.ancestorSet(allocator, candidate, changes_by_id);
    defer cand_anc.deinit();

    var ids: std.ArrayList([]const u8) = .empty;
    defer ids.deinit(allocator);
    var it = cand_anc.iterator();
    while (it.next()) |kv| {
        if (!base_anc.contains(kv.key_ptr.*)) {
            try ids.append(allocator, kv.key_ptr.*);
        }
    }
    std.mem.sort([]const u8, ids.items, {}, struct {
        fn lt(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lt);

    var ops: std.ArrayList(store.Op) = .empty;
    errdefer ops.deinit(allocator);
    for (ids.items) |id| {
        const c = changes_by_id.get(id).?;
        for (c.ops) |op| {
            try ops.append(allocator, op);
        }
    }
    return ops.toOwnedSlice(allocator);
}

fn scopeInsert(set: *std.StringHashMap(void), allocator: Allocator, s: []const u8) !void {
    if (s.len == 0 or set.contains(s)) return;
    const k = try allocator.dupe(u8, s);
    errdefer allocator.free(k);
    try set.put(k, {});
}

/// Derives the advisory scope claim — the qualified Atom names and relative
/// src paths the candidate delta touches (§8: derived-by-default keeps the
/// claim honest). Atom names resolve against the candidate's replayed table,
/// falling back to the base table for atoms the delta deleted.
pub fn deriveScope(
    allocator: Allocator,
    base: ?[]const u8,
    candidate: []const u8,
    changes_by_id: *const std.StringHashMap(store.Change),
    all_changes: []const store.Change,
) !store.HandoffScope {
    const ops = try candidateDeltaOps(allocator, base, candidate, changes_by_id);
    defer allocator.free(ops);

    // Gaps in the local copy (detached candidate ancestry, missing merged
    // tips) make the replay refuse — the scope claim degrades to best-effort
    // rather than failing the write/read verb.
    const cand_replay = store.replayStreamAtoms(allocator, candidate, all_changes) catch |err| switch (err) {
        error.Refuse => store.ReplayResult{
            .atoms = try allocator.alloc(store.StoredAtom, 0),
            .replayed = 0,
        },
        else => return err,
    };
    defer store.freeStoredAtoms(allocator, cand_replay.atoms);
    const base_replay = store.replayStreamAtoms(allocator, base, all_changes) catch |err| switch (err) {
        error.Refuse => store.ReplayResult{
            .atoms = try allocator.alloc(store.StoredAtom, 0),
            .replayed = 0,
        },
        else => return err,
    };
    defer store.freeStoredAtoms(allocator, base_replay.atoms);

    var name_by_id = std.StringHashMap(store.StoredAtom).init(allocator);
    defer name_by_id.deinit();
    for (base_replay.atoms) |a| try name_by_id.put(a.id, a);
    for (cand_replay.atoms) |a| try name_by_id.put(a.id, a);

    var paths = std.StringHashMap(void).init(allocator);
    defer {
        var it = paths.iterator();
        while (it.next()) |kv| allocator.free(kv.key_ptr.*);
        paths.deinit();
    }
    var atoms = std.StringHashMap(void).init(allocator);
    defer {
        var it = atoms.iterator();
        while (it.next()) |kv| allocator.free(kv.key_ptr.*);
        atoms.deinit();
    }

    for (ops) |op| {
        if (op.new_span) |sp| try scopeInsert(&paths, allocator, sp.file);
        if (name_by_id.get(op.atom_id)) |a| {
            try scopeInsert(&atoms, allocator, a.name);
            try scopeInsert(&paths, allocator, a.span.file);
        } else if (op.new_name.len > 0) {
            try scopeInsert(&atoms, allocator, op.new_name);
        }
    }

    var plist = try allocator.alloc([]const u8, paths.count());
    var i: usize = 0;
    var pit = paths.iterator();
    while (pit.next()) |kv| : (i += 1) {
        plist[i] = try allocator.dupe(u8, kv.key_ptr.*);
    }
    var alist = try allocator.alloc([]const u8, atoms.count());
    i = 0;
    var ait = atoms.iterator();
    while (ait.next()) |kv| : (i += 1) {
        alist[i] = try allocator.dupe(u8, kv.key_ptr.*);
    }
    return .{ .paths = plist, .atoms = alist };
}

/// Compares the declared scope against the candidate delta's actual Ops union
/// (§4): `unverifiable` on incomplete ancestry, `honest` when the claim covers
/// the delta, `exceeded` otherwise. An absent claim reads as an empty claim.
fn scopeVerdict(
    allocator: Allocator,
    propose: *const store.HandoffRecord,
    changes_by_id: *const std.StringHashMap(store.Change),
    all_changes: []const store.Change,
    ancestry_ok: bool,
) ![]const u8 {
    if (!ancestry_ok) return "unverifiable";
    const candidate = propose.candidate orelse return "unverifiable";
    const actual = deriveScope(allocator, propose.base, candidate, changes_by_id, all_changes) catch |err| switch (err) {
        error.Refuse => return "unverifiable",
        else => return err,
    };
    defer actual.deinit(allocator);

    var declared_paths = std.StringHashMap(void).init(allocator);
    defer declared_paths.deinit();
    var declared_atoms = std.StringHashMap(void).init(allocator);
    defer declared_atoms.deinit();
    if (propose.scope) |s| {
        for (s.paths) |p| try declared_paths.put(p, {});
        for (s.atoms) |a| try declared_atoms.put(a, {});
    }

    for (actual.paths) |p| {
        if (!declared_paths.contains(p)) return "exceeded";
    }
    for (actual.atoms) |a| {
        if (!declared_atoms.contains(a)) return "exceeded";
    }
    return "honest";
}

/// The §5 `ready` verdict's content leg outcome: `verified` means the bound
/// snapshot authenticates end to end; `incomplete` means required content is
/// unavailable; `invalid` means the claim's content fails authentication —
/// signature, binding, framing, or a blob id that does not match its bytes.
const ContentLeg = enum { verified, incomplete, invalid };

/// The §5 `ready` verdict's content leg: `snapshot` is the opaque #77-era
/// reference — a UUID names the manifest bound to that Change on the `work`
/// stream's log; `null` means explicitly content-degraded (still `ready`-able).
/// Presence alone is not proof (issue #96): the leg mirrors checkout's
/// non-writing verification. An unresolvable reference, a missing manifest
/// line or bound Change, an absent blob, or an explicitly incomplete entry
/// reports `incomplete`; a torn manifest log, a stream/change/author binding
/// mismatch, a failed Change or manifest signature, or blob bytes that do
/// not hash to their id reports `invalid`.
fn contentLeg(
    allocator: Allocator,
    fs: FS,
    root: []const u8,
    work: ?[]const u8,
    snapshot: ?[]const u8,
    changes_by_id: *const std.StringHashMap(store.Change),
) !ContentLeg {
    const snap = snapshot orelse return .verified;
    const work_id = work orelse return .incomplete;
    if (uuid.parseUUID(snap) == null) return .incomplete;

    const manifests = store.loadManifests(allocator, fs, root, work_id) catch |err| switch (err) {
        error.Refuse => return .invalid,
        else => return err,
    };
    defer store.freeManifests(allocator, manifests);
    const m = store.manifestForChange(manifests, snap) orelse return .incomplete;
    const bound = changes_by_id.get(snap) orelse return .incomplete;
    if (!std.mem.eql(u8, m.stream, bound.stream) or
        !std.mem.eql(u8, m.change, bound.id) or
        !std.mem.eql(u8, m.author, bound.author))
    {
        return .invalid;
    }
    const change_ok = ed25519.verifyChange(allocator, &bound) catch |err| switch (err) {
        error.Refuse => false,
        else => return err,
    };
    if (!change_ok) return .invalid;
    if (!try ed25519.verifyManifest(allocator, m.*)) return .invalid;

    for (m.files) |e| {
        if (e.blob.len == 0) return .incomplete;
        switch (try content.checkBlobContent(allocator, fs, root, e.blob)) {
            .ok => |data| allocator.free(data),
            .missing => return .incomplete,
            .malformed => return .invalid,
        }
    }
    return .verified;
}

/// Runs a pure semantic merge of `candidate` against `head` — writes nothing
/// (§5 `conflicting` leg).
fn dryMergeConflicts(
    allocator: Allocator,
    head: []const u8,
    candidate: []const u8,
    changes_by_id: *const std.StringHashMap(store.Change),
    all_changes: []const store.Change,
) !bool {
    const anc = try merge.findCommonAncestor(allocator, head, candidate, changes_by_id);
    if (anc.up_to_date) return false;
    const replayed = try store.replayStreamAtoms(allocator, anc.ancestor_id, all_changes);
    defer store.freeStoredAtoms(allocator, replayed.atoms);
    const into_ops = try merge.changesSinceAncestor(allocator, head, anc.ancestor_id, changes_by_id);
    defer allocator.free(into_ops);
    const from_ops = try merge.changesSinceAncestor(allocator, candidate, anc.ancestor_id, changes_by_id);
    defer allocator.free(from_ops);
    const res = try merge.mergeOps(allocator, replayed.atoms, into_ops, from_ops);
    defer res.deinit(allocator);
    return !res.clean;
}

fn loadChangesById(allocator: Allocator, all_changes: []const store.Change) !std.StringHashMap(store.Change) {
    var map = std.StringHashMap(store.Change).init(allocator);
    errdefer map.deinit();
    for (all_changes) |c| {
        try map.put(c.id, c);
    }
    return map;
}

fn resolveStreamRef(idx: *const store.StoreIndex, name_or_id: []const u8) ?*const store.Stream {
    return idx.streamByName(name_or_id) orelse idx.streamByID(name_or_id);
}

fn streamLabel(idx: *const store.StoreIndex, id: []const u8) []const u8 {
    if (idx.streamByID(id)) |st| return st.name;
    return id;
}

fn shortAuthor(author: []const u8) []const u8 {
    return if (author.len > 8) author[0..8] else author;
}

fn firstLine(s: []const u8) []const u8 {
    var line = s;
    if (std.mem.indexOfScalar(u8, line, '\n')) |nl| {
        line = line[0..nl];
    }
    if (std.mem.endsWith(u8, line, "\r")) {
        line = line[0 .. line.len - 1];
    }
    return line;
}

/// Bounded free-text for `flint:` output lines (§0: never unbounded).
fn boundedText(allocator: Allocator, s: []const u8) ![]u8 {
    const line = firstLine(s);
    const cap: usize = 120;
    if (line.len <= cap) return allocator.dupe(u8, line);
    return std.fmt.allocPrint(allocator, "{s}...", .{line[0..cap]});
}

// -- write path ---------------------------------------------------------------

/// §1.5 rule 5 — lifecycle legality of a non-`propose` record against
/// `entries` (the target stream's log, plus any already-staged import
/// records): the named proposal must be known and, excepting `attest`, live;
/// `withdraw` is the proposer's alone; a `supersede --replacement` must name
/// a known live proposal.
fn checkEventLifecycle(entries: []const LogEntry, rec: *const store.HandoffRecord) !void {
    if (std.mem.eql(u8, rec.kind, "propose")) return;

    var propose_rec: ?*const store.HandoffRecord = null;
    var proposal_terminated = false;
    for (entries) |*e| {
        if (e.record) |*r| {
            if (std.mem.eql(u8, r.handoff, rec.handoff)) {
                if (std.mem.eql(u8, r.kind, "propose") and std.mem.eql(u8, r.id, rec.handoff)) {
                    if (propose_rec == null) propose_rec = r;
                } else if (std.mem.eql(u8, r.kind, "accept") or
                    std.mem.eql(u8, r.kind, "supersede") or
                    std.mem.eql(u8, r.kind, "withdraw"))
                {
                    proposal_terminated = true;
                }
            }
        }
    }
    const prop = propose_rec orelse {
        return fsys.refuse("handoff_missing", rec.handoff);
    };
    if (proposal_terminated and !std.mem.eql(u8, rec.kind, "attest")) {
        return fsys.refuse("handoff_closed", rec.handoff);
    }
    if (std.mem.eql(u8, rec.kind, "withdraw")) {
        if (!std.mem.eql(u8, prop.author, rec.author)) {
            return fsys.refuse("handoff_author", rec.handoff);
        }
    }
    if (std.mem.eql(u8, rec.kind, "supersede")) {
        if (rec.replacement) |rep| {
            // The replacement must be a known live proposal (§1.5 rule 5).
            var rep_live = false;
            var rep_terminated = false;
            for (entries) |*e| {
                if (e.record) |*r| {
                    if (std.mem.eql(u8, r.handoff, rep)) {
                        if (std.mem.eql(u8, r.kind, "propose") and std.mem.eql(u8, r.id, rep)) {
                            rep_live = true;
                        } else if (std.mem.eql(u8, r.kind, "accept") or
                            std.mem.eql(u8, r.kind, "supersede") or
                            std.mem.eql(u8, r.kind, "withdraw"))
                        {
                            rep_terminated = true;
                        }
                    }
                }
            }
            if (!rep_live or rep_terminated) {
                return fsys.refuse("handoff_missing", rep);
            }
        }
    }
}

/// Builds, signs, and verifies a record (§0 verify-before-write), runs the
/// §1.5 rule-5 lifecycle checks against the target stream's log, then appends.
fn writeRecord(
    allocator: Allocator,
    fs: FS,
    root: []const u8,
    uuid_gen: *uuid.UUIDGen,
    env_sign_key: ?[]const u8,
    key_flag: []const u8,
    fields: struct {
        kind: []const u8,
        stream: []const u8,
        handoff: ?[]const u8 = null,
        base: ?[]const u8 = null,
        work: ?[]const u8 = null,
        candidate: ?[]const u8 = null,
        snapshot: ?[]const u8 = null,
        intent: ?[]const u8 = null,
        note: ?[]const u8 = null,
        scope: ?store.HandoffScope = null,
        validations: []store.HandoffValidation = &.{},
        observed_head: ?[]const u8 = null,
        replacement: ?[]const u8 = null,
    },
) !store.HandoffRecord {
    // Load the signing key before any store mutation (ADR 0049 discipline).
    var seed = try ed25519.loadSigningSeed(allocator, fs, root, key_flag, env_sign_key);
    defer std.crypto.secureZero(u8, &seed);

    const ts = try uuid_gen.nowMs();
    const id = try uuid_gen.new();

    var rec = store.HandoffRecord{
        .id = try allocator.dupe(u8, &id),
        .handoff = try allocator.dupe(u8, if (fields.handoff) |h| h else &id),
        .kind = try allocator.dupe(u8, fields.kind),
        .stream = try allocator.dupe(u8, fields.stream),
        .ts = ts,
        .author = try allocator.dupe(u8, ""),
        .sig = try allocator.dupe(u8, ""),
        .base = if (fields.base) |v| try allocator.dupe(u8, v) else null,
        .work = if (fields.work) |v| try allocator.dupe(u8, v) else null,
        .candidate = if (fields.candidate) |v| try allocator.dupe(u8, v) else null,
        .snapshot = if (fields.snapshot) |v| try allocator.dupe(u8, v) else null,
        .intent = if (fields.intent) |v| try allocator.dupe(u8, v) else null,
        .note = if (fields.note) |v| try allocator.dupe(u8, v) else null,
        .observed_head = if (fields.observed_head) |v| try allocator.dupe(u8, v) else null,
        .replacement = if (fields.replacement) |v| try allocator.dupe(u8, v) else null,
    };
    errdefer rec.deinit(allocator);
    if (fields.scope) |s| {
        rec.scope = try s.clone(allocator);
    }
    if (fields.validations.len > 0) {
        var vals = try allocator.alloc(store.HandoffValidation, fields.validations.len);
        var vi: usize = 0;
        errdefer {
            for (vals[0..vi]) |v| v.deinit(allocator);
            allocator.free(vals);
        }
        while (vi < fields.validations.len) : (vi += 1) {
            vals[vi] = try fields.validations[vi].clone(allocator);
        }
        rec.validations = vals;
    }

    var seed_copy = seed;
    try ed25519.signHandoffRecord(allocator, &rec, &seed_copy);

    // Verify-before-write (§0), then emit the signed line — it must round-trip
    // through §1.5 rules 1–3 unchanged, so marshal only after signing.
    if (!try ed25519.verifyHandoff(allocator, &rec)) {
        return fsys.refuse("sig_invalid", "");
    }
    const line = try json.marshalHandoffRecord(allocator, rec);
    defer allocator.free(line);
    if (line.len > store.MaxHandoffLineBytes + 1) {
        return fsys.refuse("handoff_malformed", "record too large");
    }
    // A writer must never emit a record that fails §1.5 rules 1–3; re-parse
    // the emitted line as a hard guard before it touches the store.
    {
        const check = json.parseHandoffRecord(allocator, line[0 .. line.len - 1]) catch {
            return fsys.refuse("handoff_malformed", "");
        };
        check.deinit(allocator);
    }

    // §1.5 rule 5 — lifecycle against the target stream's log.
    var log = try loadLog(allocator, fs, root, rec.stream);
    defer log.deinit();

    const line_body = line[0 .. line.len - 1];
    for (log.entries) |e| {
        if (e.record) |old| {
            if (std.mem.eql(u8, old.id, rec.id)) {
                // §1.5 rule 5 — a re-seen id under identical bytes dedupes;
                // different bytes (or any `propose` id collision) refuse.
                if (std.mem.eql(u8, rec.kind, "propose") or
                    !std.mem.eql(u8, e.line, line_body))
                {
                    return fsys.refuse("handoff_malformed", "id conflict");
                }
                return rec;
            }
        }
    }

    try checkEventLifecycle(log.entries, &rec);

    if (report.active) |r| r.beginLocalWrites();
    const log_path = try store.handoffLogPath(allocator, root, rec.stream);
    defer allocator.free(log_path);
    if (log.entries.len + 1 > store.MaxHandoffRecords) {
        return fsys.refuse("store_too_large", "handoffs");
    }
    try fs.appendSync(allocator, log_path, line);
    if (report.active) |r| r.localApplied();
    return rec;
}

// -- verbs --------------------------------------------------------------------

fn cmdPropose(
    allocator: Allocator,
    fs: FS,
    root: []const u8,
    uuid_gen: *uuid.UUIDGen,
    env_sign_key: ?[]const u8,
    out: *Io.Writer,
    args: []const []const u8,
) !u8 {
    var stream_flag: []const u8 = "";
    var work_flag: []const u8 = "";
    var candidate_flag: []const u8 = "";
    var base_flag: []const u8 = "";
    var snapshot_flag: ?[]const u8 = null;
    var intent: ?[]const u8 = null;
    var scope_file: []const u8 = "";
    var validations_file: []const u8 = "";
    var key_flag: []const u8 = "";

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.startsWith(u8, a, "--stream=")) {
            stream_flag = a["--stream=".len..];
        } else if (std.mem.eql(u8, a, "--stream") and i + 1 < args.len) {
            i += 1;
            stream_flag = args[i];
        } else if (std.mem.startsWith(u8, a, "--work=")) {
            work_flag = a["--work=".len..];
        } else if (std.mem.eql(u8, a, "--work") and i + 1 < args.len) {
            i += 1;
            work_flag = args[i];
        } else if (std.mem.startsWith(u8, a, "--candidate=")) {
            candidate_flag = a["--candidate=".len..];
        } else if (std.mem.eql(u8, a, "--candidate") and i + 1 < args.len) {
            i += 1;
            candidate_flag = args[i];
        } else if (std.mem.startsWith(u8, a, "--base=")) {
            base_flag = a["--base=".len..];
        } else if (std.mem.eql(u8, a, "--base") and i + 1 < args.len) {
            i += 1;
            base_flag = args[i];
        } else if (std.mem.startsWith(u8, a, "--snapshot=")) {
            snapshot_flag = a["--snapshot=".len..];
        } else if (std.mem.eql(u8, a, "--snapshot") and i + 1 < args.len) {
            i += 1;
            snapshot_flag = args[i];
        } else if (std.mem.eql(u8, a, "-m") or std.mem.eql(u8, a, "--message")) {
            if (i + 1 >= args.len) return fsys.refuse("usage", "");
            i += 1;
            intent = args[i];
        } else if (std.mem.startsWith(u8, a, "-m=")) {
            intent = a["-m=".len..];
        } else if (std.mem.startsWith(u8, a, "--message=")) {
            intent = a["--message=".len..];
        } else if (std.mem.startsWith(u8, a, "--scope-file=")) {
            scope_file = a["--scope-file=".len..];
        } else if (std.mem.eql(u8, a, "--scope-file") and i + 1 < args.len) {
            i += 1;
            scope_file = args[i];
        } else if (std.mem.startsWith(u8, a, "--validations=")) {
            validations_file = a["--validations=".len..];
        } else if (std.mem.eql(u8, a, "--validations") and i + 1 < args.len) {
            i += 1;
            validations_file = args[i];
        } else if (std.mem.startsWith(u8, a, "--key=")) {
            key_flag = a["--key=".len..];
        } else if (std.mem.eql(u8, a, "--key") and i + 1 < args.len) {
            i += 1;
            key_flag = args[i];
        } else {
            return fsys.refuse("usage", "");
        }
    }

    if (stream_flag.len == 0 or work_flag.len == 0 or intent == null) {
        return fsys.refuse("usage", "");
    }
    if (intent.?.len == 0 or intent.?.len > json.MaxHandoffTextBytes or
        !std.unicode.utf8ValidateSlice(intent.?))
    {
        return fsys.refuse("handoff_malformed", "intent");
    }

    var idx = try store.loadStoreIndex(allocator, fs, root);
    defer idx.deinit();

    // §1.5 rule 6 — local resolvability of the two streams.
    const target = resolveStreamRef(&idx, stream_flag) orelse {
        return fsys.refuse("stream_missing", stream_flag);
    };
    const work_st = resolveStreamRef(&idx, work_flag) orelse {
        return fsys.refuse("stream_missing", work_flag);
    };

    const target_id = try allocator.dupe(u8, target.id);
    defer allocator.free(target_id);
    const work_id = try allocator.dupe(u8, work_st.id);
    defer allocator.free(work_id);

    const target_loaded = try store.loadStream(allocator, fs, root, target_id);
    defer target_loaded.deinit(allocator);
    const work_loaded = try store.loadStream(allocator, fs, root, work_id);
    defer work_loaded.deinit(allocator);

    const base = if (base_flag.len > 0) base_flag else (target_loaded.stream.head orelse "");
    const candidate = if (candidate_flag.len > 0)
        candidate_flag
    else
        (work_loaded.stream.head orelse "");
    if (base.len == 0 or uuid.parseUUID(base) == null) {
        return fsys.refuse("change_missing", "base");
    }
    if (candidate.len == 0 or uuid.parseUUID(candidate) == null) {
        return fsys.refuse("change_missing", "candidate");
    }

    var base_present = false;
    for (target_loaded.changes) |c| {
        if (std.mem.eql(u8, c.id, base)) base_present = true;
    }
    if (!base_present) return fsys.refuse("change_missing", base);
    var cand_present = false;
    for (work_loaded.changes) |c| {
        if (std.mem.eql(u8, c.id, candidate)) cand_present = true;
    }
    if (!cand_present) return fsys.refuse("change_missing", candidate);

    // Snapshot defaults to the candidate's own revision id when the work
    // stream carries a captured manifest for it (snapshot identity IS the
    // Change id, docs/flint-blobs-spec.md §4); `null` is the honest answer
    // when no content was captured.
    var snapshot: ?[]const u8 = snapshot_flag;
    if (snapshot == null) {
        const manifests = try store.loadManifests(allocator, fs, root, work_id);
        defer store.freeManifests(allocator, manifests);
        if (store.manifestForChange(manifests, candidate) != null) {
            snapshot = candidate;
        }
    }
    if (snapshot) |s| {
        if (s.len == 0 or s.len > json.MaxHandoffSnapshotBytes or
            !std.unicode.utf8ValidateSlice(s))
        {
            return fsys.refuse("handoff_malformed", "snapshot");
        }
    }

    var scope: ?store.HandoffScope = null;
    defer if (scope) |s| s.deinit(allocator);
    if (scope_file.len > 0) {
        const raw = try fs.readFile(allocator, fsys.cleanMemPath(scope_file), store.MaxFileReadBytes);
        defer allocator.free(raw);
        scope = try json.parseHandoffScopeDoc(allocator, raw);
    } else {
        const all_changes = try store.loadAllStreamChanges(allocator, fs, root, &idx);
        defer store.freeChanges(allocator, all_changes);
        var changes_by_id = try loadChangesById(allocator, all_changes);
        defer changes_by_id.deinit();
        scope = try deriveScope(allocator, base, candidate, &changes_by_id, all_changes);
    }

    var validations: []store.HandoffValidation = &.{};
    defer {
        for (validations) |v| v.deinit(allocator);
        if (validations.len > 0) allocator.free(validations);
    }
    // The signer fills absent attestor/ts fields; a present-but-foreign
    // attestor is the §1.5 rule-3 violation.
    var seed = try ed25519.loadSigningSeed(allocator, fs, root, key_flag, env_sign_key);
    defer std.crypto.secureZero(u8, &seed);
    const signer_pub = try ed25519.derivePublic(seed);
    const signer_hex = ed25519.encodeHexFixedLower(32, signer_pub);

    if (validations_file.len > 0) {
        const raw = try fs.readFile(allocator, fsys.cleanMemPath(validations_file), store.MaxFileReadBytes);
        defer allocator.free(raw);
        const now = try uuid_gen.nowMs();
        validations = try json.parseHandoffValidationsDoc(allocator, raw);
        for (validations) |*v| {
            if (v.attestor.len == 0) {
                v.attestor = try allocator.dupe(u8, &signer_hex);
            } else if (!std.mem.eql(u8, v.attestor, &signer_hex)) {
                return fsys.refuse("handoff_malformed", "attestor mismatch");
            }
            if (v.ts <= 0) v.ts = now;
        }
    }

    var rec = try writeRecord(allocator, fs, root, uuid_gen, env_sign_key, key_flag, .{
        .kind = "propose",
        .stream = target_id,
        .base = base,
        .work = work_id,
        .candidate = candidate,
        .snapshot = snapshot,
        .intent = intent.?,
        .scope = scope,
        .validations = validations,
    });
    defer rec.deinit(allocator);

    if (report.active) |r| {
        try r.setScope(null, target.name);
        try r.observeBaseHead(base);
        try r.observeResultHead(target_loaded.stream.head);
        try r.fieldStr("id", rec.id);
        try r.fieldStr("handoff", rec.handoff);
        try r.fieldStr("kind", "propose");
        try r.fieldStr("stream", target.name);
        try r.fieldStr("work", work_st.name);
        try r.fieldStr("base", base);
        try r.fieldStr("candidate", candidate);
        try r.fieldOptStrOmitNull("snapshot", snapshot);
        try r.fieldStr("intent", intent.?);
    }

    try out.print(
        "flint: handoff {s} kind=propose stream={s} candidate={s}\n",
        .{ rec.id, target.name, candidate },
    );
    return 0;
}

/// Shared front half of the event verbs: resolve the proposal's log and fold.
fn loadProposal(
    allocator: Allocator,
    fs: FS,
    root: []const u8,
    handoff_id: []const u8,
) !struct { stream_id: []u8, entries: []LogEntry, fold: Fold } {
    const found = try findEntries(allocator, fs, root, handoff_id, null);
    errdefer {
        if (found.stream_id) |s| allocator.free(s);
        freeEntries(allocator, found.entries);
    }
    var fold = try foldEntries(allocator, found.entries);
    errdefer fold.deinit(allocator);
    if (fold.propose == null or found.stream_id == null) {
        return fsys.refuse("handoff_missing", handoff_id);
    }
    return .{ .stream_id = found.stream_id.?, .entries = found.entries, .fold = fold };
}

fn cmdEvent(
    allocator: Allocator,
    fs: FS,
    root: []const u8,
    uuid_gen: *uuid.UUIDGen,
    env_sign_key: ?[]const u8,
    out: *Io.Writer,
    kind: []const u8,
    args: []const []const u8,
) !u8 {
    var handoff_id: []const u8 = "";
    var command: ?[]const u8 = null;
    var result: ?[]const u8 = null;
    var toolchain: []const u8 = "";
    var env: []const u8 = "";
    var evidence: []const u8 = "";
    var note: ?[]const u8 = null;
    var replacement: ?[]const u8 = null;
    var key_flag: []const u8 = "";

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.startsWith(u8, a, "--command=")) {
            command = a["--command=".len..];
        } else if (std.mem.eql(u8, a, "--command") and i + 1 < args.len) {
            i += 1;
            command = args[i];
        } else if (std.mem.startsWith(u8, a, "--result=")) {
            result = a["--result=".len..];
        } else if (std.mem.eql(u8, a, "--result") and i + 1 < args.len) {
            i += 1;
            result = args[i];
        } else if (std.mem.startsWith(u8, a, "--toolchain=")) {
            toolchain = a["--toolchain=".len..];
        } else if (std.mem.eql(u8, a, "--toolchain") and i + 1 < args.len) {
            i += 1;
            toolchain = args[i];
        } else if (std.mem.startsWith(u8, a, "--env=")) {
            env = a["--env=".len..];
        } else if (std.mem.eql(u8, a, "--env") and i + 1 < args.len) {
            i += 1;
            env = args[i];
        } else if (std.mem.startsWith(u8, a, "--evidence=")) {
            evidence = a["--evidence=".len..];
        } else if (std.mem.eql(u8, a, "--evidence") and i + 1 < args.len) {
            i += 1;
            evidence = args[i];
        } else if (std.mem.startsWith(u8, a, "--note=")) {
            note = a["--note=".len..];
        } else if (std.mem.eql(u8, a, "--note") and i + 1 < args.len) {
            i += 1;
            note = args[i];
        } else if (std.mem.startsWith(u8, a, "--replacement=")) {
            replacement = a["--replacement=".len..];
        } else if (std.mem.eql(u8, a, "--replacement") and i + 1 < args.len) {
            i += 1;
            replacement = args[i];
        } else if (std.mem.startsWith(u8, a, "--key=")) {
            key_flag = a["--key=".len..];
        } else if (std.mem.eql(u8, a, "--key") and i + 1 < args.len) {
            i += 1;
            key_flag = args[i];
        } else if (std.mem.startsWith(u8, a, "-")) {
            return fsys.refuse("usage", "");
        } else {
            if (handoff_id.len > 0) return fsys.refuse("usage", "");
            handoff_id = a;
        }
    }

    const is_attest = std.mem.eql(u8, kind, "attest");
    if (handoff_id.len == 0 or uuid.parseUUID(handoff_id) == null) {
        return fsys.refuse("usage", "");
    }
    if (is_attest) {
        if (command == null or result == null) {
            return fsys.refuse("usage", "");
        }
        if (command.?.len == 0 or command.?.len > json.MaxHandoffCommandBytes or
            !std.unicode.utf8ValidateSlice(command.?))
        {
            return fsys.refuse("handoff_malformed", "command");
        }
        if (store.handoffResultCode(result.?) == 0) {
            return fsys.refuse("handoff_malformed", "result");
        }
        if (toolchain.len > json.MaxHandoffContextBytes or
            env.len > json.MaxHandoffContextBytes or
            evidence.len > json.MaxHandoffContextBytes)
        {
            return fsys.refuse("handoff_malformed", "");
        }
    }
    if (!is_attest) {
        if (command != null or result != null or toolchain.len > 0 or
            env.len > 0 or evidence.len > 0)
        {
            return fsys.refuse("usage", "");
        }
        // `replacement` exists only on supersede (§1.2).
        if (!std.mem.eql(u8, kind, "supersede") and replacement != null) {
            return fsys.refuse("usage", "");
        }
    } else if (replacement != null or note != null) {
        // `note`/`replacement` exist only on accept/supersede/withdraw (§1.2).
        return fsys.refuse("usage", "");
    }
    if (note) |n| {
        if (n.len > json.MaxHandoffTextBytes or !std.unicode.utf8ValidateSlice(n)) {
            return fsys.refuse("handoff_malformed", "note");
        }
        // §1.2 — empty strings read identically to omitted fields.
        if (n.len == 0) note = null;
    }
    if (replacement) |rep| {
        if (uuid.parseUUID(rep) == null) return fsys.refuse("handoff_malformed", "replacement");
    }

    const prop = try loadProposal(allocator, fs, root, handoff_id);
    defer {
        allocator.free(prop.stream_id);
        freeEntries(allocator, prop.entries);
        var f = prop.fold;
        f.deinit(allocator);
    }
    const propose = prop.fold.propose.?;
    const terminated = prop.fold.state == .accepted or
        prop.fold.state == .superseded or prop.fold.state == .withdrawn;

    var idx = try store.loadStoreIndex(allocator, fs, root);
    defer idx.deinit();

    var observed_head: ?[]u8 = null;
    defer if (observed_head) |h| allocator.free(h);
    if (std.mem.eql(u8, kind, "accept")) {
        if (terminated) return fsys.refuse("handoff_closed", handoff_id);
        // `observed_head` is recorded from the local stream record, never an
        // argument — you accept what you can see (§8).
        const target_loaded = store.loadStream(allocator, fs, root, prop.stream_id) catch |err| {
            return err;
        };
        defer target_loaded.deinit(allocator);
        observed_head = if (target_loaded.stream.head) |h| try allocator.dupe(u8, h) else null;
        if (observed_head == null) {
            return fsys.refuse("change_missing", "observed_head");
        }

        const all_changes = try store.loadAllStreamChanges(allocator, fs, root, &idx);
        defer store.freeChanges(allocator, all_changes);
        var changes_by_id = try loadChangesById(allocator, all_changes);
        defer changes_by_id.deinit();
        const cand = propose.candidate orelse return fsys.refuse("handoff_malformed", "candidate");
        if (!try ancestryComplete(allocator, cand, &changes_by_id)) {
            return fsys.refuse("change_missing", cand);
        }
    } else if (terminated and !is_attest) {
        return fsys.refuse("handoff_closed", handoff_id);
    }

    var vals: []store.HandoffValidation = &.{};
    var one_val: [1]store.HandoffValidation = undefined;
    if (is_attest) {
        const now = try uuid_gen.nowMs();
        var seed = try ed25519.loadSigningSeed(allocator, fs, root, key_flag, env_sign_key);
        defer std.crypto.secureZero(u8, &seed);
        const pub_hex = ed25519.encodeHexFixedLower(32, try ed25519.derivePublic(seed));
        one_val[0] = .{
            .command = command.?,
            .result = result.?,
            .toolchain = toolchain,
            .env = env,
            .attestor = &pub_hex,
            .ts = now,
            .evidence = evidence,
        };
        vals = &one_val;
    }

    var rec = try writeRecord(allocator, fs, root, uuid_gen, env_sign_key, key_flag, .{
        .kind = kind,
        .stream = prop.stream_id,
        .handoff = handoff_id,
        .candidate = if (is_attest or std.mem.eql(u8, kind, "accept") or
            std.mem.eql(u8, kind, "supersede")) propose.candidate else null,
        .snapshot = if (is_attest) propose.snapshot else null,
        .note = note,
        .validations = vals,
        .observed_head = observed_head,
        .replacement = replacement,
    });
    defer rec.deinit(allocator);

    if (report.active) |r| {
        try r.setScope(null, streamLabel(&idx, prop.stream_id));
        try r.fieldStr("id", rec.id);
        try r.fieldStr("handoff", rec.handoff);
        try r.fieldStr("kind", kind);
        try r.fieldOptStrOmitNull("candidate", rec.candidate);
        try r.fieldOptStrOmitNull("observed_head", rec.observed_head);
        try r.fieldOptStrOmitNull("replacement", rec.replacement);
    }

    if (std.mem.eql(u8, kind, "accept")) {
        try out.print(
            "flint: handoff {s} kind=accept id={s} observed_head={s}\n",
            .{ rec.handoff, rec.id, rec.observed_head.? },
        );
    } else {
        try out.print(
            "flint: handoff {s} kind={s} id={s}\n",
            .{ rec.handoff, kind, rec.id },
        );
    }
    return 0;
}

// -- read side ----------------------------------------------------------------

fn cmdList(
    allocator: Allocator,
    fs: FS,
    root: []const u8,
    out: *Io.Writer,
    args: []const []const u8,
) !u8 {
    var stream_flag: []const u8 = "";
    var state_flag: []const u8 = "";

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.startsWith(u8, a, "--stream=")) {
            stream_flag = a["--stream=".len..];
        } else if (std.mem.eql(u8, a, "--stream") and i + 1 < args.len) {
            i += 1;
            stream_flag = args[i];
        } else if (std.mem.startsWith(u8, a, "--state=")) {
            state_flag = a["--state=".len..];
        } else if (std.mem.eql(u8, a, "--state") and i + 1 < args.len) {
            i += 1;
            state_flag = args[i];
        } else {
            return fsys.refuse("usage", "");
        }
    }

    var idx = try store.loadStoreIndex(allocator, fs, root);
    defer idx.deinit();

    var stream_filter: ?[]const u8 = null;
    if (stream_flag.len > 0) {
        const st = resolveStreamRef(&idx, stream_flag) orelse {
            return fsys.refuse("stream_missing", stream_flag);
        };
        stream_filter = st.id;
    }

    const dir = try store.handoffsDir(allocator, root);
    defer allocator.free(dir);

    // Entries are grouped per proposal; the views borrow record fields, so
    // every loaded log must stay alive until printing is done.
    var logs: std.ArrayList(Log) = .empty;
    defer {
        for (logs.items) |l| l.deinit();
        logs.deinit(allocator);
    }

    if (fs.isDir(allocator, dir)) {
        const files = try fs.list(allocator, dir);
        defer FS.freeDirEntries(allocator, files);
        for (files) |f| {
            if (f.is_dir or !std.mem.endsWith(u8, f.name, ".jsonl")) continue;
            const sid = f.name[0 .. f.name.len - ".jsonl".len];
            if (uuid.parseUUID(sid) == null) continue;
            if (stream_filter) |sf| {
                if (!std.mem.eql(u8, sf, sid)) continue;
            }
            try logs.append(allocator, try loadLog(allocator, fs, root, sid));
        }
    }

    const ProposalView = struct {
        id: []const u8,
        ts: i64,
        state: []const u8,
        candidate: []const u8,
        author: []const u8,
        intent: []const u8,
    };
    var views: std.ArrayList(ProposalView) = .empty;
    defer views.deinit(allocator);

    var grouped = std.StringHashMap(*std.ArrayList(LogEntry)).init(allocator);
    defer {
        var git = grouped.iterator();
        while (git.next()) |kv| {
            kv.value_ptr.*.deinit(allocator);
            allocator.destroy(kv.value_ptr.*);
        }
        grouped.deinit();
    }

    for (logs.items) |*log| {
        for (log.entries) |e| {
            const h = e.handoff orelse continue;
            const gop = try grouped.getOrPut(h);
            if (!gop.found_existing) {
                const list = try allocator.create(std.ArrayList(LogEntry));
                list.* = .empty;
                gop.value_ptr.* = list;
            }
            try gop.value_ptr.*.append(allocator, e);
        }
    }

    var git = grouped.iterator();
    while (git.next()) |kv| {
        const list = kv.value_ptr.*;
        var fold = try foldEntries(allocator, list.items);
        defer fold.deinit(allocator);
        const prop = fold.propose orelse continue;
        const state_name = switch (fold.state) {
            .none => "unknown",
            .proposed => "proposed",
            .accepted => "accepted",
            .superseded => "superseded",
            .withdrawn => "withdrawn",
        };
        const bad = try countBadSigs(allocator, list.items);
        const shown_state = if (bad > 0 or fold.invalid_count > 0 or
            fold.lifecycle_invalid) "invalid" else state_name;
        if (state_flag.len > 0 and !std.mem.eql(u8, shown_state, state_flag)) {
            continue;
        }
        try views.append(allocator, .{
            .id = prop.id,
            .ts = prop.ts,
            .state = shown_state,
            .candidate = prop.candidate orelse "",
            .author = prop.author,
            .intent = prop.intent orelse "",
        });
    }

    // Newest first: propose ts desc, id desc as a stable tiebreak.
    std.mem.sort(ProposalView, views.items, {}, struct {
        fn lt(_: void, a: ProposalView, b: ProposalView) bool {
            if (a.ts != b.ts) return a.ts > b.ts;
            return std.mem.order(u8, a.id, b.id) == .gt;
        }
    }.lt);

    var json_list: std.ArrayList(u8) = .empty;
    defer json_list.deinit(allocator);
    if (report.active != null) try json_list.append(allocator, '[');

    var listed: usize = 0;
    for (views.items) |v| {
        const intent_text = try boundedText(allocator, v.intent);
        defer allocator.free(intent_text);
        try out.print(
            "flint: handoff {s} state={s} candidate={s} author={s} intent={s}\n",
            .{ v.id, v.state, v.candidate, shortAuthor(v.author), intent_text },
        );
        if (report.active != null) {
            if (listed > 0) try json_list.append(allocator, ',');
            try json_list.appendSlice(allocator, "{\"id\":");
            try report.escapeInto(&json_list, allocator, v.id);
            try json_list.appendSlice(allocator, ",\"state\":");
            try report.escapeInto(&json_list, allocator, v.state);
            try json_list.appendSlice(allocator, ",\"candidate\":");
            try report.escapeInto(&json_list, allocator, v.candidate);
            try json_list.appendSlice(allocator, ",\"author\":");
            try report.escapeInto(&json_list, allocator, v.author);
            try json_list.appendSlice(allocator, ",\"intent\":");
            try report.escapeInto(&json_list, allocator, v.intent);
            try json_list.append(allocator, '}');
            listed += 1;
        }
    }

    if (report.active) |r| {
        try json_list.append(allocator, ']');
        try r.fieldRaw("proposals", json_list.items);
    }
    return 0;
}

const Verdict = struct {
    name: []const u8,
    scope: []const u8 = "unverifiable",
};

fn computeVerdict(
    allocator: Allocator,
    fs: FS,
    root: []const u8,
    idx: *store.StoreIndex,
    stream_id: []const u8,
    entries: []const LogEntry,
    fold: *const Fold,
) !Verdict {
    if (fold.propose == null) {
        if (fold.unknown_count > 0 and entries.len == fold.unknown_count) {
            return .{ .name = "unknown" };
        }
        return .{ .name = "invalid" };
    }
    if (fold.invalid_count > 0 or fold.lifecycle_invalid) {
        return .{ .name = "invalid" };
    }
    if (try countBadSigs(allocator, entries) > 0) {
        return .{ .name = "invalid" };
    }

    const propose = fold.propose.?;
    const candidate = propose.candidate orelse return .{ .name = "invalid" };

    // Observed target head — absent stream record means the receiver does not
    // hold the stream the proposal claims against.
    var target_head: ?[]const u8 = null;
    var stream_known = false;
    if (idx.streamByID(stream_id) != null) {
        const loaded = try store.loadStream(allocator, fs, root, stream_id);
        defer loaded.deinit(allocator);
        target_head = if (loaded.stream.head) |h| try allocator.dupe(u8, h) else null;
        stream_known = true;
    }
    defer if (target_head) |h| allocator.free(h);

    const all_changes = try store.loadAllStreamChanges(allocator, fs, root, idx);
    defer store.freeChanges(allocator, all_changes);
    var changes_by_id = try loadChangesById(allocator, all_changes);
    defer changes_by_id.deinit();

    const cand_ok = changes_by_id.contains(candidate) and
        try ancestryComplete(allocator, candidate, &changes_by_id);
    const base_ok = if (propose.base) |b|
        changes_by_id.contains(b)
    else
        false;
    const ancestry_ok = cand_ok and base_ok;
    const scope = try scopeVerdict(allocator, propose, &changes_by_id, all_changes, ancestry_ok);

    if (fold.state == .accepted) {
        const acc = fold.terminal.?;
        const oh = acc.observed_head orelse return .{ .name = "invalid", .scope = scope };
        if (cand_ok and stream_known and store.optStrEql(oh, target_head)) {
            return .{ .name = "accepted", .scope = scope };
        }
        return .{ .name = "accepted_stale", .scope = scope };
    }
    if (fold.state == .superseded) return .{ .name = "superseded", .scope = scope };
    if (fold.state == .withdrawn) return .{ .name = "withdrawn", .scope = scope };
    if (fold.state != .proposed) return .{ .name = "invalid", .scope = scope };

    // Live proposal: completeness, then a dry merge, then freshness (§5).
    if (!ancestry_ok or !stream_known) {
        return .{ .name = "incomplete", .scope = scope };
    }
    switch (try contentLeg(allocator, fs, root, propose.work, propose.snapshot, &changes_by_id)) {
        .verified => {},
        .incomplete => return .{ .name = "incomplete", .scope = scope },
        .invalid => return .{ .name = "invalid", .scope = scope },
    }
    const head = target_head orelse return .{ .name = "incomplete", .scope = scope };
    const conflicts = dryMergeConflicts(allocator, head, candidate, &changes_by_id, all_changes) catch {
        return .{ .name = "incomplete", .scope = scope };
    };
    if (conflicts) return .{ .name = "conflicting", .scope = scope };
    if (!store.optStrEql(head, propose.base)) {
        return .{ .name = "stale", .scope = scope };
    }
    return .{ .name = "ready", .scope = scope };
}

fn cmdInspect(
    allocator: Allocator,
    fs: FS,
    root: []const u8,
    out: *Io.Writer,
    args: []const []const u8,
) !u8 {
    var handoff_id: []const u8 = "";
    for (args) |a| {
        if (std.mem.startsWith(u8, a, "-")) return fsys.refuse("usage", "");
        if (handoff_id.len > 0) return fsys.refuse("usage", "");
        handoff_id = a;
    }
    if (handoff_id.len == 0 or uuid.parseUUID(handoff_id) == null) {
        return fsys.refuse("usage", "");
    }

    var idx = try store.loadStoreIndex(allocator, fs, root);
    defer idx.deinit();

    const found = try findEntries(allocator, fs, root, handoff_id, null);
    defer {
        if (found.stream_id) |s| allocator.free(s);
        freeEntries(allocator, found.entries);
    }
    if (found.entries.len == 0) {
        return fsys.refuse("handoff_missing", handoff_id);
    }
    const stream_id = found.stream_id orelse blk: {
        // Only unattributable/unknown-version lines matched — attribute the
        // verdict to the log filename they were found under.
        break :blk try allocator.dupe(u8, "");
    };
    defer if (found.stream_id == null) allocator.free(stream_id);

    var fold = try foldEntries(allocator, found.entries);
    defer fold.deinit(allocator);

    const verdict = if (stream_id.len > 0)
        try computeVerdict(allocator, fs, root, &idx, stream_id, found.entries, &fold)
    else
        Verdict{ .name = if (fold.unknown_count == found.entries.len) "unknown" else "invalid" };

    const propose = fold.propose;
    const state_name = switch (fold.state) {
        .none => if (fold.unknown_count == found.entries.len) "unknown" else "invalid",
        .proposed => "proposed",
        .accepted => "accepted",
        .superseded => "superseded",
        .withdrawn => "withdrawn",
    };

    const base = if (propose) |p| (p.base orelse "none") else "none";
    const candidate = if (propose) |p| (p.candidate orelse "none") else "none";
    const observed = if (fold.terminal != null and std.mem.eql(u8, fold.terminal.?.kind, "accept"))
        fold.terminal.?.observed_head orelse "none"
    else
        "none";
    const snapshot = if (propose) |p| (p.snapshot orelse "none") else "none";
    const work = if (propose) |p| (p.work orelse "") else "";

    const work_label = if (work.len > 0) streamLabel(&idx, work) else "none";
    try out.print(
        "flint: handoff {s} state={s} verdict={s} stream={s} work={s}\n",
        .{ handoff_id, state_name, verdict.name, streamLabel(&idx, stream_id), work_label },
    );
    try out.print(
        "flint: handoff {s} base={s} candidate={s} observed_head={s} snapshot={s} scope={s}\n",
        .{ handoff_id, base, candidate, observed, snapshot, verdict.scope },
    );
    if (fold.extra_records > 0 or fold.unknown_count > 0) {
        try out.print(
            "flint: handoff {s} extra_records={d} unknown_records={d}\n",
            .{ handoff_id, fold.extra_records, fold.unknown_count },
        );
    }

    var recs_json: std.ArrayList(u8) = .empty;
    defer recs_json.deinit(allocator);
    if (report.active != null) try recs_json.append(allocator, '[');
    var recs_listed: usize = 0;

    var vals_json: std.ArrayList(u8) = .empty;
    defer vals_json.deinit(allocator);
    if (report.active != null) try vals_json.append(allocator, '[');
    var vals_listed: usize = 0;

    for (found.entries) |*e| {
        switch (e.status) {
            .unknown_version => continue,
            .invalid => {
                try out.print(
                    "flint: record {s} kind={s} author={s} sig=invalid\n",
                    .{
                        e.id orelse "?",
                        e.kind orelse "?",
                        shortAuthor(e.author orelse ""),
                    },
                );
            },
            .ok => {
                const r = &e.record.?;
                const ok = ed25519.verifyHandoff(allocator, r) catch false;
                try out.print(
                    "flint: record {s} kind={s} author={s} sig={s}\n",
                    .{ r.id, r.kind, shortAuthor(r.author), if (ok) "verified" else "invalid" },
                );
                if (report.active != null) {
                    if (recs_listed > 0) try recs_json.append(allocator, ',');
                    try recs_json.appendSlice(allocator, "{\"id\":");
                    try report.escapeInto(&recs_json, allocator, r.id);
                    try recs_json.appendSlice(allocator, ",\"kind\":");
                    try report.escapeInto(&recs_json, allocator, r.kind);
                    try recs_json.appendSlice(allocator, ",\"author\":");
                    try report.escapeInto(&recs_json, allocator, r.author);
                    try recs_json.appendSlice(allocator, ",\"sig\":");
                    try report.escapeInto(&recs_json, allocator, if (ok) "verified" else "invalid");
                    try recs_json.append(allocator, '}');
                    recs_listed += 1;
                }

                for (r.validations) |v| {
                    const via: []const u8 = if (std.mem.eql(u8, r.kind, "propose")) "propose" else "attest";
                    const cmd_text = try boundedText(allocator, v.command);
                    defer allocator.free(cmd_text);
                    try out.print(
                        "flint: validation via={s} attestor={s} result={s} command={s}\n",
                        .{ via, shortAuthor(v.attestor), v.result, cmd_text },
                    );
                    if (report.active != null) {
                        if (vals_listed > 0) try vals_json.append(allocator, ',');
                        try vals_json.appendSlice(allocator, "{\"via\":");
                        try report.escapeInto(&vals_json, allocator, via);
                        try vals_json.appendSlice(allocator, ",\"attestor\":");
                        try report.escapeInto(&vals_json, allocator, v.attestor);
                        try vals_json.appendSlice(allocator, ",\"result\":");
                        try report.escapeInto(&vals_json, allocator, v.result);
                        try vals_json.appendSlice(allocator, ",\"command\":");
                        try report.escapeInto(&vals_json, allocator, v.command);
                        try vals_json.append(allocator, '}');
                        vals_listed += 1;
                    }
                }
            },
        }
    }

    if (report.active) |r| {
        try r.setScope(null, streamLabel(&idx, stream_id));
        try r.fieldStr("id", handoff_id);
        try r.fieldStr("state", state_name);
        try r.fieldStr("verdict", verdict.name);
        try r.fieldStr("stream", streamLabel(&idx, stream_id));
        try r.fieldOptStrOmitNull("work", if (work.len > 0) streamLabel(&idx, work) else null);
        if (propose) |p| {
            try r.fieldOptStrOmitNull("base", p.base);
            try r.fieldOptStrOmitNull("candidate", p.candidate);
            try r.fieldOptStrOmitNull("snapshot", p.snapshot);
            try r.fieldOptStrOmitNull("intent", p.intent);
        }
        try r.fieldStr("scope", verdict.scope);
        try r.fieldInt("extra_records", fold.extra_records);
        try r.fieldInt("unknown_records", fold.unknown_count);
        try recs_json.append(allocator, ']');
        try r.fieldRaw("records", recs_json.items);
        try vals_json.append(allocator, ']');
        try r.fieldRaw("validations", vals_json.items);
    }
    return 0;
}

// -- standalone verify ----------------------------------------------------------

/// Implements `flint handoff verify <file>` — standalone, no store, nothing
/// written (§8). Accepts a bare NDJSON record file (every line a record) or a
/// `FLINT-HANDOFF-PACKET/1` packet whose bundled Changes verify too.
pub fn cmdVerifyFile(
    allocator: Allocator,
    fs: FS,
    out: *Io.Writer,
    args: []const []const u8,
) !u8 {
    if (args.len != 1 or args[0].len == 0 or std.mem.startsWith(u8, args[0], "-")) {
        return fsys.refuse("usage", "");
    }
    const data = try fs.readFile(allocator, fsys.cleanMemPath(args[0]), store.MaxFileReadBytes);
    defer allocator.free(data);
    if (data.len == 0) {
        return fsys.refuse("handoff_malformed", "");
    }
    const lines = try store.readHandoffLines(allocator, data);
    defer allocator.free(lines);
    if (lines.len == 0) {
        return fsys.refuse("handoff_malformed", "");
    }

    var rc: u8 = 0;
    var verified: usize = 0;
    var failed: usize = 0;
    var listed: usize = 0;
    var recs_json: std.ArrayList(u8) = .empty;
    defer recs_json.deinit(allocator);
    if (report.active != null) try recs_json.append(allocator, '[');

    var changes_json: std.ArrayList(u8) = .empty;
    defer changes_json.deinit(allocator);
    var changes_listed: usize = 0;

    const first_format = json.peekHandoffFormat(allocator, lines[0]) catch null;
    defer if (first_format) |f| allocator.free(f);
    const is_packet = first_format != null and
        std.mem.eql(u8, first_format.?, packet_format);

    var start: usize = 0;
    var want_records: ?usize = null;
    var want_changes: ?usize = null;
    var work_id: ?[]u8 = null;
    defer if (work_id) |w| allocator.free(w);

    if (is_packet) {
        const parsed = std.json.parseFromSlice(std.json.Value, allocator, lines[0], .{}) catch {
            return fsys.refuse("handoff_malformed", "packet header");
        };
        defer parsed.deinit();
        if (parsed.value != .object) return fsys.refuse("handoff_malformed", "packet header");
        const obj = parsed.value.object;
        const records_v = obj.get("records") orelse return fsys.refuse("handoff_malformed", "packet header");
        const changes_v = obj.get("changes") orelse return fsys.refuse("handoff_malformed", "packet header");
        if (records_v != .integer or changes_v != .integer or
            records_v.integer < 0 or changes_v.integer < 0)
        {
            return fsys.refuse("handoff_malformed", "packet header");
        }
        want_records = @intCast(records_v.integer);
        want_changes = @intCast(changes_v.integer);
        if (obj.get("work")) |wv| {
            if (wv == .object) {
                if (wv.object.get("id")) |wiv| {
                    if (wiv == .string) work_id = try allocator.dupe(u8, wiv.string);
                }
            }
        }
        start = 1;
        if (lines.len - 1 != want_records.? + want_changes.?) {
            return fsys.refuse("handoff_malformed", "count mismatch");
        }
        if (want_records.? == 0) return fsys.refuse("handoff_malformed", "packet header");
    }

    const n_records = want_records orelse lines.len;
    if (lines.len - start < n_records) {
        return fsys.refuse("handoff_malformed", "count mismatch");
    }

    for (lines[start .. start + n_records]) |line| {
        const rec = json.parseHandoffRecord(allocator, line) catch |err| {
            return err;
        };
        defer rec.deinit(allocator);
        const ok = ed25519.verifyHandoff(allocator, &rec) catch false;
        if (ok) {
            verified += 1;
            try out.print("flint: record {s} kind={s} sig: verified\n", .{ rec.id, rec.kind });
        } else {
            failed += 1;
            rc = 1;
            try out.print("flint: record {s} kind={s} sig_invalid\n", .{ rec.id, rec.kind });
        }
        if (report.active != null and listed < report.MaxListEntries) {
            if (listed > 0) try recs_json.append(allocator, ',');
            try recs_json.appendSlice(allocator, "{\"id\":");
            try report.escapeInto(&recs_json, allocator, rec.id);
            try recs_json.appendSlice(allocator, ",\"kind\":");
            try report.escapeInto(&recs_json, allocator, rec.kind);
            try recs_json.appendSlice(allocator, ",\"sig\":");
            try report.escapeInto(&recs_json, allocator, if (ok) "verified" else "sig_invalid");
            try recs_json.append(allocator, '}');
            listed += 1;
        }
    }

    for (lines[start + n_records ..]) |line| {
        const c = json.parseChange(allocator, line) catch |err| {
            return err;
        };
        defer c.deinit(allocator);
        // A packet's detached Changes must belong to the work stream (§7).
        if (work_id) |w| {
            if (!std.mem.eql(u8, c.stream, w)) {
                return fsys.refuse("handoff_malformed", "work mismatch");
            }
        }
        const ok = ed25519.verifyChange(allocator, &c) catch false;
        if (ok) {
            verified += 1;
            try out.print("flint: verify {s} sig: verified\n", .{c.id});
        } else {
            failed += 1;
            rc = 1;
            try out.print("flint: verify {s} sig_invalid\n", .{c.id});
        }
        if (report.active != null) {
            if (changes_listed > 0) try changes_json.append(allocator, ',');
            try changes_json.appendSlice(allocator, "{\"id\":");
            try report.escapeInto(&changes_json, allocator, c.id);
            try changes_json.appendSlice(allocator, ",\"sig\":");
            try report.escapeInto(&changes_json, allocator, if (ok) "verified" else "sig_invalid");
            try changes_json.append(allocator, '}');
            changes_listed += 1;
        }
    }

    if (report.active) |r| {
        r.setKind(if (rc == 0) .ok else .failed);
        try r.fieldInt("verified", verified);
        try r.fieldInt("failed", failed);
        try recs_json.append(allocator, ']');
        try r.fieldRaw("records", recs_json.items);
        if (is_packet) {
            try changes_json.append(allocator, ']');
            try r.fieldRaw("changes", changes_json.items);
        }
    }
    return rc;
}

// -- portable transfer (§7) ----------------------------------------------------

/// Raw Change lines of `stream_id`'s log in file order (absent → empty).
/// Local copy of the sync layer's helper — the operations layer must not
/// import sync.zig.
fn streamRawLines(allocator: Allocator, fs: FS, root: []const u8, stream_id: []const u8) ![][]u8 {
    const p = try store.streamLogPath(allocator, root, stream_id);
    defer allocator.free(p);
    if (!fs.exists(allocator, p)) {
        return try allocator.alloc([]u8, 0);
    }
    const b = try fs.readFile(allocator, p, store.MaxFileReadBytes);
    defer allocator.free(b);
    const lines = try store.readJSONLLines(allocator, b);
    defer allocator.free(lines);
    var out: std.ArrayList([]u8) = .empty;
    errdefer {
        for (out.items) |l| allocator.free(l);
        out.deinit(allocator);
    }
    for (lines) |line| {
        try out.append(allocator, try allocator.dupe(u8, line));
    }
    return out.toOwnedSlice(allocator);
}

fn freeRawLines(allocator: Allocator, lines: [][]u8) void {
    for (lines) |l| allocator.free(l);
    allocator.free(lines);
}

/// Refuses `store_too_large` when appending `extra` bytes to `log_path` would
/// push it past the file bound. Local copy of the sync layer's helper.
fn checkLogAppendBound(allocator: Allocator, fs: FS, log_path: []const u8, extra: usize) !void {
    var existing: usize = 0;
    if (fs.exists(allocator, log_path)) {
        const b = try fs.readFile(allocator, log_path, store.MaxFileReadBytes);
        defer allocator.free(b);
        existing = b.len;
    }
    if (existing + extra > store.MaxFileReadBytes) {
        return fsys.refuse("store_too_large", "file");
    }
}

/// Implements `flint handoff export <handoff-id> --out=<file> [--with-changes]`
/// — writes the §7 packet: a header line, the proposal's record lines
/// byte-verbatim in append order, then (with `--with-changes`) the
/// candidate's first-parent ancestry from the work stream's log under
/// deposit-batch ordering. `--out=-` streams the packet to stdout and puts
/// the ok line on stderr.
fn cmdExport(
    allocator: Allocator,
    fs: FS,
    root: []const u8,
    out: *Io.Writer,
    err_w: *Io.Writer,
    args: []const []const u8,
) !u8 {
    var handoff_id: []const u8 = "";
    var out_flag: []const u8 = "";
    var with_changes = false;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.startsWith(u8, a, "--out=")) {
            out_flag = a["--out=".len..];
        } else if (std.mem.eql(u8, a, "--out") and i + 1 < args.len) {
            i += 1;
            out_flag = args[i];
        } else if (std.mem.eql(u8, a, "--with-changes")) {
            with_changes = true;
        } else if (handoff_id.len == 0 and !std.mem.startsWith(u8, a, "-")) {
            handoff_id = a;
        } else {
            return fsys.refuse("usage", "");
        }
    }
    if (handoff_id.len == 0 or uuid.parseUUID(handoff_id) == null or
        out_flag.len == 0)
    {
        return fsys.refuse("usage", "");
    }

    // Locate the proposal: the first log holding a valid record for the id
    // owns it; only well-formed records can ride a packet (§1.5 rules 1–4).
    const found = try findEntries(allocator, fs, root, handoff_id, null);
    defer {
        freeEntries(allocator, found.entries);
        if (found.stream_id) |s| allocator.free(s);
    }
    const owner_id = found.stream_id orelse
        return fsys.refuse("handoff_missing", handoff_id);

    var log = try loadLog(allocator, fs, root, owner_id);
    defer log.deinit();
    var rec_lines: std.ArrayList([]const u8) = .empty;
    defer rec_lines.deinit(allocator);
    var propose: ?*const store.HandoffRecord = null;
    for (log.entries) |*e| {
        if (e.status != .ok) continue;
        const h = e.handoff orelse continue;
        if (!std.mem.eql(u8, h, handoff_id)) continue;
        try rec_lines.append(allocator, e.line);
        if (propose == null and std.mem.eql(u8, e.record.?.kind, "propose")) {
            propose = &e.record.?;
        }
    }
    const prop = propose orelse return fsys.refuse("handoff_missing", handoff_id);
    const work_id = prop.work orelse
        return fsys.refuse("handoff_malformed", "work");

    var idx = try store.loadStoreIndex(allocator, fs, root);
    defer idx.deinit();
    const work_name = if (idx.streamByID(work_id)) |w| w.name else work_id;

    // Optional detached ancestry: the candidate's first-parent chain in the
    // work stream's log, parent-before-child (deposit-batch order, §7). Raw
    // log lines outlive this block — `change_lines` maps into them.
    var change_lines: std.ArrayList([]const u8) = .empty;
    defer change_lines.deinit(allocator);
    var work_raw: [][]u8 = &.{};
    defer if (work_raw.len > 0) freeRawLines(allocator, work_raw);
    if (with_changes) {
        const candidate = prop.candidate orelse
            return fsys.refuse("handoff_malformed", "candidate");
        var work_loaded = try store.loadStream(allocator, fs, root, work_id);
        defer work_loaded.deinit(allocator);
        work_raw = try streamRawLines(allocator, fs, root, work_id);
        var by_id = std.StringHashMap(usize).init(allocator);
        defer by_id.deinit();
        for (work_loaded.changes, 0..) |c, ci| try by_id.put(c.id, ci);
        if (by_id.get(candidate) == null) {
            return fsys.refuse("change_missing", candidate);
        }
        var chain: std.ArrayList(usize) = .empty;
        defer chain.deinit(allocator);
        var cur: ?[]const u8 = candidate;
        while (cur) |cid| {
            const ci = by_id.get(cid) orelse break;
            try chain.append(allocator, ci);
            cur = work_loaded.changes[ci].parent;
        }
        std.mem.reverse(usize, chain.items);
        for (chain.items) |ci| try change_lines.append(allocator, work_raw[ci]);
    }

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    try buf.appendSlice(allocator, "{\"format\":");
    try json.appendGoJSONString(&buf, allocator, packet_format);
    try buf.appendSlice(allocator, ",\"handoff\":");
    try json.appendGoJSONString(&buf, allocator, handoff_id);
    try buf.appendSlice(allocator, ",\"stream\":");
    try json.appendGoJSONString(&buf, allocator, owner_id);
    try buf.appendSlice(allocator, ",\"work\":{\"id\":");
    try json.appendGoJSONString(&buf, allocator, work_id);
    try buf.appendSlice(allocator, ",\"name\":");
    try json.appendGoJSONString(&buf, allocator, work_name);
    try buf.print(allocator, "}},\"records\":{d},\"changes\":{d}}}\n", .{
        rec_lines.items.len, change_lines.items.len,
    });
    for (rec_lines.items) |l| {
        try buf.appendSlice(allocator, l);
        try buf.append(allocator, '\n');
    }
    for (change_lines.items) |l| {
        try buf.appendSlice(allocator, l);
        try buf.append(allocator, '\n');
    }

    if (std.mem.eql(u8, out_flag, "-")) {
        try out.writeAll(buf.items);
        try err_w.print("flint: handoff export {s} records={d} changes={d} out=-\n", .{
            handoff_id, rec_lines.items.len, change_lines.items.len,
        });
    } else {
        try fs.writeFileSafe(allocator, fsys.cleanMemPath(out_flag), buf.items);
        try out.print("flint: handoff export {s} records={d} changes={d} out={s}\n", .{
            handoff_id, rec_lines.items.len, change_lines.items.len, out_flag,
        });
    }
    if (report.active) |r| {
        r.setKind(.ok);
        try r.fieldInt("records", rec_lines.items.len);
        try r.fieldInt("changes", change_lines.items.len);
        try r.fieldStr("out", out_flag);
    }
    return 0;
}

/// Implements `flint handoff import <file>` — §7: verifies the whole packet
/// before writing anything (record signatures and lifecycle legality, Change
/// signatures and detached-ancestry rules), then per section, all-or-nothing:
/// appends the missing Change lines to `streams/<work>.jsonl` under deposit
/// discipline — the head never moves — creating the work stream record from
/// the header when absent and ancestry permits — and appends the missing
/// record lines to `handoffs/<target>.jsonl`. Dedupe by id applies to both
/// sections; re-import of the same packet is a no-op.
fn cmdImport(
    allocator: Allocator,
    fs: FS,
    root: []const u8,
    uuid_gen: *uuid.UUIDGen,
    out: *Io.Writer,
    args: []const []const u8,
) !u8 {
    if (args.len != 1 or args[0].len == 0 or std.mem.startsWith(u8, args[0], "-")) {
        return fsys.refuse("usage", "");
    }
    const data = try fs.readFile(allocator, fsys.cleanMemPath(args[0]), store.MaxFileReadBytes);
    defer allocator.free(data);
    const lines = try store.readHandoffLines(allocator, data);
    defer allocator.free(lines);
    if (lines.len == 0) return fsys.refuse("handoff_malformed", "empty");

    // Header — parsed, never byte-matched (§7).
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, lines[0], .{}) catch {
        return fsys.refuse("handoff_malformed", "packet header");
    };
    defer parsed.deinit();
    if (parsed.value != .object) return fsys.refuse("handoff_malformed", "packet header");
    const obj = parsed.value.object;
    const fmt_ok = if (obj.get("format")) |fv|
        fv == .string and std.mem.eql(u8, fv.string, packet_format)
    else
        false;
    if (!fmt_ok) return fsys.refuse("handoff_malformed", "packet header");
    const handoff_id = if (obj.get("handoff")) |v|
        if (v == .string) v.string else ""
    else
        "";
    const target_id = if (obj.get("stream")) |v|
        if (v == .string) v.string else ""
    else
        "";
    if (uuid.parseUUID(handoff_id) == null or uuid.parseUUID(target_id) == null) {
        return fsys.refuse("handoff_malformed", "packet header");
    }
    var work_id: []const u8 = "";
    var work_name: []const u8 = "";
    if (obj.get("work")) |wv| {
        if (wv == .object) {
            if (wv.object.get("id")) |iv| {
                if (iv == .string) work_id = iv.string;
            }
            if (wv.object.get("name")) |nv| {
                if (nv == .string) work_name = nv.string;
            }
        }
    }
    const n_records: usize = if (obj.get("records")) |v|
        if (v == .integer and v.integer >= 0) @intCast(v.integer) else 0
    else
        0;
    const n_changes: usize = if (obj.get("changes")) |v|
        if (v == .integer and v.integer >= 0) @intCast(v.integer) else 0
    else
        0;
    if (n_records == 0 or lines.len - 1 != n_records + n_changes) {
        return fsys.refuse("handoff_malformed", "count mismatch");
    }
    const rec_lines = lines[1 .. 1 + n_records];
    const ch_lines = lines[1 + n_records ..];

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const aa = arena.allocator();

    // Verify before write (§0): parse, bind, and sign-check every record and
    // Change while the store is still untouched.
    const recs = try aa.alloc(store.HandoffRecord, n_records);
    for (rec_lines, 0..) |line, ri| {
        recs[ri] = try json.parseHandoffRecord(aa, line);
        const r = &recs[ri];
        if (!std.mem.eql(u8, r.stream, target_id) or
            !std.mem.eql(u8, r.handoff, handoff_id))
        {
            return fsys.refuse("handoff_malformed", "binding");
        }
        if (!try ed25519.verifyHandoff(aa, r)) {
            return fsys.refuse("sig_invalid", "handoff");
        }
    }

    const changes = try aa.alloc(store.Change, n_changes);
    for (ch_lines, 0..) |line, ci| {
        changes[ci] = try json.parseChange(aa, line);
        const c = &changes[ci];
        // A packet's detached Changes must belong to the work stream (§7).
        if (work_id.len == 0 or !std.mem.eql(u8, c.stream, work_id)) {
            return fsys.refuse("handoff_malformed", "work mismatch");
        }
        if (!try ed25519.verifyChange(aa, c)) {
            return fsys.refuse("sig_invalid", "change");
        }
    }

    var idx = try store.loadStoreIndex(allocator, fs, root);
    defer idx.deinit();
    // The target stream must exist locally — records are claims on a stream
    // the receiver holds (§7).
    const target = idx.streamByID(target_id) orelse
        return fsys.refuse("stream_missing", target_id);

    // -- Change section: deposit rules against the work stream's log --------
    var work_loaded: ?store.LoadedStream = null;
    if (work_id.len > 0) {
        work_loaded = store.loadStream(allocator, fs, root, work_id) catch |err| blk: {
            if (err == error.Refuse and
                std.mem.eql(u8, fsys.last_refuse.code(), "stream_missing"))
            {
                break :blk null;
            }
            return err;
        };
    }
    defer if (work_loaded) |*wl| wl.deinit(allocator);

    var ch_by_id = std.StringHashMap([]const u8).init(allocator);
    defer ch_by_id.deinit();
    var ch_known = std.StringHashMap(void).init(allocator);
    defer ch_known.deinit();
    var work_head: ?[]const u8 = null;
    // Raw log lines outlive this block — `ch_by_id` maps into them for the
    // byte-identical dedupe comparison. Seed from the log itself rather than
    // the stream record: a `streams/<work>.jsonl` can outlive a missing
    // record (crash between append and record write on a previous import).
    var work_raw: [][]u8 = &.{};
    defer if (work_raw.len > 0) freeRawLines(allocator, work_raw);
    if (work_id.len > 0) {
        work_raw = try streamRawLines(allocator, fs, root, work_id);
        for (work_raw) |line| {
            const lc = try json.parseChange(aa, line);
            try ch_by_id.put(lc.id, line);
            try ch_known.put(lc.id, {});
        }
    }
    if (work_loaded) |*wl| {
        if (wl.stream.forked_from) |ff| try ch_known.put(ff.change, {});
        work_head = wl.stream.head;
    }

    // The bundle-import trick (§7): with no local work stream the first
    // bundled Change's parent resolves the fork — a held log's Change id
    // becomes `forked_from`, a null parent is genesis — or import refuses;
    // anything else would leave ancestry broken. The fork point counts as
    // known content for the deposit rules below.
    var new_stream: ?store.Stream = null;
    defer if (new_stream) |ns| ns.deinit(allocator);
    if (work_loaded == null and ch_lines.len > 0) {
        var forked_from: ?store.ForkOrigin = null;
        if (changes[0].parent) |p| {
            const all_changes = try store.loadAllStreamChanges(allocator, fs, root, &idx);
            defer store.freeChanges(allocator, all_changes);
            var origin: ?[]const u8 = null;
            for (all_changes) |c| {
                if (std.mem.eql(u8, c.id, p)) origin = c.stream;
            }
            const os = origin orelse
                return fsys.refuse("change_malformed", "detached parent unknown");
            const fs_dup = try allocator.dupe(u8, os);
            errdefer allocator.free(fs_dup);
            const fc_dup = try allocator.dupe(u8, p);
            forked_from = .{ .stream = fs_dup, .change = fc_dup };
            try ch_known.put(p, {});
        }
        const nid = try allocator.dupe(u8, work_id);
        errdefer allocator.free(nid);
        const nname = try allocator.dupe(
            u8,
            if (work_name.len > 0) work_name else work_id,
        );
        errdefer allocator.free(nname);
        new_stream = .{
            .id = nid,
            .name = nname,
            .head = null,
            .created = try uuid_gen.nowMs(),
            .forked_from = forked_from,
        };
    }

    var ch_buf: std.ArrayList(u8) = .empty;
    defer ch_buf.deinit(allocator);
    var ch_stored: usize = 0;
    for (ch_lines, 0..) |line, ci| {
        const c = &changes[ci];
        if (ch_by_id.get(c.id)) |existing| {
            if (!std.mem.eql(u8, existing, line)) {
                return fsys.refuse("change_malformed", "id conflict");
            }
            continue;
        }
        // An existing stream takes deposits only — a line extending the head
        // is an append, not a deposit. An absent stream has no head; its
        // first line's parent supplied the fork data above (or genesis null).
        if (work_loaded != null and store.optStrEql(c.parent, work_head)) {
            return fsys.refuse("change_malformed", "extends head");
        }
        if (c.parent) |p| {
            if (!ch_known.contains(p)) {
                return fsys.refuse("change_malformed", "detached parent unknown");
            }
        }
        try ch_by_id.put(c.id, line);
        try ch_known.put(c.id, {});
        try ch_buf.appendSlice(allocator, line);
        try ch_buf.append(allocator, '\n');
        ch_stored += 1;
    }

    // -- Record section: dedupe + lifecycle against the growing log ---------
    var log = try loadLog(allocator, fs, root, target.id);
    defer log.deinit();
    // Simulated log: the stored entries followed by the records this import
    // would append. Element copies share the log's and arena's storage; only
    // the array itself is owned here.
    var sim: std.ArrayList(LogEntry) = .empty;
    defer sim.deinit(allocator);
    try sim.appendSlice(allocator, log.entries);

    var rec_buf: std.ArrayList(u8) = .empty;
    defer rec_buf.deinit(allocator);
    var rec_stored: usize = 0;
    for (rec_lines, 0..) |line, ri| {
        const r = &recs[ri];
        var dup = false;
        for (sim.items) |e| {
            if (e.record) |old| {
                if (std.mem.eql(u8, old.id, r.id)) {
                    // §7 dedupe — byte-identical lines skip regardless of
                    // kind; the same id under different bytes is a conflict.
                    if (!std.mem.eql(u8, e.line, line)) {
                        return fsys.refuse("handoff_malformed", "id conflict");
                    }
                    dup = true;
                }
            }
        }
        if (dup) continue;
        try checkEventLifecycle(sim.items, r);
        try sim.append(allocator, .{
            .line = line,
            .handoff = r.handoff,
            .status = .ok,
            .record = r.*,
        });
        try rec_buf.appendSlice(allocator, line);
        try rec_buf.append(allocator, '\n');
        rec_stored += 1;
    }

    // Bounds are part of verify-before-write: check before any append.
    if (idx.change_count + ch_stored > store.MaxChanges) {
        return fsys.refuse("store_too_large", "changes");
    }
    if (log.entries.len + rec_stored > store.MaxHandoffRecords) {
        return fsys.refuse("store_too_large", "handoffs");
    }
    const ch_log_path = try store.streamLogPath(allocator, root, work_id);
    defer allocator.free(ch_log_path);
    try checkLogAppendBound(allocator, fs, ch_log_path, ch_buf.items.len);
    const rec_log_path = try store.handoffLogPath(allocator, root, target.id);
    defer allocator.free(rec_log_path);
    try checkLogAppendBound(allocator, fs, rec_log_path, rec_buf.items.len);

    if (report.active) |r| r.beginLocalWrites();
    if (new_stream) |ns| {
        try store.writeStreamRecord(allocator, fs, root, ns);
    }
    if (ch_stored > 0) {
        try fs.appendSync(allocator, ch_log_path, ch_buf.items);
    }
    if (rec_stored > 0) {
        try fs.appendSync(allocator, rec_log_path, rec_buf.items);
    }
    if (report.active) |r| r.localApplied();

    try out.print("flint: handoff import {s} records={d} changes={d}\n", .{
        handoff_id, rec_stored, ch_stored,
    });
    if (report.active) |r| {
        r.setKind(.ok);
        try r.fieldInt("records", rec_stored);
        try r.fieldInt("changes", ch_stored);
    }
    return 0;
}

/// Implements the `flint handoff <sub>` verb family (§8).
pub fn cmdHandoff(
    allocator: Allocator,
    fs: FS,
    root: []const u8,
    uuid_gen: *uuid.UUIDGen,
    env_sign_key: ?[]const u8,
    out: *Io.Writer,
    err_w: *Io.Writer,
    args: []const []const u8,
) !u8 {
    if (args.len == 0) return fsys.refuse("usage", "");
    const sub = args[0];
    const rest = args[1..];
    if (std.mem.eql(u8, sub, "export")) {
        return cmdExport(allocator, fs, root, out, err_w, rest);
    }
    if (std.mem.eql(u8, sub, "import")) {
        return cmdImport(allocator, fs, root, uuid_gen, out, rest);
    }
    if (std.mem.eql(u8, sub, "propose")) {
        return cmdPropose(allocator, fs, root, uuid_gen, env_sign_key, out, rest);
    }
    if (std.mem.eql(u8, sub, "attest") or std.mem.eql(u8, sub, "accept") or
        std.mem.eql(u8, sub, "supersede") or std.mem.eql(u8, sub, "withdraw"))
    {
        return cmdEvent(allocator, fs, root, uuid_gen, env_sign_key, out, sub, rest);
    }
    if (std.mem.eql(u8, sub, "list")) {
        return cmdList(allocator, fs, root, out, rest);
    }
    if (std.mem.eql(u8, sub, "inspect")) {
        return cmdInspect(allocator, fs, root, out, rest);
    }
    if (std.mem.eql(u8, sub, "verify")) {
        return cmdVerifyFile(allocator, fs, out, rest);
    }
    return fsys.refuse("usage", "");
}

// ---------------------------------------------------------------------------
// Conformance fixtures (testdata/handoffs/, spec conformance matrix)

fn readFixture(gpa: Allocator, fs: FS, name: []const u8) ![]u8 {
    const path = try std.fmt.allocPrint(gpa, "testdata/handoffs/{s}", .{name});
    defer gpa.free(path);
    return fs.readFile(gpa, path, store.MaxFileReadBytes);
}

test "handoff fixtures: golden records round-trip byte-identically and verify" {
    const gpa = std.testing.allocator;
    var host_fs = fsys.HostFS.init(std.testing.io);
    const fs = host_fs.fs();

    for ([_][]const u8{ "propose.json", "attest.json", "accept.json", "supersede.json", "withdraw.json" }) |name| {
        const raw = try readFixture(gpa, fs, name);
        defer gpa.free(raw);
        const rec = try json.parseHandoffRecord(gpa, raw[0 .. raw.len - 1]);
        defer rec.deinit(gpa);
        try std.testing.expect(try ed25519.verifyHandoff(gpa, &rec));
        const reemit = try json.marshalHandoffRecord(gpa, rec);
        defer gpa.free(reemit);
        try std.testing.expectEqualStrings(raw, reemit);
    }
}

test "handoff fixtures: preimage vector pins the canonical handoff_msg" {
    const gpa = std.testing.allocator;
    var host_fs = fsys.HostFS.init(std.testing.io);
    const fs = host_fs.fs();

    const raw = try readFixture(gpa, fs, "propose.json");
    defer gpa.free(raw);
    const rec = try json.parseHandoffRecord(gpa, raw[0 .. raw.len - 1]);
    defer rec.deinit(gpa);
    const msg = try ed25519.handoffMsg(gpa, &rec);
    defer gpa.free(msg);

    const hex_raw = try readFixture(gpa, fs, "preimage.hex");
    defer gpa.free(hex_raw);
    const hex = std.mem.trim(u8, hex_raw, " \t\r\n");
    const want = try gpa.alloc(u8, hex.len / 2);
    defer gpa.free(want);
    _ = try std.fmt.hexToBytes(want, hex);
    try std.testing.expectEqualSlices(u8, want, msg);
}

test "handoff fixtures: tampered sig parses but fails verification; attestor mismatch and unknown format refuse" {
    const gpa = std.testing.allocator;
    var host_fs = fsys.HostFS.init(std.testing.io);
    const fs = host_fs.fs();

    {
        const raw = try readFixture(gpa, fs, "tampered.json");
        defer gpa.free(raw);
        const rec = try json.parseHandoffRecord(gpa, raw[0 .. raw.len - 1]);
        defer rec.deinit(gpa);
        try std.testing.expect(!(try ed25519.verifyHandoff(gpa, &rec)));
    }
    {
        const raw = try readFixture(gpa, fs, "attestor-mismatch.json");
        defer gpa.free(raw);
        try std.testing.expectError(
            error.Refuse,
            json.parseHandoffRecord(gpa, raw[0 .. raw.len - 1]),
        );
    }
    {
        const raw = try readFixture(gpa, fs, "unknown-version.json");
        defer gpa.free(raw);
        try std.testing.expectError(
            error.Refuse,
            json.parseHandoffRecord(gpa, raw[0 .. raw.len - 1]),
        );
    }
    {
        const raw = try readFixture(gpa, fs, "torn.jsonl");
        defer gpa.free(raw);
        try std.testing.expectError(error.Refuse, store.readHandoffLines(gpa, raw));
    }
}

test "handoff log: torn final line refuses handoff_torn, unknown versions classify without refusing" {
    const gpa = std.testing.allocator;
    var mem = try fsys.MemFS.init(gpa);
    defer mem.deinit();
    const mfs = mem.fs();

    var host_fs = fsys.HostFS.init(std.testing.io);
    const hfs = host_fs.fs();
    const propose = try readFixture(gpa, hfs, "propose.json");
    defer gpa.free(propose);
    const unknown = try readFixture(gpa, hfs, "unknown-version.json");
    defer gpa.free(unknown);
    const stream_id = "019a0000-0001-7000-8000-0000000000aa";

    // A log mixing /1 records and a future format loads: /9 classified, not
    // refused, and excluded from lifecycle folds.
    const log_path = try store.handoffLogPath(gpa, "/store", stream_id);
    defer gpa.free(log_path);
    try mfs.appendSync(gpa, log_path, propose);
    try mfs.appendSync(gpa, log_path, unknown);

    const log = try loadLog(gpa, mfs, "/store", stream_id);
    defer log.deinit();
    try std.testing.expectEqual(@as(usize, 2), log.entries.len);
    try std.testing.expectEqual(.ok, log.entries[0].status);
    try std.testing.expectEqual(.unknown_version, log.entries[1].status);

    // Truncate the final newline → torn.
    const torn_path = try store.handoffLogPath(gpa, "/store2", stream_id);
    defer gpa.free(torn_path);
    try mfs.appendSync(gpa, torn_path, propose[0 .. propose.len - 1]);
    try std.testing.expectError(error.Refuse, loadLog(gpa, mfs, "/store2", stream_id));
}

test "handoff record parse: per-kind requiredness and exclusivity enforced" {
    const gpa = std.testing.allocator;

    // propose without intent → malformed.
    try std.testing.expectError(error.Refuse, json.parseHandoffRecord(gpa,
        \\{"format":"FLINT-HANDOFF/1","id":"019a0000-0006-7000-8000-000000000010","handoff":"019a0000-0006-7000-8000-000000000010","kind":"propose","stream":"019a0000-0001-7000-8000-0000000000aa","ts":1,"author":"0000000000000000000000000000000000000000000000000000000000000000","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","base":"019a0000-0003-7000-8000-000000000001","work":"019a0000-0002-7000-8000-0000000000bb","candidate":"019a0000-0005-7000-8000-000000000003"}
    ));
    // handoff != id on a non-propose is fine, but a non-propose with id == its
    // own handoff... wait: handoff==id iff propose — a withdraw with id==handoff
    // violates rule 2.
    try std.testing.expectError(error.Refuse, json.parseHandoffRecord(gpa,
        \\{"format":"FLINT-HANDOFF/1","id":"019a0000-000c-7000-8000-000000000070","handoff":"019a0000-000c-7000-8000-000000000070","kind":"withdraw","stream":"019a0000-0001-7000-8000-0000000000aa","ts":1,"author":"0000000000000000000000000000000000000000000000000000000000000000","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"}
    ));
    // accept without observed_head → malformed.
    try std.testing.expectError(error.Refuse, json.parseHandoffRecord(gpa,
        \\{"format":"FLINT-HANDOFF/1","id":"019a0000-0008-7000-8000-000000000030","handoff":"019a0000-0006-7000-8000-000000000010","kind":"accept","stream":"019a0000-0001-7000-8000-0000000000aa","ts":1,"author":"0000000000000000000000000000000000000000000000000000000000000000","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","candidate":"019a0000-0005-7000-8000-000000000003"}
    ));
    // Unknown kind → malformed.
    try std.testing.expectError(error.Refuse, json.parseHandoffRecord(gpa,
        \\{"format":"FLINT-HANDOFF/1","id":"019a0000-0008-7000-8000-000000000031","handoff":"019a0000-0006-7000-8000-000000000010","kind":"bless","stream":"019a0000-0001-7000-8000-0000000000aa","ts":1,"author":"0000000000000000000000000000000000000000000000000000000000000000","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"}
    ));
}

test "handoff fold: terminal state freezes; extra records counted; attests accumulate" {
    const gpa = std.testing.allocator;
    var mem = try fsys.MemFS.init(gpa);
    defer mem.deinit();
    const mfs = mem.fs();

    var host_fs = fsys.HostFS.init(std.testing.io);
    const hfs = host_fs.fs();
    const propose = try readFixture(gpa, hfs, "propose.json");
    defer gpa.free(propose);
    const attest = try readFixture(gpa, hfs, "attest.json");
    defer gpa.free(attest);
    const accept = try readFixture(gpa, hfs, "accept.json");
    defer gpa.free(accept);
    const supersede = try readFixture(gpa, hfs, "supersede.json");
    defer gpa.free(supersede);

    const stream_id = "019a0000-0001-7000-8000-0000000000aa";
    const log_path = try store.handoffLogPath(gpa, "/store", stream_id);
    defer gpa.free(log_path);
    // propose + attest + accept, then a late attest and a stray supersede —
    // the fold stops at accept; later records count as extra.
    try mfs.appendSync(gpa, log_path, propose);
    try mfs.appendSync(gpa, log_path, attest);
    try mfs.appendSync(gpa, log_path, accept);
    try mfs.appendSync(gpa, log_path, attest);

    const found = try findEntries(gpa, mfs, "/store", "019a0000-0006-7000-8000-000000000010", null);
    defer {
        if (found.stream_id) |s| gpa.free(s);
        freeEntries(gpa, found.entries);
    }
    var fold = try foldEntries(gpa, found.entries);
    defer fold.deinit(gpa);
    try std.testing.expectEqual(ProposalState.accepted, fold.state);
    try std.testing.expectEqual(@as(usize, 1), fold.extra_records);
    try std.testing.expectEqual(@as(usize, 2), fold.attests.items.len);
}
