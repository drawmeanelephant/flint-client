//! Content sync for FLINT-SYNC/1 spec_rev 4 (docs/flint-blobs-spec.md §9):
//! `push` publishes signed snapshot manifests and the blobs they reference,
//! `pull`/`clone` fetch and verify them so a fresh receiver can `checkout`
//! complete source. Streams always replicate; content degrades explicitly —
//! a peer that does not announce `spec_rev >= 4`, or that refuses a content
//! op with `usage` (the pre-content unknown-op refusal), completes
//! history-only: the sync still succeeds, and `checkout` of synced revisions
//! refuses `blob_missing` rather than claiming a reproducible project.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Sha256 = std.crypto.hash.sha2.Sha256;

const fsys = @import("fsys.zig");
const FS = fsys.FS;
const store = @import("store.zig");
const json = @import("json.zig");
const ed25519 = @import("ed25519.zig");
const sync = @import("sync.zig");
const report = @import("report.zig");

/// Per-invocation content reconciliation tallies — surfaced in `--json` as
/// `data.content` (docs/flint-json-results-spec.md §6 reserves the key) and,
/// on degradation, as a one-line stderr note.
pub const ContentOutcome = struct {
    /// Manifest lines appended on the receiving side / stored on the remote.
    manifests: usize = 0,
    /// Blobs transferred (fetched or uploaded).
    blobs: usize = 0,
    /// Referenced blobs the sending side could not supply — absent or
    /// corrupt locally on push. Content stays honestly incomplete.
    missing: usize = 0,
    /// Manifest lines left untransferred: on pull they bind a Change outside
    /// the local log (history this client never received); on push the bound
    /// Change is unpublished (`change_missing`).
    skipped: usize = 0,
    degraded: bool = false,
    degraded_op: []const u8 = "",
    note_emitted: bool = false,
};

/// True when the peer's announced `spec_rev` covers the four content ops.
/// Absent or <4 means a pre-content server — the caller degrades rather than
/// probing (§9's old-peer contract).
fn remoteServesContent(client: *const sync.SyncClient) bool {
    const rev = client.server_spec_rev orelse return false;
    return rev >= 4;
}

fn degrade(outcome: *ContentOutcome, op: []const u8) void {
    outcome.degraded = true;
    if (outcome.degraded_op.len == 0) outcome.degraded_op = op;
}

/// `usage` on a content op is the pre-content server's generic unknown-op
/// refusal — degrade instead of failing the sync (§9). Other refusals and
/// transport errors propagate.
fn degradedByUsage(outcome: *ContentOutcome, op: []const u8, err: anyerror) bool {
    if (err == error.Refuse and std.mem.eql(u8, fsys.last_refuse.code(), "usage")) {
        degrade(outcome, op);
        return true;
    }
    return false;
}

// ---- client-side ops -------------------------------------------------------

/// `put_manifest` (§9): appends raw signed manifest lines to the remote
/// `manifests/<stream>.jsonl`; returns the server's `stored` count.
/// All-or-nothing per batch; byte-identical resends dedupe server-side.
pub fn putManifestLines(client: *sync.SyncClient, stream_id: []const u8, lines: []const []const u8) !usize {
    if (report.active) |r| r.remoteAttemptBegin();
    const stored = putManifestLinesImpl(client, stream_id, lines) catch |err| {
        client.noteRemoteResult(err);
        return err;
    };
    client.noteRemoteResult(null);
    return stored;
}

fn putManifestLinesImpl(client: *sync.SyncClient, stream_id: []const u8, lines: []const []const u8) !usize {
    const allocator = client.allocator;
    const seq = client.nextSeq();
    var req: std.ArrayList(u8) = .empty;
    defer req.deinit(allocator);
    try req.print(allocator, "{{\"op\":\"put_manifest\",\"seq\":{d},\"stream\":", .{seq});
    try json.appendGoJSONString(&req, allocator, stream_id);
    try req.appendSlice(allocator, ",\"lines\":[");
    for (lines, 0..) |line, i| {
        if (i > 0) try req.append(allocator, ',');
        try json.appendGoJSONString(&req, allocator, std.mem.trimEnd(u8, line, "\r\n"));
    }
    try req.appendSlice(allocator, "]}");

    var parsed = try client.sendAndParse(req.items);
    defer parsed.deinit();
    const obj = try client.checkResponseOk(parsed.value, seq);

    const stored_val = obj.get("stored") orelse return fsys.refuse("change_malformed", "");
    return switch (stored_val) {
        .integer => |i| if (i >= 0) @intCast(i) else fsys.refuse("change_malformed", ""),
        else => fsys.refuse("change_malformed", ""),
    };
}

/// `get_manifest` (§9): the remote manifest log for `stream_id`, verbatim
/// and in log order. `after` mirrors `read`'s cursor — null yields all.
pub fn getManifestLines(client: *sync.SyncClient, stream_id: []const u8, after: ?[]const u8) ![][]u8 {
    const allocator = client.allocator;
    const seq = client.nextSeq();
    var req: std.ArrayList(u8) = .empty;
    defer req.deinit(allocator);
    try req.print(allocator, "{{\"op\":\"get_manifest\",\"seq\":{d},\"stream\":", .{seq});
    try json.appendGoJSONString(&req, allocator, stream_id);
    try req.appendSlice(allocator, ",\"after\":");
    if (after) |a| {
        try json.appendGoJSONString(&req, allocator, a);
    } else {
        try req.appendSlice(allocator, "null");
    }
    try req.append(allocator, '}');

    var parsed = try client.sendAndParse(req.items);
    defer parsed.deinit();
    const obj = try client.checkResponseOk(parsed.value, seq);

    const lines_val = obj.get("lines") orelse return fsys.refuse("change_malformed", "");
    const lines_arr = switch (lines_val) {
        .array => |a| a,
        else => return fsys.refuse("change_malformed", ""),
    };
    var out: std.ArrayList([]u8) = .empty;
    errdefer {
        for (out.items) |l| allocator.free(l);
        out.deinit(allocator);
    }
    for (lines_arr.items) |item| {
        const s = switch (item) {
            .string => |str| str,
            else => return fsys.refuse("change_malformed", ""),
        };
        const clean = std.mem.trimEnd(u8, s, "\r\n");
        const copy = try allocator.dupe(u8, clean);
        errdefer allocator.free(copy);
        try out.append(allocator, copy);
    }
    return out.toOwnedSlice(allocator);
}

fn hexNibble(c: u8) ?u4 {
    return switch (c) {
        '0'...'9' => @intCast(c - '0'),
        'a'...'f' => @intCast(c - 'a' + 10),
        else => null,
    };
}

/// `blob_put` (§9): stores `bytes` remotely under content id `id`.
/// Content-addressed ⇒ idempotent; the server re-checks id = SHA-256(bytes).
pub fn putBlob(client: *sync.SyncClient, id: []const u8, bytes: []const u8) !void {
    if (report.active) |r| r.remoteAttemptBegin();
    putBlobImpl(client, id, bytes) catch |err| {
        client.noteRemoteResult(err);
        return err;
    };
    client.noteRemoteResult(null);
}

fn putBlobImpl(client: *sync.SyncClient, id: []const u8, bytes: []const u8) !void {
    const allocator = client.allocator;
    const seq = client.nextSeq();
    var req: std.ArrayList(u8) = .empty;
    defer req.deinit(allocator);
    try req.print(allocator, "{{\"op\":\"blob_put\",\"seq\":{d},\"id\":", .{seq});
    try json.appendGoJSONString(&req, allocator, id);
    try req.appendSlice(allocator, ",\"hex\":\"");
    const digits = "0123456789abcdef";
    for (bytes) |b| {
        try req.append(allocator, digits[b >> 4]);
        try req.append(allocator, digits[b & 0x0f]);
    }
    try req.appendSlice(allocator, "\"}");

    var parsed = try client.sendAndParse(req.items);
    defer parsed.deinit();
    _ = try client.checkResponseOk(parsed.value, seq);
}

/// `blob_get` (§9): fetches blob `id` and verifies SHA-256(bytes) == id
/// before returning the bytes — a substituted or corrupt payload refuses
/// `blob_malformed` exactly like a corrupt local read.
pub fn getBlob(client: *sync.SyncClient, id: []const u8) ![]u8 {
    const allocator = client.allocator;
    const seq = client.nextSeq();
    var req: std.ArrayList(u8) = .empty;
    defer req.deinit(allocator);
    try req.print(allocator, "{{\"op\":\"blob_get\",\"seq\":{d},\"id\":", .{seq});
    try json.appendGoJSONString(&req, allocator, id);
    try req.append(allocator, '}');

    var parsed = try client.sendAndParse(req.items);
    defer parsed.deinit();
    const obj = try client.checkResponseOk(parsed.value, seq);

    const hex_val = obj.get("hex") orelse return fsys.refuse("blob_malformed", id);
    const hex = switch (hex_val) {
        .string => |s| s,
        else => return fsys.refuse("blob_malformed", id),
    };
    if (hex.len % 2 != 0 or hex.len / 2 > store.MaxBlobBytes) {
        return fsys.refuse("blob_malformed", id);
    }
    const bytes = try allocator.alloc(u8, hex.len / 2);
    errdefer allocator.free(bytes);
    for (bytes, 0..) |*b, i| {
        const hi = hexNibble(hex[i * 2]) orelse return fsys.refuse("blob_malformed", id);
        const lo = hexNibble(hex[i * 2 + 1]) orelse return fsys.refuse("blob_malformed", id);
        b.* = (@as(u8, hi) << 4) | @as(u8, lo);
    }
    var digest: [32]u8 = undefined;
    Sha256.hash(bytes, &digest, .{});
    const got = std.fmt.bytesToHex(digest, .lower);
    if (!std.mem.eql(u8, &got, id)) {
        return fsys.refuse("blob_malformed", id);
    }
    return bytes;
}

// ---- local manifest log -----------------------------------------------------

/// The local `manifests/<stream_id>.jsonl`: raw lines plus their parallel
/// parsed forms and a `change` → index map. A missing log is an empty log.
const LocalManifestLog = struct {
    lines: [][]u8,
    manifests: []store.Manifest,
    by_change: std.StringHashMap(usize),

    fn deinit(self: *LocalManifestLog, allocator: Allocator) void {
        for (self.lines) |l| allocator.free(l);
        allocator.free(self.lines);
        store.freeManifests(allocator, self.manifests);
        self.by_change.deinit();
    }
};

fn loadLocalManifests(allocator: Allocator, fs: FS, root: []const u8, stream_id: []const u8) !LocalManifestLog {
    var out = LocalManifestLog{
        .lines = try allocator.alloc([]u8, 0),
        .manifests = try allocator.alloc(store.Manifest, 0),
        .by_change = std.StringHashMap(usize).init(allocator),
    };
    errdefer out.deinit(allocator);

    const p = try store.manifestLogPath(allocator, root, stream_id);
    defer allocator.free(p);
    if (fs.exists(allocator, p)) {
        const b = try fs.readFile(allocator, p, store.MaxFileReadBytes);
        defer allocator.free(b);
        const raw = try store.readManifestLines(allocator, b);
        defer allocator.free(raw);
        if (raw.len > store.MaxManifests) {
            return fsys.refuse("store_too_large", "manifests");
        }
        var lines: std.ArrayList([]u8) = .empty;
        errdefer {
            for (lines.items) |l| allocator.free(l);
            lines.deinit(allocator);
        }
        var manifests: std.ArrayList(store.Manifest) = .empty;
        errdefer {
            for (manifests.items) |m| m.deinit(allocator);
            manifests.deinit(allocator);
        }
        for (raw) |line| {
            const copy = try allocator.dupe(u8, line);
            errdefer allocator.free(copy);
            const m = json.parseManifest(allocator, line) catch {
                return fsys.refuse("manifest_torn", "");
            };
            errdefer m.deinit(allocator);
            try lines.append(allocator, copy);
            try manifests.append(allocator, m);
        }
        out.lines = try lines.toOwnedSlice(allocator);
        out.manifests = try manifests.toOwnedSlice(allocator);
    }
    for (out.manifests, 0..) |m, i| try out.by_change.put(m.change, i);
    return out;
}

// ---- reconciliation ---------------------------------------------------------

/// Push-side reconciliation (§9): publishes the local manifest lines the
/// remote log lacks plus every blob those manifests reference — `blob_get`
/// probes first (`blob_missing` is the miss signal), `blob_put` uploads the
/// local copy, then `put_manifest` lands the lines. Blobs precede manifests
/// so a served manifest is always resolvable. Runs on every push for the
/// stream — matching semantic heads are not proof content transfer
/// finished. Degrades history-only on a pre-content peer.
pub fn pushStreamContent(
    allocator: Allocator,
    fs: FS,
    root: []const u8,
    client: *sync.SyncClient,
    stream_id: []const u8,
    outcome: *ContentOutcome,
) !void {
    if (outcome.degraded) return;
    if (!remoteServesContent(client)) {
        degrade(outcome, "get_manifest");
        return;
    }

    const remote_lines = getManifestLines(client, stream_id, null) catch |err| {
        if (degradedByUsage(outcome, "get_manifest", err)) return;
        return err;
    };
    defer sync.freeRawLines(allocator, remote_lines);

    // Remote coverage by bound change; a same-change different-bytes local
    // line is left for `put_manifest` to refuse (`id conflict`) — author
    // equivocation surfaces as a refusal, never a silent merge.
    var remote_by_change = std.StringHashMap([]const u8).init(allocator);
    defer remote_by_change.deinit();
    var remote_keys: std.ArrayList([]u8) = .empty;
    defer {
        for (remote_keys.items) |k| allocator.free(k);
        remote_keys.deinit(allocator);
    }

    // Blob ids the remote side must resolve once its manifest set is
    // complete: remote-kept lines plus the local lines about to ship.
    var blob_ids = std.StringHashMap(void).init(allocator);
    defer blob_ids.deinit();
    var blob_list: std.ArrayList([]u8) = .empty;
    defer {
        for (blob_list.items) |k| allocator.free(k);
        blob_list.deinit(allocator);
    }

    for (remote_lines) |line| {
        var m = json.parseManifest(allocator, line) catch return fsys.refuse("manifest_torn", "");
        defer m.deinit(allocator);
        if (!std.mem.eql(u8, m.stream, stream_id)) return fsys.refuse("manifest_torn", "");
        // The map key outlives `m` — dupe it before the per-line deinit.
        const ck = try allocator.dupe(u8, m.change);
        errdefer allocator.free(ck);
        try remote_by_change.put(ck, line);
        try remote_keys.append(allocator, ck);
        for (m.files) |e| {
            if (e.blob.len == 0 or blob_ids.contains(e.blob)) continue;
            const key = try allocator.dupe(u8, e.blob);
            errdefer allocator.free(key);
            try blob_ids.put(key, {});
            try blob_list.append(allocator, key);
        }
    }

    var local = try loadLocalManifests(allocator, fs, root, stream_id);
    defer local.deinit(allocator);

    var to_push: std.ArrayList([]const u8) = .empty;
    defer to_push.deinit(allocator);
    for (local.lines, local.manifests) |line, m| {
        if (remote_by_change.get(m.change)) |existing| {
            if (std.mem.eql(u8, existing, line)) continue;
        }
        try to_push.append(allocator, line);
        for (m.files) |e| {
            if (e.blob.len == 0 or blob_ids.contains(e.blob)) continue;
            const key = try allocator.dupe(u8, e.blob);
            errdefer allocator.free(key);
            try blob_ids.put(key, {});
            try blob_list.append(allocator, key);
        }
    }

    // Blobs first: probe each referenced id, then upload the local copy on
    // a miss. A locally absent or corrupt blob is counted, not sent — the
    // push still completes and reports the gap (`missing`).
    for (blob_list.items) |id| {
        if (getBlob(client, id)) |bytes| {
            allocator.free(bytes);
            continue;
        } else |err| {
            if (degradedByUsage(outcome, "blob_get", err)) return;
            if (!(err == error.Refuse and std.mem.eql(u8, fsys.last_refuse.code(), "blob_missing"))) {
                return err;
            }
        }
        const bp = try store.blobPath(allocator, root, id);
        defer allocator.free(bp);
        const data = fs.readFile(allocator, bp, store.MaxBlobBytes) catch |err| {
            // Absent or over-cap local blob files cannot be uploaded —
            // count the gap rather than failing the history sync.
            if (err == error.FileNotFound or
                (err == error.Refuse and std.mem.eql(u8, fsys.last_refuse.code(), "store_too_large")))
            {
                outcome.missing += 1;
                continue;
            }
            return err;
        };
        defer allocator.free(data);
        var digest: [32]u8 = undefined;
        Sha256.hash(data, &digest, .{});
        const hex = std.fmt.bytesToHex(digest, .lower);
        if (!std.mem.eql(u8, &hex, id)) {
            // Local store corruption — uploading it would be refused as
            // `blob_malformed`; report the gap instead.
            outcome.missing += 1;
            continue;
        }
        putBlob(client, id, data) catch |err| {
            if (degradedByUsage(outcome, "blob_put", err)) return;
            return err;
        };
        outcome.blobs += 1;
    }

    var sent: usize = 0;
    while (sent < to_push.items.len) {
        const end = @min(sent + sync.MaxBatchChanges, to_push.items.len);
        const batch = to_push.items[sent..end];
        const stored = putManifestLines(client, stream_id, batch) catch |err| blk: {
            if (degradedByUsage(outcome, "put_manifest", err)) return;
            if (!(err == error.Refuse and std.mem.eql(u8, fsys.last_refuse.code(), "change_missing"))) {
                return err;
            }
            // The batch is all-or-nothing, so one line binding a Change the
            // remote never received (local-only detached work) would starve
            // the rest. A `change_missing` refusal provably changed nothing
            // remote, so resubmitting line-by-line is safe: each line either
            // stores, dedupes, or skips on `change_missing`.
            var n: usize = 0;
            for (batch) |one| {
                const s = putManifestLines(client, stream_id, &.{one}) catch |perr| {
                    if (perr == error.Refuse and std.mem.eql(u8, fsys.last_refuse.code(), "change_missing")) {
                        outcome.skipped += 1;
                        continue;
                    }
                    if (degradedByUsage(outcome, "put_manifest", perr)) return;
                    return perr;
                };
                n += s;
            }
            break :blk n;
        };
        outcome.manifests += stored;
        sent = end;
    }
}

/// Pull/clone-side reconciliation (§9): `get_manifest` the remote log —
/// healing needs the whole set, matching heads are not proof content
/// finished — then append each missing line verbatim after re-verification
/// (parse, `stream` binds this stream, `change` resolves in the local log,
/// `author` matches the bound Change, signature verifies; `sig_invalid`
/// aborts before any write). Finally `blob_get` each referenced id absent
/// from `blobs/`, id-checked before storing. A `blob_malformed` mid-pull
/// leaves the Change log correct — the next pull re-heals.
pub fn pullStreamContent(
    allocator: Allocator,
    fs: FS,
    root: []const u8,
    client: *sync.SyncClient,
    stream_id: []const u8,
    outcome: *ContentOutcome,
) !void {
    if (outcome.degraded) return;
    if (!remoteServesContent(client)) {
        degrade(outcome, "get_manifest");
        return;
    }

    const remote_lines = getManifestLines(client, stream_id, null) catch |err| {
        if (degradedByUsage(outcome, "get_manifest", err)) return;
        return err;
    };
    defer sync.freeRawLines(allocator, remote_lines);

    var local = try loadLocalManifests(allocator, fs, root, stream_id);
    defer local.deinit(allocator);

    var loaded = try store.loadStream(allocator, fs, root, stream_id);
    defer loaded.deinit(allocator);
    var authors = std.StringHashMap([]const u8).init(allocator);
    defer authors.deinit();
    for (loaded.changes) |*c| try authors.put(c.id, c.author);

    var to_append: std.ArrayList([]const u8) = .empty;
    defer to_append.deinit(allocator);
    var appended: std.ArrayList(store.Manifest) = .empty;
    defer {
        for (appended.items) |m| m.deinit(allocator);
        appended.deinit(allocator);
    }

    for (remote_lines) |line| {
        var m = json.parseManifest(allocator, line) catch return fsys.refuse("manifest_torn", "");
        if (!std.mem.eql(u8, m.stream, stream_id)) {
            m.deinit(allocator);
            return fsys.refuse("manifest_torn", "");
        }
        if (local.by_change.get(m.change)) |li| {
            defer m.deinit(allocator);
            // An already-kept line must be byte-identical; the same change
            // under different bytes is a tampered mapping, not a duplicate.
            if (!std.mem.eql(u8, local.lines[li], line)) {
                return fsys.refuse("manifest_torn", "id conflict");
            }
            continue;
        }
        const author = authors.get(m.change) orelse {
            // Binds a Change the local log lacks — deposited history this
            // pull did not receive. Left unfetched; a later sync that brings
            // the Change re-heals the manifest line with it.
            m.deinit(allocator);
            outcome.skipped += 1;
            continue;
        };
        if (!std.mem.eql(u8, m.author, author) or !try ed25519.verifyManifest(allocator, m)) {
            m.deinit(allocator);
            return fsys.refuse("sig_invalid", "");
        }
        try to_append.append(allocator, line);
        try appended.append(allocator, m);
    }

    if (to_append.items.len > 0) {
        if (local.manifests.len + to_append.items.len > store.MaxManifests) {
            return fsys.refuse("store_too_large", "manifests");
        }
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(allocator);
        for (to_append.items) |l| {
            try buf.appendSlice(allocator, l);
            try buf.append(allocator, '\n');
        }
        const mlog = try store.manifestLogPath(allocator, root, stream_id);
        defer allocator.free(mlog);
        if (report.active) |r| r.beginLocalWrites();
        try fs.appendSync(allocator, mlog, buf.items);
        if (report.active) |r| r.noteLocalWriteDone();
        outcome.manifests += to_append.items.len;
    }

    // Every locally-kept manifest's referenced ids — not only the ones just
    // appended — so a transfer cut between manifest append and blob fetch
    // heals here. `blob:null` entries are explicit incompleteness, skipped.
    var seen_blobs = std.StringHashMap(void).init(allocator);
    defer seen_blobs.deinit();
    var seen_keys: std.ArrayList([]u8) = .empty;
    defer {
        for (seen_keys.items) |k| allocator.free(k);
        seen_keys.deinit(allocator);
    }
    for ([_][]const store.Manifest{ local.manifests, appended.items }) |set| {
        for (set) |m| {
            for (m.files) |e| {
                if (e.blob.len == 0 or seen_blobs.contains(e.blob)) continue;
                const key = try allocator.dupe(u8, e.blob);
                errdefer allocator.free(key);
                try seen_blobs.put(key, {});
                try seen_keys.append(allocator, key);

                const bp = try store.blobPath(allocator, root, e.blob);
                defer allocator.free(bp);
                if (fs.exists(allocator, bp)) continue;

                const data = getBlob(client, e.blob) catch |err| {
                    if (degradedByUsage(outcome, "blob_get", err)) return;
                    return err;
                };
                defer allocator.free(data);
                if (report.active) |r| r.beginLocalWrites();
                try fs.writeFileSafe(allocator, bp, data);
                if (report.active) |r| r.noteLocalWriteDone();
                outcome.blobs += 1;
            }
        }
    }
}

/// Emits the degraded-mode stderr note once and records `data.content` on the
/// active `--json` report. Diagnostics never share the result stream; the
/// envelope reports history success and content incompleteness separately.
pub fn reportContentOutcome(
    rep: ?*report.Report,
    stderr: *Io.Writer,
    outcome: *ContentOutcome,
) !void {
    if (outcome.degraded and !outcome.note_emitted) {
        outcome.note_emitted = true;
        try stderr.print(
            "flint: note remote predates content sync (proto_version {s}); history synced without source content\n",
            .{outcome.degraded_op},
        );
    }
    const r = rep orelse return;
    var buf: [160]u8 = undefined;
    const raw = if (outcome.degraded)
        try std.fmt.bufPrint(&buf, "{{\"state\":\"degraded\",\"op\":\"{s}\"}}", .{outcome.degraded_op})
    else if (outcome.missing > 0 or outcome.skipped > 0)
        try std.fmt.bufPrint(&buf, "{{\"state\":\"incomplete\",\"manifests\":{d},\"blobs\":{d},\"missing\":{d},\"skipped\":{d}}}", .{
            outcome.manifests, outcome.blobs, outcome.missing, outcome.skipped,
        })
    else
        try std.fmt.bufPrint(&buf, "{{\"state\":\"complete\",\"manifests\":{d},\"blobs\":{d}}}", .{
            outcome.manifests, outcome.blobs,
        });
    try r.fieldRaw("content", raw);
}

// ---- InProcServer fixture handlers ------------------------------------------
// Mirror the flintd content ops (flint-server §2.6) for the conformance
// fixture: same refusal names, dedupe, signature checks, and bounds. The ops
// are served regardless of the fixture's announced `spec_rev` — the client
// gates them, exactly as it gates on a real server's `hello`.

/// Classifies a `parseManifest` failure: an invalid `files[].path` is
/// `manifest_torn` (path violation), anything else `change_malformed` —
/// matching flintd's distinction.
fn manifestParseRefusal(allocator: Allocator, line: []const u8) []const u8 {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, line, .{}) catch return "change_malformed";
    defer parsed.deinit();
    if (parsed.value != .object) return "change_malformed";
    const files = parsed.value.object.get("files") orelse return "change_malformed";
    if (files != .array) return "change_malformed";
    for (files.array.items) |item| {
        if (item != .object) return "change_malformed";
        const p = item.object.get("path") orelse return "change_malformed";
        if (p != .string or !store.validManifestPath(p.string)) return "manifest_torn";
    }
    return "change_malformed";
}

fn serverStreamArg(obj: std.json.ObjectMap) ![]const u8 {
    const sv = obj.get("stream") orelse return error.Missing;
    return switch (sv) {
        .string => |s| if (s.len > 0) s else error.Missing,
        else => error.Missing,
    };
}

/// `put_manifest` fixture handler (§9): dedupe by `change` (identical bytes
/// skip, different bytes refuse `change_malformed` `id conflict`), the bound
/// Change must sit in the stream's log (`change_missing`), `author` must
/// equal the Change's author and `sig` must verify under it. Batches are
/// 1–256 lines and all-or-nothing; the stream record never moves.
pub fn servePutManifest(
    server: *sync.InProcServer,
    allocator: Allocator,
    seq: u64,
    obj: std.json.ObjectMap,
) ![]u8 {
    const s_arg = serverStreamArg(obj) catch {
        return sync.InProcServer.marshalRefuse(allocator, seq, "usage", "missing stream");
    };
    const lines_val = obj.get("lines") orelse {
        return sync.InProcServer.marshalRefuse(allocator, seq, "usage", "missing lines");
    };
    const lines_arr = switch (lines_val) {
        .array => |a| a.items,
        else => return sync.InProcServer.marshalRefuse(allocator, seq, "usage", "lines must be an array"),
    };
    if (lines_arr.len == 0 or lines_arr.len > sync.MaxBatchChanges) {
        return sync.InProcServer.marshalRefuse(allocator, seq, "change_malformed", "batch size");
    }

    var idx = store.loadStoreIndex(allocator, server.fs, server.store_root) catch |err| {
        return sync.InProcServer.marshalErrRefuse(allocator, seq, err);
    };
    defer idx.deinit();
    const st = (idx.streamByID(s_arg) orelse idx.streamByName(s_arg)) orelse {
        return sync.InProcServer.marshalRefuse(allocator, seq, "stream_missing", s_arg);
    };

    var loaded = store.loadStream(allocator, server.fs, server.store_root, st.id) catch |err| {
        return sync.InProcServer.marshalErrRefuse(allocator, seq, err);
    };
    defer loaded.deinit(allocator);

    var local = loadLocalManifests(allocator, server.fs, server.store_root, st.id) catch |err| {
        return sync.InProcServer.marshalErrRefuse(allocator, seq, err);
    };
    defer local.deinit(allocator);

    var log_buf: std.ArrayList(u8) = .empty;
    defer log_buf.deinit(allocator);
    var stored: usize = 0;
    var batch_changes = std.StringHashMap([]const u8).init(allocator);
    defer batch_changes.deinit();

    for (lines_arr) |item| {
        const raw_in = switch (item) {
            .string => |s| s,
            else => return sync.InProcServer.marshalRefuse(allocator, seq, "change_malformed", ""),
        };
        const raw = std.mem.trimEnd(u8, raw_in, "\r\n");

        var m = json.parseManifest(allocator, raw) catch {
            return sync.InProcServer.marshalRefuse(allocator, seq, manifestParseRefusal(allocator, raw), "");
        };
        defer m.deinit(allocator);

        if (!std.mem.eql(u8, m.stream, st.id)) {
            return sync.InProcServer.marshalRefuse(allocator, seq, "change_malformed", "stream mismatch");
        }

        // Dedupe by bound change: identical bytes skip, same change under
        // different bytes is an id conflict — checked against the stored log
        // and earlier lines in this batch alike.
        var duplicate = false;
        if (local.by_change.get(m.change)) |li| {
            if (!std.mem.eql(u8, local.lines[li], raw)) {
                return sync.InProcServer.marshalRefuse(allocator, seq, "change_malformed", "id conflict");
            }
            duplicate = true;
        } else if (batch_changes.get(m.change)) |earlier| {
            if (!std.mem.eql(u8, earlier, raw)) {
                return sync.InProcServer.marshalRefuse(allocator, seq, "change_malformed", "id conflict");
            }
            duplicate = true;
        }
        if (duplicate) continue;

        var bound: ?store.Change = null;
        for (loaded.changes) |*c| {
            if (std.mem.eql(u8, c.id, m.change)) {
                bound = c.*;
                break;
            }
        }
        const bch = bound orelse {
            return sync.InProcServer.marshalRefuse(allocator, seq, "change_missing", m.change);
        };
        if (!std.mem.eql(u8, m.author, bch.author)) {
            return sync.InProcServer.marshalRefuse(allocator, seq, "change_malformed", "author mismatch");
        }
        const ok = ed25519.verifyManifest(allocator, m) catch |err| {
            return sync.InProcServer.marshalErrRefuse(allocator, seq, err);
        };
        if (!ok) {
            return sync.InProcServer.marshalRefuse(allocator, seq, "sig_invalid", "");
        }
        if (server.allow_authors) |allowed| {
            var found = false;
            for (allowed) |pub_hex| {
                if (std.mem.eql(u8, pub_hex, m.author)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                return sync.InProcServer.marshalRefuse(allocator, seq, "author_not_allowed", m.author);
            }
        }

        const key = allocator.dupe(u8, m.change) catch |err| return sync.InProcServer.marshalErrRefuse(allocator, seq, err);
        batch_changes.put(key, raw) catch |err| {
            allocator.free(key);
            return sync.InProcServer.marshalErrRefuse(allocator, seq, err);
        };
        log_buf.appendSlice(allocator, raw) catch |err| return sync.InProcServer.marshalErrRefuse(allocator, seq, err);
        log_buf.append(allocator, '\n') catch |err| return sync.InProcServer.marshalErrRefuse(allocator, seq, err);
        stored += 1;
    }
    defer {
        var it = batch_changes.keyIterator();
        while (it.next()) |k| allocator.free(k.*);
    }

    if (local.manifests.len + stored > store.MaxManifests) {
        return sync.InProcServer.marshalRefuse(allocator, seq, "store_too_large", "manifests");
    }
    if (stored > 0) {
        const mlog = store.manifestLogPath(allocator, server.store_root, st.id) catch |err| {
            return sync.InProcServer.marshalErrRefuse(allocator, seq, err);
        };
        defer allocator.free(mlog);
        const mdir = store.manifestsDir(allocator, server.store_root) catch |err| {
            return sync.InProcServer.marshalErrRefuse(allocator, seq, err);
        };
        defer allocator.free(mdir);
        server.fs.mkdir(allocator, mdir) catch |err| {
            return sync.InProcServer.marshalErrRefuse(allocator, seq, err);
        };
        server.fs.appendSync(allocator, mlog, log_buf.items) catch |err| {
            return sync.InProcServer.marshalErrRefuse(allocator, seq, err);
        };
    }

    return std.fmt.allocPrint(allocator, "{{\"seq\":{d},\"ok\":true,\"stored\":{d}}}", .{ seq, stored });
}

/// `get_manifest` fixture handler (§9): returns manifest lines verbatim in
/// log order for the change range `read`'s `after` cursor produces — null
/// yields the whole log, a change id yields lines bound to changes after it
/// (log position, detached lines included), the `forked_from` change yields
/// everything, and an unknown `after` refuses `change_missing`.
pub fn serveGetManifest(
    server: *sync.InProcServer,
    allocator: Allocator,
    seq: u64,
    obj: std.json.ObjectMap,
) ![]u8 {
    const s_arg = serverStreamArg(obj) catch {
        return sync.InProcServer.marshalRefuse(allocator, seq, "usage", "missing stream");
    };
    var after_opt: ?[]const u8 = null;
    if (obj.get("after")) |av| {
        switch (av) {
            .null => {},
            .string => |s| if (s.len > 0) {
                after_opt = s;
            },
            else => return sync.InProcServer.marshalRefuse(allocator, seq, "usage", "invalid after"),
        }
    }

    var idx = store.loadStoreIndex(allocator, server.fs, server.store_root) catch |err| {
        return sync.InProcServer.marshalErrRefuse(allocator, seq, err);
    };
    defer idx.deinit();
    const st = (idx.streamByID(s_arg) orelse idx.streamByName(s_arg)) orelse {
        return sync.InProcServer.marshalRefuse(allocator, seq, "stream_missing", s_arg);
    };

    var loaded = store.loadStream(allocator, server.fs, server.store_root, st.id) catch |err| {
        return sync.InProcServer.marshalErrRefuse(allocator, seq, err);
    };
    defer loaded.deinit(allocator);

    var wanted: ?std.StringHashMap(void) = null;
    defer if (wanted) |*w| w.deinit();
    if (after_opt) |after_id| {
        var matched = false;
        for (loaded.changes, 0..) |c, i| {
            if (std.mem.eql(u8, c.id, after_id)) {
                var set = std.StringHashMap(void).init(allocator);
                for (loaded.changes[i + 1 ..]) |rest| {
                    set.put(rest.id, {}) catch return error.OutOfMemory;
                }
                wanted = set;
                matched = true;
                break;
            }
        }
        if (!matched) {
            if (loaded.stream.forked_from) |ff| {
                if (std.mem.eql(u8, ff.change, after_id)) matched = true;
            }
            if (!matched) {
                return sync.InProcServer.marshalRefuse(allocator, seq, "change_missing", after_id);
            }
        }
    }

    var local = loadLocalManifests(allocator, server.fs, server.store_root, st.id) catch |err| {
        return sync.InProcServer.marshalErrRefuse(allocator, seq, err);
    };
    defer local.deinit(allocator);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.print(allocator, "{{\"seq\":{d},\"ok\":true,\"lines\":[", .{seq});
    var emitted: usize = 0;
    for (local.lines, local.manifests) |line, m| {
        if (wanted) |*w| {
            if (!w.contains(m.change)) continue;
        }
        if (emitted > 0) try out.append(allocator, ',');
        try json.appendGoJSONString(&out, allocator, line);
        emitted += 1;
    }
    try out.appendSlice(allocator, "]}");
    return out.toOwnedSlice(allocator);
}

/// `blob_put` fixture handler (§9): `id` must be the lowercase-hex SHA-256 of
/// the decoded `hex` bytes (`blob_malformed` otherwise); decoded size over
/// the blob cap refuses `change_too_large`. Already-present ids are
/// idempotently `ok`.
pub fn serveBlobPut(
    server: *sync.InProcServer,
    allocator: Allocator,
    seq: u64,
    obj: std.json.ObjectMap,
) ![]u8 {
    const id = switch (obj.get("id") orelse return sync.InProcServer.marshalRefuse(allocator, seq, "usage", "missing id")) {
        .string => |s| if (s.len > 0) s else return sync.InProcServer.marshalRefuse(allocator, seq, "usage", "empty id"),
        else => return sync.InProcServer.marshalRefuse(allocator, seq, "usage", "invalid id"),
    };
    const hex = switch (obj.get("hex") orelse return sync.InProcServer.marshalRefuse(allocator, seq, "usage", "missing hex")) {
        .string => |s| s,
        else => return sync.InProcServer.marshalRefuse(allocator, seq, "usage", "invalid hex"),
    };

    const bp = store.blobPath(allocator, server.store_root, id) catch |err| {
        return sync.InProcServer.marshalErrRefuse(allocator, seq, err);
    };
    defer allocator.free(bp);
    if (hex.len % 2 != 0 or hex.len / 2 > store.MaxBlobBytes) {
        return sync.InProcServer.marshalRefuse(allocator, seq, "change_too_large", "");
    }

    const bytes = allocator.alloc(u8, hex.len / 2) catch |err| {
        return sync.InProcServer.marshalErrRefuse(allocator, seq, err);
    };
    defer allocator.free(bytes);
    for (bytes, 0..) |*b, i| {
        const hi = hexNibble(hex[i * 2]) orelse {
            return sync.InProcServer.marshalRefuse(allocator, seq, "blob_malformed", "");
        };
        const lo = hexNibble(hex[i * 2 + 1]) orelse {
            return sync.InProcServer.marshalRefuse(allocator, seq, "blob_malformed", "");
        };
        b.* = (@as(u8, hi) << 4) | @as(u8, lo);
    }
    var digest: [32]u8 = undefined;
    Sha256.hash(bytes, &digest, .{});
    const got = std.fmt.bytesToHex(digest, .lower);
    if (!std.mem.eql(u8, &got, id)) {
        return sync.InProcServer.marshalRefuse(allocator, seq, "blob_malformed", "");
    }

    if (!server.fs.exists(allocator, bp)) {
        server.fs.writeFileSafe(allocator, bp, bytes) catch |err| {
            return sync.InProcServer.marshalErrRefuse(allocator, seq, err);
        };
    }
    return std.fmt.allocPrint(allocator, "{{\"seq\":{d},\"ok\":true}}", .{seq});
}

/// `blob_get` fixture handler (§9): returns the stored bytes as lowercase
/// hex; a missing id refuses `blob_missing` and stored bytes are re-hashed
/// on every read — a mismatch refuses `blob_malformed`.
pub fn serveBlobGet(
    server: *sync.InProcServer,
    allocator: Allocator,
    seq: u64,
    obj: std.json.ObjectMap,
) ![]u8 {
    const id = switch (obj.get("id") orelse return sync.InProcServer.marshalRefuse(allocator, seq, "usage", "missing id")) {
        .string => |s| if (s.len > 0) s else return sync.InProcServer.marshalRefuse(allocator, seq, "usage", "empty id"),
        else => return sync.InProcServer.marshalRefuse(allocator, seq, "usage", "invalid id"),
    };

    const bp = store.blobPath(allocator, server.store_root, id) catch |err| {
        return sync.InProcServer.marshalErrRefuse(allocator, seq, err);
    };
    defer allocator.free(bp);
    const data = server.fs.readFile(allocator, bp, store.MaxBlobBytes + 1) catch |err| {
        if (err == error.FileNotFound) {
            return sync.InProcServer.marshalRefuse(allocator, seq, "blob_missing", id);
        }
        return sync.InProcServer.marshalErrRefuse(allocator, seq, err);
    };
    defer allocator.free(data);
    var digest: [32]u8 = undefined;
    Sha256.hash(data, &digest, .{});
    const got = std.fmt.bytesToHex(digest, .lower);
    if (!std.mem.eql(u8, &got, id)) {
        return sync.InProcServer.marshalRefuse(allocator, seq, "blob_malformed", id);
    }

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.print(allocator, "{{\"seq\":{d},\"ok\":true,\"hex\":\"", .{seq});
    const digits = "0123456789abcdef";
    for (data) |b| {
        try out.append(allocator, digits[b >> 4]);
        try out.append(allocator, digits[b & 0x0f]);
    }
    try out.appendSlice(allocator, "\"}");
    return out.toOwnedSlice(allocator);
}
