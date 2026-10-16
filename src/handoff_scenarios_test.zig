//! `flint handoff` end-to-end scenarios — record lifecycle, verdicts,
//! refusals, and fixtures (docs/flint-handoffs-spec.md §8, conformance matrix).
const std = @import("std");
const Allocator = std.mem.Allocator;
const store = @import("store.zig");
const fsys = @import("fsys.zig");
const json = @import("json.zig");
const ed25519 = @import("ed25519.zig");

const main = @import("main.zig");
const TestHarness = main.TestHarness;
const rfc8032_seed_hex = main.rfc8032_seed_hex;

fn runExpect(
    h: *TestHarness,
    gpa: Allocator,
    args: []const []const u8,
    want_rc: u8,
) !void {
    const res = try h.runCmd(args);
    defer gpa.free(res.out);
    try std.testing.expectEqual(want_rc, res.rc);
}

fn runOut(
    h: *TestHarness,
    gpa: Allocator,
    args: []const []const u8,
    want_rc: u8,
) ![]u8 {
    const res = try h.runCmd(args);
    errdefer gpa.free(res.out);
    try std.testing.expectEqual(want_rc, res.rc);
    return res.out;
}

fn expectRefuse(h: *TestHarness, gpa: Allocator, args: []const []const u8, want: []const u8) !void {
    const res = try h.runCmd(args);
    defer gpa.free(res.out);
    try std.testing.expectEqual(@as(u8, 1), res.rc);
    try std.testing.expect(std.mem.startsWith(u8, res.out, want));
}

fn handoffId(gpa: Allocator, out: []const u8) ![]u8 {
    const prefix = "flint: handoff ";
    try std.testing.expect(std.mem.startsWith(u8, out, prefix));
    const rest = out[prefix.len..];
    const end = std.mem.indexOfScalar(u8, rest, ' ') orelse rest.len;
    return gpa.dupe(u8, rest[0..end]);
}

fn commitId(gpa: Allocator, out: []const u8) ![]u8 {
    const prefix = "flint: commit ok id=";
    try std.testing.expect(std.mem.startsWith(u8, out, prefix));
    const rest = out[prefix.len..];
    const end = std.mem.indexOfScalar(u8, rest, ' ') orelse rest.len;
    return gpa.dupe(u8, rest[0..end]);
}

fn streamIdByName(gpa: Allocator, mfs: fsys.FS, root: []const u8, name: []const u8) ![]u8 {
    var idx = try store.loadStoreIndex(gpa, mfs, root);
    defer idx.deinit();
    const st = idx.streamByName(name).?;
    return gpa.dupe(u8, st.id);
}

/// Builds and signs a record line for a store planted directly in memory —
/// the receiver side of a handoff where the writer's log arrived out of band.
fn signRecordLine(
    gpa: Allocator,
    seed_hex: []const u8,
    rec: *store.HandoffRecord,
) ![]u8 {
    // signHandoffRecord frees author/sig — hand it allocated strings.
    const author = try gpa.dupe(u8, "");
    const sig = try gpa.dupe(u8, "");
    rec.author = author;
    rec.sig = sig;
    var s: [32]u8 = ed25519.parseHex32Lower(seed_hex).?;
    try ed25519.signHandoffRecord(gpa, rec, &s);
    const line = try json.marshalHandoffRecord(gpa, rec.*);
    gpa.free(rec.author);
    gpa.free(rec.sig);
    return line;
}

/// Sets up the two-stream world shared by the verdict tests: `main` holds a
/// base commit, `a-work` was forked and carries one candidate commit.
fn setupTwoStreams(h: *TestHarness, gpa: Allocator, mfs: fsys.FS) ![]u8 {
    try mfs.writeFileSafe(gpa, "/host/src/calc.go", "package calc\n\nfunc Add(a, b int) int {\n\treturn a + b\n}\n");
    try runExpect(h, gpa, &.{ "init", "--name=w", "--src=/host/src" }, 0);
    try runExpect(h, gpa, &.{ "add", "/host/src" }, 0);
    const base_out = try runOut(h, gpa, &.{ "commit", "-m", "base" }, 0);
    defer gpa.free(base_out);
    const base = try commitId(gpa, base_out);
    errdefer gpa.free(base);

    try runExpect(h, gpa, &.{ "fork", "main", "a-work" }, 0);
    try mfs.writeFileSafe(gpa, "/host/srcb/calc.go", "package calc\n\nfunc Add(a, b int) int {\n\treturn a + b\n}\n\nfunc Sub(a, b int) int {\n\treturn a - b\n}\n");
    try runExpect(h, gpa, &.{ "init", "--name=aw", "--src=/host/srcb", "--stream=a-work" }, 0);
    try runExpect(h, gpa, &.{ "add", "--ws=aw", "/host/srcb" }, 0);
    try runExpect(h, gpa, &.{ "commit", "--ws=aw", "-m", "add Sub" }, 0);
    return base;
}

test "handoff: two-stream propose→attest→accept journey binds base, candidate, snapshot" {
    const gpa = std.testing.allocator;
    var h = try TestHarness.init(gpa);
    defer h.deinit();
    h.env_sign_key = rfc8032_seed_hex;
    const mfs = h.mem.fs();

    const base = try setupTwoStreams(h, gpa, mfs);
    defer gpa.free(base);
    const cand = blk: {
        const id = try streamIdByName(gpa, mfs, h.root, "a-work");
        defer gpa.free(id);
        var idx = try store.loadStoreIndex(gpa, mfs, h.root);
        defer idx.deinit();
        break :blk try gpa.dupe(u8, idx.streamByID(id).?.head.?);
    };
    defer gpa.free(cand);
    const sid = try streamIdByName(gpa, mfs, h.root, "main");
    defer gpa.free(sid);

    const p_out = try runOut(h, gpa, &.{
        "handoff", "propose", "--stream=main", "--work=a-work", "-m", "adds Sub; ready",
    }, 0);
    defer gpa.free(p_out);
    const hid = try handoffId(gpa, p_out);
    defer gpa.free(hid);

    // The stored line parses, verifies, and carries the revision bindings.
    const log_path = try store.handoffLogPath(gpa, h.root, sid);
    defer gpa.free(log_path);
    const log_raw = try mfs.readFile(gpa, log_path, store.MaxFileReadBytes);
    defer gpa.free(log_raw);
    const rec = try json.parseHandoffRecord(gpa, log_raw[0 .. log_raw.len - 1]);
    defer rec.deinit(gpa);
    try std.testing.expectEqualStrings("propose", rec.kind);
    try std.testing.expectEqualStrings(base, rec.base.?);
    try std.testing.expectEqualStrings(cand, rec.candidate.?);
    // Snapshot defaults to the candidate's own revision id (its manifest).
    try std.testing.expectEqualStrings(cand, rec.snapshot.?);
    try std.testing.expect(try ed25519.verifyHandoff(gpa, &rec));
    // Derived scope covers the delta: calc.Sub under calc.go.
    const s = rec.scope.?;
    try std.testing.expectEqual(@as(usize, 1), s.paths.len);
    try std.testing.expectEqualStrings("calc.go", s.paths[0]);
    try std.testing.expectEqualStrings("calc.Sub", s.atoms[0]);

    {
        const out = try runOut(h, gpa, &.{ "handoff", "list", "--stream=main" }, 0);
        defer gpa.free(out);
        try std.testing.expect(std.mem.indexOf(u8, out, "state=proposed") != null);
        try std.testing.expect(std.mem.indexOf(u8, out, hid) != null);
    }
    {
        const out = try runOut(h, gpa, &.{ "handoff", "inspect", hid }, 0);
        defer gpa.free(out);
        try std.testing.expect(std.mem.indexOf(u8, out, "state=proposed verdict=ready") != null);
        try std.testing.expect(std.mem.indexOf(u8, out, "scope=honest") != null);
        try std.testing.expect(std.mem.indexOf(u8, out, "sig=verified") != null);
    }

    try runExpect(h, gpa, &.{
        "handoff", "attest", hid, "--command=zig build test", "--result=pass", "--toolchain=zig 0.17.0",
    }, 0);

    // accept binds the locally observed head, never an argument.
    {
        const out = try runOut(h, gpa, &.{ "handoff", "accept", hid }, 0);
        defer gpa.free(out);
        try std.testing.expect(std.mem.indexOf(u8, out, "kind=accept") != null);
        try std.testing.expect(std.mem.indexOf(u8, out, "observed_head=") != null);
    }
    {
        const out = try runOut(h, gpa, &.{ "handoff", "inspect", hid }, 0);
        defer gpa.free(out);
        try std.testing.expect(std.mem.indexOf(u8, out, "state=accepted verdict=accepted") != null);
        try std.testing.expect(std.mem.indexOf(u8, out, "via=attest") != null);
        try std.testing.expect(std.mem.indexOf(u8, out, "result=pass") != null);
    }

    // Accepting an accepted proposal is a second terminal transition.
    try expectRefuse(h, gpa, &.{ "handoff", "accept", hid }, "flint: refuse handoff_closed");

    // The accept is revision-bound: moving main's head flips it stale.
    try mfs.writeFileSafe(gpa, "/host/src/notes.md", "unrelated\n");
    try runExpect(h, gpa, &.{ "add", "--ws=w", "/host/src" }, 0);
    try runExpect(h, gpa, &.{ "commit", "--ws=w", "-m", "move main" }, 0);
    {
        const out = try runOut(h, gpa, &.{ "handoff", "inspect", hid }, 0);
        defer gpa.free(out);
        try std.testing.expect(std.mem.indexOf(u8, out, "verdict=accepted_stale") != null);
    }
}

test "handoff: stale verdict after head moves, conflicting on overlapping edits" {
    const gpa = std.testing.allocator;
    var h = try TestHarness.init(gpa);
    defer h.deinit();
    h.env_sign_key = rfc8032_seed_hex;
    const mfs = h.mem.fs();

    const base = try setupTwoStreams(h, gpa, mfs);
    defer gpa.free(base);

    const p_out = try runOut(h, gpa, &.{
        "handoff", "propose", "--stream=main", "--work=a-work", "-m", "candidate ready",
    }, 0);
    defer gpa.free(p_out);
    const hid = try handoffId(gpa, p_out);
    defer gpa.free(hid);

    // A non-overlapping commit on main → stale (merge stays clean).
    try mfs.writeFileSafe(gpa, "/host/src/calc.go", "package calc\n\nfunc Add(a, b int) int {\n\treturn a + b\n}\n\nfunc Mul(a, b int) int {\n\treturn a * b\n}\n");
    try runExpect(h, gpa, &.{ "add", "--ws=w", "/host/src" }, 0);
    try runExpect(h, gpa, &.{ "commit", "--ws=w", "-m", "add Mul" }, 0);
    {
        const out = try runOut(h, gpa, &.{ "handoff", "inspect", hid }, 0);
        defer gpa.free(out);
        try std.testing.expect(std.mem.indexOf(u8, out, "verdict=stale") != null);
    }

    // Withdraw the stale proposal; a fresh proposal on the same candidate is
    // stale relative to the moved head but carries no new conflicts.
    try runExpect(h, gpa, &.{ "handoff", "withdraw", hid }, 0);
    {
        const out = try runOut(h, gpa, &.{ "handoff", "list" }, 0);
        defer gpa.free(out);
        try std.testing.expect(std.mem.indexOf(u8, out, "state=withdrawn") != null);
    }
}

test "handoff: overlapping edits on both sides report conflicting" {
    const gpa = std.testing.allocator;
    var h = try TestHarness.init(gpa);
    defer h.deinit();
    h.env_sign_key = rfc8032_seed_hex;
    const mfs = h.mem.fs();

    // Both sides edit the same atom after the fork: a-work changes the Add
    // body, then main changes it differently → dry merge conflicts.
    try mfs.writeFileSafe(gpa, "/host/src/calc.go", "package calc\n\nfunc Add(a, b int) int {\n\treturn a + b\n}\n");
    try runExpect(h, gpa, &.{ "init", "--name=w", "--src=/host/src" }, 0);
    try runExpect(h, gpa, &.{ "add", "/host/src" }, 0);
    try runExpect(h, gpa, &.{ "commit", "-m", "base" }, 0);
    try runExpect(h, gpa, &.{ "fork", "main", "a-work" }, 0);

    try mfs.writeFileSafe(gpa, "/host/srcb/calc.go", "package calc\n\nfunc Add(a, b int) int {\n\treturn a + b + 1\n}\n");
    try runExpect(h, gpa, &.{ "init", "--name=aw", "--src=/host/srcb", "--stream=a-work" }, 0);
    try runExpect(h, gpa, &.{ "add", "--ws=aw", "/host/srcb" }, 0);
    try runExpect(h, gpa, &.{ "commit", "--ws=aw", "-m", "work side" }, 0);

    try mfs.writeFileSafe(gpa, "/host/src/calc.go", "package calc\n\nfunc Add(a, b int) int {\n\treturn a + b + 2\n}\n");
    try runExpect(h, gpa, &.{ "add", "--ws=w", "/host/src" }, 0);
    try runExpect(h, gpa, &.{ "commit", "--ws=w", "-m", "main side" }, 0);

    const p_out = try runOut(h, gpa, &.{
        "handoff", "propose", "--stream=main", "--work=a-work", "-m", "conflicting work",
    }, 0);
    defer gpa.free(p_out);
    const hid = try handoffId(gpa, p_out);
    defer gpa.free(hid);

    const out = try runOut(h, gpa, &.{ "handoff", "inspect", hid }, 0);
    defer gpa.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "verdict=conflicting") != null);
}

test "handoff: lifecycle refusals — missing, closed, author, malformed, torn" {
    const gpa = std.testing.allocator;
    var h = try TestHarness.init(gpa);
    defer h.deinit();
    h.env_sign_key = rfc8032_seed_hex;
    const mfs = h.mem.fs();

    const unknown = "019a0000-ffff-7000-8000-00000000dead";
    try expectRefuse(h, gpa, &.{ "handoff", "inspect", unknown }, "flint: refuse handoff_missing");
    try expectRefuse(h, gpa, &.{
        "handoff", "attest", unknown, "--command=zig build test", "--result=pass",
    }, "flint: refuse handoff_missing");
    try expectRefuse(h, gpa, &.{ "handoff", "withdraw", unknown }, "flint: refuse handoff_missing");

    // Unknown/missing streams and candidates are the existing refusal names.
    try expectRefuse(h, gpa, &.{
        "handoff", "propose", "--stream=nope", "--work=a-work", "-m", "x",
    }, "flint: refuse stream_missing");
    try expectRefuse(h, gpa, &.{
        "handoff", "propose", "--stream=main", "--work=a-work", "-m", "x",
    }, "flint: refuse stream_missing");
    try runExpect(h, gpa, &.{ "init", "--name=w", "--src=/host/src" }, 1); // src_missing

    try mfs.writeFileSafe(gpa, "/host/src/calc.go", "package calc\n\nfunc Add(a, b int) int {\n\treturn a + b\n}\n");
    try runExpect(h, gpa, &.{ "init", "--name=w", "--src=/host/src" }, 0);
    try runExpect(h, gpa, &.{ "add", "/host/src" }, 0);
    try runExpect(h, gpa, &.{ "commit", "-m", "base" }, 0);
    try runExpect(h, gpa, &.{ "fork", "main", "a-work" }, 0);

    try expectRefuse(h, gpa, &.{
        "handoff",                              "propose", "--stream=main", "--work=a-work", "-m", "x", "--candidate",
        "019a0000-ffff-7000-8000-0000000000ee",
    }, "flint: refuse change_missing");

    try mfs.writeFileSafe(gpa, "/host/srcb/calc.go", "package calc\n\nfunc Add(a, b int) int {\n\treturn a + b\n}\n\nfunc Sub(a, b int) int {\n\treturn a - b\n}\n");
    try runExpect(h, gpa, &.{ "init", "--name=aw", "--src=/host/srcb", "--stream=a-work" }, 0);
    try runExpect(h, gpa, &.{ "add", "--ws=aw", "/host/srcb" }, 0);
    try runExpect(h, gpa, &.{ "commit", "--ws=aw", "-m", "add Sub" }, 0);

    const p_out = try runOut(h, gpa, &.{
        "handoff", "propose", "--stream=main", "--work=a-work", "-m", "candidate",
    }, 0);
    defer gpa.free(p_out);
    const hid = try handoffId(gpa, p_out);
    defer gpa.free(hid);

    // Withdraw signed by a different key → handoff_author.
    try runExpect(h, gpa, &.{ "keygen", "--name=d" }, 0);
    try expectRefuse(h, gpa, &.{ "handoff", "withdraw", hid, "--key=d" }, "flint: refuse handoff_author");

    // Proposer withdraws; a second terminal transition refuses closed.
    try runExpect(h, gpa, &.{ "handoff", "withdraw", hid, "--note", "abandoned" }, 0);
    try expectRefuse(h, gpa, &.{ "handoff", "accept", hid }, "flint: refuse handoff_closed");
    try expectRefuse(h, gpa, &.{ "handoff", "supersede", hid }, "flint: refuse handoff_closed");
    {
        const out = try runOut(h, gpa, &.{ "handoff", "inspect", hid }, 0);
        defer gpa.free(out);
        try std.testing.expect(std.mem.indexOf(u8, out, "state=withdrawn verdict=withdrawn") != null);
    }
    // attest stays legal after termination (evidence may arrive late).
    try runExpect(h, gpa, &.{
        "handoff", "attest", hid, "--command=zig build test", "--result=skip",
    }, 0);

    // A torn final line refuses handoff_torn on any log reader.
    const sid = try streamIdByName(gpa, mfs, h.root, "main");
    defer gpa.free(sid);
    const log_path = try store.handoffLogPath(gpa, h.root, sid);
    defer gpa.free(log_path);
    try mfs.appendSync(gpa, log_path, "{\"format\":\"partial");
    try expectRefuse(h, gpa, &.{ "handoff", "list" }, "flint: refuse handoff_torn");
    try expectRefuse(h, gpa, &.{ "handoff", "inspect", hid }, "flint: refuse handoff_torn");

    // A non-JSON line refuses handoff_malformed (framing, not unknown version).
    const raw = try mfs.readFile(gpa, log_path, store.MaxFileReadBytes);
    defer gpa.free(raw);
    try mfs.writeFileSafe(gpa, log_path, raw[0 .. raw.len - "{\"format\":\"partial".len]);
    try mfs.appendSync(gpa, log_path, "not json at all\n");
    try expectRefuse(h, gpa, &.{ "handoff", "list" }, "flint: refuse handoff_malformed");
}

test "handoff: receiver-side inspect reports incomplete, unknown, invalid" {
    const gpa = std.testing.allocator;
    var h = try TestHarness.init(gpa);
    defer h.deinit();
    h.env_sign_key = rfc8032_seed_hex;
    const mfs = h.mem.fs();

    // Receiver store: holds main's history but not the work stream.
    try mfs.writeFileSafe(gpa, "/host/src/calc.go", "package calc\n\nfunc Add(a, b int) int {\n\treturn a + b\n}\n");
    try runExpect(h, gpa, &.{ "init", "--name=w", "--src=/host/src" }, 0);
    try runExpect(h, gpa, &.{ "add", "/host/src" }, 0);
    const base_out = try runOut(h, gpa, &.{ "commit", "-m", "base" }, 0);
    defer gpa.free(base_out);
    const base = try commitId(gpa, base_out);
    defer gpa.free(base);
    const sid = try streamIdByName(gpa, mfs, h.root, "main");
    defer gpa.free(sid);

    const work_id = "019a0000-0002-7000-8000-0000000000bb";
    const missing_cand = "019a0000-0005-7000-8000-000000000003";

    // A signed propose naming a candidate the receiver does not hold →
    // incomplete, never silently ready.
    var rec = store.HandoffRecord{
        .id = "019a0000-0006-7000-8000-000000000010",
        .handoff = "019a0000-0006-7000-8000-000000000010",
        .kind = "propose",
        .stream = sid,
        .ts = 1760000000000,
        .author = "",
        .sig = "",
        .base = base,
        .work = work_id,
        .candidate = missing_cand,
        .snapshot = missing_cand,
        .intent = "receiver cannot resolve me",
    };
    const line = try signRecordLine(gpa, rfc8032_seed_hex, &rec);
    defer gpa.free(line);
    const log_path = try store.handoffLogPath(gpa, h.root, sid);
    defer gpa.free(log_path);
    try mfs.appendSync(gpa, log_path, line);

    {
        const out = try runOut(h, gpa, &.{ "handoff", "inspect", rec.id }, 0);
        defer gpa.free(out);
        try std.testing.expect(std.mem.indexOf(u8, out, "verdict=incomplete") != null);
        try std.testing.expect(std.mem.indexOf(u8, out, "scope=unverifiable") != null);
    }

    // An unknown-version record folds to `unknown` and does not taint others.
    const h9 = "019a0000-000d-7000-8000-000000000080";
    const zeros32 = "0000000000000000000000000000000000000000000000000000000000000000";
    const zeros64 = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    const unknown_line = try std.fmt.allocPrint(gpa,
        \\{{"format":"FLINT-HANDOFF/9","id":"{s}","handoff":"{s}","kind":"propose","stream":"{s}","ts":1,"author":"{s}","sig":"{s}"}}
        \\
    , .{ h9, h9, sid, zeros32, zeros64 });
    defer gpa.free(unknown_line);
    try mfs.appendSync(gpa, log_path, unknown_line);
    {
        const out = try runOut(h, gpa, &.{ "handoff", "inspect", h9 }, 0);
        defer gpa.free(out);
        try std.testing.expect(std.mem.indexOf(u8, out, "verdict=unknown") != null);
    }
    // …while the real proposal still inspects as incomplete.
    {
        const out = try runOut(h, gpa, &.{ "handoff", "inspect", rec.id }, 0);
        defer gpa.free(out);
        try std.testing.expect(std.mem.indexOf(u8, out, "verdict=incomplete") != null);
    }

    // A signature-tampered /1 record flips the proposal to invalid.
    const mut = try gpa.dupe(u8, line);
    defer gpa.free(mut);
    const sig_key = "\"sig\":\"";
    const at = std.mem.indexOf(u8, mut, sig_key).? + sig_key.len;
    mut[at] = if (mut[at] == '0') '1' else '0';
    const raw = try mfs.readFile(gpa, log_path, store.MaxFileReadBytes);
    defer gpa.free(raw);
    const replaced = try std.mem.replaceOwned(u8, gpa, raw, line, mut);
    defer gpa.free(replaced);
    try mfs.writeFileSafe(gpa, log_path, replaced);
    {
        const out = try runOut(h, gpa, &.{ "handoff", "inspect", rec.id }, 0);
        defer gpa.free(out);
        try std.testing.expect(std.mem.indexOf(u8, out, "verdict=invalid") != null);
        try std.testing.expect(std.mem.indexOf(u8, out, "sig=invalid") != null);
    }
}

test "handoff: verbs never touch workspaces, stage, streams, or Change history" {
    const gpa = std.testing.allocator;
    var h = try TestHarness.init(gpa);
    defer h.deinit();
    h.env_sign_key = rfc8032_seed_hex;
    const mfs = h.mem.fs();

    const base = try setupTwoStreams(h, gpa, mfs);
    defer gpa.free(base);
    const sid = try streamIdByName(gpa, mfs, h.root, "main");
    defer gpa.free(sid);

    // Stage pending work so the test also proves STAGE survives untouched.
    try mfs.writeFileSafe(gpa, "/host/src/newfile.go", "package calc\n\nfunc New() int {\n\treturn 7\n}\n");
    try runExpect(h, gpa, &.{ "add", "--ws=w", "/host/src" }, 0);

    const stage_raw = try mfs.readFile(gpa, "/host/FLINT/ws/w/STAGE.jsonl", store.MaxFileReadBytes);
    defer gpa.free(stage_raw);
    const base_raw = try mfs.readFile(gpa, "/host/FLINT/ws/w/BASE.json", store.MaxFileReadBytes);
    defer gpa.free(base_raw);
    const stream_rec_path = try std.fmt.allocPrint(gpa, "{s}/streams/{s}.json", .{ h.root, sid });
    defer gpa.free(stream_rec_path);
    const stream_raw = try mfs.readFile(gpa, stream_rec_path, store.MaxFileReadBytes);
    defer gpa.free(stream_raw);
    const stream_log_path = try store.streamLogPath(gpa, h.root, sid);
    defer gpa.free(stream_log_path);
    const stream_log = try mfs.readFile(gpa, stream_log_path, store.MaxFileReadBytes);
    defer gpa.free(stream_log);
    const src_raw = try mfs.readFile(gpa, "/host/src/calc.go", store.MaxFileReadBytes);
    defer gpa.free(src_raw);

    // Every write by a read verb is a bug — hook catches write/append/mkdir.
    const NoWrite = struct {
        calls: usize = 0,
        fn hook(ctx: ?*anyopaque, op: []const u8, path: []const u8) anyerror!void {
            _ = op;
            _ = path;
            const c: *usize = @ptrCast(@alignCast(ctx.?));
            c.* += 1;
        }
    };
    var write_calls: usize = 0;
    h.mem.before_write_ctx = &write_calls;
    h.mem.before_write = NoWrite.hook;

    const p_out = try runOut(h, gpa, &.{
        "handoff", "propose", "--stream=main", "--work=a-work", "-m", "candidate",
    }, 0);
    defer gpa.free(p_out);
    const hid = try handoffId(gpa, p_out);
    defer gpa.free(hid);

    // propose writes (the handoffs log); inspect/list are pure reads.
    try std.testing.expect(write_calls > 0);
    write_calls = 0;
    try runExpect(h, gpa, &.{ "handoff", "inspect", hid }, 0);
    try runExpect(h, gpa, &.{ "handoff", "list", "--stream=main" }, 0);
    try std.testing.expectEqual(@as(usize, 0), write_calls);
    try runExpect(h, gpa, &.{ "handoff", "attest", hid, "--command=x", "--result=skip" }, 0);
    h.mem.before_write = null;

    const stage2 = try mfs.readFile(gpa, "/host/FLINT/ws/w/STAGE.jsonl", store.MaxFileReadBytes);
    defer gpa.free(stage2);
    const base2 = try mfs.readFile(gpa, "/host/FLINT/ws/w/BASE.json", store.MaxFileReadBytes);
    defer gpa.free(base2);
    const stream2 = try mfs.readFile(gpa, stream_rec_path, store.MaxFileReadBytes);
    defer gpa.free(stream2);
    const stream_log2 = try mfs.readFile(gpa, stream_log_path, store.MaxFileReadBytes);
    defer gpa.free(stream_log2);
    const src2 = try mfs.readFile(gpa, "/host/src/calc.go", store.MaxFileReadBytes);
    defer gpa.free(src2);

    try std.testing.expectEqualStrings(stage_raw, stage2);
    try std.testing.expectEqualStrings(base_raw, base2);
    try std.testing.expectEqualStrings(stream_raw, stream2);
    try std.testing.expectEqualStrings(stream_log, stream_log2);
    try std.testing.expectEqualStrings(src_raw, src2);
}

test "handoff: supersede chains proposals; scope-file and validations embed claims" {
    const gpa = std.testing.allocator;
    var h = try TestHarness.init(gpa);
    defer h.deinit();
    h.env_sign_key = rfc8032_seed_hex;
    const mfs = h.mem.fs();

    const base = try setupTwoStreams(h, gpa, mfs);
    defer gpa.free(base);
    const sid = try streamIdByName(gpa, mfs, h.root, "main");
    defer gpa.free(sid);

    try mfs.writeFileSafe(gpa, "/host/scope.json", "{\"paths\":[\"calc.go\"],\"atoms\":[\"calc.Add\",\"calc.Sub\"]}\n");
    try mfs.writeFileSafe(gpa, "/host/vals.json", "[{\"command\":\"zig build test\",\"result\":\"pass\",\"toolchain\":\"zig 0.17.0\"}]\n");

    const p1_out = try runOut(h, gpa, &.{
        "handoff",                       "propose",                       "--stream=main", "--work=a-work", "-m", "v1",
        "--scope-file=/host/scope.json", "--validations=/host/vals.json",
    }, 0);
    defer gpa.free(p1_out);
    const h1 = try handoffId(gpa, p1_out);
    defer gpa.free(h1);

    // The propose embeds the claimed scope and the self-asserted validation.
    const log_path = try store.handoffLogPath(gpa, h.root, sid);
    defer gpa.free(log_path);
    const log_raw = try mfs.readFile(gpa, log_path, store.MaxFileReadBytes);
    defer gpa.free(log_raw);
    const rec = try json.parseHandoffRecord(gpa, log_raw[0 .. log_raw.len - 1]);
    defer rec.deinit(gpa);
    try std.testing.expectEqual(@as(usize, 2), rec.scope.?.atoms.len);
    try std.testing.expectEqual(@as(usize, 1), rec.validations.len);
    try std.testing.expectEqualStrings("zig build test", rec.validations[0].command);
    try std.testing.expectEqualStrings(rec.author, rec.validations[0].attestor);
    try std.testing.expect(try ed25519.verifyHandoff(gpa, &rec));

    // A foreign attestor embedded in --validations refuses.
    try mfs.writeFileSafe(gpa, "/host/vals-foreign.json", "[{\"command\":\"x\",\"result\":\"pass\",\"attestor\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"ts\":1}]\n");
    try expectRefuse(h, gpa, &.{
        "handoff",                               "propose", "--stream=main", "--work=a-work", "-m", "bad",
        "--validations=/host/vals-foreign.json",
    }, "flint: refuse handoff_malformed");

    // supersede with a live replacement; then the replaced proposal is closed.
    const p2_out = try runOut(h, gpa, &.{
        "handoff", "propose", "--stream=main", "--work=a-work", "-m", "v2",
    }, 0);
    defer gpa.free(p2_out);
    const h2 = try handoffId(gpa, p2_out);
    defer gpa.free(h2);

    try runExpect(h, gpa, &.{ "handoff", "supersede", h1, "--replacement", h2 }, 0);
    try expectRefuse(h, gpa, &.{ "handoff", "accept", h1 }, "flint: refuse handoff_closed");
    // A replacement that is not a known live proposal refuses.
    try expectRefuse(h, gpa, &.{
        "handoff", "supersede", h2, "--replacement", "019a0000-ffff-7000-8000-00000000dead",
    }, "flint: refuse handoff_missing");
    {
        const out = try runOut(h, gpa, &.{ "handoff", "inspect", h1 }, 0);
        defer gpa.free(out);
        try std.testing.expect(std.mem.indexOf(u8, out, "state=superseded verdict=superseded") != null);
        try std.testing.expect(std.mem.indexOf(u8, out, "via=propose") != null);
    }
}

test "handoff: --json envelopes carry handoff data and stay protocol-clean" {
    const gpa = std.testing.allocator;
    var h = try TestHarness.init(gpa);
    defer h.deinit();
    h.env_sign_key = rfc8032_seed_hex;
    const mfs = h.mem.fs();

    const base = try setupTwoStreams(h, gpa, mfs);
    defer gpa.free(base);

    const p_out = try runOut(h, gpa, &.{
        "--json", "handoff", "propose", "--stream=main", "--work=a-work", "-m", "json path",
    }, 0);
    defer gpa.free(p_out);
    const parsed = try std.json.parseFromSlice(std.json.Value, gpa, p_out, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;
    try std.testing.expectEqualStrings("handoff", obj.get("verb").?.string);
    try std.testing.expect(obj.get("ok").?.bool);
    const data = obj.get("data").?.object;
    try std.testing.expectEqualStrings("propose", data.get("kind").?.string);
    const hid = try gpa.dupe(u8, data.get("id").?.string);
    defer gpa.free(hid);

    {
        const out = try runOut(h, gpa, &.{ "--json", "handoff", "inspect", hid }, 0);
        defer gpa.free(out);
        const iparsed = try std.json.parseFromSlice(std.json.Value, gpa, out, .{});
        defer iparsed.deinit();
        const idata = iparsed.value.object.get("data").?.object;
        try std.testing.expectEqualStrings("ready", idata.get("verdict").?.string);
        try std.testing.expectEqualStrings("proposed", idata.get("state").?.string);
    }
    {
        const out = try runOut(h, gpa, &.{ "--json", "handoff", "list" }, 0);
        defer gpa.free(out);
        try std.testing.expect(std.mem.indexOf(u8, out, "\"proposals\":[") != null);
    }
    // Refusals keep the envelope shape too.
    {
        const res = try h.runCmd(&.{ "--json", "handoff", "inspect", "019a0000-ffff-7000-8000-00000000dead" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        const rparsed = try std.json.parseFromSlice(std.json.Value, gpa, res.out, .{});
        defer rparsed.deinit();
        const robj = rparsed.value.object;
        try std.testing.expectEqualStrings("handoff_missing", robj.get("refusal").?.object.get("name").?.string);
    }
}

test "handoff verify: golden packet and record fixtures through the CLI" {
    const gpa = std.testing.allocator;
    var host_fs = fsys.HostFS.init(std.testing.io);
    const fs = host_fs.fs();

    var h = try TestHarness.init(gpa);
    defer h.deinit();
    const mfs = h.mem.fs();

    for ([_][]const u8{ "propose", "attest", "accept", "supersede", "withdraw" }) |name| {
        const path = try std.fmt.allocPrint(gpa, "testdata/handoffs/{s}.json", .{name});
        defer gpa.free(path);
        const raw = try fs.readFile(gpa, path, store.MaxFileReadBytes);
        defer gpa.free(raw);
        const mem_path = try std.fmt.allocPrint(gpa, "/host/fix/{s}.json", .{name});
        defer gpa.free(mem_path);
        try mfs.writeFileSafe(gpa, mem_path, raw);

        const arg = try std.fmt.allocPrint(gpa, "{s}", .{mem_path});
        defer gpa.free(arg);
        const out = try runOut(h, gpa, &.{ "handoff", "verify", arg }, 0);
        defer gpa.free(out);
        try std.testing.expect(std.mem.indexOf(u8, out, "sig: verified") != null);
    }

    // Packet: header + records + detached Changes all verify.
    {
        const raw = try fs.readFile(gpa, "testdata/handoffs/packet.ndjson", store.MaxFileReadBytes);
        defer gpa.free(raw);
        try mfs.writeFileSafe(gpa, "/host/fix/packet.ndjson", raw);
        const out = try runOut(h, gpa, &.{ "handoff", "verify", "/host/fix/packet.ndjson" }, 0);
        defer gpa.free(out);
        try std.testing.expect(std.mem.indexOf(u8, out, "kind=propose sig: verified") != null);
        try std.testing.expect(std.mem.indexOf(u8, out, "kind=attest sig: verified") != null);
        try std.testing.expectEqual(@as(usize, 2), countOccurrences(out, "flint: verify "));
    }

    // Tampered sig → line printed, exit 1. Torn → handoff_torn. Unknown
    // format → handoff_malformed. Attestor mismatch → handoff_malformed.
    {
        const raw = try fs.readFile(gpa, "testdata/handoffs/tampered.json", store.MaxFileReadBytes);
        defer gpa.free(raw);
        try mfs.writeFileSafe(gpa, "/host/fix/tampered.json", raw);
        const res = try h.runCmd(&.{ "handoff", "verify", "/host/fix/tampered.json" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expect(std.mem.indexOf(u8, res.out, "sig_invalid") != null);
    }
    {
        const raw = try fs.readFile(gpa, "testdata/handoffs/torn.jsonl", store.MaxFileReadBytes);
        defer gpa.free(raw);
        try mfs.writeFileSafe(gpa, "/host/fix/torn.jsonl", raw);
        const res = try h.runCmd(&.{ "handoff", "verify", "/host/fix/torn.jsonl" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse handoff_torn\n", res.out);
    }
    {
        const raw = try fs.readFile(gpa, "testdata/handoffs/unknown-version.json", store.MaxFileReadBytes);
        defer gpa.free(raw);
        try mfs.writeFileSafe(gpa, "/host/fix/unknown.json", raw);
        const res = try h.runCmd(&.{ "handoff", "verify", "/host/fix/unknown.json" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse handoff_malformed unknown format\n", res.out);
    }
    {
        const raw = try fs.readFile(gpa, "testdata/handoffs/attestor-mismatch.json", store.MaxFileReadBytes);
        defer gpa.free(raw);
        try mfs.writeFileSafe(gpa, "/host/fix/mismatch.json", raw);
        const res = try h.runCmd(&.{ "handoff", "verify", "/host/fix/mismatch.json" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        try std.testing.expectEqualStrings("flint: refuse handoff_malformed attestor mismatch\n", res.out);
    }
}

/// Copies `src_rel` (a file or directory, recursively) between two harness
/// stores — the offline "receiver already pulled" half of the §9 flow.
fn copyStorePath(
    gpa: Allocator,
    src_fs: fsys.FS,
    dst_fs: fsys.FS,
    src_root: []const u8,
    dst_root: []const u8,
    rel: []const u8,
) !void {
    const sp = try fsys.joinPath(gpa, &.{ src_root, rel });
    defer gpa.free(sp);
    const dp = try fsys.joinPath(gpa, &.{ dst_root, rel });
    defer gpa.free(dp);
    if (!src_fs.exists(gpa, sp)) return;
    if (src_fs.isDir(gpa, sp)) {
        try dst_fs.mkdir(gpa, dp);
        const entries = try src_fs.list(gpa, sp);
        defer fsys.FS.freeDirEntries(gpa, entries);
        for (entries) |e| {
            const child = try fsys.joinPath(gpa, &.{ rel, e.name });
            defer gpa.free(child);
            try copyStorePath(gpa, src_fs, dst_fs, src_root, dst_root, child);
        }
    } else {
        const b = try src_fs.readFile(gpa, sp, store.MaxFileReadBytes);
        defer gpa.free(b);
        try dst_fs.writeFileSafe(gpa, dp, b);
    }
}

/// Copies one stream's record plus log between harness stores.
fn copyStream(gpa: Allocator, src_fs: fsys.FS, dst_fs: fsys.FS, src_root: []const u8, dst_root: []const u8, sid: []const u8) !void {
    for ([_][]const u8{ "json", "jsonl" }) |ext| {
        const rel = try std.fmt.allocPrint(gpa, "streams/{s}.{s}", .{ sid, ext });
        defer gpa.free(rel);
        try copyStorePath(gpa, src_fs, dst_fs, src_root, dst_root, rel);
    }
}

test "handoff packet: export → verify → import round trip; re-import dedupes" {
    const gpa = std.testing.allocator;
    var h = try TestHarness.init(gpa);
    defer h.deinit();
    h.env_sign_key = rfc8032_seed_hex;
    const mfs = h.mem.fs();

    const base = try setupTwoStreams(h, gpa, mfs);
    defer gpa.free(base);
    const p_out = try runOut(h, gpa, &.{
        "handoff", "propose", "--stream=main", "--work=a-work", "-m", "packet me",
    }, 0);
    defer gpa.free(p_out);
    const hid = try handoffId(gpa, p_out);
    defer gpa.free(hid);
    try runExpect(h, gpa, &.{
        "handoff", "attest", hid, "--command=zig build test", "--result=pass",
    }, 0);

    // §7 export — header + records + the candidate's detached ancestry.
    {
        const out = try runOut(h, gpa, &.{
            "handoff", "export", hid, "--out=/host/packet.ndjson", "--with-changes",
        }, 0);
        defer gpa.free(out);
        try std.testing.expect(std.mem.indexOf(u8, out, "records=2 changes=1") != null);
    }
    const packet = try mfs.readFile(gpa, "/host/packet.ndjson", store.MaxFileReadBytes);
    defer gpa.free(packet);
    try std.testing.expect(std.mem.startsWith(u8, packet, "{\"format\":\"FLINT-HANDOFF-PACKET/1\""));
    try std.testing.expect(std.mem.indexOf(u8, packet, "\"records\":2,\"changes\":1") != null);
    {
        const out = try runOut(h, gpa, &.{ "handoff", "verify", "/host/packet.ndjson" }, 0);
        defer gpa.free(out);
        try std.testing.expectEqual(@as(usize, 3), countOccurrences(out, "sig: verified"));
        try std.testing.expectEqual(@as(usize, 1), countOccurrences(out, "flint: verify "));
    }

    // --out=- streams the packet to stdout; the ok line lands on stderr.
    {
        const res = try h.runCmd(&.{ "handoff", "export", hid, "--out=-" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        try std.testing.expect(std.mem.startsWith(u8, res.out, "{\"format\":\"FLINT-HANDOFF-PACKET/1\""));
        try std.testing.expect(std.mem.indexOf(u8, res.out, "\"changes\":0") != null);
        try std.testing.expect(std.mem.startsWith(u8, h.last_err.items, "flint: handoff export "));
    }

    const sid = try streamIdByName(gpa, mfs, h.root, "main");
    defer gpa.free(sid);
    const awid = try streamIdByName(gpa, mfs, h.root, "a-work");
    defer gpa.free(awid);

    // Receiver store: holds main only (record + log). The work stream is
    // absent — import must create it from the header and deposit the
    // candidate's ancestry.
    var h2 = try TestHarness.init(gpa);
    defer h2.deinit();
    const mfs2 = h2.mem.fs();
    try copyStream(gpa, mfs, mfs2, h.root, h2.root, sid);
    try mfs2.writeFileSafe(gpa, "/host/packet.ndjson", packet);

    {
        const out = try runOut(h2, gpa, &.{ "handoff", "import", "/host/packet.ndjson" }, 0);
        defer gpa.free(out);
        const want = try std.fmt.allocPrint(gpa, "flint: handoff import {s} records=2 changes=1\n", .{hid});
        defer gpa.free(want);
        try std.testing.expectEqualStrings(want, out);
    }

    // The work stream record came from the header plus verified fork data:
    // the first bundled Change's parent resolves in main's log.
    {
        var idx2 = try store.loadStoreIndex(gpa, mfs2, h2.root);
        defer idx2.deinit();
        const w = idx2.streamByID(awid).?;
        try std.testing.expectEqualStrings("a-work", w.name);
        try std.testing.expectEqualStrings(sid, w.forked_from.?.stream);
        try std.testing.expectEqualStrings(base, w.forked_from.?.change);
        try std.testing.expect(w.head == null);
    }

    // Record bytes landed verbatim on the target's handoffs log; the
    // candidate's Change line sits detached on the work stream's log.
    {
        const rlog_path = try store.handoffLogPath(gpa, h2.root, sid);
        defer gpa.free(rlog_path);
        const got = try mfs2.readFile(gpa, rlog_path, store.MaxFileReadBytes);
        defer gpa.free(got);
        const olog_path = try store.handoffLogPath(gpa, h.root, sid);
        defer gpa.free(olog_path);
        const want = try mfs.readFile(gpa, olog_path, store.MaxFileReadBytes);
        defer gpa.free(want);
        try std.testing.expectEqualStrings(want, got);
        const wlog_path = try store.streamLogPath(gpa, h2.root, awid);
        defer gpa.free(wlog_path);
        const wlog = try mfs2.readFile(gpa, wlog_path, store.MaxFileReadBytes);
        defer gpa.free(wlog);
        try std.testing.expectEqual(@as(usize, 1), countOccurrences(wlog, "\n"));
    }

    // Ancestry resolves through the deposit; captured content is absent, so
    // the honest verdict is incomplete — not silently ready.
    {
        const out = try runOut(h2, gpa, &.{ "handoff", "inspect", hid }, 0);
        defer gpa.free(out);
        try std.testing.expect(std.mem.indexOf(u8, out, "state=proposed verdict=incomplete") != null);
    }

    // Re-import of the same packet is a no-op, not an error.
    {
        const out = try runOut(h2, gpa, &.{ "handoff", "import", "/host/packet.ndjson" }, 0);
        defer gpa.free(out);
        try std.testing.expect(std.mem.indexOf(u8, out, "records=0 changes=0") != null);
    }
}

test "handoff packet: receiver holding the bundle verdicts ready after import" {
    const gpa = std.testing.allocator;
    var h = try TestHarness.init(gpa);
    defer h.deinit();
    h.env_sign_key = rfc8032_seed_hex;
    const mfs = h.mem.fs();

    const base = try setupTwoStreams(h, gpa, mfs);
    defer gpa.free(base);
    const p_out = try runOut(h, gpa, &.{
        "handoff", "propose", "--stream=main", "--work=a-work", "-m", "bundle path",
    }, 0);
    defer gpa.free(p_out);
    const hid = try handoffId(gpa, p_out);
    defer gpa.free(hid);

    try runExpect(h, gpa, &.{ "handoff", "export", hid, "--out=/host/packet.ndjson" }, 0);
    const packet = try mfs.readFile(gpa, "/host/packet.ndjson", store.MaxFileReadBytes);
    defer gpa.free(packet);
    try std.testing.expect(std.mem.indexOf(u8, packet, "\"changes\":0") != null);

    const sid = try streamIdByName(gpa, mfs, h.root, "main");
    defer gpa.free(sid);
    const awid = try streamIdByName(gpa, mfs, h.root, "a-work");
    defer gpa.free(awid);

    // Receiver holds both streams' history and the work stream's captured
    // content — the companion-bundle half of §7 (packet carries changes=0).
    var h2 = try TestHarness.init(gpa);
    defer h2.deinit();
    const mfs2 = h2.mem.fs();
    try copyStream(gpa, mfs, mfs2, h.root, h2.root, sid);
    try copyStream(gpa, mfs, mfs2, h.root, h2.root, awid);
    try copyStorePath(gpa, mfs, mfs2, h.root, h2.root, "manifests");
    try copyStorePath(gpa, mfs, mfs2, h.root, h2.root, "blobs");
    try mfs2.writeFileSafe(gpa, "/host/packet.ndjson", packet);

    const i_out = try runOut(h2, gpa, &.{ "handoff", "import", "/host/packet.ndjson" }, 0);
    defer gpa.free(i_out);
    try std.testing.expect(std.mem.indexOf(u8, i_out, "records=1 changes=0") != null);

    const ins = try runOut(h2, gpa, &.{ "handoff", "inspect", hid }, 0);
    defer gpa.free(ins);
    try std.testing.expect(std.mem.indexOf(u8, ins, "state=proposed verdict=ready") != null);
}

test "handoff packet: the golden fixture imports into a store holding only the target" {
    const gpa = std.testing.allocator;
    var host_fs = fsys.HostFS.init(std.testing.io);
    const fs = host_fs.fs();

    var h = try TestHarness.init(gpa);
    defer h.deinit();
    const mfs = h.mem.fs();

    const target_id = "019a0000-0001-7000-8000-0000000000aa";
    const work_id = "019a0000-0002-7000-8000-0000000000bb";

    // The receiver holds the target stream record but neither the work
    // stream nor the base Change — the records land, ancestry stays
    // honestly incomplete.
    const st = store.Stream{
        .id = target_id,
        .name = "main",
        .head = null,
        .created = 1760000000000,
        .forked_from = null,
    };
    const rec_path = try store.streamRecordPath(gpa, h.root, target_id);
    defer gpa.free(rec_path);
    {
        const line = try json.marshalStreamLine(gpa, st);
        defer gpa.free(line);
        try mfs.writeFileSafe(gpa, rec_path, line);
    }

    const raw = try fs.readFile(gpa, "testdata/handoffs/packet.ndjson", store.MaxFileReadBytes);
    defer gpa.free(raw);
    try mfs.writeFileSafe(gpa, "/host/fix/packet.ndjson", raw);

    {
        const out = try runOut(h, gpa, &.{ "handoff", "import", "/host/fix/packet.ndjson" }, 0);
        defer gpa.free(out);
        try std.testing.expectEqualStrings(
            "flint: handoff import 019a0000-0006-7000-8000-000000000010 records=2 changes=2\n",
            out,
        );
    }

    // Genesis chain: the first bundled Change has no parent, so the created
    // work stream carries no fork origin and no head movement.
    {
        var idx = try store.loadStoreIndex(gpa, mfs, h.root);
        defer idx.deinit();
        const w = idx.streamByID(work_id).?;
        try std.testing.expectEqualStrings("a-work", w.name);
        try std.testing.expect(w.forked_from == null);
        try std.testing.expect(w.head == null);
    }
    {
        const out = try runOut(h, gpa, &.{ "handoff", "inspect", "019a0000-0006-7000-8000-000000000010" }, 0);
        defer gpa.free(out);
        try std.testing.expect(std.mem.indexOf(u8, out, "verdict=incomplete") != null);
        try std.testing.expect(std.mem.indexOf(u8, out, "sig=verified") != null);
    }
    // Re-import dedupes both sections.
    {
        const out = try runOut(h, gpa, &.{ "handoff", "import", "/host/fix/packet.ndjson" }, 0);
        defer gpa.free(out);
        try std.testing.expect(std.mem.indexOf(u8, out, "records=0 changes=0") != null);
    }
}

test "handoff packet: import refusals verify-before-write and leave nothing behind" {
    const gpa = std.testing.allocator;
    var h = try TestHarness.init(gpa);
    defer h.deinit();
    h.env_sign_key = rfc8032_seed_hex;
    const mfs = h.mem.fs();

    const base = try setupTwoStreams(h, gpa, mfs);
    defer gpa.free(base);
    const p_out = try runOut(h, gpa, &.{
        "handoff", "propose", "--stream=main", "--work=a-work", "-m", "refusal path",
    }, 0);
    defer gpa.free(p_out);
    const hid = try handoffId(gpa, p_out);
    defer gpa.free(hid);
    const sid = try streamIdByName(gpa, mfs, h.root, "main");
    defer gpa.free(sid);

    // Export refusals.
    try expectRefuse(h, gpa, &.{
        "handoff", "export", "019a0000-0000-7000-8000-000000000000", "--out=/host/x",
    }, "flint: refuse handoff_missing");
    {
        // A missing --out is a usage refusal — exit 2, not 1.
        const res = try h.runCmd(&.{ "handoff", "export", hid });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 2), res.rc);
        try std.testing.expectEqualStrings("flint: refuse usage\n", res.out);
    }

    try runExpect(h, gpa, &.{ "handoff", "export", hid, "--out=/host/packet.ndjson", "--with-changes" }, 0);
    const packet = try mfs.readFile(gpa, "/host/packet.ndjson", store.MaxFileReadBytes);
    defer gpa.free(packet);

    // Receiver holding only main.
    var h2 = try TestHarness.init(gpa);
    defer h2.deinit();
    const mfs2 = h2.mem.fs();
    try copyStream(gpa, mfs, mfs2, h.root, h2.root, sid);
    try mfs2.writeFileSafe(gpa, "/host/packet.ndjson", packet);

    // A store with no matching target stream refuses stream_missing. A
    // fresh seed keeps the deterministic uuids from colliding with h's.
    var h3 = try TestHarness.init(gpa);
    defer h3.deinit();
    h3.rng_seed = 77;
    const mfs3 = h3.mem.fs();
    try mfs3.writeFileSafe(gpa, "/host/src/f.go", "package f\n");
    try runExpect(h3, gpa, &.{ "init", "--name=w3", "--src=/host/src" }, 0);
    try mfs3.writeFileSafe(gpa, "/host/packet.ndjson", packet);
    try expectRefuse(h3, gpa, &.{ "handoff", "import", "/host/packet.ndjson" }, "flint: refuse stream_missing");

    // A store holding the target but not the bundled ancestry's root parent
    // refuses `detached parent unknown` — the create-stream trick needs
    // verified fork data.
    var h4 = try TestHarness.init(gpa);
    defer h4.deinit();
    const mfs4 = h4.mem.fs();
    {
        const rel = try std.fmt.allocPrint(gpa, "streams/{s}.json", .{sid});
        defer gpa.free(rel);
        try copyStorePath(gpa, mfs, mfs4, h.root, h4.root, rel);
    }
    try mfs4.writeFileSafe(gpa, "/host/packet.ndjson", packet);
    try expectRefuse(h4, gpa, &.{ "handoff", "import", "/host/packet.ndjson" }, "flint: refuse change_malformed detached parent unknown");

    // A torn packet refuses before a byte lands.
    {
        const torn = try gpa.dupe(u8, packet[0 .. packet.len - 1]);
        defer gpa.free(torn);
        try mfs2.writeFileSafe(gpa, "/host/torn.ndjson", torn);
        try expectRefuse(h2, gpa, &.{ "handoff", "import", "/host/torn.ndjson" }, "flint: refuse handoff_torn");
    }

    // Count mismatch in the header refuses handoff_malformed.
    {
        const bad = try std.mem.replaceOwned(u8, gpa, packet, "\"records\":1", "\"records\":9");
        defer gpa.free(bad);
        try mfs2.writeFileSafe(gpa, "/host/badcount.ndjson", bad);
        try expectRefuse(h2, gpa, &.{
            "handoff", "import", "/host/badcount.ndjson",
        }, "flint: refuse handoff_malformed count mismatch");
    }

    // A tampered record signature refuses sig_invalid and writes nothing —
    // the handoffs directory must not exist afterwards.
    {
        const mut = try gpa.dupe(u8, packet);
        defer gpa.free(mut);
        const at = std.mem.indexOf(u8, mut, "\"sig\":\"").? + "\"sig\":\"".len;
        mut[at] = if (mut[at] == '0') '1' else '0';
        try mfs2.writeFileSafe(gpa, "/host/tampered.ndjson", mut);
        try expectRefuse(h2, gpa, &.{ "handoff", "import", "/host/tampered.ndjson" }, "flint: refuse sig_invalid");
        const hdir = try store.handoffsDir(gpa, h2.root);
        defer gpa.free(hdir);
        try std.testing.expect(!mfs2.exists(gpa, hdir));
    }

    // Valid import, then a same-id record under different bytes refuses
    // `id conflict` — re-signing under another key changes author+sig while
    // keeping the record id.
    try runExpect(h2, gpa, &.{ "handoff", "import", "/host/packet.ndjson" }, 0);
    {
        // Another key — different author+sig bytes under the same record id.
        const other_seed = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
        var it = std.mem.splitScalar(u8, packet, '\n');
        _ = it.next(); // header
        const rec_line = it.next().?;
        var rec = try json.parseHandoffRecord(gpa, rec_line);
        defer rec.deinit(gpa);
        // signRecordLine owns and frees author/sig — sign a shallow copy so
        // `rec` stays intact for deinit.
        var signed = rec;
        signed.author = "";
        signed.sig = "";
        const relined = try signRecordLine(gpa, other_seed, &signed);
        defer gpa.free(relined);
        const conflict = try std.mem.replaceOwned(u8, gpa, packet, rec_line, relined[0 .. relined.len - 1]);
        defer gpa.free(conflict);
        try mfs2.writeFileSafe(gpa, "/host/conflict.ndjson", conflict);
        try expectRefuse(h2, gpa, &.{
            "handoff", "import", "/host/conflict.ndjson",
        }, "flint: refuse handoff_malformed id conflict");
    }

    // A packet whose bundled Change stream does not match the header's
    // work id — rewrite only the header so the Change line still carries
    // the real one.
    {
        const awid = try streamIdByName(gpa, mfs, h.root, "a-work");
        defer gpa.free(awid);
        const hdr_work = try std.fmt.allocPrint(gpa, "\"work\":{{\"id\":\"{s}\"", .{awid});
        defer gpa.free(hdr_work);
        const bad = try std.mem.replaceOwned(u8, gpa, packet, hdr_work, "\"work\":{\"id\":\"019a0000-0009-7000-8000-0000000000ff\"");
        defer gpa.free(bad);
        try mfs2.writeFileSafe(gpa, "/host/workmismatch.ndjson", bad);
        try expectRefuse(h2, gpa, &.{
            "handoff", "import", "/host/workmismatch.ndjson",
        }, "flint: refuse handoff_malformed work mismatch");
    }
}

fn countOccurrences(haystack: []const u8, needle: []const u8) usize {
    var n: usize = 0;
    var i: usize = 0;
    while (std.mem.indexOfPos(u8, haystack, i, needle)) |pos| {
        n += 1;
        i = pos + 1;
    }
    return n;
}
