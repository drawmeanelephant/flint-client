//! `--json` result-envelope CLI coverage (docs/flint-json-results-spec.md).
//! Sync-side scenarios (push/pull/clone, lost append acks) live in
//! `sync_scenarios_test.zig`.
const std = @import("std");
const Allocator = std.mem.Allocator;
const store = @import("store.zig");

const main = @import("main.zig");
const TestHarness = main.TestHarness;
const rfc8032_seed_hex = main.rfc8032_seed_hex;

/// Parses a `--json` envelope for assertions; the envelope must be exactly
/// one JSON object followed by a newline and nothing else.
fn parseJsonResult(gpa: Allocator, out: []const u8) !std.json.Parsed(std.json.Value) {
    try std.testing.expect(std.mem.endsWith(u8, out, "\n"));
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, out, "\n"));
    return std.json.parseFromSlice(std.json.Value, gpa, out, .{});
}

fn jsonStr(v: std.json.Value, key: []const u8) []const u8 {
    return v.object.get(key).?.string;
}

fn jsonInt(v: std.json.Value, key: []const u8) i64 {
    return v.object.get(key).?.integer;
}

test "--json: status/add/commit/verify envelopes carry structured results (#79)" {
    const gpa = std.testing.allocator;
    var h = try TestHarness.init(gpa);
    defer h.deinit();
    h.env_sign_key = rfc8032_seed_hex;
    const mfs = h.mem.fs();

    try mfs.writeFileSafe(gpa, "/host/SRJ/calc.go", "package calc\n\nfunc X() int {\n\treturn 1\n}\n");
    {
        const res = try h.runCmd(&.{ "init", "--name=a", "--src=/host/SRJ" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }

    // status on a fresh workspace: clean, nothing staged.
    {
        const res = try h.runCmd(&.{ "status", "--json" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        var p = try parseJsonResult(gpa, res.out);
        defer p.deinit();
        const o = p.value;
        try std.testing.expectEqual(@as(i64, 1), jsonInt(o, "v"));
        try std.testing.expectEqualStrings("status", jsonStr(o, "verb"));
        try std.testing.expect(o.object.get("ok").?.bool);
        try std.testing.expectEqual(@as(i64, 0), jsonInt(o, "exit"));
        try std.testing.expectEqualStrings("ok", jsonStr(o, "kind"));
        try std.testing.expectEqualStrings("a", jsonStr(o, "workspace"));
        try std.testing.expectEqualStrings("main", jsonStr(o, "stream"));
        try std.testing.expectEqualStrings("unchanged", jsonStr(o, "local"));
        try std.testing.expect(o.object.get("remote").? == .null);
        const d = o.object.get("data").?.object;
        try std.testing.expectEqual(@as(i64, 0), jsonInt(.{ .object = d }, "atoms"));
        try std.testing.expectEqual(@as(i64, 0), jsonInt(.{ .object = d }, "staged"));
        try std.testing.expectEqual(@as(usize, 0), d.get("ops").?.array.items.len);
    }

    // add: one new atom, heads.base null (stream has no head yet).
    {
        const res = try h.runCmd(&.{ "add", "--json" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        var p = try parseJsonResult(gpa, res.out);
        defer p.deinit();
        const o = p.value;
        try std.testing.expectEqualStrings("add", jsonStr(o, "verb"));
        try std.testing.expectEqualStrings("applied", jsonStr(o, "local"));
        const heads = o.object.get("heads").?.object;
        try std.testing.expect(heads.get("base").? == .null);
        const d = o.object.get("data").?.object;
        try std.testing.expectEqual(@as(i64, 1), jsonInt(.{ .object = d }, "new"));
        try std.testing.expectEqual(@as(i64, 1), jsonInt(.{ .object = d }, "files"));
        const affected = d.get("affected").?.array.items;
        try std.testing.expectEqual(@as(usize, 1), affected.len);
        try std.testing.expectEqualStrings("calc.go", affected[0].string);
    }

    // status with a staged op: structured ops list, not prose.
    {
        const res = try h.runCmd(&.{ "status", "--json" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        var p = try parseJsonResult(gpa, res.out);
        defer p.deinit();
        const d = p.value.object.get("data").?.object;
        try std.testing.expectEqual(@as(i64, 1), jsonInt(.{ .object = d }, "staged"));
        try std.testing.expectEqual(@as(i64, 1), jsonInt(.{ .object = d }, "add"));
        const ops = d.get("ops").?.array.items;
        try std.testing.expectEqual(@as(usize, 1), ops.len);
        const op0 = ops[0].object;
        try std.testing.expectEqualStrings("add", op0.get("type").?.string);
        try std.testing.expectEqualStrings("calc.X", op0.get("name").?.string);
        try std.testing.expectEqualStrings("calc.go", op0.get("file").?.string);
        try std.testing.expect(op0.get("atom").?.string.len == 36);
    }

    // commit: new Change id surfaces via data.id, changes.affected and
    // heads.result.
    var commit_id: []u8 = &.{};
    defer if (commit_id.len > 0) gpa.free(commit_id);
    {
        const res = try h.runCmd(&.{ "commit", "--json", "-m", "c1" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        var p = try parseJsonResult(gpa, res.out);
        defer p.deinit();
        const o = p.value;
        try std.testing.expectEqualStrings("commit", jsonStr(o, "verb"));
        try std.testing.expectEqualStrings("applied", jsonStr(o, "local"));
        const heads = o.object.get("heads").?.object;
        const d = o.object.get("data").?.object;
        const id = d.get("id").?.string;
        try std.testing.expectEqualStrings(id, heads.get("result").?.string);
        try std.testing.expect(heads.get("base").? == .null);
        try std.testing.expectEqual(@as(i64, 1), jsonInt(.{ .object = d }, "ops"));
        try std.testing.expectEqualStrings("c1", d.get("message").?.string);
        try std.testing.expect(!d.get("merge_resolution").?.bool);
        try std.testing.expect(d.get("merged") == null);
        const affected = o.object.get("changes").?.object.get("affected").?.array.items;
        try std.testing.expectEqual(@as(usize, 1), affected.len);
        try std.testing.expectEqualStrings(id, affected[0].string);
        commit_id = try gpa.dupe(u8, id);
    }

    // verify --all: the committed change verifies.
    {
        const res = try h.runCmd(&.{ "verify", "--all", "--json" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
        var p = try parseJsonResult(gpa, res.out);
        defer p.deinit();
        const d = p.value.object.get("data").?.object;
        try std.testing.expectEqual(@as(i64, 1), jsonInt(.{ .object = d }, "verified"));
        try std.testing.expectEqual(@as(i64, 0), jsonInt(.{ .object = d }, "failed"));
        const ch = d.get("changes").?.array.items;
        try std.testing.expectEqual(@as(usize, 1), ch.len);
        try std.testing.expectEqualStrings(commit_id, ch[0].object.get("id").?.string);
        try std.testing.expectEqualStrings("verified", ch[0].object.get("sig").?.string);
    }

    // verify <id> on a missing change is a refusal, not a failed verdict.
    {
        const res = try h.runCmd(&.{ "verify", "0199de2d-dc00-7000-8000-000000000999", "--json" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        var p = try parseJsonResult(gpa, res.out);
        defer p.deinit();
        try std.testing.expectEqualStrings("refused", jsonStr(p.value, "kind"));
        try std.testing.expectEqualStrings("change_missing", p.value.object.get("refusal").?.object.get("name").?.string);
        try std.testing.expect(!p.value.object.get("ok").?.bool);
    }

    // verify on a tampered log: verdict negative -> kind failed, exit 1.
    {
        const log_path = blk: {
            var idx = try store.loadStoreIndex(gpa, mfs, h.root);
            defer idx.deinit();
            const st = idx.streamByName("main").?;
            break :blk try store.streamLogPath(gpa, h.root, st.id);
        };
        defer gpa.free(log_path);
        const good_raw = try mfs.readFile(gpa, log_path, store.MaxFileReadBytes);
        defer gpa.free(good_raw);
        // Flip a byte inside the signature so parsing succeeds but
        // verification fails.
        const sig_pos = std.mem.indexOf(u8, good_raw, "\"sig\":\"").? + 7;
        var bad = try gpa.dupe(u8, good_raw);
        defer gpa.free(bad);
        bad[sig_pos] = if (bad[sig_pos] == '0') '1' else '0';
        try mfs.writeFileSafe(gpa, "/host/scratch/badlog.jsonl", bad);
        const res = try h.runCmd(&.{ "verify", "--file=/host/scratch/badlog.jsonl", "--json" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        var p = try parseJsonResult(gpa, res.out);
        defer p.deinit();
        try std.testing.expectEqualStrings("failed", jsonStr(p.value, "kind"));
        const d = p.value.object.get("data").?.object;
        try std.testing.expectEqual(@as(i64, 1), jsonInt(.{ .object = d }, "failed"));
    }

    // Refused mutation: empty stage refuses nothing_to_commit (exit 1),
    // distinguishable from a usage refusal (exit 2) via refusal.name.
    {
        const res = try h.runCmd(&.{ "commit", "--json", "-m", "empty" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 1), res.rc);
        var p = try parseJsonResult(gpa, res.out);
        defer p.deinit();
        try std.testing.expectEqualStrings("refused", jsonStr(p.value, "kind"));
        try std.testing.expectEqualStrings("nothing_to_commit", p.value.object.get("refusal").?.object.get("name").?.string);
        // Workspace/stream context survives the refusal.
        try std.testing.expectEqualStrings("a", jsonStr(p.value, "workspace"));
    }
    {
        const res = try h.runCmd(&.{ "commit", "--json" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 2), res.rc);
        var p = try parseJsonResult(gpa, res.out);
        defer p.deinit();
        try std.testing.expectEqualStrings("refused", jsonStr(p.value, "kind"));
        try std.testing.expectEqualStrings("usage", p.value.object.get("refusal").?.object.get("name").?.string);
        try std.testing.expectEqual(@as(i64, 2), jsonInt(p.value, "exit"));
    }

    // No verb at all still answers with an envelope.
    {
        const res = try h.runCmd(&.{"--json"});
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 2), res.rc);
        var p = try parseJsonResult(gpa, res.out);
        defer p.deinit();
        try std.testing.expectEqualStrings("usage", p.value.object.get("refusal").?.object.get("name").?.string);
    }
}

test "--json: merge conflicts are structured, distinct from usage refusals" {
    const gpa = std.testing.allocator;
    var h = try TestHarness.init(gpa);
    defer h.deinit();
    h.env_sign_key = rfc8032_seed_hex;
    const mfs = h.mem.fs();

    const base_src = "package calc\n\nfunc X() int {\n\treturn 1\n}\n\nfunc Y() int {\n\treturn 2\n}\n";
    try mfs.writeFileSafe(gpa, "/host/SRCA/calc.go", base_src);
    try mfs.writeFileSafe(gpa, "/host/SRCB/calc.go", base_src);

    for ([_][]const []const u8{
        &.{ "init", "--name=a", "--src=/host/SRCA" },
        &.{ "add", "/host/SRCA" },
        &.{ "commit", "-m", "base" },
        &.{ "fork", "main", "feature" },
        &.{ "init", "--name=b", "--src=/host/SRCB", "--stream=feature" },
    }) |cmd| {
        const res = try h.runCmd(cmd);
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }

    try mfs.writeFileSafe(gpa, "/host/SRCB/calc.go", "package calc\n\nfunc X() int {\n\treturn 10\n}\n\nfunc Y() int {\n\treturn 2\n}\n");
    h.now += 5;
    for ([_][]const []const u8{
        &.{ "add", "/host/SRCB" },
        &.{ "commit", "--ws=b", "-m", "feat" },
    }) |cmd| {
        const res = try h.runCmd(cmd);
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }

    try mfs.writeFileSafe(gpa, "/host/SRCA/calc.go", "package calc\n\nfunc X() int {\n\treturn 99\n}\n\nfunc Y() int {\n\treturn 2\n}\n");
    h.now += 5;
    for ([_][]const []const u8{
        &.{ "add", "/host/SRCA" },
        &.{ "commit", "--ws=a", "-m", "main" },
    }) |cmd| {
        const res = try h.runCmd(cmd);
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 0), res.rc);
    }

    // Overlapping merge conflict: exit 2 like `usage`, but kind differs.
    {
        const res = try h.runCmd(&.{ "merge", "--json", "feature" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 2), res.rc);
        var p = try parseJsonResult(gpa, res.out);
        defer p.deinit();
        const o = p.value;
        try std.testing.expectEqualStrings("merge", jsonStr(o, "verb"));
        try std.testing.expectEqualStrings("conflicts", jsonStr(o, "kind"));
        try std.testing.expect(!o.object.get("ok").?.bool);
        try std.testing.expect(o.object.get("refusal").? == .null);
        try std.testing.expectEqualStrings("applied", jsonStr(o, "local"));
        const conflicts = o.object.get("conflicts").?.array.items;
        try std.testing.expectEqual(@as(usize, 1), conflicts.len);
        const c0 = conflicts[0].object;
        try std.testing.expectEqualStrings("calc.X", c0.get("name").?.string);
        try std.testing.expectEqualStrings("concurrent_modify", c0.get("type").?.string);
        try std.testing.expect(c0.get("atom").?.string.len == 36);
        const d = o.object.get("data").?.object;
        try std.testing.expectEqualStrings("feature", d.get("from").?.string);
        try std.testing.expect(d.get("from_head").?.string.len == 36);
        const heads = o.object.get("heads").?.object;
        try std.testing.expect(heads.get("base").?.string.len == 36);
        try std.testing.expect(heads.get("result").? == .null);
    }

    // Same exit code, different envelope: `merge` with no stream is a usage
    // refusal, not a conflict report.
    {
        const res = try h.runCmd(&.{ "merge", "--json" });
        defer gpa.free(res.out);
        try std.testing.expectEqual(@as(u8, 2), res.rc);
        var p = try parseJsonResult(gpa, res.out);
        defer p.deinit();
        try std.testing.expectEqualStrings("refused", jsonStr(p.value, "kind"));
        try std.testing.expectEqualStrings("usage", p.value.object.get("refusal").?.object.get("name").?.string);
        try std.testing.expect(p.value.object.get("conflicts").? == .null);
    }
}

const fsys = @import("fsys.zig");

/// The schema's fixed envelope key order — also the conformance order for
/// testdata/results fixtures.
const envelope_keys = [_][]const u8{
    "v",     "verb",    "ok",        "exit",    "kind",  "workspace", "stream",
    "heads", "changes", "conflicts", "refusal", "error", "local",     "remote",
    "data",
};

fn expectJsonType(v: std.json.Value, comptime allowed: []const std.meta.Tag(std.json.Value), path: []const u8) !void {
    inline for (allowed) |tag| {
        if (v == tag) return;
    }
    std.debug.print("fixture field {s} has unexpected type\n", .{path});
    return error.TestUnexpectedResult;
}

test "--json: testdata/results fixtures match the frozen envelope schema" {
    const gpa = std.testing.allocator;
    var host_fs = fsys.HostFS.init(std.testing.io);
    const fs = host_fs.fs();

    const fixture_names = [_][]const u8{
        "commit-ok",
        "status-noop",
        "refused-nothing-to-commit",
        "merge-conflicts",
        "push-lost-ack",
        "push-partial",
        "pull-unknown",
    };

    const kind_ok = std.StaticStringMap(void).initComptime(.{
        .{"ok"},        .{"noop"},   .{"refused"},
        .{"conflicts"}, .{"failed"}, .{"error"},
    });
    const outcomes = std.StaticStringMap(void).initComptime(.{
        .{"unchanged"}, .{"applied"}, .{"partial"}, .{"unknown"},
    });

    for (fixture_names) |name| {
        const path = try std.fmt.allocPrint(gpa, "testdata/results/{s}.json", .{name});
        defer gpa.free(path);
        const raw = try fs.readFile(gpa, path, store.MaxFileReadBytes);
        defer gpa.free(raw);

        // Framing: one complete object, newline-terminated, single line.
        try std.testing.expect(std.mem.endsWith(u8, raw, "\n"));
        try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, raw, "\n"));

        var p = try std.json.parseFromSlice(std.json.Value, gpa, raw, .{});
        defer p.deinit();
        const o = p.value.object;

        // Fixed envelope keys, in order.
        const keys = o.keys();
        try std.testing.expectEqual(envelope_keys.len, keys.len);
        for (envelope_keys, keys) |want, got| {
            try std.testing.expectEqualStrings(want, got);
        }

        try std.testing.expectEqual(@as(i64, 1), o.get("v").?.integer);
        try std.testing.expect(o.get("verb").?.string.len > 0);
        try std.testing.expect(o.get("ok").? == .bool);
        try std.testing.expectEqual(o.get("ok").?.bool, o.get("exit").?.integer == 0);
        const kind = o.get("kind").?.string;
        try std.testing.expect(kind_ok.has(kind));

        // kind/refusal/error invariants.
        const refusal = o.get("refusal").?;
        const errv = o.get("error").?;
        if (std.mem.eql(u8, kind, "refused")) {
            try std.testing.expect(refusal == .object);
            try std.testing.expect(refusal.object.get("name").?.string.len > 0);
        } else {
            try std.testing.expect(refusal == .null);
        }
        if (std.mem.eql(u8, kind, "error")) {
            try std.testing.expect(errv == .object);
            try std.testing.expect(errv.object.get("name").?.string.len > 0);
        } else {
            try std.testing.expect(errv == .null);
        }
        if (std.mem.eql(u8, kind, "conflicts")) {
            try std.testing.expect(o.get("conflicts").? == .array);
        }

        try expectJsonType(o.get("local").?, &.{.string}, "local");
        try std.testing.expect(outcomes.has(o.get("local").?.string));

        if (o.get("remote")) |rv| {
            if (rv == .object) {
                try std.testing.expect(outcomes.has(rv.object.get("outcome").?.string));
                try expectJsonType(rv.object.get("sent").?, &.{.integer}, "remote.sent");
                try expectJsonType(rv.object.get("received").?, &.{.integer}, "remote.received");
            }
        }
        try expectJsonType(o.get("data").?, &.{.object}, "data");
    }
}
