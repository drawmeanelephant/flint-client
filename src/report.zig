const std = @import("std");
const Allocator = std.mem.Allocator;
const json = @import("json.zig");

/// Versioned JSON result envelope for `flint --json` — see
/// docs/flint-json-results-spec.md. One envelope per invocation on stdout;
/// verb implementations populate a Report as they compute results and the
/// CLI marshals it once at the end (never re-parses text output).
pub const SchemaVersion: u32 = 1;

/// Ordered id/path lists emit at most this many entries; the remainder is
/// counted in a sibling `<list>_omitted` key (spec §7).
pub const MaxListEntries: usize = 256;

/// Envelope serialization must stay under this bound (spec §7).
pub const MaxResultBytes: usize = 64 * 1024;

pub const Kind = enum {
    ok,
    noop,
    conflicts,
    refused,
    failed,
    err,

    fn name(self: Kind) []const u8 {
        return switch (self) {
            .ok => "ok",
            .noop => "noop",
            .conflicts => "conflicts",
            .refused => "refused",
            .failed => "failed",
            .err => "error",
        };
    }
};

pub const Outcome = enum {
    unchanged,
    applied,
    partial,
    unknown,

    fn name(self: Outcome) []const u8 {
        return @tagName(self);
    }
};

pub const Conflict = struct {
    atom_id: []const u8,
    name: []const u8,
    type: []const u8,
};

/// The active report for the current command, or null in text mode.
/// Verb implementations populate it unconditionally through `if (report.active)`
/// blocks; in `--json` mode `main.zig` installs one before dispatch and
/// marshals it after. Follows the `fsys.last_refuse` threadlocal convention.
pub threadlocal var active: ?*Report = null;

pub const Report = struct {
    arena: std.heap.ArenaAllocator,
    verb: []const u8,
    kind: Kind = .ok,
    exit_code: u8 = 0,

    workspace: ?[]const u8 = null,
    stream: ?[]const u8 = null,

    heads_set: bool = false,
    base_head: ?[]const u8 = null,
    result_head: ?[]const u8 = null,
    remote_head: ?[]const u8 = null,

    refusal_name: ?[]const u8 = null,
    refusal_detail: ?[]const u8 = null,
    error_name: ?[]const u8 = null,

    local: ?Outcome = null,
    local_writes_done: usize = 0,
    local_may_write: bool = false,

    remote_url: ?[]const u8 = null,
    remote_outcome: ?Outcome = null,
    remote_error_outcome: ?Outcome = null,
    remote_sent: usize = 0,
    remote_received: usize = 0,
    remote_spec_rev: ?u32 = null,
    remote_confirmed: usize = 0,
    remote_pending: bool = false,

    affected: std.ArrayList([]const u8) = .empty,
    affected_omitted: usize = 0,
    conflicts: ?std.ArrayList(Conflict) = null,
    conflicts_omitted: usize = 0,

    data: std.ArrayList(u8) = .empty,
    data_fields: usize = 0,

    pub fn init(gpa: Allocator, verb: []const u8) Report {
        return .{
            .arena = std.heap.ArenaAllocator.init(gpa),
            .verb = verb,
        };
    }

    pub fn deinit(self: *Report) void {
        self.data.deinit(self.a());
        self.affected.deinit(self.a());
        if (self.conflicts) |*c| c.deinit(self.a());
        self.arena.deinit();
    }

    fn a(self: *Report) Allocator {
        return self.arena.allocator();
    }

    fn dupe(self: *Report, s: []const u8) ![]u8 {
        return self.a().dupe(u8, s);
    }

    /// Records the resolved workspace/stream names (either may be null when
    /// only one was resolved).
    pub fn setScope(self: *Report, ws: ?[]const u8, stream_name: ?[]const u8) !void {
        if (ws) |w| self.workspace = try self.dupe(w);
        if (stream_name) |s| self.stream = try self.dupe(s);
    }

    /// `heads.base` — the head the operation observed/asserted before acting.
    /// `h` may be null: an observed empty head is distinct from no observation.
    pub fn observeBaseHead(self: *Report, h: ?[]const u8) !void {
        self.heads_set = true;
        self.base_head = if (h) |x| try self.dupe(x) else null;
    }

    /// `heads.result` — the resulting head after the operation.
    pub fn observeResultHead(self: *Report, h: ?[]const u8) !void {
        self.heads_set = true;
        self.result_head = if (h) |x| try self.dupe(x) else null;
    }

    /// `heads.remote` — the last head the remote confirmed or advertised.
    pub fn observeRemoteHead(self: *Report, h: ?[]const u8) !void {
        self.heads_set = true;
        self.remote_head = if (h) |x| try self.dupe(x) else null;
    }

    pub fn setRefusal(self: *Report, name: []const u8, detail: []const u8) !void {
        self.kind = .refused;
        self.refusal_name = try self.dupe(name);
        self.refusal_detail = if (detail.len > 0) try self.dupe(detail) else null;
    }

    pub fn setError(self: *Report, name: []const u8) !void {
        self.kind = .err;
        self.error_name = try self.dupe(name);
    }

    pub fn setKind(self: *Report, k: Kind) void {
        self.kind = k;
    }

    // -- local outcome tracking -------------------------------------------------

    /// Mark the start of the local write section: a later non-refusal error
    /// can no longer report `unchanged`.
    pub fn beginLocalWrites(self: *Report) void {
        self.local_may_write = true;
    }

    /// One local write completed; on later failure `local` reports `partial`.
    pub fn noteLocalWriteDone(self: *Report) void {
        self.local_writes_done += 1;
    }

    /// The operation's local writes completed — success paths.
    pub fn localApplied(self: *Report) void {
        self.local_may_write = true;
        self.local = .applied;
    }

    // -- remote tracking ---------------------------------------------------------

    /// The resolved remote URL; makes the `remote` block appear.
    pub fn setRemoteUrl(self: *Report, url: []const u8) !void {
        self.remote_url = try self.dupe(url);
    }

    pub fn setRemoteSpecRev(self: *Report, rev: ?u32) void {
        self.remote_spec_rev = rev;
    }

    /// Fallback `remote.outcome` for non-refusal errors on read-only remote
    /// verbs (`pull`, `clone`): the remote state could not be fully observed.
    pub fn setRemoteErrorOutcome(self: *Report, o: Outcome) void {
        self.remote_error_outcome = o;
    }

    /// A mutating remote request (create/append/deposit) is about to be sent.
    /// If it fails without a wire refusal the outcome is uncertain.
    pub fn remoteAttemptBegin(self: *Report) void {
        self.remote_pending = true;
    }

    /// The remote confirmed a mutation.
    pub fn remoteAttemptApplied(self: *Report) void {
        self.remote_pending = false;
        self.remote_confirmed += 1;
    }

    /// The remote actively refused a mutation — no remote change.
    pub fn remoteAttemptRefused(self: *Report) void {
        self.remote_pending = false;
    }

    /// `n` Change lines were confirmed stored remotely.
    pub fn noteRemoteSent(self: *Report, n: usize) void {
        self.remote_sent += n;
    }

    /// `n` Change lines were fetched and stored locally.
    pub fn noteRemoteReceived(self: *Report, n: usize) void {
        self.remote_received += n;
    }

    // -- affected changes / conflicts ---------------------------------------------

    /// A Change id created, published, or received by this invocation.
    pub fn noteAffected(self: *Report, id: []const u8) !void {
        if (self.affected.items.len >= MaxListEntries) {
            self.affected_omitted += 1;
            return;
        }
        try self.affected.append(self.a(), try self.dupe(id));
    }

    /// Emit the `conflicts` array (possibly empty) — merge always emits one.
    pub fn beginConflicts(self: *Report) void {
        if (self.conflicts == null) self.conflicts = .empty;
    }

    pub fn noteConflict(self: *Report, atom_id: []const u8, name: []const u8, ctype: []const u8) !void {
        self.beginConflicts();
        if (self.conflicts.?.items.len >= MaxListEntries) {
            self.conflicts_omitted += 1;
            return;
        }
        try self.conflicts.?.append(self.a(), .{
            .atom_id = try self.dupe(atom_id),
            .name = try self.dupe(name),
            .type = try self.dupe(ctype),
        });
    }

    // -- per-verb `data` payload ---------------------------------------------------

    fn dataKey(self: *Report, name: []const u8) !void {
        if (self.data_fields > 0) try self.data.append(self.a(), ',');
        try json.appendGoJSONString(&self.data, self.a(), name);
        try self.data.append(self.a(), ':');
        self.data_fields += 1;
    }

    pub fn fieldStr(self: *Report, name: []const u8, value: []const u8) !void {
        try self.dataKey(name);
        try json.appendGoJSONString(&self.data, self.a(), value);
    }

    /// Emits `null` for absent values — presence of the key is part of the
    /// payload's frozen shape.
    pub fn fieldOptStr(self: *Report, name: []const u8, value: ?[]const u8) !void {
        try self.dataKey(name);
        if (value) |v| {
            try json.appendGoJSONString(&self.data, self.a(), v);
        } else {
            try self.data.appendSlice(self.a(), "null");
        }
    }

    /// Omits the key entirely when `value` is null — for conditionally
    /// present fields like `merged`.
    pub fn fieldOptStrOmitNull(self: *Report, name: []const u8, value: ?[]const u8) !void {
        const v = value orelse return;
        try self.fieldStr(name, v);
    }

    pub fn fieldInt(self: *Report, name: []const u8, value: usize) !void {
        try self.dataKey(name);
        try self.data.print(self.a(), "{d}", .{value});
    }

    pub fn fieldBool(self: *Report, name: []const u8, value: bool) !void {
        try self.dataKey(name);
        try self.data.appendSlice(self.a(), if (value) "true" else "false");
    }

    /// Emits a caller-built JSON fragment (array/object) verbatim under `name`.
    pub fn fieldRaw(self: *Report, name: []const u8, raw_json: []const u8) !void {
        try self.dataKey(name);
        try self.data.appendSlice(self.a(), raw_json);
    }

    // -- serialization -------------------------------------------------------------

    fn effectiveLocal(self: *const Report) Outcome {
        if (self.local) |o| return o;
        if (self.local_writes_done > 0) {
            return switch (self.kind) {
                .err, .refused => .partial,
                else => .applied,
            };
        }
        if (self.local_may_write) {
            // The write section was entered but nothing completed —
            // a non-refusal error leaves a write possibly in flight.
            return switch (self.kind) {
                .err => .unknown,
                else => .unchanged,
            };
        }
        return .unchanged;
    }

    fn remotePresent(self: *const Report) bool {
        return self.remote_url != null or self.remote_outcome != null or
            self.remote_sent > 0 or self.remote_received > 0 or
            self.remote_confirmed > 0 or self.remote_pending;
    }

    fn effectiveRemote(self: *const Report) Outcome {
        if (self.remote_outcome) |o| return o;
        if (self.remote_pending) {
            // A mutation's acknowledgment was lost or the connection died
            // mid-flight — never claim the server changed nothing.
            return if (self.remote_confirmed > 0 or self.remote_sent > 0) .partial else .unknown;
        }
        return switch (self.kind) {
            .err, .refused => {
                if (self.remote_error_outcome) |o| return o;
                if (self.remote_confirmed > 0 or self.remote_sent > 0) return .partial;
                return .unchanged;
            },
            else => self.confirmedRemoteOutcome(),
        };
    }

    fn confirmedRemoteOutcome(self: *const Report) Outcome {
        return if (self.remote_confirmed > 0 or self.remote_sent > 0) .applied else .unchanged;
    }

    /// Serializes the envelope: one JSON object in the spec's fixed key order,
    /// terminated by `\n`. Caller owns the result (allocated from `gpa`).
    pub fn marshal(self: *Report, gpa: Allocator) ![]u8 {
        var buf: std.ArrayList(u8) = .empty;
        errdefer buf.deinit(gpa);

        try buf.appendSlice(gpa, "{\"v\":");
        try buf.print(gpa, "{d}", .{SchemaVersion});
        try buf.appendSlice(gpa, ",\"verb\":");
        try json.appendGoJSONString(&buf, gpa, self.verb);
        try buf.appendSlice(gpa, ",\"ok\":");
        try buf.appendSlice(gpa, if (self.kind == .ok or self.kind == .noop) "true" else "false");
        try buf.appendSlice(gpa, ",\"exit\":");
        try buf.print(gpa, "{d}", .{self.exit_code});
        try buf.appendSlice(gpa, ",\"kind\":");
        try json.appendGoJSONString(&buf, gpa, self.kind.name());

        try buf.appendSlice(gpa, ",\"workspace\":");
        try appendOptStr(&buf, gpa, self.workspace);
        try buf.appendSlice(gpa, ",\"stream\":");
        try appendOptStr(&buf, gpa, self.stream);

        try buf.appendSlice(gpa, ",\"heads\":");
        if (self.heads_set) {
            try buf.appendSlice(gpa, "{\"base\":");
            try appendOptStr(&buf, gpa, self.base_head);
            try buf.appendSlice(gpa, ",\"result\":");
            try appendOptStr(&buf, gpa, self.result_head);
            try buf.appendSlice(gpa, ",\"remote\":");
            try appendOptStr(&buf, gpa, self.remote_head);
            try buf.append(gpa, '}');
        } else {
            try buf.appendSlice(gpa, "null");
        }

        try buf.appendSlice(gpa, ",\"changes\":");
        if (self.affected.items.len > 0 or self.affected_omitted > 0) {
            try buf.appendSlice(gpa, "{\"affected\":[");
            for (self.affected.items, 0..) |id, i| {
                if (i > 0) try buf.append(gpa, ',');
                try json.appendGoJSONString(&buf, gpa, id);
            }
            try buf.print(gpa, "],\"affected_omitted\":{d}}}", .{self.affected_omitted});
        } else {
            try buf.appendSlice(gpa, "null");
        }

        try buf.appendSlice(gpa, ",\"conflicts\":");
        if (self.conflicts) |list| {
            try buf.append(gpa, '[');
            for (list.items, 0..) |c, i| {
                if (i > 0) try buf.append(gpa, ',');
                try buf.appendSlice(gpa, "{\"atom\":");
                try json.appendGoJSONString(&buf, gpa, c.atom_id);
                try buf.appendSlice(gpa, ",\"name\":");
                try json.appendGoJSONString(&buf, gpa, c.name);
                try buf.appendSlice(gpa, ",\"type\":");
                try json.appendGoJSONString(&buf, gpa, c.type);
                try buf.append(gpa, '}');
            }
            try buf.append(gpa, ']');
        } else {
            try buf.appendSlice(gpa, "null");
        }

        try buf.appendSlice(gpa, ",\"refusal\":");
        if (self.refusal_name) |name| {
            try buf.appendSlice(gpa, "{\"name\":");
            try json.appendGoJSONString(&buf, gpa, name);
            if (self.refusal_detail) |d| {
                try buf.appendSlice(gpa, ",\"detail\":");
                try json.appendGoJSONString(&buf, gpa, d);
            }
            try buf.append(gpa, '}');
        } else {
            try buf.appendSlice(gpa, "null");
        }

        try buf.appendSlice(gpa, ",\"error\":");
        if (self.error_name) |name| {
            try buf.appendSlice(gpa, "{\"name\":");
            try json.appendGoJSONString(&buf, gpa, name);
            try buf.append(gpa, '}');
        } else {
            try buf.appendSlice(gpa, "null");
        }

        try buf.appendSlice(gpa, ",\"local\":");
        try json.appendGoJSONString(&buf, gpa, self.effectiveLocal().name());

        try buf.appendSlice(gpa, ",\"remote\":");
        if (self.remotePresent()) {
            try buf.appendSlice(gpa, "{\"url\":");
            try appendOptStr(&buf, gpa, self.remote_url);
            try buf.appendSlice(gpa, ",\"outcome\":");
            try json.appendGoJSONString(&buf, gpa, self.effectiveRemote().name());
            try buf.print(gpa, ",\"sent\":{d},\"received\":{d},\"spec_rev\":", .{ self.remote_sent, self.remote_received });
            if (self.remote_spec_rev) |rev| {
                try buf.print(gpa, "{d}", .{rev});
            } else {
                try buf.appendSlice(gpa, "null");
            }
            try buf.append(gpa, '}');
        } else {
            try buf.appendSlice(gpa, "null");
        }

        try buf.appendSlice(gpa, ",\"data\":{");
        try buf.appendSlice(gpa, self.data.items);
        try buf.appendSlice(gpa, "}}\n");

        if (buf.items.len > MaxResultBytes) return error.ResultTooLarge;
        return buf.toOwnedSlice(gpa);
    }

    fn appendOptStr(buf: *std.ArrayList(u8), gpa: Allocator, s: ?[]const u8) !void {
        if (s) |v| {
            try json.appendGoJSONString(buf, gpa, v);
        } else {
            try buf.appendSlice(gpa, "null");
        }
    }
};

/// Escapes `s` into `buf` as a JSON string literal — the wire's Go-compatible
/// escaping — for callers assembling array/object fragments for `fieldRaw`.
pub fn escapeInto(buf: *std.ArrayList(u8), allocator: Allocator, s: []const u8) !void {
    try json.appendGoJSONString(buf, allocator, s);
}

test "report: marshal fixed key order and null shape" {
    const gpa = std.testing.allocator;
    var r = Report.init(gpa, "status");
    defer r.deinit();
    r.exit_code = 0;
    const out = try r.marshal(gpa);
    defer gpa.free(out);
    try std.testing.expectEqualStrings(
        "{\"v\":1,\"verb\":\"status\",\"ok\":true,\"exit\":0,\"kind\":\"ok\",\"workspace\":null,\"stream\":null,\"heads\":null,\"changes\":null,\"conflicts\":null,\"refusal\":null,\"error\":null,\"local\":\"unchanged\",\"remote\":null,\"data\":{}}\n",
        out,
    );
}

test "report: lost append ack reports unknown, never unchanged" {
    const gpa = std.testing.allocator;
    var r = Report.init(gpa, "push");
    defer r.deinit();
    try r.setRemoteUrl("tcp://127.0.0.1:4748");
    r.remoteAttemptBegin(); // append sent; ack lost
    r.kind = .err;
    try r.setError("connection reset by peer");
    const out = try r.marshal(gpa);
    defer gpa.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"outcome\":\"unknown\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"kind\":\"error\"") != null);
}

test "report: confirmed mutation then lost ack reports partial" {
    const gpa = std.testing.allocator;
    var r = Report.init(gpa, "push");
    defer r.deinit();
    try r.setRemoteUrl("tcp://x:1");
    r.remoteAttemptBegin();
    r.remoteAttemptApplied();
    r.noteRemoteSent(3);
    r.remoteAttemptBegin(); // second batch's ack lost
    r.kind = .err;
    const out = try r.marshal(gpa);
    defer gpa.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"outcome\":\"partial\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"sent\":3") != null);
}

test "report: escaping follows the wire's Go-compatible rules" {
    const gpa = std.testing.allocator;
    var r = Report.init(gpa, "commit");
    defer r.deinit();
    try r.fieldStr("message", "a<b>&\"\\\n\xe2\x80\xa8");
    const out = try r.marshal(gpa);
    defer gpa.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "a\\u003cb\\u003e\\u0026\\\"\\\\\\n\\u2028") != null);
}
