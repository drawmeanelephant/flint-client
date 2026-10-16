const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Ed25519 = std.crypto.sign.Ed25519;
const Sha256 = std.crypto.hash.sha2.Sha256;
const fsys = @import("fsys.zig");
const FS = fsys.FS;
const uuid = @import("uuid.zig");
const store = @import("store.zig");
const json = @import("json.zig");
const report = @import("report.zig");

const hex_digits = "0123456789abcdef";

pub const domain_ops = "FLINT-OPS/1\x00";
pub const domain_change = "FLINT-CHANGE/1\x00";
/// Manifest preimage domain (docs/flint-blobs-spec.md §5): deliberately
/// disjoint from the Change preimage domain.
pub const domain_manifest = "flint-manifest-v1\n";

fn lowerNibble(c: u8) ?u8 {
    if (c >= '0' and c <= '9') return c - '0';
    if (c >= 'a' and c <= 'f') return c - 'a' + 10;
    return null;
}

pub fn parseHexFixedLower(comptime N: usize, s: []const u8) ?[N]u8 {
    if (s.len != N * 2) return null;
    var out: [N]u8 = undefined;
    var i: usize = 0;
    while (i < N) : (i += 1) {
        const hi = lowerNibble(s[2 * i]) orelse return null;
        const lo = lowerNibble(s[2 * i + 1]) orelse return null;
        out[i] = (hi << 4) | lo;
    }
    return out;
}

pub fn parseHex32Lower(s: []const u8) ?[32]u8 {
    return parseHexFixedLower(32, s);
}

pub fn parseHex64Lower(s: []const u8) ?[64]u8 {
    return parseHexFixedLower(64, s);
}

pub fn encodeHexFixedLower(comptime N: usize, src: [N]u8) [N * 2]u8 {
    var out: [N * 2]u8 = undefined;
    for (src, 0..) |b, i| {
        out[2 * i] = hex_digits[b >> 4];
        out[2 * i + 1] = hex_digits[b & 0x0f];
    }
    return out;
}

pub fn encodeHexLower(dst: []u8, src: []const u8) void {
    std.debug.assert(dst.len == src.len * 2);
    for (src, 0..) |b, i| {
        dst[2 * i] = hex_digits[b >> 4];
        dst[2 * i + 1] = hex_digits[b & 0x0f];
    }
}

fn writeU32LE(buf: *std.ArrayList(u8), allocator: Allocator, v: u32) !void {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, v, .little);
    try buf.appendSlice(allocator, &b);
}

fn writeU64LE(buf: *std.ArrayList(u8), allocator: Allocator, v: u64) !void {
    var b: [8]u8 = undefined;
    std.mem.writeInt(u64, &b, v, .little);
    try buf.appendSlice(allocator, &b);
}

fn writeStr(buf: *std.ArrayList(u8), allocator: Allocator, s: []const u8) !void {
    try writeU32LE(buf, allocator, @intCast(s.len));
    try buf.appendSlice(allocator, s);
}

fn writeOptStr(buf: *std.ArrayList(u8), allocator: Allocator, s: []const u8) !void {
    if (s.len == 0) {
        try buf.append(allocator, 0x00);
        return;
    }
    try buf.append(allocator, 0x01);
    try writeStr(buf, allocator, s);
}

fn writeOptSpan(buf: *std.ArrayList(u8), allocator: Allocator, sp: ?store.Span) !void {
    if (sp == null) {
        try buf.append(allocator, 0x00);
        return;
    }
    try buf.append(allocator, 0x01);
    try writeStr(buf, allocator, sp.?.file);
    try writeU32LE(buf, allocator, sp.?.start);
    try writeU32LE(buf, allocator, sp.?.end);
}

fn writeOptHash32(buf: *std.ArrayList(u8), allocator: Allocator, hex_str: []const u8) !bool {
    if (hex_str.len == 0) {
        try buf.append(allocator, 0x00);
        return true;
    }
    const h = parseHex32Lower(hex_str) orelse return false;
    try buf.append(allocator, 0x01);
    try buf.appendSlice(allocator, &h);
    return true;
}

fn writeOptUUID(buf: *std.ArrayList(u8), allocator: Allocator, u: ?[]const u8) !bool {
    if (u == null) {
        try buf.append(allocator, 0x00);
        return true;
    }
    const id = uuid.parseUUID(u.?) orelse return false;
    try buf.append(allocator, 0x01);
    try buf.appendSlice(allocator, &id);
    return true;
}

/// opBytes encodes a single Op into its ADR 0049 §Canonical bytes representation.
pub fn opBytes(allocator: Allocator, op: store.Op) ![]u8 {
    const code = store.opTypeCode(op.type);
    if (code == 0) {
        return fsys.refuse("change_malformed", "");
    }
    const atom_id = uuid.parseUUID(op.atom_id) orelse {
        return fsys.refuse("change_malformed", "");
    };

    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    try buf.append(allocator, code);
    try buf.appendSlice(allocator, &atom_id);
    try writeOptStr(&buf, allocator, op.kind);
    try writeOptStr(&buf, allocator, op.new_name);
    try writeOptSpan(&buf, allocator, op.new_span);
    if (!try writeOptHash32(&buf, allocator, op.new_hash)) {
        return fsys.refuse("change_malformed", "");
    }
    if (!try writeOptHash32(&buf, allocator, op.new_sig_hash)) {
        return fsys.refuse("change_malformed", "");
    }
    if (!try writeOptHash32(&buf, allocator, op.old_hash)) {
        return fsys.refuse("change_malformed", "");
    }
    return buf.toOwnedSlice(allocator);
}

/// opsHash computes SHA-256("FLINT-OPS/1\x00" || u32le(n) || op_bytes(op_1) || ... || op_bytes(op_n))
/// with ops sorted by (atom_id bytes, type code).
pub fn opsHash(allocator: Allocator, ops: []const store.Op) ![32]u8 {
    const sorted = try allocator.dupe(store.Op, ops);
    defer allocator.free(sorted);
    store.sortOps(sorted);

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);

    try buf.appendSlice(allocator, domain_ops);
    try writeU32LE(&buf, allocator, @intCast(sorted.len));
    for (sorted) |op| {
        const ob = try opBytes(allocator, op);
        defer allocator.free(ob);
        try buf.appendSlice(allocator, ob);
    }

    var digest: [32]u8 = undefined;
    Sha256.hash(buf.items, &digest, .{});
    return digest;
}

/// sigMsg computes the canonical Change preimage signed by Ed25519 per ADR 0049 §Canonical bytes:
/// "FLINT-CHANGE/1\x00" || id[16] || opt(parent[16]) || stream[16]
/// || u64le(ts) || author[32] || str(message) || opt(merged[16]) || ops_hash[32]
pub fn sigMsg(allocator: Allocator, c: *const store.Change) ![]u8 {
    const id_bytes = uuid.parseUUID(c.id) orelse {
        return fsys.refuse("change_malformed", "");
    };
    const stream_bytes = uuid.parseUUID(c.stream) orelse {
        return fsys.refuse("change_malformed", "");
    };
    if (c.ts < 0) {
        return fsys.refuse("change_malformed", "");
    }
    const author_bytes = parseHex32Lower(c.author) orelse {
        return fsys.refuse("change_malformed", "");
    };
    if (!std.unicode.utf8ValidateSlice(c.message)) {
        return fsys.refuse("change_malformed", "");
    }

    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    try buf.appendSlice(allocator, domain_change);
    try buf.appendSlice(allocator, &id_bytes);
    if (!try writeOptUUID(&buf, allocator, c.parent)) {
        return fsys.refuse("change_malformed", "");
    }
    try buf.appendSlice(allocator, &stream_bytes);
    try writeU64LE(&buf, allocator, @intCast(c.ts));
    try buf.appendSlice(allocator, &author_bytes);
    try writeStr(&buf, allocator, c.message);
    if (!try writeOptUUID(&buf, allocator, c.merged)) {
        return fsys.refuse("change_malformed", "");
    }
    const oh = try opsHash(allocator, c.ops);
    try buf.appendSlice(allocator, &oh);

    return buf.toOwnedSlice(allocator);
}

/// Validates a parsed Change's fields against `sigMsg` and `sig` requirements.
pub fn validateParsedChange(allocator: Allocator, c: *const store.Change) !void {
    if (c.ts <= 0) {
        return fsys.refuse("change_malformed", "");
    }
    if (parseHex64Lower(c.sig) == null) {
        return fsys.refuse("change_malformed", "");
    }
    const msg = try sigMsg(allocator, c);
    allocator.free(msg);
}

/// Derives the 32-byte Ed25519 public key from a 32-byte RFC 8032 seed.
pub fn derivePublic(seed: [32]u8) ![32]u8 {
    var kp = try Ed25519.KeyPair.generateDeterministic(seed);
    defer std.crypto.secureZero(u8, &kp.secret_key.bytes);
    return kp.public_key.bytes;
}

/// Signs `msg` with a 32-byte Ed25519 seed, wiping the expanded secret key.
pub fn signMsg(msg: []const u8, seed: [32]u8) ![64]u8 {
    var kp = try Ed25519.KeyPair.generateDeterministic(seed);
    defer std.crypto.secureZero(u8, &kp.secret_key.bytes);
    const sig = try kp.sign(msg, null);
    return sig.toBytes();
}

/// Verifies an Ed25519 signature over `msg` against a 32-byte public key.
pub fn verifySig(sig_bytes: [64]u8, msg: []const u8, author_bytes: [32]u8) bool {
    const pk = Ed25519.PublicKey.fromBytes(author_bytes) catch return false;
    const sig = Ed25519.Signature.fromBytes(sig_bytes);
    sig.verify(msg, pk) catch return false;
    return true;
}

/// manifestSigMsg computes the manifest signature preimage:
/// `"flint-manifest-v1\n" || canonical(<stream,change,author,files>)` where
/// canonical is the Go-marshaled manifest object with `sig` excluded.
pub fn manifestSigMsg(allocator: Allocator, m: store.Manifest) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    try buf.appendSlice(allocator, domain_manifest);
    try json.appendManifestBody(&buf, allocator, m);
    return buf.toOwnedSlice(allocator);
}

/// Signs a manifest's canonical form with `seed` and stores the hex signature
/// in `m.sig`. The seed is NOT wiped — callers needing the Change signature
/// still sign through `signChangeWithSeed`, which wipes.
pub fn signManifestWithSeed(allocator: Allocator, m: *store.Manifest, seed: [32]u8) !void {
    defer std.crypto.secureZero(u8, @constCast(&seed)[0..]);
    const msg = try manifestSigMsg(allocator, m.*);
    defer allocator.free(msg);
    const sig_bytes = try signMsg(msg, seed);
    const sig_hex = encodeHexFixedLower(64, sig_bytes);
    const new_sig = try allocator.dupe(u8, &sig_hex);
    allocator.free(m.sig);
    m.sig = new_sig;
}

/// VerifyManifest recomputes the manifest preimage and checks `m.sig` against
/// `m.author` — which must equal the bound Change's author (caller's check).
pub fn verifyManifest(allocator: Allocator, m: store.Manifest) !bool {
    const msg = try manifestSigMsg(allocator, m);
    defer allocator.free(msg);
    const author = parseHex32Lower(m.author) orelse return false;
    const sig = parseHex64Lower(m.sig) orelse return false;
    return verifySig(sig, msg, author);
}

/// VerifyChange recomputes sig_msg from c's parsed fields and verifies c.sig against c.author.
pub fn verifyChange(allocator: Allocator, c: *const store.Change) !bool {
    const msg = try sigMsg(allocator, c);
    defer allocator.free(msg);
    const author = parseHex32Lower(c.author) orelse {
        return fsys.refuse("change_malformed", "");
    };
    const sig = parseHex64Lower(c.sig) orelse {
        return fsys.refuse("change_malformed", "");
    };
    return verifySig(sig, msg, author);
}

/// signChangeWithSeed sets c.author from derivePublic(seed), sorts c.ops, computes sig_msg,
/// sets c.sig from signMsg(sig_msg, seed), and wipes the caller's seed buffer.
pub fn signChangeWithSeed(allocator: Allocator, c: *store.Change, seed: *[32]u8) !void {
    defer std.crypto.secureZero(u8, seed);

    const pub_bytes = try derivePublic(seed.*);
    const pub_hex = encodeHexFixedLower(32, pub_bytes);
    const new_author = try allocator.dupe(u8, &pub_hex);
    allocator.free(c.author);
    c.author = new_author;

    if (c.ops.len > 1) {
        store.sortOps(@constCast(c.ops));
    }

    const msg = try sigMsg(allocator, c);
    defer allocator.free(msg);

    const sig_bytes = try signMsg(msg, seed.*);
    const sig_hex = encodeHexFixedLower(64, sig_bytes);
    const new_sig = try allocator.dupe(u8, &sig_hex);
    allocator.free(c.sig);
    c.sig = new_sig;
}

/// Validates a FLINT identifier name (`[a-z0-9-]{1,32}`).
pub fn isValidName(name: []const u8) bool {
    if (name.len == 0 or name.len > 32) return false;
    for (name) |ch| {
        const ok = (ch >= 'a' and ch <= 'z') or (ch >= '0' and ch <= '9') or ch == '-';
        if (!ok) return false;
    }
    return true;
}

fn parseSeedFileContent(raw: []const u8) ![32]u8 {
    // Key file is 64 lowercase hex chars + optional trailing '\n' (or '\r\n').
    const trimmed = if (std.mem.endsWith(u8, raw, "\r\n"))
        raw[0 .. raw.len - 2]
    else if (std.mem.endsWith(u8, raw, "\n"))
        raw[0 .. raw.len - 1]
    else
        raw;

    return parseHex32Lower(trimmed) orelse fsys.refuse("secret_malformed", "");
}

/// Resolves and loads the 32-byte signing seed per `docs/flint-client-spec.md` §2.3:
/// 1. `--key <n>` (key name in `<store>/keys/<n>` or 64-hex seed literal)
/// 2. `FLINT_SIGN_KEY` env var (key name in `<store>/keys/<n>` or 64-hex seed literal)
/// 3. The store's sole key in `<store>/keys/` if exactly one exists
/// 4. Refuse `secret_not_found`.
pub fn loadSigningSeed(
    allocator: Allocator,
    fs: FS,
    root: []const u8,
    key_flag: []const u8,
    env_sign_key: ?[]const u8,
) ![32]u8 {
    const spec: []const u8 = if (key_flag.len > 0)
        key_flag
    else if (env_sign_key) |ev|
        ev
    else
        "";

    if (spec.len > 0) {
        // Check if `<store>/keys/<spec>` exists first when `spec` is a valid key name
        if (isValidName(spec)) {
            const kp = try store.keyFilePath(allocator, root, spec);
            defer allocator.free(kp);
            if (fs.exists(allocator, kp)) {
                const raw = try fs.readFile(allocator, kp, store.MaxFileReadBytes);
                defer {
                    std.crypto.secureZero(u8, raw);
                    allocator.free(raw);
                }
                return parseSeedFileContent(raw);
            }
        }
        // Check if `spec` is a 64-char lowercase hex seed literal
        if (spec.len == 64) {
            if (parseHex32Lower(spec)) |seed| {
                return seed;
            }
            return fsys.refuse("secret_malformed", "");
        }
        // If `spec` was a valid key name that did not exist, refuse `secret_not_found`
        if (isValidName(spec)) {
            return fsys.refuse("secret_not_found", "");
        }
        return fsys.refuse("secret_malformed", "");
    }

    // Check `<store>/keys/` for a sole key
    const kd = try store.keysDir(allocator, root);
    defer allocator.free(kd);
    if (!fs.exists(allocator, kd)) {
        return fsys.refuse("secret_not_found", "");
    }

    const entries = try fs.list(allocator, kd);
    defer FS.freeDirEntries(allocator, entries);

    var sole_name: ?[]const u8 = null;
    for (entries) |e| {
        if (e.is_dir) continue;
        if (sole_name != null) {
            // Multiple keys present and none specified -> secret_not_found
            return fsys.refuse("secret_not_found", "");
        }
        sole_name = e.name;
    }

    const name = sole_name orelse return fsys.refuse("secret_not_found", "");
    const kp = try store.keyFilePath(allocator, root, name);
    defer allocator.free(kp);
    const raw = try fs.readFile(allocator, kp, store.MaxFileReadBytes);
    defer {
        std.crypto.secureZero(u8, raw);
        allocator.free(raw);
    }
    return parseSeedFileContent(raw);
}

/// Implements `flint keygen [--name=<n>]` per `docs/flint-client-spec.md` §1 & §2.3.
/// Writes `<store>/keys/<n>` containing 64 lowercase hex chars + newline, mode 0600.
/// Refuses `key_exists` if present. Prints the derived public key hex.
pub fn cmdKeygen(
    allocator: Allocator,
    fs: FS,
    root: []const u8,
    uuid_gen: *uuid.UUIDGen,
    args: []const []const u8,
    out: *Io.Writer,
) !void {
    var name: []const u8 = "default";
    var has_name = false;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.startsWith(u8, a, "--name=")) {
            if (has_name) return fsys.refuse("usage", "");
            name = a["--name=".len..];
            has_name = true;
        } else if (std.mem.eql(u8, a, "--name")) {
            if (has_name or i + 1 >= args.len) return fsys.refuse("usage", "");
            i += 1;
            name = args[i];
            has_name = true;
        } else {
            return fsys.refuse("usage", "");
        }
    }

    if (!isValidName(name)) {
        return fsys.refuse("usage", "");
    }

    const key_path = try store.keyFilePath(allocator, root, name);
    defer allocator.free(key_path);

    if (fs.exists(allocator, key_path)) {
        return fsys.refuse("key_exists", "");
    }

    var seed: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &seed);
    uuid_gen.fillRand(&seed);

    const pub_bytes = try derivePublic(seed);
    const pub_hex = encodeHexFixedLower(32, pub_bytes);

    var seed_line: [65]u8 = undefined;
    defer std.crypto.secureZero(u8, &seed_line);
    const seed_hex = encodeHexFixedLower(32, seed);
    @memcpy(seed_line[0..64], &seed_hex);
    seed_line[64] = '\n';

    try fs.writeKeyFile(allocator, key_path, &seed_line);

    try out.print("flint: keygen {s}\n", .{&pub_hex});
}

fn verifyChangeList(allocator: Allocator, changes: []const store.Change, out: *Io.Writer) !u8 {
    var rc: u8 = 0;
    var verified: usize = 0;
    var failed: usize = 0;
    var listed: usize = 0;
    var omitted: usize = 0;
    var list_buf: std.ArrayList(u8) = .empty;
    defer list_buf.deinit(allocator);
    if (report.active != null) try list_buf.append(allocator, '[');
    for (changes) |*c| {
        const ok = try verifyChange(allocator, c);
        if (ok) {
            verified += 1;
            try out.print("flint: verify {s} sig: verified\n", .{c.id});
        } else {
            failed += 1;
            try out.print("flint: verify {s} sig_invalid\n", .{c.id});
            rc = 1;
        }
        if (report.active != null) {
            if (listed < report.MaxListEntries) {
                if (listed > 0) try list_buf.append(allocator, ',');
                try list_buf.appendSlice(allocator, "{\"id\":");
                try report.escapeInto(&list_buf, allocator, c.id);
                try list_buf.appendSlice(allocator, ",\"sig\":");
                try report.escapeInto(&list_buf, allocator, if (ok) "verified" else "sig_invalid");
                try list_buf.append(allocator, '}');
                listed += 1;
            } else {
                omitted += 1;
            }
        }
    }
    if (report.active) |r| {
        r.setKind(if (rc == 0) .ok else .failed);
        try r.fieldInt("verified", verified);
        try r.fieldInt("failed", failed);
        try list_buf.append(allocator, ']');
        try r.fieldRaw("changes", list_buf.items);
        if (omitted > 0) try r.fieldInt("changes_omitted", omitted);
    }
    return rc;
}

/// Checks whether `args` to `verify` use `--file` (which does not require a store root).
pub fn verifyFileArg(args: []const []const u8) ?[]const u8 {
    if (args.len == 1 and std.mem.startsWith(u8, args[0], "--file=")) {
        return args[0]["--file=".len..];
    }
    if (args.len == 2 and std.mem.eql(u8, args[0], "--file")) {
        return args[1];
    }
    return null;
}

/// Implements `flint verify <id> | --all | --file=<log>` matching `commit.go:cmdVerify`.
pub fn cmdVerify(
    allocator: Allocator,
    fs: FS,
    root: ?[]const u8,
    args: []const []const u8,
    out: *Io.Writer,
) !u8 {
    if (verifyFileArg(args)) |raw_path| {
        const log_path = fsys.cleanMemPath(raw_path);
        if (log_path.len == 0) {
            return fsys.refuse("usage", "");
        }
        const b = try fs.readFile(allocator, log_path, store.MaxFileReadBytes);
        defer allocator.free(b);

        const lines = try store.readJSONLLines(allocator, b);
        defer allocator.free(lines);
        if (lines.len == 0) {
            return fsys.refuse("change_malformed", "");
        }

        var changes: std.ArrayList(store.Change) = .empty;
        defer {
            for (changes.items) |c| c.deinit(allocator);
            changes.deinit(allocator);
        }

        for (lines) |line| {
            const c = try json.parseChange(allocator, line);
            errdefer c.deinit(allocator);
            try validateParsedChange(allocator, &c);
            try changes.append(allocator, c);
        }
        return verifyChangeList(allocator, changes.items, out);
    }

    if (args.len != 1 or args[0].len == 0) {
        return fsys.refuse("usage", "");
    }
    const arg = args[0];
    const store_root = root orelse return fsys.refuse("store_not_found", "");

    if (std.mem.eql(u8, arg, "--all")) {
        var idx = try store.loadStoreIndex(allocator, fs, store_root);
        defer idx.deinit();
        const changes = try store.loadAllStreamChanges(allocator, fs, store_root, &idx);
        defer store.freeChanges(allocator, changes);
        for (changes) |*c| {
            try validateParsedChange(allocator, c);
        }
        return verifyChangeList(allocator, changes, out);
    }

    if (std.mem.startsWith(u8, arg, "-")) {
        return fsys.refuse("usage", "");
    }

    var idx = try store.loadStoreIndex(allocator, fs, store_root);
    defer idx.deinit();
    const changes = try store.loadAllStreamChanges(allocator, fs, store_root, &idx);
    defer store.freeChanges(allocator, changes);

    for (changes) |*c| {
        if (std.mem.eql(u8, c.id, arg)) {
            try validateParsedChange(allocator, c);
            return verifyChangeList(allocator, c[0..1], out);
        }
    }
    return fsys.refuse("change_missing", arg);
}

test "Pinned sig vectors (testdata/sig) and RFC 8032 §7.1 TEST 1 oracle" {
    const gpa = std.testing.allocator;
    var host_fs = fsys.HostFS.init(std.testing.io);
    const fs = host_fs.fs();

    const seed_raw = try fs.readFile(gpa, "testdata/sig/seed.hex", store.MaxFileReadBytes);
    defer gpa.free(seed_raw);
    const preimage_raw = try fs.readFile(gpa, "testdata/sig/preimage.hex", store.MaxFileReadBytes);
    defer gpa.free(preimage_raw);
    const good_raw = try fs.readFile(gpa, "testdata/sig/good.jsonl", store.MaxFileReadBytes);
    defer gpa.free(good_raw);
    const bad_raw = try fs.readFile(gpa, "testdata/sig/bad.jsonl", store.MaxFileReadBytes);
    defer gpa.free(bad_raw);

    const seed_hex = std.mem.trim(u8, seed_raw, " \t\r\n");
    const preimage_hex = std.mem.trim(u8, preimage_raw, " \t\r\n");

    const seed = parseHex32Lower(seed_hex).?;
    const want_preimage = try gpa.alloc(u8, preimage_hex.len / 2);
    defer gpa.free(want_preimage);
    _ = try std.fmt.hexToBytes(want_preimage, preimage_hex);

    const good_lines = try store.readJSONLLines(gpa, good_raw);
    defer gpa.free(good_lines);
    try std.testing.expectEqual(@as(usize, 1), good_lines.len);

    const good = try json.parseChange(gpa, good_lines[0]);
    defer good.deinit(gpa);
    try validateParsedChange(gpa, &good);

    // 1. sigMsg(good) equals preimage.hex byte for byte.
    const got_msg = try sigMsg(gpa, &good);
    defer gpa.free(got_msg);
    try std.testing.expectEqualSlices(u8, want_preimage, got_msg);

    // 2. derivePublic(seed) equals good.author and RFC 8032 TEST 1 pubkey.
    const want_rfc8032_pub = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const derived_pub = try derivePublic(seed);
    const derived_pub_hex = encodeHexFixedLower(32, derived_pub);
    try std.testing.expectEqualStrings(want_rfc8032_pub, &derived_pub_hex);
    try std.testing.expectEqualStrings(good.author, &derived_pub_hex);

    // 3. signMsg(got_msg, seed) equals stored good.sig.
    const got_sig = try signMsg(got_msg, seed);
    const got_sig_hex = encodeHexFixedLower(64, got_sig);
    try std.testing.expectEqualStrings(good.sig, &got_sig_hex);
    try std.testing.expect(try verifyChange(gpa, &good));

    // 4. MarshalChangeLine(good) round-trips byte-for-byte with good.jsonl.
    const marshaled_good = try json.marshalChangeLine(gpa, good);
    defer gpa.free(marshaled_good);
    try std.testing.expectEqualStrings(good_raw, marshaled_good);

    // 5. bad.jsonl fails verification.
    const bad_lines = try store.readJSONLLines(gpa, bad_raw);
    defer gpa.free(bad_lines);
    try std.testing.expectEqual(@as(usize, 1), bad_lines.len);
    const bad = try json.parseChange(gpa, bad_lines[0]);
    defer bad.deinit(gpa);
    try validateParsedChange(gpa, &bad);
    try std.testing.expect(!(try verifyChange(gpa, &bad)));
}
