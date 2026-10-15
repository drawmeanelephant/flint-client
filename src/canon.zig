const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const atom_domain = "FLINT-ATOM/1\x00";
pub const sig_domain = "FLINT-SIG/1\x00";

pub const CTok = struct {
    start: usize,
    end: usize,
    text: []const u8,
};

pub const CanonResult = struct {
    hash: [32]u8,
    sig_hash: [32]u8,
};

pub const CanonTexts = struct {
    all: []u8,
    sig: []u8,
};

pub fn canonText(
    allocator: std.mem.Allocator,
    toks: []const CTok,
    blank_pos: usize,
    sig_cut: usize,
    iota_idx: isize,
) !CanonTexts {
    var all: std.ArrayList(u8) = .empty;
    errdefer all.deinit(allocator);
    var sig: std.ArrayList(u8) = .empty;
    errdefer sig.deinit(allocator);

    var first = true;
    for (toks) |t| {
        const text = if (t.start == blank_pos) "_" else t.text;
        if (!first) {
            try all.append(allocator, ' ');
        }
        first = false;
        try all.appendSlice(allocator, text);
        if (t.start < sig_cut) {
            try sig.appendSlice(allocator, text);
            try sig.append(allocator, ' ');
        }
    }
    if (iota_idx >= 0) {
        var ibuf: [24]u8 = undefined;
        const istr = std.fmt.bufPrint(&ibuf, "{d}", .{iota_idx}) catch unreachable;
        try all.appendSlice(allocator, " iota=");
        try all.appendSlice(allocator, istr);
        try sig.appendSlice(allocator, "iota=");
        try sig.appendSlice(allocator, istr);
        try sig.append(allocator, ' ');
    }
    if (sig.items.len > 0 and sig.items[sig.items.len - 1] == ' ') {
        _ = sig.pop();
    }
    return .{
        .all = try all.toOwnedSlice(allocator),
        .sig = try sig.toOwnedSlice(allocator),
    };
}

pub fn hashDomainBody(domain: []const u8, kind: []const u8, body: []const u8) [32]u8 {
    var h = Sha256.init(.{});
    h.update(domain);
    h.update(kind);
    h.update(&[_]u8{0});
    h.update(body);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

pub fn canonize(
    allocator: std.mem.Allocator,
    kind: []const u8,
    qname: []const u8,
    toks: []const CTok,
    blank_pos: usize,
    sig_cut: usize,
    iota_idx: isize,
    sink: ?*std.StringHashMap([]const u8),
) !CanonResult {
    const texts = try canonText(allocator, toks, blank_pos, sig_cut, iota_idx);
    defer allocator.free(texts.sig);
    errdefer allocator.free(texts.all);

    const sh = hashDomainBody(atom_domain, kind, texts.all);
    const ss = hashDomainBody(sig_domain, kind, texts.sig);

    if (sink) |m| {
        const key_dup = try allocator.dupe(u8, qname);
        errdefer allocator.free(key_dup);
        const gop = try m.getOrPut(key_dup);
        if (gop.found_existing) {
            allocator.free(key_dup);
            allocator.free(gop.value_ptr.*);
        }
        gop.value_ptr.* = texts.all;
    } else {
        allocator.free(texts.all);
    }

    return .{
        .hash = sh,
        .sig_hash = ss,
    };
}
