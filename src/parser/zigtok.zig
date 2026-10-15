const std = @import("std");
const canon = @import("../canon.zig");
const CTok = canon.CTok;

pub const ZKind = enum {
    ident,
    str,
    char,
    num,
    punct,
    eof,
};

pub const LexError = struct {
    offset: usize,
    code: []const u8,
};

pub fn zigTokens(
    allocator: std.mem.Allocator,
    src: []const u8,
    err_out: *?LexError,
) ![]CTok {
    var out: std.ArrayList(CTok) = .empty;
    errdefer out.deinit(allocator);

    var i: usize = 0;
    while (i < src.len) {
        const c = src[i];
        if (c == ' ' or c == '\t' or c == '\r' or c == '\n') {
            i += 1;
        } else if (c == '/' and i + 1 < src.len and src[i + 1] == '/') {
            while (i < src.len and src[i] != '\n') : (i += 1) {}
        } else if (c == '\\' and i + 1 < src.len and src[i + 1] == '\\') {
            const start = i;
            while (i < src.len and src[i] != '\n') : (i += 1) {}
            try out.append(allocator, .{ .start = start, .end = i, .text = src[start..i] });
        } else if (c == '"') {
            const start = i;
            i += 1;
            while (i < src.len and src[i] != '"') {
                if (src[i] == '\\') {
                    i += 1;
                    if (i >= src.len) break;
                }
                i += 1;
            }
            if (i >= src.len) {
                err_out.* = .{ .offset = start, .code = "syntax" };
                return error.ParseFailed;
            }
            i += 1;
            try out.append(allocator, .{ .start = start, .end = i, .text = src[start..i] });
        } else if (c == '\'') {
            const start = i;
            i += 1;
            if (i < src.len and src[i] == '\'') {
                err_out.* = .{ .offset = start, .code = "syntax" };
                return error.ParseFailed;
            }
            while (i < src.len and src[i] != '\'' and src[i] != '\n') {
                if (src[i] == '\\') {
                    i += 1;
                    if (i >= src.len) break;
                }
                i += 1;
            }
            if (i >= src.len or src[i] != '\'') {
                err_out.* = .{ .offset = start, .code = "syntax" };
                return error.ParseFailed;
            }
            i += 1;
            try out.append(allocator, .{ .start = start, .end = i, .text = src[start..i] });
        } else if (c == '@' and i + 1 < src.len and src[i + 1] == '"') {
            const start = i;
            i += 2;
            while (i < src.len and src[i] != '"' and src[i] != '\n') {
                if (src[i] == '\\') {
                    i += 1;
                    if (i >= src.len) break;
                }
                i += 1;
            }
            if (i >= src.len or src[i] != '"') {
                err_out.* = .{ .offset = start, .code = "syntax" };
                return error.ParseFailed;
            }
            i += 1;
            try out.append(allocator, .{ .start = start, .end = i, .text = src[start..i] });
        } else if (c == '@' and i + 1 < src.len and isZIdentStart(src[i + 1])) {
            const start = i;
            i += 2;
            while (i < src.len and isZIdent(src[i])) : (i += 1) {}
            try out.append(allocator, .{ .start = start, .end = i, .text = src[start..i] });
        } else if (isZIdentStart(c)) {
            const start = i;
            i += 1;
            while (i < src.len and isZIdent(src[i])) : (i += 1) {}
            try out.append(allocator, .{ .start = start, .end = i, .text = src[start..i] });
        } else if (isZDigit(c)) {
            const start = i;
            const hex_lit = c == '0' and i + 1 < src.len and (src[i + 1] == 'x' or src[i + 1] == 'X');
            i += 1;
            while (i < src.len) {
                const d = src[i];
                if (isZNum(d)) {
                    i += 1;
                    continue;
                }
                if (d == '.' and i + 1 < src.len and isZDigit(src[i + 1])) {
                    i += 1;
                    continue;
                }
                if ((d == '+' or d == '-') and i + 1 < src.len and isZDigit(src[i + 1])) {
                    const prev = src[i - 1];
                    if ((!hex_lit and (prev == 'e' or prev == 'E')) or (hex_lit and (prev == 'p' or prev == 'P'))) {
                        i += 1;
                        continue;
                    }
                }
                break;
            }
            try out.append(allocator, .{ .start = start, .end = i, .text = src[start..i] });
        } else {
            try out.append(allocator, .{ .start = i, .end = i + 1, .text = src[i .. i + 1] });
            i += 1;
        }
    }

    try out.append(allocator, .{ .start = src.len, .end = src.len, .text = "" });
    return out.toOwnedSlice(allocator);
}

pub fn zkindOf(t: CTok) ZKind {
    if (t.start == t.end or t.text.len == 0) return .eof;
    const c = t.text[0];
    if (c == '"' or c == '\\') return .str;
    if (c == '\'') return .char;
    if (isZDigit(c)) return .num;
    if (isZIdentStart(c) or c == '@') return .ident;
    return .punct;
}

pub fn isZIdentStart(c: u8) bool {
    return c == '_' or (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z');
}

pub fn isZIdent(c: u8) bool {
    return isZIdentStart(c) or isZDigit(c);
}

pub fn isZDigit(c: u8) bool {
    return c >= '0' and c <= '9';
}

pub fn isZNum(c: u8) bool {
    return isZDigit(c) or c == '_' or (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z');
}
