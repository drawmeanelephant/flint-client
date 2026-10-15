const std = @import("std");
const canon = @import("../canon.zig");
const CTok = canon.CTok;

pub const GoTokKind = enum {
    ident,
    basic_lit,
    keyword,
    punct,
    semi,
    eof,
};

pub const GoTok = struct {
    kind: GoTokKind,
    start: usize,
    end: usize,
    text: []const u8,
    synthetic_semi: bool = false,
};

pub const LexError = struct {
    offset: usize,
    code: []const u8,
};

pub fn isGoKeyword(text: []const u8) bool {
    const keywords = [_][]const u8{
        "break",       "case",   "chan",   "const",   "continue",
        "default",     "defer",  "else",   "fallthrough", "for",
        "func",        "go",     "goto",   "if",      "import",
        "interface",   "map",    "package", "range",  "return",
        "select",      "struct", "switch", "type",    "var",
    };
    for (keywords) |kw| {
        if (std.mem.eql(u8, text, kw)) return true;
    }
    return false;
}

fn canInsertSemi(tok: GoTok) bool {
    return switch (tok.kind) {
        .ident, .basic_lit => true,
        .keyword => std.mem.eql(u8, tok.text, "break") or
            std.mem.eql(u8, tok.text, "continue") or
            std.mem.eql(u8, tok.text, "fallthrough") or
            std.mem.eql(u8, tok.text, "return"),
        .punct => std.mem.eql(u8, tok.text, "++") or
            std.mem.eql(u8, tok.text, "--") or
            std.mem.eql(u8, tok.text, ")") or
            std.mem.eql(u8, tok.text, "]") or
            std.mem.eql(u8, tok.text, "}"),
        .semi, .eof => false,
    };
}

fn maybeInsertSemi(allocator: std.mem.Allocator, out: *std.ArrayList(GoTok), pos: usize) !void {
    if (out.items.len == 0) return;
    const last = out.items[out.items.len - 1];
    if (canInsertSemi(last)) {
        try out.append(allocator, .{
            .kind = .semi,
            .start = pos,
            .end = pos,
            .text = "\n",
            .synthetic_semi = true,
        });
    }
}

pub fn goTokens(
    allocator: std.mem.Allocator,
    src: []const u8,
    err_out: *?LexError,
) ![]GoTok {
    var out: std.ArrayList(GoTok) = .empty;
    errdefer out.deinit(allocator);

    var i: usize = 0;
    while (i < src.len) {
        const c = src[i];

        // Whitespace
        if (c == ' ' or c == '\t' or c == '\r') {
            i += 1;
            continue;
        }
        if (c == '\n') {
            try maybeInsertSemi(allocator, &out, i);
            i += 1;
            continue;
        }

        // Line comment //
        if (c == '/' and i + 1 < src.len and src[i + 1] == '/') {
            i += 2;
            while (i < src.len and src[i] != '\n') : (i += 1) {}
            if (i < src.len and src[i] == '\n') {
                try maybeInsertSemi(allocator, &out, i);
                i += 1;
            }
            continue;
        }

        // Block comment /* ... */
        if (c == '/' and i + 1 < src.len and src[i + 1] == '*') {
            const start = i;
            i += 2;
            var has_nl = false;
            var nl_pos: usize = start;
            while (i + 1 < src.len and !(src[i] == '*' and src[i + 1] == '/')) : (i += 1) {
                if (src[i] == '\n' and !has_nl) {
                    has_nl = true;
                    nl_pos = i;
                }
            }
            if (i + 1 >= src.len) {
                err_out.* = .{ .offset = start, .code = "syntax" };
                return error.ParseFailed;
            }
            i += 2;
            if (has_nl) {
                try maybeInsertSemi(allocator, &out, nl_pos);
            }
            continue;
        }

        // Interpreted string literal "..."
        if (c == '"') {
            const start = i;
            i += 1;
            while (i < src.len and src[i] != '"' and src[i] != '\n') {
                if (src[i] == '\\') {
                    i += 1;
                    if (i >= src.len or src[i] == '\n') break;
                }
                i += 1;
            }
            if (i >= src.len or src[i] != '"') {
                err_out.* = .{ .offset = start, .code = "syntax" };
                return error.ParseFailed;
            }
            i += 1;
            try out.append(allocator, .{ .kind = .basic_lit, .start = start, .end = i, .text = src[start..i] });
            continue;
        }

        // Raw string literal `...`
        if (c == '`') {
            const start = i;
            i += 1;
            while (i < src.len and src[i] != '`') : (i += 1) {}
            if (i >= src.len) {
                err_out.* = .{ .offset = start, .code = "syntax" };
                return error.ParseFailed;
            }
            i += 1;
            try out.append(allocator, .{ .kind = .basic_lit, .start = start, .end = i, .text = src[start..i] });
            continue;
        }

        // Rune literal '...'
        if (c == '\'') {
            const start = i;
            i += 1;
            if (i < src.len and src[i] == '\'') {
                err_out.* = .{ .offset = start, .code = "syntax" };
                return error.ParseFailed;
            }
            while (i < src.len and src[i] != '\'' and src[i] != '\n') {
                if (src[i] == '\\') {
                    i += 1;
                    if (i >= src.len or src[i] == '\n') break;
                }
                i += 1;
            }
            if (i >= src.len or src[i] != '\'') {
                err_out.* = .{ .offset = start, .code = "syntax" };
                return error.ParseFailed;
            }
            i += 1;
            try out.append(allocator, .{ .kind = .basic_lit, .start = start, .end = i, .text = src[start..i] });
            continue;
        }

        // Identifier or keyword
        if (isGoIdentStart(c)) {
            const start = i;
            i += 1;
            while (i < src.len and isGoIdentCont(src[i])) : (i += 1) {}
            const text = src[start..i];
            const kind: GoTokKind = if (isGoKeyword(text)) .keyword else .ident;
            try out.append(allocator, .{ .kind = kind, .start = start, .end = i, .text = text });
            continue;
        }

        // Number literal (starts with digit, or '.' followed by digit)
        if (isGoDigit(c) or (c == '.' and i + 1 < src.len and isGoDigit(src[i + 1]))) {
            const start = i;
            const hex_lit = c == '0' and i + 1 < src.len and (src[i + 1] == 'x' or src[i + 1] == 'X');
            i += 1;
            while (i < src.len) {
                const d = src[i];
                if (isGoNumChar(d)) {
                    i += 1;
                    continue;
                }
                if (d == '.' and !(i + 1 < src.len and src[i + 1] == '.')) {
                    i += 1;
                    continue;
                }
                if ((d == '+' or d == '-') and i > start) {
                    const prev = src[i - 1];
                    if ((!hex_lit and (prev == 'e' or prev == 'E')) or (hex_lit and (prev == 'p' or prev == 'P'))) {
                        i += 1;
                        continue;
                    }
                }
                break;
            }
            try out.append(allocator, .{ .kind = .basic_lit, .start = start, .end = i, .text = src[start..i] });
            continue;
        }

        // Explicit semicolon
        if (c == ';') {
            try out.append(allocator, .{ .kind = .semi, .start = i, .end = i + 1, .text = src[i .. i + 1], .synthetic_semi = false });
            i += 1;
            continue;
        }

        // Operators and delimiters (longest match: 3, 2, 1)
        const op_len = matchGoOp(src[i..]);
        if (op_len == 0) {
            err_out.* = .{ .offset = i, .code = "syntax" };
            return error.ParseFailed;
        }
        try out.append(allocator, .{ .kind = .punct, .start = i, .end = i + op_len, .text = src[i .. i + op_len] });
        i += op_len;
    }

    try maybeInsertSemi(allocator, &out, src.len);
    try out.append(allocator, .{ .kind = .eof, .start = src.len, .end = src.len, .text = "" });
    return out.toOwnedSlice(allocator);
}

pub fn toCanonTokens(allocator: std.mem.Allocator, toks: []const GoTok) ![]CTok {
    var out: std.ArrayList(CTok) = .empty;
    errdefer out.deinit(allocator);
    for (toks) |t| {
        if (t.kind == .eof) continue;
        if (t.kind == .semi and t.synthetic_semi) continue;
        try out.append(allocator, .{
            .start = t.start,
            .end = t.end,
            .text = t.text,
        });
    }
    return out.toOwnedSlice(allocator);
}

fn matchGoOp(rem: []const u8) usize {
    if (rem.len >= 3) {
        const s3 = rem[0..3];
        if (std.mem.eql(u8, s3, "<<=") or
            std.mem.eql(u8, s3, ">>=") or
            std.mem.eql(u8, s3, "&^=") or
            std.mem.eql(u8, s3, "..."))
        {
            return 3;
        }
    }
    if (rem.len >= 2) {
        const s2 = rem[0..2];
        const ops2 = [_][]const u8{
            "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=",
            "<<", ">>", "&^", "&&", "||", "<-", "++", "--",
            "==", "!=", "<=", ">=", ":=",
        };
        for (ops2) |op| {
            if (std.mem.eql(u8, s2, op)) return 2;
        }
    }
    if (rem.len >= 1) {
        const c = rem[0];
        switch (c) {
            '+', '-', '*', '/', '%', '&', '|', '^', '<', '>', '=', '!', '~',
            '(', ')', '[', ']', '{', '}', ',', '.', ':' => return 1,
            else => {},
        }
    }
    return 0;
}

fn isGoIdentStart(c: u8) bool {
    return c == '_' or (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or c >= 0x80;
}

fn isGoIdentCont(c: u8) bool {
    return isGoIdentStart(c) or isGoDigit(c);
}

fn isGoDigit(c: u8) bool {
    return c >= '0' and c <= '9';
}

fn isGoNumChar(c: u8) bool {
    return isGoDigit(c) or c == '_' or (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z');
}
