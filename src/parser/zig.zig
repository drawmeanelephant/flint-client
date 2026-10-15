const std = @import("std");
const canon = @import("../canon.zig");
const zigtok = @import("zigtok.zig");
const parser = @import("parser.zig");

const CTok = canon.CTok;
const Atom = parser.Atom;
const ParseErrorInfo = parser.ParseErrorInfo;

const no_sig_cut: usize = @as(usize, 1) << 60;

pub fn parse(
    allocator: std.mem.Allocator,
    file: []const u8,
    src: []const u8,
    sink: ?*std.StringHashMap([]const u8),
    err_info: *?ParseErrorInfo,
) ![]Atom {
    var lex_err: ?zigtok.LexError = null;
    const toks = zigtok.zigTokens(allocator, src, &lex_err) catch |err| {
        if (err == error.ParseFailed) {
            if (lex_err) |le| {
                err_info.* = .{ .file = file, .offset = le.offset, .code = le.code };
            }
        }
        return err;
    };
    defer allocator.free(toks);

    var scan = ZScan{
        .allocator = allocator,
        .file = file,
        .src = src,
        .toks = toks,
        .stem = zigStem(file),
        .sink = sink,
        .err_info = err_info,
    };
    return scan.decls();
}

pub fn zigStem(file: []const u8) []const u8 {
    var base = file;
    if (std.mem.lastIndexOfScalar(u8, base, '/')) |idx| {
        base = base[idx + 1 ..];
    }
    if (std.mem.endsWith(u8, base, ".zig")) {
        base = base[0 .. base.len - 4];
    }
    return base;
}

fn isZQual(text: []const u8) bool {
    return std.mem.eql(u8, text, "pub") or
        std.mem.eql(u8, text, "export") or
        std.mem.eql(u8, text, "extern") or
        std.mem.eql(u8, text, "inline") or
        std.mem.eql(u8, text, "noinline") or
        std.mem.eql(u8, text, "threadlocal") or
        std.mem.eql(u8, text, "comptime");
}

fn isZAnonBrace(text: []const u8) bool {
    return std.mem.eql(u8, text, "struct") or
        std.mem.eql(u8, text, "enum") or
        std.mem.eql(u8, text, "union") or
        std.mem.eql(u8, text, "opaque") or
        std.mem.eql(u8, text, "error") or
        std.mem.eql(u8, text, "packed");
}

fn zname(t: CTok) []const u8 {
    if (std.mem.startsWith(u8, t.text, "@\"") and t.text.len >= 3) {
        return t.text[2 .. t.text.len - 1];
    }
    return t.text;
}

const ZScan = struct {
    allocator: std.mem.Allocator,
    file: []const u8,
    src: []const u8,
    toks: []const CTok,
    stem: []const u8,
    sink: ?*std.StringHashMap([]const u8),
    err_info: *?ParseErrorInfo,
    i: usize = 0,

    fn at(self: *const ZScan, idx: usize) CTok {
        if (idx < self.toks.len) return self.toks[idx];
        return self.toks[self.toks.len - 1];
    }

    fn is(self: *const ZScan, idx: usize, text: []const u8) bool {
        const t = self.at(idx);
        return zigtok.zkindOf(t) == .ident and std.mem.eql(u8, t.text, text);
    }

    fn punct(self: *const ZScan, idx: usize, text: []const u8) bool {
        const t = self.at(idx);
        return zigtok.zkindOf(t) == .punct and std.mem.eql(u8, t.text, text);
    }

    fn unsupported(self: *ZScan, off: usize) error{ParseFailed} {
        self.err_info.* = .{ .file = self.file, .offset = off, .code = "parse_unsupported" };
        return error.ParseFailed;
    }

    fn syntaxErr(self: *ZScan, off: usize) error{ParseFailed} {
        self.err_info.* = .{ .file = self.file, .offset = off, .code = "syntax" };
        return error.ParseFailed;
    }

    fn skipBalanced(self: *ZScan, start_idx: usize) !usize {
        const open = self.toks[start_idx].text;
        const close: []const u8 = if (std.mem.eql(u8, open, "("))
            ")"
        else if (std.mem.eql(u8, open, "["))
            "]"
        else if (std.mem.eql(u8, open, "{"))
            "}"
        else
            return self.syntaxErr(self.toks[start_idx].start);

        var depth: usize = 1;
        var idx = start_idx + 1;
        while (idx < self.toks.len) : (idx += 1) {
            const t = self.toks[idx];
            if (zigtok.zkindOf(t) != .punct) continue;
            if (std.mem.eql(u8, t.text, open)) {
                depth += 1;
            } else if (std.mem.eql(u8, t.text, close)) {
                depth -= 1;
                if (depth == 0) return idx;
            }
        }
        return self.syntaxErr(self.at(idx - 1).end);
    }

    fn skipSemi(self: *ZScan, start_idx: usize) !usize {
        var depth: isize = 0;
        var idx = start_idx;
        while (idx < self.toks.len) : (idx += 1) {
            const t = self.toks[idx];
            if (zigtok.zkindOf(t) != .punct) continue;
            if (std.mem.eql(u8, t.text, "(") or std.mem.eql(u8, t.text, "[") or std.mem.eql(u8, t.text, "{")) {
                depth += 1;
            } else if (std.mem.eql(u8, t.text, ")") or std.mem.eql(u8, t.text, "]") or std.mem.eql(u8, t.text, "}")) {
                depth -= 1;
            } else if (std.mem.eql(u8, t.text, ";") and depth == 0) {
                return idx;
            }
        }
        return self.syntaxErr(self.src.len);
    }

    fn decls(self: *ZScan) ![]Atom {
        var atoms: std.ArrayList(Atom) = .empty;
        errdefer {
            for (atoms.items) |*a| a.deinit(self.allocator);
            atoms.deinit(self.allocator);
        }

        while (self.i < self.toks.len - 1) {
            const t = self.toks[self.i];
            if (self.is(self.i, "comptime") and self.punct(self.i + 1, "{")) {
                const close = try self.skipBalanced(self.i + 1);
                self.i = close + 1;
                continue;
            }
            const start = t.start;
            while (self.i < self.toks.len - 1 and zigtok.zkindOf(self.toks[self.i]) == .ident and isZQual(self.toks[self.i].text)) {
                if (self.is(self.i, "extern") and zigtok.zkindOf(self.at(self.i + 1)) == .str) {
                    self.i += 1;
                }
                self.i += 1;
            }
            if (self.i >= self.toks.len - 1) {
                return self.syntaxErr(start);
            }
            const kw = self.toks[self.i];
            if (zigtok.zkindOf(kw) != .ident) {
                return self.unsupported(kw.start);
            }
            if (std.mem.eql(u8, kw.text, "fn")) {
                const a = try self.scanFn(start);
                try atoms.append(self.allocator, a);
            } else if (std.mem.eql(u8, kw.text, "const") or std.mem.eql(u8, kw.text, "var")) {
                if (try self.scanVarConst(start, kw.text)) |a| {
                    try atoms.append(self.allocator, a);
                }
            } else if (std.mem.eql(u8, kw.text, "test")) {
                if (try self.scanTest(start)) |a| {
                    try atoms.append(self.allocator, a);
                }
            } else if (std.mem.eql(u8, kw.text, "usingnamespace")) {
                const semi = try self.skipSemi(self.i + 1);
                self.i = semi + 1;
            } else {
                return self.unsupported(kw.start);
            }
        }

        return atoms.toOwnedSlice(self.allocator);
    }

    fn emit(
        self: *ZScan,
        kind: []const u8,
        qname: []const u8,
        start: usize,
        end: usize,
        name_pos: usize,
        sig_cut: usize,
    ) !Atom {
        var in_toks: std.ArrayList(CTok) = .empty;
        defer in_toks.deinit(self.allocator);

        for (self.toks) |t| {
            if (t.text.len != 0 and t.start >= start and t.start < end) {
                try in_toks.append(self.allocator, t);
            }
        }

        const hashes = try canon.canonize(
            self.allocator,
            kind,
            qname,
            in_toks.items,
            name_pos,
            sig_cut,
            -1,
            self.sink,
        );

        const kind_dup = try self.allocator.dupe(u8, kind);
        errdefer self.allocator.free(kind_dup);
        const name_dup = try self.allocator.dupe(u8, qname);
        errdefer self.allocator.free(name_dup);
        const file_dup = try self.allocator.dupe(u8, self.file);
        errdefer self.allocator.free(file_dup);

        return .{
            .kind = kind_dup,
            .name = name_dup,
            .file = file_dup,
            .start = @intCast(start),
            .end = @intCast(end),
            .hash = hashes.hash,
            .sig_hash = hashes.sig_hash,
        };
    }

    fn scanFn(self: *ZScan, start: usize) !Atom {
        var idx = self.i + 1;
        const name_tok = self.at(idx);
        if (zigtok.zkindOf(name_tok) != .ident) {
            return self.unsupported(name_tok.start);
        }
        const name = zname(name_tok);
        idx += 1;
        if (!self.punct(idx, "(")) {
            return self.unsupported(self.at(idx).start);
        }
        const close = try self.skipBalanced(idx);
        idx = close + 1;

        var depth: isize = 0;
        while (idx < self.toks.len) : (idx += 1) {
            const t = self.toks[idx];
            if (zigtok.zkindOf(t) != .punct) continue;
            if (std.mem.eql(u8, t.text, "(") or std.mem.eql(u8, t.text, "[")) {
                depth += 1;
            } else if (std.mem.eql(u8, t.text, ")") or std.mem.eql(u8, t.text, "]")) {
                depth -= 1;
            } else if (std.mem.eql(u8, t.text, "{")) {
                if (depth != 0) continue;
                const prev = self.at(idx - 1);
                if (zigtok.zkindOf(prev) == .ident and isZAnonBrace(prev.text)) {
                    return self.unsupported(prev.start);
                }
                const body_close = try self.skipBalanced(idx);
                const end = self.toks[body_close].end;
                self.i = body_close + 1;
                const qname = try std.fmt.allocPrint(self.allocator, "{s}.{s}", .{ self.stem, name });
                defer self.allocator.free(qname);
                return self.emit("fn", qname, start, end, name_tok.start, t.start);
            } else if (std.mem.eql(u8, t.text, ";")) {
                if (depth != 0) continue;
                const end = t.end;
                self.i = idx + 1;
                const qname = try std.fmt.allocPrint(self.allocator, "{s}.{s}", .{ self.stem, name });
                defer self.allocator.free(qname);
                return self.emit("fn", qname, start, end, name_tok.start, no_sig_cut);
            }
        }
        return self.syntaxErr(start);
    }

    fn scanVarConst(self: *ZScan, start: usize, kw: []const u8) !?Atom {
        var idx = self.i + 1;
        const name_tok = self.at(idx);
        if (zigtok.zkindOf(name_tok) != .ident) {
            return self.unsupported(name_tok.start);
        }
        const name = zname(name_tok);
        idx += 1;
        if (std.mem.eql(u8, name, "_")) {
            const semi = try self.skipSemi(idx);
            self.i = semi + 1;
            return null;
        }

        var depth: isize = 0;
        var found_eq = false;
        while (idx < self.toks.len) : (idx += 1) {
            const t = self.toks[idx];
            if (zigtok.zkindOf(t) != .punct) continue;
            if (std.mem.eql(u8, t.text, "(") or std.mem.eql(u8, t.text, "[") or std.mem.eql(u8, t.text, "{")) {
                depth += 1;
            } else if (std.mem.eql(u8, t.text, ")") or std.mem.eql(u8, t.text, "]") or std.mem.eql(u8, t.text, "}")) {
                depth -= 1;
            } else if (std.mem.eql(u8, t.text, "=") and depth == 0) {
                found_eq = true;
                break;
            } else if (std.mem.eql(u8, t.text, ";") and depth == 0) {
                self.i = idx + 1;
                const sig_cut = if (std.mem.eql(u8, kw, "var")) t.start else no_sig_cut;
                const qname = try std.fmt.allocPrint(self.allocator, "{s}.{s}", .{ self.stem, name });
                defer self.allocator.free(qname);
                return try self.emit(kw, qname, start, t.end, name_tok.start, sig_cut);
            }
        }
        if (!found_eq) {
            return self.syntaxErr(start);
        }

        idx += 1; // past '='
        const eq_tok_start = self.toks[idx - 1].start;
        var v = self.at(idx);
        while (zigtok.zkindOf(v) == .ident and (std.mem.eql(u8, v.text, "extern") or std.mem.eql(u8, v.text, "packed"))) {
            idx += 1;
            if (std.mem.eql(u8, self.at(idx - 1).text, "packed") and self.punct(idx, "(")) {
                const close = try self.skipBalanced(idx);
                idx = close + 1;
            }
            v = self.at(idx);
        }
        if (zigtok.zkindOf(v) == .ident and std.mem.eql(u8, v.text, "@import")) {
            const semi = try self.skipSemi(idx);
            self.i = semi + 1;
            return null;
        }
        if (zigtok.zkindOf(v) == .ident and std.mem.eql(u8, v.text, "opaque")) {
            return self.unsupported(v.start);
        }
        if (zigtok.zkindOf(v) == .ident and
            (std.mem.eql(u8, v.text, "struct") or std.mem.eql(u8, v.text, "enum") or std.mem.eql(u8, v.text, "union")))
        {
            const kind = v.text;
            idx += 1;
            if (self.punct(idx, "(")) {
                const close = try self.skipBalanced(idx);
                idx = close + 1;
            }
            if (!self.punct(idx, "{")) {
                return self.unsupported(self.at(idx).start);
            }
            const close = try self.skipBalanced(idx);
            idx = close + 1;
            var end = self.toks[close].end;
            if (self.punct(idx, ";")) {
                end = self.toks[idx].end;
                idx += 1;
            }
            self.i = idx;
            const qname = try std.fmt.allocPrint(self.allocator, "{s}.{s}", .{ self.stem, name });
            defer self.allocator.free(qname);
            return try self.emit(kind, qname, start, end, name_tok.start, no_sig_cut);
        }

        const sig_cut = if (std.mem.eql(u8, kw, "var")) eq_tok_start else no_sig_cut;
        const semi = try self.skipSemi(idx);
        self.i = semi + 1;
        const qname = try std.fmt.allocPrint(self.allocator, "{s}.{s}", .{ self.stem, name });
        defer self.allocator.free(qname);
        return try self.emit(kw, qname, start, self.toks[semi].end, name_tok.start, sig_cut);
    }

    fn scanTest(self: *ZScan, start: usize) !?Atom {
        var idx = self.i + 1;
        const t = self.at(idx);
        if (zigtok.zkindOf(t) == .punct and std.mem.eql(u8, t.text, "{")) {
            const close = try self.skipBalanced(idx);
            self.i = close + 1;
            return null;
        }
        if (zigtok.zkindOf(t) != .str) {
            return self.unsupported(t.start);
        }
        const label = t.text[1 .. t.text.len - 1];
        idx += 1;
        if (!self.punct(idx, "{")) {
            return self.unsupported(self.at(idx).start);
        }
        const close = try self.skipBalanced(idx);
        self.i = close + 1;
        const qname = try std.fmt.allocPrint(self.allocator, "{s}.test:{s}", .{ self.stem, label });
        defer self.allocator.free(qname);
        return try self.emit("test", qname, start, self.toks[close].end, t.start, self.toks[idx].start);
    }
};
