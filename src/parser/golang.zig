const std = @import("std");
const canon = @import("../canon.zig");
const store = @import("../store.zig");
const gotok = @import("gotok.zig");
const parser = @import("parser.zig");

const CTok = canon.CTok;
const GoTok = gotok.GoTok;
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
    var lex_err: ?gotok.LexError = null;
    const toks = gotok.goTokens(allocator, src, &lex_err) catch |err| {
        if (err == error.ParseFailed) {
            if (lex_err) |le| {
                err_info.* = .{ .file = file, .offset = le.offset, .code = le.code };
            }
        }
        return err;
    };
    defer allocator.free(toks);

    const ctoks = try gotok.toCanonTokens(allocator, toks);
    defer allocator.free(ctoks);

    var scan = GScan{
        .allocator = allocator,
        .file = file,
        .src = src,
        .toks = toks,
        .ctoks = ctoks,
        .sink = sink,
        .err_info = err_info,
    };
    return scan.parseFileDecls();
}

fn dropName(name: []const u8) bool {
    return std.mem.eql(u8, name, "_") or std.mem.eql(u8, name, "init");
}

const GScan = struct {
    allocator: std.mem.Allocator,
    file: []const u8,
    src: []const u8,
    toks: []const GoTok,
    ctoks: []const CTok,
    pkg: []const u8 = "",
    sink: ?*std.StringHashMap([]const u8),
    err_info: *?ParseErrorInfo,
    i: usize = 0,

    fn at(self: *const GScan, idx: usize) GoTok {
        if (idx < self.toks.len) return self.toks[idx];
        return self.toks[self.toks.len - 1];
    }

    fn isKw(self: *const GScan, idx: usize, text: []const u8) bool {
        const t = self.at(idx);
        return t.kind == .keyword and std.mem.eql(u8, t.text, text);
    }

    fn isPunct(self: *const GScan, idx: usize, text: []const u8) bool {
        const t = self.at(idx);
        return t.kind == .punct and std.mem.eql(u8, t.text, text);
    }

    fn syntaxErr(self: *GScan, off: usize) error{ParseFailed} {
        self.err_info.* = .{ .file = self.file, .offset = off, .code = "syntax" };
        return error.ParseFailed;
    }

    fn skipSemis(self: *GScan) void {
        while (self.at(self.i).kind == .semi) : (self.i += 1) {}
    }

    fn skipBalanced(self: *GScan, start_idx: usize) !usize {
        const open = self.at(start_idx).text;
        const close: []const u8 = if (std.mem.eql(u8, open, "("))
            ")"
        else if (std.mem.eql(u8, open, "["))
            "]"
        else if (std.mem.eql(u8, open, "{"))
            "}"
        else
            return self.syntaxErr(self.at(start_idx).start);

        var depth: usize = 1;
        var idx = start_idx + 1;
        while (idx < self.toks.len and self.toks[idx].kind != .eof) : (idx += 1) {
            const t = self.toks[idx];
            if (t.kind != .punct) continue;
            if (std.mem.eql(u8, t.text, open)) {
                depth += 1;
            } else if (std.mem.eql(u8, t.text, close)) {
                depth -= 1;
                if (depth == 0) return idx;
            }
        }
        return self.syntaxErr(self.at(idx).start);
    }

    /// Skips a `( ... )` parameter/receiver/result list where a `{` is only valid
    /// immediately after `struct` or `interface`.
    fn skipFieldListParens(self: *GScan, start_idx: usize) !usize {
        if (!self.isPunct(start_idx, "(")) {
            return self.syntaxErr(self.at(start_idx).start);
        }
        var depth: usize = 1;
        var idx = start_idx + 1;
        while (idx < self.toks.len and self.toks[idx].kind != .eof) : (idx += 1) {
            const t = self.toks[idx];
            if (t.kind != .punct) continue;
            if (std.mem.eql(u8, t.text, "(")) {
                depth += 1;
            } else if (std.mem.eql(u8, t.text, ")")) {
                depth -= 1;
                if (depth == 0) return idx;
            } else if (std.mem.eql(u8, t.text, "[")) {
                idx = try self.skipBalanced(idx);
            } else if (std.mem.eql(u8, t.text, "{")) {
                const prev = self.at(idx - 1);
                const ok_brace = prev.kind == .keyword and
                    (std.mem.eql(u8, prev.text, "struct") or std.mem.eql(u8, prev.text, "interface"));
                if (!ok_brace) {
                    return self.syntaxErr(t.start);
                }
                idx = try self.skipBalanced(idx);
            } else if (std.mem.eql(u8, t.text, "]") or std.mem.eql(u8, t.text, "}")) {
                return self.syntaxErr(t.start);
            }
        }
        return self.syntaxErr(self.at(idx).start);
    }

    fn parseFileDecls(self: *GScan) ![]Atom {
        var atoms: std.ArrayList(Atom) = .empty;
        errdefer {
            for (atoms.items) |*a| a.deinit(self.allocator);
            atoms.deinit(self.allocator);
        }

        self.skipSemis();
        if (!self.isKw(self.i, "package")) {
            return self.syntaxErr(self.at(self.i).start);
        }
        self.i += 1;
        const pkg_tok = self.at(self.i);
        if (pkg_tok.kind != .ident) {
            return self.syntaxErr(pkg_tok.start);
        }
        self.pkg = pkg_tok.text;
        self.i += 1;
        if (self.at(self.i).kind != .semi and self.at(self.i).kind != .eof) {
            return self.syntaxErr(self.at(self.i).start);
        }
        self.skipSemis();

        while (self.at(self.i).kind != .eof) {
            self.skipSemis();
            const t = self.at(self.i);
            if (t.kind == .eof) break;
            if (t.kind != .keyword) {
                return self.syntaxErr(t.start);
            }
            if (std.mem.eql(u8, t.text, "import")) {
                try self.parseImportDecl();
            } else if (std.mem.eql(u8, t.text, "type")) {
                try self.parseTypeDecl(&atoms);
            } else if (std.mem.eql(u8, t.text, "const") or std.mem.eql(u8, t.text, "var")) {
                try self.parseValueDecl(t.text, &atoms);
            } else if (std.mem.eql(u8, t.text, "func")) {
                try self.parseFuncDecl(&atoms);
            } else {
                return self.syntaxErr(t.start);
            }
        }

        return atoms.toOwnedSlice(self.allocator);
    }

    fn parseImportDecl(self: *GScan) !void {
        self.i += 1; // past 'import'
        if (self.isPunct(self.i, "(")) {
            const close = try self.skipBalanced(self.i);
            self.i = close + 1;
            self.skipSemis();
            return;
        }
        if (self.at(self.i).kind == .ident or self.isPunct(self.i, ".")) {
            self.i += 1;
        }
        const path_tok = self.at(self.i);
        if (path_tok.kind != .basic_lit) {
            return self.syntaxErr(path_tok.start);
        }
        self.i += 1;
        if (self.at(self.i).kind != .semi and self.at(self.i).kind != .eof) {
            return self.syntaxErr(self.at(self.i).start);
        }
        self.skipSemis();
    }

    fn parseTypeDecl(self: *GScan, atoms: *std.ArrayList(Atom)) !void {
        self.i += 1; // past 'type'
        if (self.isPunct(self.i, "(")) {
            self.i += 1;
            while (self.at(self.i).kind != .eof) {
                self.skipSemis();
                if (self.isPunct(self.i, ")")) {
                    self.i += 1;
                    self.skipSemis();
                    return;
                }
                try self.parseTypeSpec(atoms);
            }
            return self.syntaxErr(self.at(self.i).start);
        }
        try self.parseTypeSpec(atoms);
    }

    fn parseTypeSpec(self: *GScan, atoms: *std.ArrayList(Atom)) !void {
        const name_tok = self.at(self.i);
        if (name_tok.kind != .ident) {
            return self.syntaxErr(name_tok.start);
        }
        const spec_start = name_tok.start;
        self.i += 1;

        if (self.isPunct(self.i, "[")) {
            const close = try self.skipBalanced(self.i);
            self.i = close + 1;
        }

        var is_alias = false;
        if (self.isPunct(self.i, "=")) {
            is_alias = true;
            self.i += 1;
        }

        const type_first = self.at(self.i);
        if (type_first.kind == .semi or type_first.kind == .eof or self.isPunct(self.i, ")")) {
            return self.syntaxErr(type_first.start);
        }

        const kind: []const u8 = if (is_alias)
            "type_alias"
        else if (type_first.kind == .keyword and std.mem.eql(u8, type_first.text, "struct"))
            "struct"
        else if (type_first.kind == .keyword and std.mem.eql(u8, type_first.text, "interface"))
            "interface"
        else
            "type";

        var last_end = type_first.end;
        while (self.at(self.i).kind != .eof) {
            const cur = self.at(self.i);
            if (cur.kind == .semi or self.isPunct(self.i, ")")) {
                break;
            }
            if (self.isPunct(self.i, "(") or self.isPunct(self.i, "[") or self.isPunct(self.i, "{")) {
                const close = try self.skipBalanced(self.i);
                last_end = self.toks[close].end;
                self.i = close + 1;
                continue;
            }
            if (self.isPunct(self.i, "]") or self.isPunct(self.i, "}")) {
                return self.syntaxErr(cur.start);
            }
            last_end = cur.end;
            self.i += 1;
        }

        if (self.at(self.i).kind == .semi) {
            self.i += 1;
        }

        if (!dropName(name_tok.text)) {
            const qname = try std.fmt.allocPrint(self.allocator, "{s}.{s}", .{ self.pkg, name_tok.text });
            defer self.allocator.free(qname);
            const a = try self.emitGoAtom(kind, qname, spec_start, last_end, name_tok.start, null, -1, &.{});
            try atoms.append(self.allocator, a);
        }
    }

    fn parseValueDecl(self: *GScan, kw: []const u8, atoms: *std.ArrayList(Atom)) !void {
        self.i += 1; // past 'const' or 'var'
        if (self.isPunct(self.i, "(")) {
            self.i += 1;
            var spec_idx: usize = 0;
            while (self.at(self.i).kind != .eof) {
                self.skipSemis();
                if (self.isPunct(self.i, ")")) {
                    self.i += 1;
                    self.skipSemis();
                    return;
                }
                try self.parseValueSpec(kw, true, spec_idx, atoms);
                spec_idx += 1;
            }
            return self.syntaxErr(self.at(self.i).start);
        }
        try self.parseValueSpec(kw, false, 0, atoms);
    }

    fn parseValueSpec(self: *GScan, kw: []const u8, in_group: bool, spec_idx: usize, atoms: *std.ArrayList(Atom)) !void {
        const first_name = self.at(self.i);
        if (first_name.kind != .ident) {
            return self.syntaxErr(first_name.start);
        }
        const spec_start = first_name.start;

        var names: std.ArrayList(GoTok) = .empty;
        defer names.deinit(self.allocator);
        try names.append(self.allocator, first_name);
        self.i += 1;

        while (self.isPunct(self.i, ",")) {
            self.i += 1;
            const next_name = self.at(self.i);
            if (next_name.kind != .ident) {
                return self.syntaxErr(next_name.start);
            }
            try names.append(self.allocator, next_name);
            self.i += 1;
        }

        var has_values = false;
        var has_extra_toks = false;
        var last_end = names.items[names.items.len - 1].end;
        while (self.at(self.i).kind != .eof) {
            const cur = self.at(self.i);
            if (cur.kind == .semi or self.isPunct(self.i, ")")) {
                break;
            }
            has_extra_toks = true;
            if (self.isPunct(self.i, "(") or self.isPunct(self.i, "[") or self.isPunct(self.i, "{")) {
                const close = try self.skipBalanced(self.i);
                last_end = self.toks[close].end;
                self.i = close + 1;
                continue;
            }
            if (self.isPunct(self.i, "]") or self.isPunct(self.i, "}")) {
                return self.syntaxErr(cur.start);
            }
            if (self.isPunct(self.i, "=")) {
                has_values = true;
            }
            last_end = cur.end;
            self.i += 1;
        }

        if (std.mem.eql(u8, kw, "const") and !has_values) {
            if (!in_group or spec_idx == 0 or has_extra_toks) {
                return self.syntaxErr(spec_start);
            }
        } else if (std.mem.eql(u8, kw, "var") and !has_values and !has_extra_toks) {
            return self.syntaxErr(spec_start);
        }

        if (self.at(self.i).kind == .semi) {
            self.i += 1;
        }

        const iota_idx: isize = if (std.mem.eql(u8, kw, "const") and !has_values)
            @intCast(spec_idx)
        else
            -1;

        for (names.items) |n| {
            if (dropName(n.text)) continue;
            const qname = try std.fmt.allocPrint(self.allocator, "{s}.{s}", .{ self.pkg, n.text });
            defer self.allocator.free(qname);
            const a = try self.emitGoAtom(kw, qname, spec_start, last_end, n.start, null, iota_idx, &.{});
            try atoms.append(self.allocator, a);
        }
    }

    const ReceiverInfo = struct {
        written: []u8,
        base: []u8,
    };

    fn parseFuncDecl(self: *GScan, atoms: *std.ArrayList(Atom)) !void {
        const func_start = self.at(self.i).start;
        self.i += 1; // past 'func'

        var recv_info: ?ReceiverInfo = null;
        defer if (recv_info) |ri| {
            self.allocator.free(ri.written);
            self.allocator.free(ri.base);
        };

        if (self.isPunct(self.i, "(")) {
            const recv_open = self.i;
            const recv_close = try self.skipFieldListParens(recv_open);
            recv_info = try self.extractReceiver(self.toks[recv_open + 1 .. recv_close]);
            self.i = recv_close + 1;
        }

        const name_tok = self.at(self.i);
        if (name_tok.kind != .ident) {
            return self.syntaxErr(name_tok.start);
        }
        self.i += 1;

        var has_type_params = false;
        if (self.isPunct(self.i, "[")) {
            has_type_params = true;
            const tp_close = try self.skipBalanced(self.i);
            self.i = tp_close + 1;
        }

        if (!self.isPunct(self.i, "(")) {
            return self.syntaxErr(self.at(self.i).start);
        }
        const params_open = self.i;
        const params_close = try self.skipFieldListParens(params_open);
        const param_toks = self.toks[params_open + 1 .. params_close];
        self.i = params_close + 1;

        const after_params_idx = self.i;
        var has_results = false;
        var body_sig_off: usize = 0;
        var func_end: usize = self.toks[params_close].end;
        var found_end = false;

        while (self.at(self.i).kind != .eof) {
            const cur = self.at(self.i);
            if (cur.kind == .semi) {
                has_results = (self.i > after_params_idx);
                func_end = self.toks[self.i - 1].end;
                body_sig_off = func_end;
                self.i += 1;
                found_end = true;
                break;
            }
            if (self.isPunct(self.i, "(")) {
                const close = try self.skipFieldListParens(self.i);
                func_end = self.toks[close].end;
                self.i = close + 1;
                continue;
            }
            if (self.isPunct(self.i, "[")) {
                const close = try self.skipBalanced(self.i);
                func_end = self.toks[close].end;
                self.i = close + 1;
                continue;
            }
            if (cur.kind == .keyword and
                (std.mem.eql(u8, cur.text, "struct") or std.mem.eql(u8, cur.text, "interface")) and
                self.isPunct(self.i + 1, "{"))
            {
                const close = try self.skipBalanced(self.i + 1);
                func_end = self.toks[close].end;
                self.i = close + 1;
                continue;
            }
            if (self.isPunct(self.i, "{")) {
                has_results = (self.i > after_params_idx);
                body_sig_off = cur.start;
                const body_close = try self.skipBalanced(self.i);
                func_end = self.toks[body_close].end;
                self.i = body_close + 1;
                if (self.at(self.i).kind == .semi) {
                    self.i += 1;
                }
                found_end = true;
                break;
            }
            if (self.isPunct(self.i, ")") or self.isPunct(self.i, "]") or self.isPunct(self.i, "}")) {
                return self.syntaxErr(cur.start);
            }
            func_end = cur.end;
            self.i += 1;
        }

        if (!found_end) {
            return self.syntaxErr(func_start);
        }

        if (dropName(name_tok.text)) return;

        if (recv_info) |ri| {
            const qname = try std.fmt.allocPrint(self.allocator, "{s}.{s}.{s}", .{ self.pkg, ri.base, name_tok.text });
            defer self.allocator.free(qname);
            var meta = try self.allocator.alloc(store.MetaEntry, 1);
            errdefer self.allocator.free(meta);
            const k_dup = try self.allocator.dupe(u8, "receiver");
            errdefer self.allocator.free(k_dup);
            const v_dup = try self.allocator.dupe(u8, ri.written);
            meta[0] = .{ .key = k_dup, .value = v_dup };

            const a = try self.emitGoAtom(
                "method",
                qname,
                func_start,
                func_end,
                name_tok.start,
                body_sig_off,
                -1,
                meta,
            );
            try atoms.append(self.allocator, a);
            return;
        }

        const is_test = isTestFunc(name_tok.text, has_type_params, has_results, param_toks);
        const kind = if (is_test) "test" else "fn";
        const qname = if (is_test)
            try std.fmt.allocPrint(self.allocator, "{s}.test:{s}", .{ self.pkg, name_tok.text })
        else
            try std.fmt.allocPrint(self.allocator, "{s}.{s}", .{ self.pkg, name_tok.text });
        defer self.allocator.free(qname);

        const a = try self.emitGoAtom(
            kind,
            qname,
            func_start,
            func_end,
            name_tok.start,
            body_sig_off,
            -1,
            &.{},
        );
        try atoms.append(self.allocator, a);
    }

    fn extractReceiver(self: *GScan, recv_toks: []const GoTok) !ReceiverInfo {
        var slice = recv_toks;
        while (slice.len > 0 and (slice[slice.len - 1].kind == .semi or
            (slice[slice.len - 1].kind == .punct and std.mem.eql(u8, slice[slice.len - 1].text, ","))))
        {
            slice = slice[0 .. slice.len - 1];
        }
        if (slice.len == 0) {
            return self.syntaxErr(self.at(self.i).start);
        }

        // If first token is receiver identifier followed by type tokens, skip receiver name
        if (slice[0].kind == .ident and slice.len >= 2) {
            const second = slice[1];
            const is_type_cont = second.kind == .punct and
                (std.mem.eql(u8, second.text, ".") or std.mem.eql(u8, second.text, "["));
            if (!is_type_cont) {
                slice = slice[1..];
            }
        }

        // Strip outer parens if any
        while (slice.len >= 2 and
            slice[0].kind == .punct and std.mem.eql(u8, slice[0].text, "(") and
            slice[slice.len - 1].kind == .punct and std.mem.eql(u8, slice[slice.len - 1].text, ")"))
        {
            slice = slice[1 .. slice.len - 1];
        }

        var written: std.ArrayList(u8) = .empty;
        errdefer written.deinit(self.allocator);
        var base: std.ArrayList(u8) = .empty;
        errdefer base.deinit(self.allocator);

        var in_brackets: usize = 0;
        for (slice) |t| {
            if (t.kind == .semi) continue;
            if (t.kind == .punct and std.mem.eql(u8, t.text, "(")) continue;
            if (t.kind == .punct and std.mem.eql(u8, t.text, ")")) continue;

            if (t.kind == .punct and std.mem.eql(u8, t.text, "[")) {
                in_brackets += 1;
                try written.appendSlice(self.allocator, t.text);
                continue;
            }
            if (t.kind == .punct and std.mem.eql(u8, t.text, "]")) {
                if (in_brackets > 0) in_brackets -= 1;
                try written.appendSlice(self.allocator, t.text);
                continue;
            }
            try written.appendSlice(self.allocator, t.text);
            if (in_brackets == 0 and !(t.kind == .punct and std.mem.eql(u8, t.text, "*"))) {
                try base.appendSlice(self.allocator, t.text);
            }
        }

        if (base.items.len == 0) {
            try base.appendSlice(self.allocator, "_");
        }
        if (written.items.len == 0) {
            try written.appendSlice(self.allocator, "_");
        }

        return .{
            .written = try written.toOwnedSlice(self.allocator),
            .base = try base.toOwnedSlice(self.allocator),
        };
    }

    fn emitGoAtom(
        self: *GScan,
        kind: []const u8,
        qname: []const u8,
        start: usize,
        stop: usize,
        name_pos: usize,
        sig_off: ?usize,
        iota_idx: isize,
        meta: []store.MetaEntry,
    ) !Atom {
        var in_toks: std.ArrayList(CTok) = .empty;
        defer in_toks.deinit(self.allocator);

        for (self.ctoks) |t| {
            if (t.text.len != 0 and t.start >= start and t.start < stop) {
                try in_toks.append(self.allocator, t);
            }
        }

        var sig_cut: usize = no_sig_cut;
        if (sig_off) |so| {
            sig_cut = so;
        } else if (std.mem.eql(u8, kind, "var")) {
            for (in_toks.items) |t| {
                if (std.mem.eql(u8, t.text, "=")) {
                    sig_cut = t.start;
                    break;
                }
            }
        }

        const hashes = try canon.canonize(
            self.allocator,
            kind,
            qname,
            in_toks.items,
            name_pos,
            sig_cut,
            iota_idx,
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
            .end = @intCast(stop),
            .hash = hashes.hash,
            .sig_hash = hashes.sig_hash,
            .meta = meta,
        };
    }
};

fn isTestFunc(
    name: []const u8,
    has_type_params: bool,
    has_results: bool,
    param_toks: []const GoTok,
) bool {
    if (name.len < 5 or !std.mem.startsWith(u8, name, "Test") or (name[4] >= 'a' and name[4] <= 'z')) return false;
    if (has_type_params or has_results) return false;

    var filtered: [8]GoTok = undefined;
    var count: usize = 0;
    for (param_toks) |t| {
        if (t.kind == .semi) continue;
        if (count >= filtered.len) return false;
        filtered[count] = t;
        count += 1;
    }
    if (count > 0 and filtered[count - 1].kind == .punct and std.mem.eql(u8, filtered[count - 1].text, ",")) {
        count -= 1;
    }

    var idx: usize = 0;
    if (count == 5) {
        if (filtered[0].kind != .ident) return false;
        idx = 1;
    } else if (count == 4) {
        idx = 0;
    } else {
        return false;
    }

    return filtered[idx].kind == .punct and std.mem.eql(u8, filtered[idx].text, "*") and
        filtered[idx + 1].kind == .ident and std.mem.eql(u8, filtered[idx + 1].text, "testing") and
        filtered[idx + 2].kind == .punct and std.mem.eql(u8, filtered[idx + 2].text, ".") and
        filtered[idx + 3].kind == .ident and std.mem.eql(u8, filtered[idx + 3].text, "T");
}
