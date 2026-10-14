//! Ignored top-level forms.
// Line comment.
/// Doc comment on an ignored import.
const std = @import("std");
const fs = @import("fs.zig");

comptime {
    _ = 1;
}

test {
    _ = 2;
}

const _ = 5;
