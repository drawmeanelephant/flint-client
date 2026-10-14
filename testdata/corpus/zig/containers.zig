pub const Inner = struct {
    a: u8,
};

pub const Packed = packed struct(u32) {
    lo: u16,
    hi: u16,
};

pub const ExternT = extern struct {
    x: c_int,
};

pub const Tag = enum {
    first,
    second,
};

pub const NumTag = enum(u8) {
    a = 1,
    b = 2,
};

pub const U = union(enum) {
    none,
    int: i32,
    text: []const u8,
};
