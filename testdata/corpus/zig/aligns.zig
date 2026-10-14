const Aligned = extern struct {
    x: u32 align(8),
    y: u64,
};

pub var buf: [4096]u8 align(4096) = undefined;
