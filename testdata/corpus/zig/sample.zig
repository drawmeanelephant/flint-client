const limit = 100;

pub const Point = struct {
    x: i32,
    y: i32,
};

pub fn add(a: i32, b: i32) i32 {
    return a + b;
}

fn helper(x: i32) i32 {
    return x * 2;
}

export fn entry() void {}

test "add works" {
    const r = add(1, 2);
    _ = r;
}
