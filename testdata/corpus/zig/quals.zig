pub fn one() void {}
export fn two() void {}
extern fn three() void;
inline fn four(x: i32) i32 {
    return x;
}
noinline fn five() void {}
extern "c" fn six() void;
threadlocal var counter: i32 = 0;
