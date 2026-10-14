pub export fn handler() callconv(.C) void {}

fn local() callconv(.Inline) i32 {
    return 1;
}
