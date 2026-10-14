const banner =
    \\ first line
    \\ second line
    \\ third { with brace
;

pub fn greet() []const u8 {
    return banner;
}
