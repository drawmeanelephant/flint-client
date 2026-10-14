//! Top-level doc comment.

/// Doc for Widget.
pub const Widget = struct {
    size: i32,
};

/// Doc for draw.
pub fn draw(w: Widget) i32 {
    return w.size;
}
