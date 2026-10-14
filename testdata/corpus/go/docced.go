package docs

// Widget renders things.
type Widget struct {
	Size int
}

// Draw paints the widget.
func Draw(w Widget) int {
	return w.Size
}
