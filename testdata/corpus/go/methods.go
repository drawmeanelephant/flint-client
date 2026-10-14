package shapes

type Circle struct {
	Radius float64
}

type Rect struct {
	W, H float64
}

func (c Circle) Area() float64 {
	return 3.14159 * c.Radius * c.Radius
}

func (r *Rect) Scale(f float64) {
	r.W *= f
	r.H *= f
}

func (r Rect) Perimeter() float64 {
	return 2 * (r.W + r.H)
}
