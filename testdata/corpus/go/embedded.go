package emb

type Base struct {
	ID int
}

type Derived struct {
	Base
	Tag string
}
