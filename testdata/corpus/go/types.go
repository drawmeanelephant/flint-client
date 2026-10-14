package defs

type Config struct {
	Name string
	Ver  int
}

type Reader interface {
	Read(p []byte) (int, error)
}

type Closer interface {
	Close() error
}

type Handle uint64

type Level int

type Alias = Config
