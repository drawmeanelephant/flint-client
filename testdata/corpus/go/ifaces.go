package wire

type Dialer interface {
	Dial(addr string) error
}

type Listener interface {
	Accept() (Dialer, error)
}
