package receiptsigner

import (
	"errors"
	"net"
	"sync"
)

// LimitListener bounds accepted live connections. This is separate from the
// handler semaphore because clients can otherwise retain idle or partial HTTP
// connections without occupying a signing slot.
func LimitListener(listener net.Listener, maximum int) (net.Listener, error) {
	if listener == nil || maximum <= 0 || maximum > MaxConcurrent {
		return nil, errors.New("invalid receipt signer connection limit")
	}
	return &limitedListener{
		Listener: listener, slots: make(chan struct{}, maximum),
		closed: make(chan struct{}),
	}, nil
}

type limitedListener struct {
	net.Listener
	slots     chan struct{}
	closed    chan struct{}
	closeOnce sync.Once
	closeErr  error
}

func (l *limitedListener) Accept() (net.Conn, error) {
	select {
	case l.slots <- struct{}{}:
	case <-l.closed:
		return nil, net.ErrClosed
	}
	connection, err := l.Listener.Accept()
	if err != nil {
		<-l.slots
		return nil, err
	}
	return &limitedConnection{
		Conn:    connection,
		release: func() { <-l.slots },
	}, nil
}

func (l *limitedListener) Close() error {
	l.closeOnce.Do(func() {
		close(l.closed)
		l.closeErr = l.Listener.Close()
	})
	return l.closeErr
}

type limitedConnection struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *limitedConnection) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
