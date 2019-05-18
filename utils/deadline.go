package utils

import (
	"net"
	"time"
)

func SetListenerDeadline(l net.Listener, t time.Time) error {
	switch v := l.(type) {
	case *net.TCPListener:
		return v.SetDeadline(t)
	case *net.UnixListener:
		return v.SetDeadline(t)
	}
	return nil
}
