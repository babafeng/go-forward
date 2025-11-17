package proxy

import (
	"io"
	"net"
	"sync"
	"time"
)

func linkConns(a, b net.Conn) {
	var wg sync.WaitGroup
	copyFunc := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if tcp, ok := dst.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		} else {
			_ = dst.SetDeadline(time.Now())
		}
	}

	wg.Add(2)
	go copyFunc(a, b)
	go copyFunc(b, a)
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
}
