package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"time"

	"go-forward/route/internal/runtime"
)

// UnifiedServer handles both HTTP and SOCKS5 proxy connections on the same port.
type UnifiedServer struct {
	addr    string
	runtime *runtime.Store
	logger  *slog.Logger
	http    *HTTPServer
	socks5  *SOCKS5Server
}

// NewUnifiedServer creates a unified proxy server that handles both HTTP and SOCKS5.
func NewUnifiedServer(addr string, store *runtime.Store, logger *slog.Logger) *UnifiedServer {
	return &UnifiedServer{
		addr:    addr,
		runtime: store,
		logger:  logger,
		http:    NewHTTPServer(addr, store, logger),
		socks5:  NewSOCKS5Server(addr, store, logger),
	}
}

// Serve listens and serves both HTTP and SOCKS5 proxy connections until ctx is cancelled.
func (s *UnifiedServer) Serve(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("listen unified proxy: %w", err)
	}
	log.Printf("unified proxy (HTTP + SOCKS5) listening: %s", s.addr)

	// Start UDP listener for SOCKS5
	udpAddr, err := net.ResolveUDPAddr("udp", s.socks5.udpAddr)
	if err != nil {
		return fmt.Errorf("resolve udp addr: %w", err)
	}
	s.socks5.udpConn, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("listen udp: %w", err)
	}
	log.Printf("unified proxy UDP (SOCKS5) listening: %s", s.socks5.udpAddr)

	go func() {
		<-ctx.Done()
		_ = listener.Close()
		if s.socks5.udpConn != nil {
			_ = s.socks5.udpConn.Close()
		}
	}()

	// Start UDP handler for SOCKS5
	go s.socks5.handleUDP(ctx)

	var tempDelay time.Duration
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if tempDelay > time.Second {
					tempDelay = time.Second
				}
				time.Sleep(tempDelay)
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept unified proxy: %w", err)
		}
		tempDelay = 0
		go s.handleConnection(ctx, conn)
	}
}

// handleConnection detects whether the connection is HTTP or SOCKS5 and routes accordingly.
func (s *UnifiedServer) handleConnection(ctx context.Context, conn net.Conn) {
	// Peek at the first byte to determine protocol
	reader := bufio.NewReader(conn)
	firstByte, err := reader.Peek(1)
	if err != nil {
		if !errors.Is(err, io.EOF) {
			log.Printf("failed to peek first byte: %v", err)
		}
		conn.Close()
		return
	}

	// SOCKS5 starts with 0x05 (version 5)
	// HTTP methods start with ASCII letters (GET, POST, CONNECT, etc.)
	if firstByte[0] == 0x05 {
		// SOCKS5 protocol
		s.handleSOCKS5Connection(ctx, conn, reader)
	} else {
		// HTTP protocol
		s.handleHTTPConnection(ctx, conn, reader)
	}
}

func (s *UnifiedServer) handleSOCKS5Connection(ctx context.Context, conn net.Conn, reader *bufio.Reader) {
	// Reuse the SOCKS5 server's handleConnection logic
	// We need to create a custom connection that uses our buffered reader
	bufferedConn := &bufferedConn{
		Conn:   conn,
		reader: reader,
	}
	s.socks5.handleConnection(ctx, bufferedConn)
}

func (s *UnifiedServer) handleHTTPConnection(ctx context.Context, conn net.Conn, reader *bufio.Reader) {
	// Reuse the HTTP server's handleConnection logic
	// We need to create a custom connection that uses our buffered reader
	bufferedConn := &bufferedConn{
		Conn:   conn,
		reader: reader,
	}
	s.http.handleConnection(ctx, bufferedConn)
}

// bufferedConn wraps a net.Conn with a bufio.Reader to allow protocol detection.
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (bc *bufferedConn) Read(p []byte) (int, error) {
	return bc.reader.Read(p)
}
