package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"log/slog"

	"go-forward/route/internal/router"
	"go-forward/route/internal/runtime"
)

// SOCKS5Server handles SOCKS5 proxy connections.
type SOCKS5Server struct {
	addr    string
	runtime *runtime.Store
	logger  *slog.Logger
}

// NewSOCKS5Server creates a SOCKS5 server instance.
func NewSOCKS5Server(addr string, store *runtime.Store, logger *slog.Logger) *SOCKS5Server {
	return &SOCKS5Server{addr: addr, runtime: store, logger: logger}
}

// Serve runs the SOCKS5 server until context cancellation.
func (s *SOCKS5Server) Serve(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("listen socks5: %w", err)
	}
	log.Printf("socks5 proxy listening: %s", s.addr)

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

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
			return fmt.Errorf("accept socks5: %w", err)
		}
		tempDelay = 0
		go s.handleConnection(ctx, conn)
	}
}

func (s *SOCKS5Server) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)

	if err := s.handleGreeting(reader, conn); err != nil {
		log.Printf("socks5 read request failed: %v", err)
		return
	}

	req, err := s.readRequest(reader)
	if err != nil {
		log.Printf("socks5 read request failed: %v", err)
		s.sendReply(conn, 0x01, "")
		return
	}

	snapshot := s.runtime.Load()
	if snapshot == nil || snapshot.Router == nil {
		s.sendReply(conn, 0x01, "")
		log.Printf("socks runtime missing")
		return
	}

	domainLower := strings.ToLower(req.host)
	decision := snapshot.Router.Decide(domainLower)
	s.logDecision(req, decision)

	switch decision.Action {
	case router.ActionReject:
		s.sendReply(conn, 0x02, "")
		return
	}

	target := net.JoinHostPort(req.host, req.port)
	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	targetConn, err := snapshot.Dialers.DialContext(dialCtx, upstreamName(decision), "tcp", target)
	if err != nil {
		log.Printf("socks dial failed: %s, %v", target, err)
		s.sendReply(conn, 0x05, "")
		return
	}

	if err := s.sendReply(conn, 0x00, ""); err != nil {
		targetConn.Close()
		return
	}

	linkConns(conn, targetConn)
}

func (s *SOCKS5Server) handleGreeting(reader *bufio.Reader, conn net.Conn) error {
	version, err := reader.ReadByte()
	if err != nil {
		return err
	}
	if version != 0x05 {
		return fmt.Errorf("unsupported socks version %d", version)
	}
	methodsCount, err := reader.ReadByte()
	if err != nil {
		return err
	}
	methods := make([]byte, methodsCount)
	if _, err := io.ReadFull(reader, methods); err != nil {
		return err
	}
	// Only "no authentication" is supported.
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return err
	}
	return nil
}

func (s *SOCKS5Server) readRequest(reader *bufio.Reader) (*socksRequest, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	if header[0] != 0x05 {
		return nil, fmt.Errorf("invalid version %d", header[0])
	}
	if header[1] != 0x01 {
		return nil, fmt.Errorf("unsupported command %d", header[1])
	}

	addrType := header[3]
	var host string
	switch addrType {
	case 0x01: // IPv4
		addr := make([]byte, 4)
		if _, err := io.ReadFull(reader, addr); err != nil {
			return nil, err
		}
		host = net.IP(addr).String()
	case 0x03: // domain name
		size, err := reader.ReadByte()
		if err != nil {
			return nil, err
		}
		domain := make([]byte, size)
		if _, err := io.ReadFull(reader, domain); err != nil {
			return nil, err
		}
		host = string(domain)
	case 0x04: // IPv6
		addr := make([]byte, 16)
		if _, err := io.ReadFull(reader, addr); err != nil {
			return nil, err
		}
		host = net.IP(addr).String()
	default:
		return nil, fmt.Errorf("address type %d not supported", addrType)
	}

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(reader, portBytes); err != nil {
		return nil, err
	}
	port := fmt.Sprintf("%d", binary.BigEndian.Uint16(portBytes))

	return &socksRequest{host: host, port: port, atyp: addrType}, nil
}

func (s *SOCKS5Server) sendReply(conn net.Conn, rep byte, bindAddr string) error {
	response := []byte{0x05, rep, 0x00}
	if bindAddr == "" {
		response = append(response, 0x01)
		response = append(response, []byte{0, 0, 0, 0}...)
		response = append(response, 0, 0)
	} else {
		response = append(response, 0x03)
		response = append(response, byte(len(bindAddr)))
		response = append(response, []byte(bindAddr)...)
		response = append(response, 0, 0)
	}
	_, err := conn.Write(response)
	return err
}

func (s *SOCKS5Server) logDecision(req *socksRequest, decision router.Decision) {
	attrs := []any{
		slog.String("action", decision.Action.String()),
		slog.Bool("matched", decision.Matched),
	}
	if decision.Proxy != "" {
		attrs = append(attrs, slog.String("upstream", decision.Proxy))
	}
	if decision.Rule != nil {
		attrs = append(attrs,
			slog.String("rule_type", decision.Rule.MatchTypeString()),
			slog.String("rule_value", decision.Rule.Value),
			slog.Int("rule_index", decision.Rule.Index),
		)
	}
	log.Printf("routing: socks5 --> %v %v", net.JoinHostPort(req.host, req.port), attrs)
}

type socksRequest struct {
	host string
	port string
	atyp byte
}
