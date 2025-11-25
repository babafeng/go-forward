package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"log/slog"

	"go-forward/route/internal/router"
	"go-forward/route/internal/runtime"
)

// HTTPServer implements a high-performance HTTP(S) forward proxy.
type HTTPServer struct {
	addr    string
	runtime *runtime.Store
	logger  *slog.Logger
}

// NewHTTPServer constructs a HTTP proxy server bound to addr.
func NewHTTPServer(addr string, store *runtime.Store, logger *slog.Logger) *HTTPServer {
	return &HTTPServer{addr: addr, runtime: store, logger: logger}
}

// Serve listens and serves HTTP proxy connections until ctx is cancelled.
func (s *HTTPServer) Serve(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("listen http proxy: %w", err)
	}
	log.Printf("http proxy listening: %s", s.addr)

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
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				time.Sleep(tempDelay)
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept http proxy: %w", err)
		}
		tempDelay = 0
		go s.handleConnection(ctx, conn)
	}
}

func (s *HTTPServer) handleConnection(ctx context.Context, conn net.Conn) {
	start := time.Now()
	remoteAddr := conn.RemoteAddr().String()
	defer conn.Close()
	reader := bufio.NewReader(conn)

	req, err := http.ReadRequest(reader)
	if err != nil {
		if !errors.Is(err, io.EOF) {
			log.Printf("failed to read http request from %s: %v", remoteAddr, err)
		}
		conn.Close()
		return
	}
	defer req.Body.Close()

	snapshot := s.runtime.Load()
	if snapshot == nil || snapshot.Router == nil {
		respondError(conn, http.StatusServiceUnavailable, "runtime not ready")
		log.Printf("http runtime missing: %s", remoteAddr)
		return
	}

	if strings.EqualFold(req.Method, http.MethodConnect) {
		s.handleConnect(ctx, conn, req, snapshot, start, remoteAddr)
		return
	}

	s.handleForward(ctx, conn, req, snapshot, start, remoteAddr)
}

func (s *HTTPServer) handleConnect(ctx context.Context, client net.Conn, req *http.Request, snap *runtime.Snapshot, start time.Time, remoteAddr string) {
	host := req.Host
	if host == "" {
		respondError(client, http.StatusBadRequest, "missing host")
		log.Printf("connect without host: %s", remoteAddr)
		return
	}
	domain, port := splitHostPort(host, "443")
	decision := snap.Router.Decide(domain)

	if decision.Action == router.ActionReject {
		s.logDecision("http-connect", domain, port, decision, remoteAddr, start, errors.New("rejected by policy"))
		respondError(client, http.StatusForbidden, "blocked")
		return
	}

	target := net.JoinHostPort(domain, port)
	ctxDial, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	targetConn, err := snap.Dialers.DialContext(ctxDial, upstreamName(decision), "tcp", target)
	if err != nil {
		s.logDecision("http-connect", domain, port, decision, remoteAddr, start, err)
		respondError(client, http.StatusBadGateway, "upstream error")
		log.Printf("connect dial failed: %s, %v", target, err)
		return
	}
	s.logDecision("http-connect", domain, port, decision, remoteAddr, start, nil)

	_, _ = io.WriteString(client, "HTTP/1.1 200 Connection Established\r\nProxy-Agent: g-route\r\n\r\n")

	linkConns(client, targetConn)
}

func (s *HTTPServer) handleForward(ctx context.Context, client net.Conn, req *http.Request, snap *runtime.Snapshot, start time.Time, remoteAddr string) {
	host := req.URL.Host
	if host == "" {
		host = req.Host
	}
	if host == "" {
		respondError(client, http.StatusBadRequest, "missing host")
		log.Printf("http request missing host: %s", remoteAddr)
		return
	}

	scheme := strings.ToLower(req.URL.Scheme)
	defaultPort := "80"
	if scheme == "https" {
		defaultPort = "443"
	}
	domain, port := splitHostPort(host, defaultPort)
	decision := snap.Router.Decide(domain)
	if decision.Action == router.ActionReject {
		s.logDecision("http", domain, port, decision, remoteAddr, start, errors.New("rejected by policy"))
		respondError(client, http.StatusForbidden, "blocked")
		return
	}

	target := net.JoinHostPort(domain, port)
	ctxDial, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	targetConn, err := snap.Dialers.DialContext(ctxDial, upstreamName(decision), "tcp", target)
	if err != nil {
		s.logDecision("http", domain, port, decision, remoteAddr, start, err)
		respondError(client, http.StatusBadGateway, "upstream error")
		log.Printf("forward dial failed: %s, %v", target, err)
		return
	}
	defer targetConn.Close()
	s.logDecision("http", domain, port, decision, remoteAddr, start, nil)

	prepareRequestForForward(req)

	if err := req.Write(targetConn); err != nil {
		log.Printf("write request failed: %v", err)
		respondError(client, http.StatusBadGateway, "write error")
		return
	}

	if _, err := io.Copy(client, targetConn); err != nil {
		if !errors.Is(err, io.EOF) {
			log.Printf("copy http response failed: %v", err)
		}
	}
}

func upstreamName(decision router.Decision) string {
	if decision.Action == router.ActionProxy {
		return decision.Proxy
	}
	return ""
}

func prepareRequestForForward(req *http.Request) {
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Proxy-Authorization")
	if req.URL.Scheme != "" {
		req.URL.Scheme = ""
	}
	if req.URL.Host != "" {
		req.URL.Host = ""
	}
	req.RequestURI = req.URL.RequestURI()
	if req.RequestURI == "" {
		req.RequestURI = "/"
	}
}

func respondError(conn net.Conn, status int, message string) {
	response := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%s", status, http.StatusText(status), len(message), message)
	_, _ = io.WriteString(conn, response)
	_ = conn.Close()
}

func splitHostPort(host, defaultPort string) (string, string) {
	if strings.Contains(host, ":") {
		h, p, err := net.SplitHostPort(host)
		if err == nil {
			return strings.ToLower(h), p
		}
	}
	return strings.ToLower(host), defaultPort
}

func (s *HTTPServer) logDecision(proto, domain, port string, decision router.Decision, remote string, start time.Time, err error) {
	attrs := []any{
		slog.String("action", decision.Action.String()),
		slog.Bool("matched", decision.Matched),
		slog.Duration("latency", time.Since(start)),
	}
	upstream := "None"
	if decision.Proxy != "" {
		upstream = decision.Proxy
	}
	if decision.Rule != nil {
		attrs = append(attrs,
			slog.String("rule_type", decision.Rule.MatchTypeString()),
			slog.String("rule_value", decision.Rule.Value),
			slog.Int("rule_index", decision.Rule.Index),
		)
	}
	if err != nil {
		attrs = append(attrs, slog.Any("err", err))
		log.Printf("routing: %v", attrs)
		return
	}
	log.Printf("routing: %v %v %v --> %v %v", upstream, proto, remote, net.JoinHostPort(domain, port), attrs)
}
