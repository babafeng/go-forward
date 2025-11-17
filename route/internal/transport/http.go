package transport

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strings"
	"time"
)

type httpDialer struct {
	name       string
	address    string
	timeout    time.Duration
	authHeader string
	label      string
}

func newHTTPDialer(spec Spec) (Dialer, error) {
	if spec.Address == "" {
		return nil, errors.New("http dialer requires address")
	}
	var authHeader string
	if spec.Username != "" {
		token := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", spec.Username, spec.Password)))
		authHeader = "Proxy-Authorization: Basic " + token + "\r\n"
	}
	if spec.Timeout <= 0 {
		spec.Timeout = 8 * time.Second
	}
	return &httpDialer{
		name:       spec.Name,
		address:    spec.Address,
		timeout:    spec.Timeout,
		authHeader: authHeader,
		label:      fmt.Sprintf("http://%s", spec.Address),
	}, nil
}

func (d *httpDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network == "" {
		network = "tcp"
	}
	if !strings.EqualFold(network, "tcp") {
		return nil, fmt.Errorf("http dialer only supports tcp, got %s", network)
	}

	dialer := &net.Dialer{Timeout: d.timeout, KeepAlive: 30 * time.Second}
	conn, err := dialer.DialContext(ctx, network, d.address)
	if err != nil {
		return nil, fmt.Errorf("dial upstream %s: %w", d.address, err)
	}

	deadline := time.Now().Add(d.timeout)
	_ = conn.SetDeadline(deadline)

	if err := d.doConnectHandshake(conn, address); err != nil {
		conn.Close()
		return nil, err
	}

	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func (d *httpDialer) doConnectHandshake(conn net.Conn, address string) error {
	target := address
	if !strings.Contains(target, ":") {
		target += ":80"
	}
	builder := strings.Builder{}
	builder.WriteString("CONNECT ")
	builder.WriteString(target)
	builder.WriteString(" HTTP/1.1\r\n")
	builder.WriteString("Host: ")
	builder.WriteString(target)
	builder.WriteString("\r\n")
	builder.WriteString("Proxy-Connection: Keep-Alive\r\n")
	if d.authHeader != "" {
		builder.WriteString(d.authHeader)
	}
	builder.WriteString("\r\n")

	if _, err := io.WriteString(conn, builder.String()); err != nil {
		return fmt.Errorf("write CONNECT handshake: %w", err)
	}

	reader := bufio.NewReader(conn)
	line, err := textproto.NewReader(reader).ReadLine()
	if err != nil {
		return fmt.Errorf("read CONNECT response: %w", err)
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return fmt.Errorf("invalid CONNECT response: %s", line)
	}
	if fields[1] != "200" {
		return fmt.Errorf("upstream CONNECT failed: %s", line)
	}

	// Consume headers until blank line.
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("read CONNECT headers: %w", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	return nil
}

func (d *httpDialer) String() string { return d.label }
