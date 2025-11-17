package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	xproxy "golang.org/x/net/proxy"
)

// Spec describes an upstream proxy target.
type Spec struct {
	Name     string
	Type     string
	Address  string
	Username string
	Password string
	Timeout  time.Duration
}

// Dialer represents an object capable of dialing outbound connections.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
	String() string
}

// Manager resolves dialers based on configuration.
type Manager struct {
	direct  Dialer
	dialers map[string]Dialer
}

// NewManager builds dialers for each upstream specification.
func NewManager(specs []Spec) (*Manager, error) {
	m := &Manager{dialers: make(map[string]Dialer)}
	m.direct = newDirectDialer(8 * time.Second)
	for _, spec := range specs {
		dialer, err := buildDialer(spec)
		if err != nil {
			return nil, err
		}
		m.dialers[spec.Name] = dialer
	}
	return m, nil
}

func buildDialer(spec Spec) (Dialer, error) {
	if spec.Name == "" {
		return nil, errors.New("dialer requires name")
	}
	if spec.Timeout <= 0 {
		spec.Timeout = 8 * time.Second
	}
	switch spec.Type {
	case "socks5":
		return newSOCKS5Dialer(spec)
	case "http":
		return newHTTPDialer(spec)
	default:
		return nil, fmt.Errorf("unsupported upstream type %s", spec.Type)
	}
}

// DialContext retrieves the appropriate dialer and establishes a connection.
func (m *Manager) DialContext(ctx context.Context, upstream string, network, address string) (net.Conn, error) {
	if upstream == "" {
		return m.direct.DialContext(ctx, network, address)
	}
	dialer, ok := m.dialers[upstream]
	if !ok {
		return nil, fmt.Errorf("unknown upstream %s", upstream)
	}
	return dialer.DialContext(ctx, network, address)
}

// DirectDialer returns the default direct dialer.
func (m *Manager) DirectDialer() Dialer {
	return m.direct
}

// DialerNames lists configured upstream names.
func (m *Manager) DialerNames() []string {
	names := make([]string, 0, len(m.dialers))
	for name := range m.dialers {
		names = append(names, name)
	}
	return names
}

// newDirectDialer creates a dialer for direct connections.
func newDirectDialer(timeout time.Duration) Dialer {
	return &directDialer{dialer: &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}}
}

// SOCKS5 dialer implementation.
type socks5Dialer struct {
	name  string
	inner xproxy.Dialer
	label string
	to    time.Duration
}

func newSOCKS5Dialer(spec Spec) (Dialer, error) {
	var auth *xproxy.Auth
	if spec.Username != "" {
		auth = &xproxy.Auth{User: spec.Username, Password: spec.Password}
	}
	base := &net.Dialer{Timeout: spec.Timeout, KeepAlive: 30 * time.Second}
	dialer, err := xproxy.SOCKS5("tcp", spec.Address, auth, base)
	if err != nil {
		return nil, fmt.Errorf("create socks5 dialer %s: %w", spec.Name, err)
	}
	return &socks5Dialer{name: spec.Name, inner: dialer, label: fmt.Sprintf("socks5://%s", spec.Address), to: spec.Timeout}, nil
}

func (d *socks5Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network == "" {
		network = "tcp"
	}
	result := make(chan struct {
		conn net.Conn
		err  error
	}, 1)
	go func() {
		conn, err := d.inner.Dial(network, address)
		result <- struct {
			conn net.Conn
			err  error
		}{conn: conn, err: err}
	}()

	select {
	case <-ctx.Done():
		go func() {
			res := <-result
			if res.conn != nil {
				res.conn.Close()
			}
		}()
		return nil, ctx.Err()
	case res := <-result:
		return res.conn, res.err
	}
}

func (d *socks5Dialer) String() string { return d.label }

// directDialer wraps net.Dialer to satisfy Dialer interface.
type directDialer struct {
	dialer *net.Dialer
}

func (d *directDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network == "" {
		network = "tcp"
	}
	return d.dialer.DialContext(ctx, network, address)
}

func (d *directDialer) String() string { return "direct" }
