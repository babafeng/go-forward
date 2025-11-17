//go:build darwin

package systemproxy

import (
	"bufio"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"

	"log/slog"
)

// ProxyType defines the type of proxy to configure
type ProxyType int

const (
	ProxyTypeHTTP ProxyType = iota
	ProxyTypeSOCKS5
)

// Manager controls macOS system proxy settings for HTTP/HTTPS or SOCKS5 traffic.
type Manager struct {
	mu        sync.Mutex
	proxyType ProxyType
	host      string
	port      string
	bypass    []string
	services  []string
}

// Enable configures the system HTTP(S) proxy to the provided listen address.
// It returns a Manager that can update bypass domains and disable the proxy on shutdown.
func Enable(httpAddr string, bypass []string, logger *slog.Logger) (*Manager, error) {
	return enable(ProxyTypeHTTP, httpAddr, bypass, logger)
}

// EnableSOCKS5 configures the system SOCKS5 proxy to the provided listen address.
// It returns a Manager that can update bypass domains and disable the proxy on shutdown.
func EnableSOCKS5(socksAddr string, bypass []string, logger *slog.Logger) (*Manager, error) {
	return enable(ProxyTypeSOCKS5, socksAddr, bypass, logger)
}

func enable(proxyType ProxyType, addr string, bypass []string, logger *slog.Logger) (*Manager, error) {
	host, port, err := parseListenAddress(addr)
	if err != nil {
		return nil, err
	}
	services, err := listNetworkServices()
	if err != nil {
		return nil, err
	}
	if len(services) == 0 {
		return nil, fmt.Errorf("no active network services detected")
	}
	mgr := &Manager{
		proxyType: proxyType,
		host:      host,
		port:      port,
		bypass:    normalizeBypass(bypass),
		services:  services,
	}
	if err := mgr.apply(true, logger); err != nil {
		return nil, err
	}
	return mgr, nil
}

// Update refreshes proxy bypass domains without toggling the proxy state.
func (m *Manager) Update(bypass []string, logger *slog.Logger) error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	next := normalizeBypass(bypass)
	if slicesEqual(m.bypass, next) {
		return nil
	}
	m.bypass = next

	var firstErr error
	for _, service := range m.services {
		if err := setBypassDomains(service, m.bypass); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			if logger != nil {
				logger.Warn("failed to update proxy bypass domains", slog.String("service", service), slog.Any("err", err))
			}
		}
	}
	if firstErr == nil && logger != nil {
		logger.Info("system proxy bypass domains updated", slog.Any("domains", m.bypass))
	}
	return firstErr
}

// Disable switches off the system proxies previously enabled by this manager.
func (m *Manager) Disable(logger *slog.Logger) error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.apply(false, logger)
}

func (m *Manager) apply(enable bool, logger *slog.Logger) error {
	var firstErr error
	success := 0
	for _, service := range m.services {
		var err error
		if enable {
			err = enableService(service, m.host, m.port, m.bypass, m.proxyType)
		} else {
			err = disableService(service, m.proxyType)
		}
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			if logger != nil {
				if enable {
					logger.Warn("failed to configure system proxy", slog.String("service", service), slog.Any("err", err))
				} else {
					logger.Error("failed to disable system proxy", slog.String("service", service), slog.Any("err", err))
				}
			}
			continue
		}
		success++
	}
	if logger != nil && success > 0 {
		if enable {
			proxyTypeName := "HTTP/HTTPS"
			if m.proxyType == ProxyTypeSOCKS5 {
				proxyTypeName = "SOCKS5"
			}
			logger.Info("system proxy enabled", slog.String("type", proxyTypeName), slog.String("host", m.host), slog.String("port", m.port), slog.Int("services", success))
		} else {
			logger.Info("system proxy disabled", slog.Int("services", success))
		}
	}
	return firstErr
}

func parseListenAddress(addr string) (string, string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// Fall back to assuming missing host, e.g. ":1080"
		if strings.Count(addr, ":") == 1 && !strings.HasPrefix(addr, "[") {
			port = strings.TrimPrefix(addr, ":")
			if port == "" {
				return "", "", fmt.Errorf("invalid listen address %q", addr)
			}
			host = "127.0.0.1"
		} else {
			return "", "", fmt.Errorf("parse listener address %q: %w", addr, err)
		}
	}
	if host == "" {
		host = "127.0.0.1"
	}
	return host, port, nil
}

func listNetworkServices() ([]string, error) {
	cmd := exec.Command("networksetup", "-listallnetworkservices")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("list network services: %w", err)
	}
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	var services []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "An asterisk") {
			continue
		}
		if strings.HasPrefix(line, "*") {
			// Disabled service
			continue
		}
		services = append(services, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return services, nil
}

func enableService(service, host, port string, bypass []string, proxyType ProxyType) error {
	switch proxyType {
	case ProxyTypeHTTP:
		if err := runNetworksetup("-setwebproxy", service, host, port); err != nil {
			return err
		}
		if err := runNetworksetup("-setsecurewebproxy", service, host, port); err != nil {
			return err
		}
		if err := setBypassDomains(service, bypass); err != nil {
			return err
		}
		if err := runNetworksetup("-setwebproxystate", service, "on"); err != nil {
			return err
		}
		if err := runNetworksetup("-setsecurewebproxystate", service, "on"); err != nil {
			return err
		}
	case ProxyTypeSOCKS5:
		if err := runNetworksetup("-setsocksfirewallproxy", service, host, port); err != nil {
			return err
		}
		if err := setBypassDomains(service, bypass); err != nil {
			return err
		}
		if err := runNetworksetup("-setsocksfirewallproxystate", service, "on"); err != nil {
			return err
		}
	}
	return nil
}

func disableService(service string, proxyType ProxyType) error {
	switch proxyType {
	case ProxyTypeHTTP:
		if err := runNetworksetup("-setwebproxystate", service, "off"); err != nil {
			return err
		}
		if err := runNetworksetup("-setsecurewebproxystate", service, "off"); err != nil {
			return err
		}
	case ProxyTypeSOCKS5:
		if err := runNetworksetup("-setsocksfirewallproxystate", service, "off"); err != nil {
			return err
		}
	}
	return nil
}

func setBypassDomains(service string, bypass []string) error {
	args := []string{"-setproxybypassdomains", service}
	if len(bypass) == 0 {
		args = append(args, "Empty")
	} else {
		args = append(args, bypass...)
	}
	return runNetworksetup(args...)
}

func runNetworksetup(args ...string) error {
	cmd := exec.Command("networksetup", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("networksetup %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func normalizeBypass(domains []string) []string {
	seen := make(map[string]struct{}, len(domains))
	result := make([]string, 0, len(domains))
	for _, d := range domains {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		key := strings.ToLower(d)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, d)
	}
	return result
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
