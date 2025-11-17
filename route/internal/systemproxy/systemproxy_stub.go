//go:build !darwin

package systemproxy

import "log/slog"

// Manager is a no-op placeholder for non-macOS platforms.
type Manager struct{}

// Enable is not supported on this platform; it returns nil without error.
func Enable(httpAddr string, bypass []string, logger *slog.Logger) (*Manager, error) {
	return nil, nil
}

// EnableSOCKS5 is not supported on this platform; it returns nil without error.
func EnableSOCKS5(socksAddr string, bypass []string, logger *slog.Logger) (*Manager, error) {
	return nil, nil
}

// Update is a no-op on unsupported platforms.
func (m *Manager) Update(bypass []string, logger *slog.Logger) error {
	return nil
}

// Disable is a no-op on unsupported platforms.
func (m *Manager) Disable(logger *slog.Logger) error {
	return nil
}
