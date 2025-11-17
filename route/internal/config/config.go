package config

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// ListenConfig defines local listener addresses.
type ListenConfig struct {
	HTTP   string
	SOCKS5 string
}

// LogConfig configures logging output.
type LogConfig struct {
	Level  string
	Format string
}

// ServerConfig describes an upstream proxy server.
type ServerConfig struct {
	Name     string
	Type     string
	Address  string
	Username string
	Password string
	Timeout  time.Duration
}

// RuleConfig is a single routing rule read from configuration.
type RuleConfig struct {
	Type     string
	Value    string
	Action   string
	Proxy    string
	Fallback string
}

// GeneralConfig stores auxiliary options from the [General] section.
type GeneralConfig struct {
	PreferIPv6   bool
	IPv6         bool
	BypassSystem bool
	SkipProxy    []string
	DNSServer    []string
	DefaultProxy string
	Raw          map[string]string
}

// Config is the top-level configuration structure.
type Config struct {
	General GeneralConfig
	Listen  ListenConfig
	Servers []ServerConfig
	Rules   []RuleConfig
	Log     LogConfig
}

// Load reads configuration from an INI-style file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg, err := parseConfig(string(data))
	if err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.normalize(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func parseConfig(input string) (*Config, error) {
	cfg := &Config{}
	cfg.General.Raw = make(map[string]string)
	section := ""
	scanner := bufio.NewScanner(strings.NewReader(input))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := stripComments(scanner.Text())
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToUpper(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}
		switch section {
		case "GENERAL":
			if err := parseGeneralLine(cfg, line); err != nil {
				return nil, fmt.Errorf("general line %d: %w", lineNum, err)
			}
		case "PROXY":
			srv, err := parseProxyLine(line)
			if err != nil {
				return nil, fmt.Errorf("proxy line %d: %w", lineNum, err)
			}
			cfg.Servers = append(cfg.Servers, srv)
		case "RULE":
			rule, err := parseRuleLine(line, &cfg.General)
			if err != nil {
				return nil, fmt.Errorf("rule line %d: %w", lineNum, err)
			}
			cfg.Rules = append(cfg.Rules, rule)
		default:
			return nil, fmt.Errorf("line %d: entry outside known sections", lineNum)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func parseGeneralLine(cfg *Config, line string) error {
	key, value, err := splitKeyValue(line)
	if err != nil {
		return err
	}
	keyLower := strings.ToLower(key)
	cfg.General.Raw[keyLower] = value
	switch keyLower {
	case "http-listen", "http_listen", "http":
		cfg.Listen.HTTP = value
	case "socks5-listen", "socks5_listen", "socks5":
		cfg.Listen.SOCKS5 = value
	case "log-level", "loglevel":
		cfg.Log.Level = value
	case "log-format", "logformat":
		cfg.Log.Format = value
	case "prefer-ipv6":
		cfg.General.PreferIPv6 = parseBool(value)
	case "ipv6":
		cfg.General.IPv6 = parseBool(value)
	case "bypass-system":
		cfg.General.BypassSystem = parseBool(value)
	case "skip-proxy", "skip_proxy":
		cfg.General.SkipProxy = splitList(value)
	case "dns-server", "dns_server":
		cfg.General.DNSServer = splitList(value)
	case "default-proxy", "default_proxy":
		cfg.General.DefaultProxy = value
	default:
		// store in raw map only
	}
	return nil
}

func parseProxyLine(line string) (ServerConfig, error) {
	name, value, err := splitKeyValue(line)
	if err != nil {
		return ServerConfig{}, err
	}
	if name == "" {
		return ServerConfig{}, errors.New("proxy name cannot be empty")
	}
	fields := splitCSV(value)
	if len(fields) < 2 {
		return ServerConfig{}, errors.New("proxy definition requires at least type and address")
	}
	server := ServerConfig{
		Name:    name,
		Type:    strings.ToLower(fields[0]),
		Address: fields[1],
	}
	if len(fields) >= 3 {
		server.Username = fields[2]
	}
	if len(fields) >= 4 {
		server.Password = fields[3]
	}
	if len(fields) >= 5 && fields[4] != "" {
		dur, err := time.ParseDuration(fields[4])
		if err != nil {
			return ServerConfig{}, fmt.Errorf("invalid timeout: %w", err)
		}
		server.Timeout = dur
	}
	return server, nil
}

func parseRuleLine(line string, general *GeneralConfig) (RuleConfig, error) {
	parts := splitCSV(line)
	if len(parts) == 0 {
		return RuleConfig{}, errors.New("empty rule")
	}
	ruleType := strings.ToUpper(parts[0])
	if ruleType == "IP-CIDR" || ruleType == "IPCIDR" {
		ruleType = "CIDR"
	}
	rule := RuleConfig{Type: ruleType}
	if ruleType == "FINAL" {
		rule.Action = "FINAL"
		if len(parts) >= 2 {
			fallbackToken := parts[1]
			fallbackUpper := strings.ToUpper(fallbackToken)
			switch fallbackUpper {
			case "DIRECT", "REJECT":
				rule.Fallback = fallbackUpper
			default:
				rule.Fallback = "PROXY"
				rule.Proxy = fallbackToken
			}
		}
		if rule.Fallback == "" {
			rule.Fallback = "DIRECT"
		}
		return rule, nil
	}
	if len(parts) < 3 {
		return RuleConfig{}, errors.New("rule requires at least three fields")
	}
	rule.Value = parts[1]
	policyToken := parts[2]
	policyUpper := strings.ToUpper(policyToken)
	switch policyUpper {
	case "DIRECT", "REJECT":
		rule.Action = policyUpper
	case "FINAL":
		return RuleConfig{}, errors.New("rule policy cannot be FINAL")
	default:
		rule.Action = "PROXY"
		rule.Proxy = policyToken
	}
	if len(parts) >= 4 && rule.Action == "PROXY" && parts[3] != "" {
		rule.Proxy = parts[3]
	}
	if rule.Action == "PROXY" && rule.Proxy == "" && general != nil && general.DefaultProxy != "" {
		rule.Proxy = general.DefaultProxy
	}
	return rule, nil
}

func splitKeyValue(line string) (string, string, error) {
	var key, value string
	if idx := strings.IndexRune(line, '='); idx >= 0 {
		key = strings.TrimSpace(line[:idx])
		value = strings.TrimSpace(line[idx+1:])
	} else if idx := strings.IndexRune(line, ':'); idx >= 0 {
		key = strings.TrimSpace(line[:idx])
		value = strings.TrimSpace(line[idx+1:])
	} else {
		return "", "", errors.New("invalid key/value pair")
	}
	return key, value, nil
}

func splitCSV(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		result = append(result, trimmed)
	}
	return result
}

func splitList(value string) []string {
	parts := splitCSV(value)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseBool(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func stripComments(line string) string {
	for _, marker := range []string{"//", "#", ";"} {
		if idx := strings.Index(line, marker); idx >= 0 {
			return line[:idx]
		}
	}
	return line
}

// normalize applies defaults and validation rules.
func (c *Config) normalize() error {
	c.General.DefaultProxy = strings.TrimSpace(c.General.DefaultProxy)

	if c.Listen.HTTP == "" {
		c.Listen.HTTP = "127.0.0.1:1080"
	}
	if c.Listen.SOCKS5 == "" {
		c.Listen.SOCKS5 = "127.0.0.1:1081"
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}

	seen := make(map[string]struct{}, len(c.Servers))
	for i := range c.Servers {
		s := &c.Servers[i]
		s.Type = strings.ToLower(strings.TrimSpace(s.Type))
		s.Name = strings.TrimSpace(s.Name)
		s.Address = strings.TrimSpace(s.Address)
		if s.Name == "" {
			return errors.New("server name cannot be empty")
		}
		if _, ok := seen[s.Name]; ok {
			return fmt.Errorf("duplicate server name: %s", s.Name)
		}
		seen[s.Name] = struct{}{}
		s.Timeout = normalizeTimeout(s.Timeout)
		s.Type = normalizeProxyType(s.Type)
		if s.Type == "" {
			return fmt.Errorf("server %s has unsupported type", s.Name)
		}
		if s.Address == "" {
			return fmt.Errorf("server %s missing address", s.Name)
		}
	}

	if len(c.Rules) == 0 {
		return errors.New("at least one rule must be defined")
	}

	seenFinal := false
	for i := range c.Rules {
		r := &c.Rules[i]
		r.Type = strings.ToUpper(strings.TrimSpace(r.Type))
		r.Action = strings.ToUpper(strings.TrimSpace(r.Action))
		r.Value = strings.TrimSpace(r.Value)
		r.Proxy = strings.TrimSpace(r.Proxy)
		r.Fallback = strings.ToUpper(strings.TrimSpace(r.Fallback))

		if r.Action == "FINAL" || r.Type == "FINAL" {
			if seenFinal {
				return errors.New("only one FINAL rule is allowed")
			}
			seenFinal = true
			if r.Fallback == "" {
				r.Fallback = "DIRECT"
			}
			if !isSupportedAction(r.Fallback) {
				return fmt.Errorf("final rule fallback %s is not supported", r.Fallback)
			}
			if strings.EqualFold(r.Fallback, "FINAL") {
				return errors.New("final rule fallback cannot be FINAL")
			}
			if r.Fallback == "PROXY" && r.Proxy == "" {
				return errors.New("final rule with PROXY fallback must set proxy")
			}
			continue
		}

		if !isSupportedMatchType(r.Type) {
			return fmt.Errorf("unsupported rule match type: %s", r.Type)
		}
		if r.Value == "" {
			return fmt.Errorf("rule of type %s requires a value", r.Type)
		}
		if !isSupportedAction(r.Action) {
			return fmt.Errorf("unsupported rule action: %s", r.Action)
		}
		if r.Action == "PROXY" && r.Proxy == "" {
			return fmt.Errorf("rule %s requires proxy name", r.Value)
		}
	}
	if !seenFinal {
		return errors.New("a FINAL rule must be provided as default policy")
	}
	return nil
}

func normalizeTimeout(d time.Duration) time.Duration {
	if d <= 0 {
		return 8 * time.Second
	}
	return d
}

func normalizeProxyType(t string) string {
	switch t {
	case "socks5", "socks", "socks5h":
		return "socks5"
	case "http", "https":
		return "http"
	default:
		return ""
	}
}

func isSupportedMatchType(t string) bool {
	switch t {
	case "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "CIDR":
		return true
	default:
		return false
	}
}

func isSupportedAction(a string) bool {
	switch a {
	case "PROXY", "DIRECT", "REJECT", "FINAL":
		return true
	default:
		return false
	}
}

// Watcher monitors the configuration file for changes and emits updated configs.
type Watcher struct {
	mu      sync.Mutex
	path    string
	watcher *fsnotify.Watcher
	updates chan *Config
	errors  chan error
	closing chan struct{}
}

// NewWatcher creates a new watcher for the provided configuration file.
func NewWatcher(path string) (*Watcher, error) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("create watcher: %w", err)
	}
	dir := filepath.Dir(path)
	if err := w.Add(dir); err != nil {
		w.Close()
		return nil, fmt.Errorf("watch dir: %w", err)
	}
	watcher := &Watcher{
		path:    path,
		watcher: w,
		updates: make(chan *Config, 1),
		errors:  make(chan error, 1),
		closing: make(chan struct{}),
	}
	go watcher.loop()
	return watcher, nil
}

func (w *Watcher) loop() {
	debounce := time.NewTimer(0)
	if !debounce.Stop() {
		<-debounce.C
	}
	for {
		select {
		case event, ok := <-w.watcher.Events:
			if !ok {
				return
			}
			if !w.interested(event) {
				continue
			}
			if !debounce.Stop() {
				select {
				case <-debounce.C:
				default:
				}
			}
			debounce.Reset(150 * time.Millisecond)
		case <-debounce.C:
			w.reload()
		case err, ok := <-w.watcher.Errors:
			if !ok {
				return
			}
			w.sendError(err)
		case <-w.closing:
			return
		}
	}
}

func (w *Watcher) interested(event fsnotify.Event) bool {
	if filepath.Clean(event.Name) != filepath.Clean(w.path) {
		return false
	}
	if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Remove|fsnotify.Rename) != 0 {
		return true
	}
	return false
}

func (w *Watcher) reload() {
	cfg, err := Load(w.path)
	if err != nil {
		w.sendError(err)
		return
	}
	select {
	case w.updates <- cfg:
	default:
		// Drop update if channel full to avoid blocking.
	}
}

func (w *Watcher) sendError(err error) {
	select {
	case w.errors <- err:
	default:
	}
}

// Updates returns a channel receiving latest configurations.
func (w *Watcher) Updates() <-chan *Config {
	return w.updates
}

// Errors returns a channel receiving watch errors.
func (w *Watcher) Errors() <-chan error {
	return w.errors
}

// Close stops watching the configuration file.
func (w *Watcher) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	select {
	case <-w.closing:
		// already closed
	default:
		close(w.closing)
	}
	return w.watcher.Close()
}

// Exists checks whether the config file is present.
func Exists(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("%s is a directory", path)
	}
	return nil
}

// LastModified returns modification time of the file if accessible.
func LastModified(path string) (time.Time, error) {
	info, err := os.Stat(path)
	if err != nil {
		return time.Time{}, err
	}
	return info.ModTime(), nil
}

// ReadFS loads configuration from a filesystem interface. Primarily used for testing.
func ReadFS(fsys fs.FS, name string) (*Config, error) {
	data, err := fs.ReadFile(fsys, name)
	if err != nil {
		return nil, err
	}
	cfg, err := parseConfig(string(data))
	if err != nil {
		return nil, err
	}
	if err := cfg.normalize(); err != nil {
		return nil, err
	}
	return cfg, nil
}
