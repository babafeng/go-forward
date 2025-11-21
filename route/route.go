package route

import (
	"context"
	"errors"
	"fmt"
	"log"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"go-forward/route/internal/config"
	"go-forward/route/internal/proxy"
	"go-forward/route/internal/router"
	"go-forward/route/internal/runtime"
	"go-forward/route/internal/systemproxy"
	"go-forward/route/internal/transport"

	"github.com/oschwald/geoip2-golang"
	"golang.org/x/sync/errgroup"
)

type Options struct {
	ConfigPath string
	HTTPAddr   string
	SOCKS5Addr string
}

func watchConfig(ctx context.Context, watcher *config.Watcher, store *runtime.Store, levelVar *slog.LevelVar, logger *slog.Logger, listenCfg config.ListenConfig, httpProxyMgr, socks5ProxyMgr *systemproxy.Manager, mmdbReader *geoip2.Reader) error {
	currentListen := listenCfg
	for {
		select {
		case <-ctx.Done():
			return nil
		case cfg := <-watcher.Updates():
			if cfg == nil {
				continue
			}
			if cfg.Listen != currentListen {
				log.Printf("listen address changes require restart: current_http=%s, new_http=%s, current_socks5=%s, new_socks5=%s", currentListen.HTTP, cfg.Listen.HTTP, currentListen.SOCKS5, cfg.Listen.SOCKS5)
				cfg.Listen = currentListen
			}
			snapshot, err := buildSnapshot(cfg, mmdbReader)
			if err != nil {
				log.Printf("failed to rebuild runtime: %v", err)
				continue
			}
			store.Update(snapshot)
			if httpProxyMgr != nil {
				if err := httpProxyMgr.Update(cfg.General.SkipProxy, logger); err != nil {
					log.Printf("failed to refresh HTTP system proxy bypass: %v", err)
				}
			}
			if socks5ProxyMgr != nil {
				if err := socks5ProxyMgr.Update(cfg.General.SkipProxy, logger); err != nil {
					log.Printf("failed to refresh SOCKS5 system proxy bypass: %v", err)
				}
			}
			levelVar.Set(parseLogLevel(cfg.Log.Level))
			log.Printf("configuration reloaded")
		case err := <-watcher.Errors():
			log.Printf("config watch error: %v", err)
		}
	}
}

func parseLogLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	case "info":
		fallthrough
	default:
		return slog.LevelInfo
	}
}

func newLogger(level *slog.LevelVar, format string) *slog.Logger {
	handlerOpts := &slog.HandlerOptions{Level: level, AddSource: false}
	if strings.EqualFold(format, "json") {
		return slog.New(slog.NewJSONHandler(os.Stdout, handlerOpts))
	}
	// return slog.New(newStdTextHandler(os.Stdout, handlerOpts))
	return slog.New(slog.NewTextHandler(os.Stdout, handlerOpts))
}

func buildSnapshot(cfg *config.Config, mmdbReader *geoip2.Reader) (*runtime.Snapshot, error) {
	serverSpecs := make([]transport.Spec, 0, len(cfg.Servers))
	for _, srv := range cfg.Servers {
		serverSpecs = append(serverSpecs, transport.Spec{
			Name:     srv.Name,
			Type:     srv.Type,
			Address:  srv.Address,
			Username: srv.Username,
			Password: srv.Password,
			Timeout:  srv.Timeout,
		})
	}

	ruleSpecs := make([]router.RuleSpec, 0, len(cfg.Rules))
	for _, rule := range cfg.Rules {
		ruleSpecs = append(ruleSpecs, router.RuleSpec{
			Type:     rule.Type,
			Value:    rule.Value,
			Action:   rule.Action,
			Proxy:    rule.Proxy,
			Fallback: rule.Fallback,
		})
	}

	mgr, err := transport.NewManager(serverSpecs)
	if err != nil {
		return nil, err
	}
	eng, err := router.NewEngine(ruleSpecs, mmdbReader)
	if err != nil {
		return nil, err
	}
	return &runtime.Snapshot{Router: eng, Dialers: mgr}, nil
}

func Run(ctx context.Context, opts Options) error {
	configPath := opts.ConfigPath
	configPath = opts.ConfigPath
	if configPath == "" {
		configPath = "~/.forward/proxy-config.conf"
	}
	configPath = expandPath(configPath)

	// Ensure directory exists
	configDir := filepath.Dir(configPath)
	if err := ensureDir(configDir); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Check if config exists, if not create default
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		log.Printf("Config file not found, creating default at %s", configPath)
		if err := os.WriteFile(configPath, []byte(defaultConfig), 0644); err != nil {
			return fmt.Errorf("failed to create default config: %w", err)
		}
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if opts.HTTPAddr != "" {
		cfg.Listen.HTTP = opts.HTTPAddr
	}
	if opts.SOCKS5Addr != "" {
		cfg.Listen.SOCKS5 = opts.SOCKS5Addr
	}

	levelVar := new(slog.LevelVar)
	levelVar.Set(parseLogLevel(cfg.Log.Level))
	logger := newLogger(levelVar, cfg.Log.Format)

	var proxyMgr *systemproxy.Manager
	if cfg.Listen.HTTP != "" {
		log.Printf("enabling system HTTP proxy: %s", cfg.Listen.HTTP)
		mgr, err := systemproxy.Enable(cfg.Listen.HTTP, cfg.General.SkipProxy, logger)
		if err != nil {
			log.Printf("failed to enable system proxy: %v", err)
		} else {
			proxyMgr = mgr
			defer func() {
				if err := proxyMgr.Disable(logger); err != nil {
					log.Printf("failed to disable system proxy: %v", err)
				}
			}()
		}
	}

	var socks5ProxyMgr *systemproxy.Manager
	if cfg.Listen.SOCKS5 != "" {
		log.Printf("enabling system SOCKS5 proxy: %s", cfg.Listen.SOCKS5)
		mgr, err := systemproxy.EnableSOCKS5(cfg.Listen.SOCKS5, cfg.General.SkipProxy, logger)
		if err != nil {
			log.Printf("failed to enable SOCKS5 system proxy: %v", err)
		} else {
			socks5ProxyMgr = mgr
			defer func() {
				if err := socks5ProxyMgr.Disable(logger); err != nil {
					log.Printf("failed to disable SOCKS5 system proxy: %v", err)
				}
			}()
		}
	}

	var mmdbReader *geoip2.Reader
	mmdbPath := filepath.Join(filepath.Dir(configPath), "Country.mmdb")
	
	// Check if MMDB exists, if not download
	if _, err := os.Stat(mmdbPath); os.IsNotExist(err) {
		log.Printf("Country.mmdb not found at %s, downloading...", mmdbPath)
		if err := downloadMMDB(mmdbPath); err != nil {
			log.Printf("failed to download Country.mmdb: %v", err)
		} else {
			log.Printf("Country.mmdb downloaded successfully")
		}
	}

	if _, err := os.Stat(mmdbPath); err == nil {
		reader, err := geoip2.Open(mmdbPath)
		if err != nil {
			log.Printf("failed to open Country.mmdb: %v", err)
		} else {
			mmdbReader = reader
			defer mmdbReader.Close()
			log.Printf("loaded Country.mmdb")
		}
	} else {
		log.Printf("Country.mmdb not found, GEOIP rules will not work")
	}

	snapshot, err := buildSnapshot(cfg, mmdbReader)
	if err != nil {
		log.Printf("unable to build runtime: %v", err)
		return err
	}
	store := runtime.NewStore(snapshot)

	log.Printf("configuration loaded: http=%s, socks5=%s", cfg.Listen.HTTP, cfg.Listen.SOCKS5)

	group, ctx := errgroup.WithContext(ctx)

	if cfg.Listen.HTTP != "" {
		httpSrv := proxy.NewHTTPServer(cfg.Listen.HTTP, store, logger)
		group.Go(func() error { return httpSrv.Serve(ctx) })
	}
	if cfg.Listen.SOCKS5 != "" {
		socksSrv := proxy.NewSOCKS5Server(cfg.Listen.SOCKS5, store, logger)
		group.Go(func() error { return socksSrv.Serve(ctx) })
	}

	watcher, err := config.NewWatcher(configPath)
	if err != nil {
		log.Printf("config hot reload disabled: %v", err)
	} else {
		defer watcher.Close()
		group.Go(func() error {
			return watchConfig(ctx, watcher, store, levelVar, logger, cfg.Listen, nil, nil, mmdbReader)
		})
	}

	if err := group.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		log.Printf("proxy terminated with error: %v", err)
		return err
	}

	log.Printf("proxy shutdown complete")
	return nil
}

func expandPath(path string) string {
	if path == "" {
		return path
	}
	path = os.ExpandEnv(path)
	if strings.HasPrefix(path, "~") {
		home, err := os.UserHomeDir()
		if err == nil {
			path = strings.Replace(path, "~", home, 1)
		}
	}
	return path
}


func ensureDir(path string) error {
	return os.MkdirAll(path, 0755)
}

func downloadMMDB(path string) error {
	url := "https://github.com/Loyalsoldier/geoip/releases/latest/download/Country.mmdb"
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	out, err := os.Create(path)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

const defaultConfig = `[General]
http-listen = 127.0.0.1:1080
socks5-listen = 127.0.0.1:1081
log-level = info
log-format = text
prefer-ipv6 = true
ipv6 = true
bypass-system = true
skip-proxy = 192.168.0.0/16, 127.0.0.1/32
dns-server = system
default-proxy = PROXY

[Proxy]
PROXY0 = http, 127.0.0.1:1001, user, pass, 5s
PROXY1 = http, 127.0.0.1:1002, , , 5s
PROXY2 = socks5, 127.0.0.1:1003, , , 5s

[Rule]
DOMAIN-KEYWORD,vscode.com,PROXY0
DOMAIN-KEYWORD,google.com,PROXY1
DOMAIN,gemini.google.com,PROXY2
IP-CIDR,10.0.0.0/8,PROXY2

GEOIP,CN,DIRECT

FINAL,PROXY0
`
