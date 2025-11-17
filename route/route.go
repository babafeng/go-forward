package route

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"go-forward/route/internal/config"
	"go-forward/route/internal/proxy"
	"go-forward/route/internal/router"
	"go-forward/route/internal/runtime"
	"go-forward/route/internal/systemproxy"
	"go-forward/route/internal/transport"

	"golang.org/x/sync/errgroup"
)

type Options struct {
	ConfigPath string
	HTTPAddr   string
	SOCKS5Addr string
}

func watchConfig(ctx context.Context, watcher *config.Watcher, store *runtime.Store, levelVar *slog.LevelVar, logger *slog.Logger, listenCfg config.ListenConfig, httpProxyMgr, socks5ProxyMgr *systemproxy.Manager) error {
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
				logger.Warn("listen address changes require restart", slog.String("current_http", currentListen.HTTP), slog.String("new_http", cfg.Listen.HTTP), slog.String("current_socks5", currentListen.SOCKS5), slog.String("new_socks5", cfg.Listen.SOCKS5))
				cfg.Listen = currentListen
			}
			snapshot, err := buildSnapshot(cfg)
			if err != nil {
				logger.Error("failed to rebuild runtime", slog.Any("err", err))
				continue
			}
			store.Update(snapshot)
			if httpProxyMgr != nil {
				if err := httpProxyMgr.Update(cfg.General.SkipProxy, logger); err != nil {
					logger.Warn("failed to refresh HTTP system proxy bypass", slog.Any("err", err))
				}
			}
			if socks5ProxyMgr != nil {
				if err := socks5ProxyMgr.Update(cfg.General.SkipProxy, logger); err != nil {
					logger.Warn("failed to refresh SOCKS5 system proxy bypass", slog.Any("err", err))
				}
			}
			levelVar.Set(parseLogLevel(cfg.Log.Level))
			logger.Info("configuration reloaded")
		case err := <-watcher.Errors():
			logger.Error("config watch error", slog.Any("err", err))
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
	return slog.New(slog.NewTextHandler(os.Stdout, handlerOpts))
}

func buildSnapshot(cfg *config.Config) (*runtime.Snapshot, error) {
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
	eng, err := router.NewEngine(ruleSpecs)
	if err != nil {
		return nil, err
	}
	return &runtime.Snapshot{Router: eng, Dialers: mgr}, nil
}

func Run(ctx context.Context, opts Options) error {
	configPath := opts.ConfigPath
	if configPath == "" {
		configPath = "~/proxy-policy.conf"
	}
	configPath = expandPath(configPath)
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

	// var proxyMgr *systemproxy.Manager
	// if cfg.Listen.HTTP != "" {
	// 	mgr, err := systemproxy.Enable(cfg.Listen.HTTP, cfg.General.SkipProxy, logger)
	// 	if err != nil {
	// 		logger.Warn("failed to enable system proxy", slog.Any("err", err))
	// 	} else {
	// 		proxyMgr = mgr
	// 		defer func() {
	// 			if err := proxyMgr.Disable(logger); err != nil {
	// 				logger.Warn("failed to disable system proxy", slog.Any("err", err))
	// 			}
	// 		}()
	// 	}
	// }

	// var socks5ProxyMgr *systemproxy.Manager
	// if cfg.Listen.SOCKS5 != "" {
	// 	mgr, err := systemproxy.EnableSOCKS5(cfg.Listen.SOCKS5, cfg.General.SkipProxy, logger)
	// 	if err != nil {
	// 		logger.Warn("failed to enable SOCKS5 system proxy", slog.Any("err", err))
	// 	} else {
	// 		socks5ProxyMgr = mgr
	// 		defer func() {
	// 			if err := socks5ProxyMgr.Disable(logger); err != nil {
	// 				logger.Warn("failed to disable SOCKS5 system proxy", slog.Any("err", err))
	// 			}
	// 		}()
	// 	}
	// }

	snapshot, err := buildSnapshot(cfg)
	if err != nil {
		logger.Error("unable to build runtime", slog.Any("err", err))
		return err
	}
	store := runtime.NewStore(snapshot)

	logger.Info("configuration loaded", slog.String("http", cfg.Listen.HTTP), slog.String("socks5", cfg.Listen.SOCKS5))

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
		logger.Warn("config hot reload disabled", slog.Any("err", err))
	} else {
		defer watcher.Close()
		group.Go(func() error {
			return watchConfig(ctx, watcher, store, levelVar, logger, cfg.Listen, nil, nil)
		})
	}

	if err := group.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("proxy terminated with error", slog.Any("err", err))
		return err
	}

	logger.Info("proxy shutdown complete")
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

// func main() {
// 	var opts Options
// 	flag.StringVar(&opts.ConfigPath, "config", "~/proxy-policy.conf", "Path to configuration file")
// 	flag.StringVar(&opts.HTTPAddr, "http", "", "Override HTTP proxy listen address")
// 	flag.StringVar(&opts.SOCKS5Addr, "socks5", "", "Override SOCKS5 proxy listen address")
// 	flag.Parse()

// 	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
// 	defer stop()

// 	if err := Run(ctx, opts); err != nil {
// 		fmt.Fprintf(os.Stderr, "route exited with error: %v\n", err)
// 		os.Exit(1)
// 	}
// }
