package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"go-forward/route"
	"go-forward/tools"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// --- Custom Flag Type for Multiple -L ---
type multiStringFlag []string

func (m *multiStringFlag) String() string {
	return fmt.Sprintf("%v", *m)
}

func (m *multiStringFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

// --- Service Configuration Structs ---
type ProxyConfig struct {
	ListenAddr string
	User       string
	Pass       string
	Server     string
	IsHTTP     bool
	IsTLS      bool
}

type ClientConfig struct {
	ServerAddr      string // From -F
	PublicPort      string
	LocalTargetAddr string
}

type ServerConfig struct {
	PublicPort string
	ServerHost string
}

// 添加辅助函数用于解析端口范围
func parsePortRange(rangeStr, sep string) (int, int, error) {
	parts := strings.Split(rangeStr, sep)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid range: %s", rangeStr)
	}
	start, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, err
	}
	end, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, err
	}
	return start, end, nil
}

func requiresPrivilegedPort(addr string) bool {
	port, err := extractPort(addr)
	if err != nil {
		return false
	}
	return port > 0 && port < 1024
}

func extractPort(addr string) (int, error) {
	if !strings.Contains(addr, ":") {
		return 0, fmt.Errorf("address %s missing port", addr)
	}
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		if strings.HasPrefix(addr, ":") {
			portStr = strings.TrimPrefix(addr, ":")
		} else {
			return 0, err
		}
	}
	return strconv.Atoi(portStr)
}

// --- Main Function ---
func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	var lFlags multiStringFlag
	flag.Var(&lFlags, "L", "Service definition:\n"+
		"  Proxy:      socks5://[user:pass@]host:port OR http://[user:pass@]host:port\n"+
		"  Rev Tunnel: publicPort//localTargetAddr (requires -F)\n"+
		"  Forward:    listenPort//targetAddr (without -F)")

	serverAddr := flag.String("F", "", "Server address (host:port) for reverse tunnel client mode")
	serverHost := flag.String("H", "127.0.0.1", "H is used to tls cert/hostname verification")
	cert := flag.String("C", "", "C is used to specify the TLS certificate base64 string")
	key := flag.String("K", "", "K is used to specify the TLS key base64 string")
	genkey := flag.String("genkey", "", "gen key and cert for tls proxy, format: genkey=hostname")
	socksMax := flag.Int("socks-max", 100, "Maximum concurrent SOCKS5 connections")
	routeConfigPath := flag.String("R", "", "Enable router mode with the given proxy policy config file")
	flag.Parse()

	if genkey != nil && *genkey != "" {
		log.Printf("Generating key and cert for TLS proxy with hostname: %s\n", *genkey)
		certPEM, keyPEM := tools.GenerateSelfSignedCert(*genkey)
		fmt.Printf("Key Pem: %s\n", base64.StdEncoding.EncodeToString([]byte(keyPEM)))
		fmt.Printf("Cert Pem: %s\n", base64.StdEncoding.EncodeToString([]byte(certPEM)))
		return
	}

	routeEnabled := *routeConfigPath != ""

	if len(lFlags) == 0 && !routeEnabled {
		log.Println("Error: At least one -L flag is required.")
		printUsage()
		return
	}

	if *serverAddr != "" && *cert == "" {
		log.Println("Error: -C <base64_cert> is required when using reverse tunnel client mode (-F)")
		return
	}

	tools.SetSocksConcurrencyLimit(*socksMax)

	var (
		proxies  []ProxyConfig
		clients  []ClientConfig
		forwards []tools.ForwardConfig
		servers  []ServerConfig
		wg       sync.WaitGroup
	)

	var (
		routeCancel context.CancelFunc
		routeDone   chan struct{}
	)
	if routeEnabled {
		routeCtx, cancel := context.WithCancel(context.Background())
		routeCancel = cancel
		routeDone = make(chan struct{})
		cfgPath := *routeConfigPath
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer close(routeDone)
			if err := route.Run(routeCtx, route.Options{ConfigPath: cfgPath}); err != nil {
				log.Fatalf("router mode failed: %v", err)
			}
		}()
	}

	hasClientConfig := false
	isTLSProxies := false

	for _, lVal := range lFlags {
		prefixes := []string{"socks://", "socks5://", "http://", "https://", "tls://"}
		isProxies := false
		for _, p := range prefixes {
			if strings.HasPrefix(lVal, p) {
				isProxies = true
				break
			}
		}
		isTLSProxies = strings.HasPrefix(lVal, "http://") && strings.HasPrefix(*serverAddr, "tls://")

		if isProxies {
			// Check for proxy protocols
			isHttpProxy := strings.HasPrefix(lVal, "http://")
			IsTLS := strings.HasPrefix(lVal, "tls://")
			parsedURL, err := url.Parse(lVal)
			if err != nil {
				log.Printf("Error parsing proxy address %s: %v\n", lVal, err)
				continue // Skip this invalid config
			}
			proxyListenAddr := parsedURL.Host
			if proxyListenAddr == "" {
				log.Printf("Error: Missing host:port in proxy address %s\n", lVal)
				continue // Skip
			}
			var proxyUser, proxyPass string
			if parsedURL.User != nil {
				proxyUser = parsedURL.User.Username()
				proxyPass, _ = parsedURL.User.Password()
			}

			if requiresPrivilegedPort(proxyListenAddr) && !isCurrentUserPrivileged() {
				log.Fatalf("port %s requires elevated privileges; please use sudo or choose a port >= 1024", proxyListenAddr)
			}
			proxies = append(proxies, ProxyConfig{
				ListenAddr: proxyListenAddr,
				User:       proxyUser,
				Pass:       proxyPass,
				Server:     *serverHost,
				IsHTTP:     isHttpProxy,
				IsTLS:      IsTLS,
			})
			log.Printf("Parsed Proxy Config: Listen=%s, Auth=%t, HTTP=%t, HTTPS=%t\n", proxyListenAddr, proxyUser != "", isHttpProxy, IsTLS)

		} else if strings.Contains(lVal, "//") { // Check for client or forward mode
			parts := strings.SplitN(lVal, "//", 2)
			if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
				log.Printf("Error: Invalid format for client/forward mode %s. Expected '[localPort | range]//[targetHost:targetPort | range]'\n", lVal)
				continue // Skip
			}
			localPart := parts[0]
			targetPart := parts[1]

			if *serverAddr != "" { // If -F is set, it's client (reverse tunnel or tls proxy) mode
				clients = append(clients, ClientConfig{
					ServerAddr:      *serverAddr,
					PublicPort:      localPart,
					LocalTargetAddr: targetPart,
				})
				hasClientConfig = true
				log.Printf("Parsed Client Config: Server=%s, PublicPort=%s, LocalTarget=%s\n", *serverAddr, localPart, targetPart)

			} else { // If -F is not set, it's forward mode (single or range)
				isRange := strings.Contains(localPart, "-") && strings.Contains(targetPart, "-")
				var fwdCfg tools.ForwardConfig
				fwdCfg.IsRange = isRange

				if isRange {
					localStart, localEnd, err := parsePortRange(localPart, "-")
					if err != nil {
						log.Printf("Error parsing local port range in %s: %v\n", lVal, err)
						continue
					}
					fwdCfg.LocalStartPort = localStart
					fwdCfg.LocalEndPort = localEnd

					targetHostPortRange := strings.SplitN(targetPart, ":", 2)
					if len(targetHostPortRange) != 2 {
						log.Printf("Error: Invalid range format in %s. Expected 'localStart-localEnd//host:targetStart-targetEnd'\n", lVal)
						continue
					}
					fwdCfg.TargetHost = targetHostPortRange[0]
					targetStart, targetEnd, err := parsePortRange(targetHostPortRange[1], "-")
					if err != nil {
						log.Printf("Error parsing target port range in %s: %v\n", lVal, err)
						continue
					}
					fwdCfg.TargetStartPort = targetStart
					fwdCfg.TargetEndPort = targetEnd

					// Validate ranges
					if fwdCfg.LocalStartPort > fwdCfg.LocalEndPort || fwdCfg.TargetStartPort > fwdCfg.TargetEndPort {
						log.Printf("Error: Invalid port range order in %s (start must be <= end)\n", lVal)
						continue
					}
					localRangeSize := fwdCfg.LocalEndPort - fwdCfg.LocalStartPort
					targetRangeSize := fwdCfg.TargetEndPort - fwdCfg.TargetStartPort
					if localRangeSize != targetRangeSize {
						log.Printf("Error: Local port range size (%d) must match target port range size (%d) in %s\n", localRangeSize+1, targetRangeSize+1, lVal)
						continue
					}
					log.Printf("Parsed Forward Range Config: Local=%d-%d, Target=%s:%d-%d\n", fwdCfg.LocalStartPort, fwdCfg.LocalEndPort, fwdCfg.TargetHost, fwdCfg.TargetStartPort, fwdCfg.TargetEndPort)

				} else { // Single port forward
					// Format local listen address
					localListenAddr := localPart
					if !strings.Contains(localListenAddr, ":") {
						localListenAddr = ":" + localListenAddr
					}
					fwdCfg.ListenAddr = localListenAddr
					fwdCfg.TargetAddr = targetPart // Target includes host:port
					log.Printf("Parsed Forward Single Config: Listen=%s, Target=%s\n", fwdCfg.ListenAddr, fwdCfg.TargetAddr)
				}
				forwards = append(forwards, fwdCfg)
			}
		} else {
			re := regexp.MustCompile(`^[0-9:]+$`)
			if re.MatchString(lVal) {
				servers = append(servers, ServerConfig{
					PublicPort: lVal,
					ServerHost: *serverHost,
				})
			} else {
				log.Printf("Warning: Ignoring unsupported -L format: %s (Server mode not supported in multi-service setup)\n", lVal)
			}
		}
	}

	// Validate configurations
	if hasClientConfig && *serverAddr == "" {
		log.Println("Error: -F <server_addr> is required when using reverse tunnel client mode (e.g., -L port//host:port)")
		// It's already checked above, but double-checking logic might be useful.
		return
	}
	if len(proxies)+len(clients)+len(forwards)+len(servers) == 0 {
		if routeEnabled {
			log.Println("Router mode enabled without local services; running route only.")
		} else {
			log.Println("Error: No valid services were configured.")
			return
		}
	}

	// Start Proxies
	for _, p := range proxies {
		wg.Add(1)
		go func(cfg ProxyConfig) {
			defer wg.Done()
			if isTLSProxies {
				tools.TlsClient(cfg.ListenAddr, *serverAddr, cfg.User, cfg.Pass, *cert)
			} else if cfg.IsTLS {
				tools.TlsProxy(cfg.ListenAddr, cfg.Server, *key, *cert)
			} else if cfg.IsHTTP {
				tools.LocaHttpProxy(cfg.ListenAddr, cfg.User, cfg.Pass)
			} else {
				tools.LocalSocksProxy(cfg.ListenAddr, cfg.User, cfg.Pass)
			}
		}(p)
	}

	// Start Forwarders (handles both single and range)
	for _, f := range forwards {
		wg.Add(1)
		go func(cfg tools.ForwardConfig) {
			defer wg.Done()
			tools.HandleTCPForward(cfg) // Pass the whole config struct
		}(f)
	}

	// Start Forwarders
	for _, f := range servers {
		wg.Add(1)
		go func(cfg ServerConfig) {
			defer wg.Done()
			tools.RunServer(cfg.PublicPort, cfg.ServerHost, *key, *cert) // Pass the whole config struct
		}(f)
	}

	// Start Clients (Reverse Tunnels)
	// Add a small delay to allow proxies/servers to potentially start listening first
	if len(clients) > 0 {
		log.Println("Waiting briefly before starting reverse tunnel clients...")
		time.Sleep(1 * time.Second) // Simple delay, might need more robust readiness check
	}
	for _, c := range clients {
		wg.Add(1)
		go func(cfg ClientConfig) {
			defer wg.Done()
			// Note: runClient runs indefinitely until connection breaks
			tools.RunClient(cfg.ServerAddr, cfg.PublicPort, cfg.LocalTargetAddr, *cert)
			log.Printf("Reverse tunnel client (%s//%s) disconnected from server %s.\n", cfg.PublicPort, cfg.LocalTargetAddr, cfg.ServerAddr)
		}(c)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigChan)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	log.Println("All configured services started. Running indefinitely...")
	select {
	case sig := <-sigChan:
		log.Printf("Received signal %s, exiting...", sig)
		if routeCancel != nil {
			routeCancel()
		}
		if routeDone != nil {
			<-routeDone
		}
	case <-done:
		log.Println("All services have stopped.")
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "\nUsage: go-forward [options]")
	fmt.Fprintln(os.Stderr, "\nOptions:")
	flag.PrintDefaults()
	fmt.Fprintln(os.Stderr, "\nExamples:")
	fmt.Fprintln(os.Stderr, "  Reverse Tunnel Server: go-forward -L 7000 -H example.com (Note: Server mode is exclusive, use dedicated flag if needed alongside others, -H is used to tls cert/hostname verification)")
	fmt.Fprintln(os.Stderr, "  Reverse Tunnel Client: go-forward -L 2080//127.0.0.1:1080 -F your.server.com:7000")
	fmt.Fprintln(os.Stderr, "  SOCKS5 Proxy (No Auth): go-forward -L socks5://0.0.0.0:1080")
	fmt.Fprintln(os.Stderr, "  SOCKS5 Proxy (Auth): go-forward -L socks5://myuser:mypass@0.0.0.0:1080")
	fmt.Fprintln(os.Stderr, "  HTTP Proxy (No Auth): go-forward -L http://0.0.0.0:8080")
	fmt.Fprintln(os.Stderr, "  HTTP Proxy (Auth): go-forward -L http://myuser:mypass@0.0.0.0:8080")
	fmt.Fprintln(os.Stderr, "  HTTPS Proxy (No Auth): go-forward -L https://0.0.0.0:8081")
	fmt.Fprintln(os.Stderr, "  HTTPS Proxy (Auth): go-forward -L https://myuser:mypass@0.0.0.0:8081")
	fmt.Fprintln(os.Stderr, "  Local Port Forward (Single): go-forward -L 9000//remote.host:80")
	fmt.Fprintln(os.Stderr, "  Local Port Forward (Range): go-forward -L 1000-1005//target.host:3000-3005") // New example
	fmt.Fprintln(os.Stderr, "  Router Mode: go-forward -R /path/to/proxy-policy.conf")
	fmt.Fprintln(os.Stderr, "  Combined Proxy + Reverse Tunnel:")
	fmt.Fprintln(os.Stderr, "    go-forward -L http://0.0.0.0:8080 -L 2020//127.0.0.1:8080 -F tunnel.server.com:7000")
}
