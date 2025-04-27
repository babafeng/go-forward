package main

import (
	"flag" // Import flag package
	"fmt"
	"log"     // Import net package
	"net/url" // Import net/url package
	"os"
	"regexp"
	"strconv" // Import strconv package
	"strings"
	"sync" // Import sync package
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
	IsHTTP     bool
}

type ClientConfig struct {
	ServerAddr      string // From -F
	PublicPort      string
	LocalTargetAddr string
}

type ServerConfig struct {
	PublicPort string
}

// Updated ForwardConfig for ranges
type ForwardConfig struct {
	ListenAddr      string // For single port listen (e.g., ":8080")
	TargetAddr      string // For single port target (e.g., "host:80")
	IsRange         bool
	LocalStartPort  int
	LocalEndPort    int
	TargetHost      string
	TargetStartPort int
	TargetEndPort   int
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

	flag.Parse()

	if len(lFlags) == 0 {
		log.Println("Error: At least one -L flag is required.")
		printUsage()
		return
	}

	var proxies []ProxyConfig
	var clients []ClientConfig
	var forwards []ForwardConfig
	var servers []ServerConfig
	// Server mode is excluded in this multi-service setup for simplicity.
	// Use a dedicated flag if server mode needs to run alongside others.

	hasClientConfig := false // Track if any client config is found

	for _, lVal := range lFlags {
		isHttpProxy := false
		// Check for proxy protocols
		if strings.HasPrefix(lVal, "socks://") || strings.HasPrefix(lVal, "socks5://") || strings.HasPrefix(lVal, "http://") {
			if strings.HasPrefix(lVal, "http://") {
				isHttpProxy = true
			}
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
			proxies = append(proxies, ProxyConfig{
				ListenAddr: proxyListenAddr,
				User:       proxyUser,
				Pass:       proxyPass,
				IsHTTP:     isHttpProxy,
			})
			log.Printf("Parsed Proxy Config: Listen=%s, Auth=%t, HTTP=%t\n", proxyListenAddr, proxyUser != "", isHttpProxy)

		} else if strings.Contains(lVal, "//") { // Check for client or forward mode
			parts := strings.SplitN(lVal, "//", 2)
			if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
				log.Printf("Error: Invalid format for client/forward mode %s. Expected '[localPort | range]//[targetHost:targetPort | range]'\n", lVal)
				continue // Skip
			}
			localPart := parts[0]
			targetPart := parts[1]

			if *serverAddr != "" { // If -F is set, it's client (reverse tunnel) mode
				clients = append(clients, ClientConfig{
					ServerAddr:      *serverAddr,
					PublicPort:      localPart,
					LocalTargetAddr: targetPart,
				})
				hasClientConfig = true
				log.Printf("Parsed Client Config: Server=%s, PublicPort=%s, LocalTarget=%s\n", *serverAddr, localPart, targetPart)
			} else { // If -F is not set, it's forward mode (single or range)
				isRange := strings.Contains(localPart, "-") && strings.Contains(targetPart, "-")
				var fwdCfg ForwardConfig
				fwdCfg.IsRange = isRange

				if isRange {
					// Parse local range
					localRangeParts := strings.SplitN(localPart, "-", 2)
					targetHostPortRange := strings.SplitN(targetPart, ":", 2) // Split host:portRange first
					if len(localRangeParts) != 2 || len(targetHostPortRange) != 2 {
						log.Printf("Error: Invalid range format in %s. Expected 'localStart-localEnd//host:targetStart-targetEnd'\n", lVal)
						continue
					}
					targetHost := targetHostPortRange[0]
					targetRangePart := targetHostPortRange[1]
					targetRangeParts := strings.SplitN(targetRangePart, "-", 2)
					if len(targetRangeParts) != 2 {
						log.Printf("Error: Invalid target range format in %s. Expected 'host:targetStart-targetEnd'\n", lVal)
						continue
					}

					// Convert ports to int
					var err error
					fwdCfg.LocalStartPort, err = strconv.Atoi(localRangeParts[0])
					if err == nil {
						fwdCfg.LocalEndPort, err = strconv.Atoi(localRangeParts[1])
					}
					if err == nil {
						fwdCfg.TargetStartPort, err = strconv.Atoi(targetRangeParts[0])
					}
					if err == nil {
						fwdCfg.TargetEndPort, err = strconv.Atoi(targetRangeParts[1])
					}

					if err != nil {
						log.Printf("Error parsing port numbers in range %s: %v\n", lVal, err)
						continue
					}

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
					fwdCfg.TargetHost = targetHost
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
			if lVal != "" {

			}
			re := regexp.MustCompile(`^[0-9:]+$`)
			if re.MatchString(lVal) {
				servers = append(servers, ServerConfig{
					PublicPort: lVal,
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
	if len(proxies) == 0 && len(clients) == 0 && len(forwards) == 0 && len(servers) == 0 {
		log.Println("Error: No valid services were configured.")
		return
	}

	// --- Start Services ---
	var wg sync.WaitGroup

	// Start Proxies
	for _, p := range proxies {
		wg.Add(1)
		go func(cfg ProxyConfig) {
			defer wg.Done()
			if cfg.IsHTTP {
				local_http_proxy(cfg.ListenAddr, cfg.User, cfg.Pass)
			} else {
				local_socks_proxy(cfg.ListenAddr, cfg.User, cfg.Pass)
			}
		}(p)
	}

	// Start Forwarders (handles both single and range)
	for _, f := range forwards {
		wg.Add(1)
		go func(cfg ForwardConfig) {
			defer wg.Done()
			handleTCPForward(cfg) // Pass the whole config struct
		}(f)
	}

	// Start Forwarders
	for _, f := range servers {
		wg.Add(1)
		go func(cfg ServerConfig) {
			defer wg.Done()
			runServer(cfg.PublicPort)
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
			runClient(cfg.ServerAddr, cfg.PublicPort, cfg.LocalTargetAddr)
			log.Printf("Reverse tunnel client (%s//%s) disconnected from server %s.\n", cfg.PublicPort, cfg.LocalTargetAddr, cfg.ServerAddr)
		}(c)
	}

	log.Println("All configured services started. Running indefinitely...")
	wg.Wait() // Wait for all service goroutines to finish (they shouldn't in normal operation)
	log.Println("All services have stopped.")
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "\nUsage: go-forward [options]")
	fmt.Fprintln(os.Stderr, "\nOptions:")
	flag.PrintDefaults()
	fmt.Fprintln(os.Stderr, "\nExamples:")
	fmt.Fprintln(os.Stderr, "  Reverse Tunnel Server: go-forward -L 7000 (Note: Server mode is exclusive, use dedicated flag if needed alongside others)")
	fmt.Fprintln(os.Stderr, "  Reverse Tunnel Client: go-forward -L 2080//127.0.0.1:1080 -F your.server.com:7000")
	fmt.Fprintln(os.Stderr, "  SOCKS5 Proxy (No Auth): go-forward -L socks5://0.0.0.0:1080")
	fmt.Fprintln(os.Stderr, "  SOCKS5 Proxy (Auth): go-forward -L socks5://myuser:mypass@0.0.0.0:1080")
	fmt.Fprintln(os.Stderr, "  HTTP Proxy (No Auth): go-forward -L http://0.0.0.0:8080")
	fmt.Fprintln(os.Stderr, "  HTTP Proxy (Auth): go-forward -L http://myuser:mypass@0.0.0.0:8080")
	fmt.Fprintln(os.Stderr, "  Local Port Forward (Single): go-forward -L 9000//remote.host:80")
	fmt.Fprintln(os.Stderr, "  Local Port Forward (Range): go-forward -L 1000-1005//target.host:3000-3005") // New example
	fmt.Fprintln(os.Stderr, "  Combined Proxy + Reverse Tunnel:")
	fmt.Fprintln(os.Stderr, "    go-forward -L http://0.0.0.0:8080 -L 2020//127.0.0.1:8080 -F tunnel.server.com:7000")
}
