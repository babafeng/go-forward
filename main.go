package main

import (
	"flag" // Import flag package
	"fmt"
	"log"
	"net/url" // Import net/url package
	"os"
	"strings"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	listenAddr := flag.String("L", "", "Server control port (e.g., 7000), Client reverse port (e.g., 2080//127.0.0.1:1080), or Proxy (e.g., socks5://[user:pass@]host:port, http://[user:pass@]host:port)") // Updated description
	serverAddr := flag.String("F", "", "Server address (host:port) for the client to connect to (e.g., example.com:7000)")

	// Parse flags
	flag.Parse()

	var listenPort, targetAddr string
	var proxyUser, proxyPass string // Use generic names for proxy credentials
	var isHttpProxy bool            // Flag to indicate HTTP proxy

	mode := "server"
	proxyListenAddr := *listenAddr // Store original for proxy mode

	// Check for proxy protocols first
	if strings.HasPrefix(*listenAddr, "socks://") || strings.HasPrefix(*listenAddr, "socks5://") || strings.HasPrefix(*listenAddr, "http://") {
		mode = "proxy"
		if strings.HasPrefix(*listenAddr, "http://") {
			isHttpProxy = true
		}
		// Parse URL to extract user:pass and host:port
		parsedURL, err := url.Parse(*listenAddr)
		if err != nil {
			log.Printf("Error parsing proxy address %s: %v\n", *listenAddr, err)
			printUsage()
			return
		}

		if parsedURL.User != nil {
			proxyUser = parsedURL.User.Username()
			proxyPass, _ = parsedURL.User.Password()
		}
		// Reconstruct listen address without user info for net.Listen
		proxyListenAddr = parsedURL.Host
		if proxyListenAddr == "" {
			log.Println("Error: Missing host:port in proxy address")
			printUsage()
			return
		}
	} else if strings.Contains(*listenAddr, "//") {
		if strings.Contains(*listenAddr, "-F") {
			mode = "client"
		} else {
			mode = "forward"
		}
		listenAddrSplit := strings.Split(*listenAddr, "//")
		if len(listenAddrSplit) != 2 {
			log.Println("Error: -L must be in the format 'listenPort//targetAddr' (e.g., 2080//127.0.0.1:1080)")
			printUsage()
			return
		}

		listenPort = listenAddrSplit[0]
		targetAddr = listenAddrSplit[1]
	}

	switch mode {
	case "server":
		if *listenAddr == "" {
			log.Println("Error: -L is required for server mode")
			printUsage()
			return
		}
		runServer(*listenAddr)
	case "client":
		if listenPort == "" || targetAddr == "" {
			log.Println("Error: Parsing public port or local target from -L failed for client mode.")
			printUsage()
			return
		}
		runClient(*serverAddr, listenPort, targetAddr)
	case "proxy":
		if isHttpProxy {
			local_http_proxy(proxyListenAddr, proxyUser, proxyPass) // Pass credentials
		} else {
			local_socks_proxy(proxyListenAddr, proxyUser, proxyPass) // Pass credentials
		}
	case "forward":
		// Format listenPort correctly before passing
		handleTCPForward(listenPort, targetAddr)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "\nOptions:")
	flag.PrintDefaults()
	fmt.Fprintln(os.Stderr, "\nExamples:")
	fmt.Fprintln(os.Stderr, "  Server: go-forward -L 7000")
	fmt.Fprintln(os.Stderr, "  Client (reverse tunnel): go-forward -L 2080//127.0.0.1:1080 -F your.server.com:7000")
	fmt.Fprintln(os.Stderr, "  SOCKS5 Proxy (No Auth): go-forward -L socks5://0.0.0.0:1080")
	fmt.Fprintln(os.Stderr, "  SOCKS5 Proxy (Auth): go-forward -L socks5://myuser:mypass@0.0.0.0:1080")
	fmt.Fprintln(os.Stderr, "  HTTP Proxy (No Auth): go-forward -L http://0.0.0.0:8080")            // New example
	fmt.Fprintln(os.Stderr, "  HTTP Proxy (Auth): go-forward -L http://myuser:mypass@0.0.0.0:8080") // New example
}
