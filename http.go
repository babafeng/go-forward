package main

import (
	"encoding/base64" // Import encoding/base64
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// Modified signature to accept username and password
func local_http_proxy(listenAddr, username, password string) {
	if username != "" {
		log.Printf("Starting HTTP proxy server on %s with authentication ENABLED\n", listenAddr)
	} else {
		log.Printf("Starting HTTP proxy server on %s with authentication DISABLED\n", listenAddr)
	}

	// Define the core handler
	coreHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			handleHTTPS(w, r) // 处理 HTTPS 请求
		} else {
			handleHTTP(w, r) // 处理 HTTP 请求
		}
	})

	// Wrap the core handler with authentication middleware
	authHandler := withProxyAuth(coreHandler, username, password)

	proxy := &http.Server{
		Addr:    listenAddr,
		Handler: authHandler, // Use the wrapped handler
		// Set timeouts to avoid resource exhaustion
		ReadTimeout:  30 * time.Second, // Increased ReadTimeout
		WriteTimeout: 30 * time.Second, // Increased WriteTimeout
		IdleTimeout:  120 * time.Second,
	}

	if err := proxy.ListenAndServe(); err != nil && err != http.ErrServerClosed { // Check for ErrServerClosed
		log.Fatalf("HTTP Proxy ListenAndServe error: %v", err) // Use Fatalf
	}
}

// Middleware for Proxy Basic Authentication
func withProxyAuth(next http.Handler, requiredUser, requiredPass string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If no username is configured, skip authentication
		if requiredUser == "" {
			next.ServeHTTP(w, r)
			return
		}

		authHeader := r.Header.Get("Proxy-Authorization")
		if authHeader == "" {
			log.Printf("Proxy auth required for %s %s from %s, but header missing\n", r.Method, r.RequestURI, r.RemoteAddr)
			w.Header().Set("Proxy-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Proxy authentication required", http.StatusProxyAuthRequired) // 407
			return
		}

		// Check if the auth type is Basic
		if !strings.HasPrefix(authHeader, "Basic ") {
			log.Printf("Unsupported proxy auth type for %s %s from %s\n", r.Method, r.RequestURI, r.RemoteAddr)
			http.Error(w, "Unsupported proxy authentication scheme", http.StatusBadRequest) // 400 or 407? 407 seems more appropriate
			return
		}

		// Decode base64 credentials
		encodedCreds := strings.TrimPrefix(authHeader, "Basic ")
		creds, err := base64.StdEncoding.DecodeString(encodedCreds)
		if err != nil {
			log.Printf("Invalid base64 proxy auth credentials from %s\n", r.RemoteAddr)
			http.Error(w, "Invalid proxy credentials", http.StatusBadRequest) // 400
			return
		}

		// Split username:password
		parts := strings.SplitN(string(creds), ":", 2)
		if len(parts) != 2 {
			log.Printf("Invalid proxy auth format from %s\n", r.RemoteAddr)
			http.Error(w, "Invalid proxy credentials format", http.StatusBadRequest) // 400
			return
		}

		user := parts[0]
		pass := parts[1]

		// Validate credentials
		if user == requiredUser && pass == requiredPass {
			log.Printf("Proxy authentication successful for user '%s' from %s\n", user, r.RemoteAddr)
			next.ServeHTTP(w, r) // Credentials are valid, proceed
		} else {
			log.Printf("Proxy authentication failed for user '%s' from %s\n", user, r.RemoteAddr)
			w.Header().Set("Proxy-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Invalid proxy credentials", http.StatusProxyAuthRequired) // 407
		}
	})
}

func copyHeaders(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func tunnel(dst net.Conn, src net.Conn) {
	defer dst.Close()
	defer src.Close()

	log.Printf("Tunnel: src=%s -> dst=%s", src.RemoteAddr(), dst.RemoteAddr())
	written, err := io.Copy(dst, src)
	if (err != nil) && !strings.Contains(err.Error(), "use of closed network connection") {
		log.Printf("Tunnel error: %v", err)
	}
	log.Printf("Tunnel transferred %d bytes from %s to %s", written, src.RemoteAddr(), dst.RemoteAddr())
}

func handleHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("HTTP: %s %s", r.Method, r.URL)
	// 创建到目标服务器的请求
	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	// 将响应头复制到客户端
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func handleHTTPS(w http.ResponseWriter, r *http.Request) {
	log.Printf("HTTPS: Establishing tunnel to %s", r.Host)
	// 与目标服务器建立连接
	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	// 通知客户端连接已建立
	w.WriteHeader(http.StatusOK)

	// 劫持客户端连接
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	// 开始双向数据转发
	go tunnel(destConn, clientConn)
	go tunnel(clientConn, destConn)
}
