package tools

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
func LocaHttpProxy(listenAddr, username, password string) {
	if username != "" {
		log.Printf("Starting HTTP proxy server on %s with authentication ENABLED", listenAddr)
	} else {
		log.Printf("Starting HTTP proxy server on %s with authentication DISABLED", listenAddr)
	}
	coreHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			handleHTTPS(w, r)
		} else {
			handleHTTP(w, r)
		}
	})
	authHandler := withProxyAuth(coreHandler, username, password)
	proxy := &http.Server{
		Addr:         listenAddr,
		Handler:      authHandler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	if err := proxy.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("HTTP Proxy ListenAndServe error: %v", err)
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
			w.Header().Set("Proxy-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Proxy authentication required", http.StatusProxyAuthRequired)
			return
		}

		// Check if the auth type is Basic
		if !strings.HasPrefix(authHeader, "Basic ") {
			http.Error(w, "Unsupported proxy authentication scheme", http.StatusBadRequest)
			return
		}

		// Decode base64 credentials
		encodedCreds := strings.TrimPrefix(authHeader, "Basic ")
		creds, err := base64.StdEncoding.DecodeString(encodedCreds)
		if err != nil {
			http.Error(w, "Invalid proxy credentials", http.StatusBadRequest)
			return
		}

		// Split username:password
		parts := strings.SplitN(string(creds), ":", 2)
		if len(parts) != 2 {
			http.Error(w, "Invalid proxy credentials format", http.StatusBadRequest)
			return
		}

		user := parts[0]
		pass := parts[1]

		// Validate credentials
		if user == requiredUser && pass == requiredPass {
			next.ServeHTTP(w, r) // Credentials are valid, proceed
		} else {
			w.Header().Set("Proxy-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Invalid proxy credentials", http.StatusProxyAuthRequired)
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

func handleHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("HTTP: %s %s", r.Method, r.URL)
	req := sanitizeProxyRequest(r)
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

var hopByHopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func sanitizeProxyRequest(r *http.Request) *http.Request {
	req := r.Clone(r.Context())
	req.RequestURI = ""
	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
	}
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}
	stripHopHeaders(req.Header)
	return req
}

func stripHopHeaders(headers http.Header) {
	for _, h := range hopByHopHeaders {
		headers.Del(h)
	}
	if connectionVals, ok := headers["Connection"]; ok {
		for _, v := range connectionVals {
			for _, token := range strings.Split(v, ",") {
				headers.Del(strings.TrimSpace(token))
			}
		}
	}
	headers.Del("Connection")
}

func handleHTTPS(w http.ResponseWriter, r *http.Request) {
	log.Printf("HTTPS: Establishing tunnel to %s", r.Host)
	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
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
	TunnelCopy(clientConn, destConn)
}
