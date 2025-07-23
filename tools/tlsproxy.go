package tools

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

func TlsClient(listenAddr, serverAddr, user, pass, cert string) {
	if user != "" {
		log.Printf("Starting HTTP proxy server on %s with authentication ENABLED", listenAddr)
	} else {
		log.Printf("Starting HTTP proxy server on %s with authentication DISABLED", listenAddr)
	}

	caPool := x509.NewCertPool()
	certBytes, err := base64.StdEncoding.DecodeString(cert)
	if err != nil {
		log.Fatalf("failed to decode base64 cert: %v", err)
	}
	if !caPool.AppendCertsFromPEM(certBytes) {
		log.Fatal("failed to append CA cert")
	}

	tlsConfig := NewClientTLSConfig(caPool)

	parsedaddr, err := url.Parse(serverAddr)
	if err != nil {
		log.Printf("Error parsing proxy address %s: %v\n", serverAddr, err)
	}

	proxyHandler := &ProxyHandler{
		RemoteAddress: parsedaddr.Host,
		TLSConfig:     tlsConfig,
		User:          user,
		Pass:          pass,
	}

	log.Printf("Local http proxy is listening: %s", listenAddr)
	log.Printf("All traffic will be forwarded through a TLS tunnel: %s", serverAddr)

	err = http.ListenAndServe(listenAddr, proxyHandler)
	if err != nil {
		log.Fatalf("Failed to start local http proxy: %v", err)
	}
}

// LocalHttpsProxy starts the HTTPS proxy server.
func TlsProxy(listenAddr, serverHost, user, pass string) {
	log.Printf("Starting HTTPS proxy on %s with hostname %s\n", listenAddr, serverHost)

	certPEM, keyPEM := GenerateSelfSignedCert(serverHost)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	fmt.Printf("Cert Pem: %s\n", base64.StdEncoding.EncodeToString([]byte(certPEM)))
	if err != nil {
		log.Fatalf("Failed to parse certificate: %v\n", err)
	}

	tlsConfig, err := NewServerTLSConfig(cert)
	if err != nil {
		log.Fatalf("Failed to create server TLS config: %v\n", err)
	}

	// 启动 TLS 监听
	listener, err := tls.Listen("tcp", listenAddr, tlsConfig)
	if err != nil {
		log.Fatalf("Failed to listen tls on control port %s: %v\n", listenAddr, err)
	}

	defer listener.Close()
	log.Printf("TLS Server starting HTTPS proxy on %s\n", listenAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept control connection: %v\n", err)
			continue
		}
		log.Printf("Accepted tls proxy connection from %s\n", conn.RemoteAddr())
		go handleProxyRequest(conn)
	}
}

// ProxyHandler 是我们自定义的 HTTP 代理处理器
type ProxyHandler struct {
	RemoteAddress string
	TLSConfig     *tls.Config
	User          string
	Pass          string
}

// ServeHTTP 是处理代理请求的核心逻辑
func (p *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p.User != "" {
		auth := r.Header.Get("Proxy-Authorization")
		username, password, ok := parseBasicAuth(auth)
		if !ok || username != p.User || password != p.Pass {
			log.Printf("Proxy authentication failed for user: %s from %s", username, r.RemoteAddr)
			w.Header().Set("Proxy-Authenticate", `Basic realm="Proxy"`)
			http.Error(w, "Proxy authentication required", http.StatusProxyAuthRequired)
			return
		}
	}

	log.Printf("Request received: %s %s %s", r.Method, r.Host, r.Proto)

	// 建立到远程 TLS 服务的连接
	remoteConn, err := tls.Dial("tcp", p.RemoteAddress, p.TLSConfig)
	if err != nil {
		log.Printf("Failed to connect to the remote TLS service: %v", err)
		http.Error(w, "Unable to connect to the remote proxy", http.StatusServiceUnavailable)
		return
	}
	defer remoteConn.Close()

	// 处理 HTTPS 的 CONNECT 请求
	if r.Method == http.MethodConnect {
		// 劫持连接以获取底层的 TCP 连接
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			log.Println("Hijacking not supported")
			http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
			return
		}
		clientConn, _, err := hijacker.Hijack()
		if err != nil {
			log.Printf("Connection hijacking failed: %v", err)
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		defer clientConn.Close()

		// 将原始的 CONNECT 请求转发给远程服务
		// 注意：这里我们不能简单地 r.Write(remoteConn)，因为那会包含 Host 头部，
		// 对于 CONNECT 请求，我们只需要 Host 在请求行中。
		// 但对于这个场景，直接 Write 也可以工作。
		err = r.Write(remoteConn)
		if err != nil {
			log.Printf("Failed to forward the CONNECT request to the remote service: %v", err)
			return
		}

		// 在两个连接之间双向转发数据
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			io.Copy(clientConn, remoteConn)
		}()
		go func() {
			defer wg.Done()
			io.Copy(remoteConn, clientConn)
		}()
		wg.Wait()

	} else {
		// 处理普通的 HTTP 请求
		// 对于标准的 HTTP 代理请求，我们不应该修改请求。
		// 原始请求中包含了完整的 URL (例如 GET http://google.com/ HTTP/1.1)，
		// 我们需要将它原封不动地转发给远程服务器。
		// 下面被注释掉的代码是导致错误的原因。
		/*
			r.RequestURI = ""
			r.Header.Del("Proxy-Connection")
			r.Header.Del("Connection")
		*/

		// 将请求直接转发到远程服务
		err := r.Write(remoteConn)
		if err != nil {
			log.Printf("Failed to forward HTTP request to remote service: %v", err)
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}

		// 将远程服务的响应复制回原始的 http.ResponseWriter
		resp, err := http.ReadResponse(bufio.NewReader(remoteConn), r)
		if err != nil {
			log.Printf("Failed to read response from remote service: %v", err)
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		defer resp.Body.Close()

		// 复制响应头
		for key, values := range resp.Header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		// 写入响应状态码
		w.WriteHeader(resp.StatusCode)
		// 复制响应体
		io.Copy(w, resp.Body)
	}
}

// handleTunneling 在两个连接之间双向转发数据
func handleTunneling(clientConn, destConn net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(destConn, clientConn)
		destConn.Close()
	}()
	go func() {
		defer wg.Done()
		io.Copy(clientConn, destConn)
		clientConn.Close()
	}()

	wg.Wait()
}

// handleHTTP 处理普通的 HTTP 请求
func handleHttpRequest(clientConn net.Conn, req *http.Request) {
	req.URL.Scheme = "http"
	req.URL.Host = req.Host

	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		log.Printf("Failed to execute HTTP request: %v", err)
		http.Error(&connResponseWriter{conn: clientConn}, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	err = resp.Write(clientConn)
	if err != nil {
		log.Printf("Failed to write response to the client: %v", err)
	}
}

// handleProxyRequest 是每个连接的主处理函数
func handleProxyRequest(clientConn net.Conn) {
	defer clientConn.Close()

	// 设置读取超时，防止恶意连接占用资源
	clientConn.SetReadDeadline(time.Now().Add(10 * time.Second))

	// 读取并解析来自客户端的初始 HTTP 请求
	req, err := http.ReadRequest(bufio.NewReader(clientConn))
	if err != nil {
		if err != io.EOF {
			log.Printf("Failed to read request: %v", err)
		}
		return
	}

	clientConn.SetReadDeadline(time.Time{})

	// 根据请求类型进行处理
	if req.Method == http.MethodConnect {
		// HTTPS 流量
		log.Printf("HTTPS: Establishing tunnel to %s", req.Host)
		// 连接到最终目标
		destConn, err := net.Dial("tcp", req.Host)
		if err != nil {
			log.Printf("Failed to connect to target %s: %v", req.Host, err)
			// 向客户端返回一个错误响应
			http.Error(&connResponseWriter{conn: clientConn}, err.Error(), http.StatusServiceUnavailable)
			return
		}
		// 通知客户端连接已建立
		clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		// 开始隧道转发
		handleTunneling(clientConn, destConn)
	} else {
		// HTTP 流量
		log.Printf("HTTP: Establishing tunnel to %s", req.Host)
		handleHttpRequest(clientConn, req)
	}
}

type connResponseWriter struct {
	conn net.Conn
}

func (w *connResponseWriter) Header() http.Header {
	return http.Header{}
}

func (w *connResponseWriter) Write(b []byte) (int, error) {
	return w.conn.Write(b)
}

func (w *connResponseWriter) WriteHeader(statusCode int) {
	statusLine := "HTTP/1.1 " + http.StatusText(statusCode) + "\r\n\r\n"
	w.conn.Write([]byte(statusLine))
}

// 解析 Proxy-Authorization: Basic ... 头部
func parseBasicAuth(auth string) (username, password string, ok bool) {
	const prefix = "Basic "
	if len(auth) < len(prefix) || auth[:len(prefix)] != prefix {
		return
	}
	decoded, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return
	}
	creds := string(decoded)
	for i := 0; i < len(creds); i++ {
		if creds[i] == ':' {
			return creds[:i], creds[i+1:], true
		}
	}
	return
}
