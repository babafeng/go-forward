package main

import (
	// <-- 添加 bytes 包
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"
)

// certCache 用于缓存已生成的证书，以便同一个域名多次握手复用
var (
	certCache      = make(map[string]tls.Certificate)
	certCacheMutex sync.Mutex
)

// generateSelfSignedCert 根据传入的域名或 IP 生成一个自签名证书
func generateSelfSignedCert(host string) (tls.Certificate, error) {
	// 生成 RSA 私钥（2048 位）
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	// 设置证书有效期（当前到 1 年后）
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	// 生成一个随机序列号
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, err
	}

	// 配置证书模板
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// 根据 host 判断是 IP 地址还是 DNS 名称
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	// 根据模板生成证书，注意此处自签名，故使用同一个模板做签名和被签名对象
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	// 将生成的证书和私钥编码为 PEM 格式
	certPEM, keyPEM := pemEncode(derBytes, priv)
	return tls.X509KeyPair(certPEM, keyPEM)
}

// pemEncode 将 DER 格式的数据编码为 PEM 格式
func pemEncode(derBytes []byte, key *rsa.PrivateKey) ([]byte, []byte) {
	certPemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}
	keyPemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	certPEM := pem.EncodeToMemory(certPemBlock)
	keyPEM := pem.EncodeToMemory(keyPemBlock)
	return certPEM, keyPEM
}

// --- Server Logic ---
func runServer(controlAddr string) {
	addr := controlAddr
	if !strings.HasPrefix(addr, ":") {
		addr = ":" + addr
	}

	tlsConfig := &tls.Config{
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// 根据 ClientHello 中的 ServerName 生成证书，若没有提供，则采用 "localhost"
			host := chi.ServerName
			if host == "" {
				host = "example.com"
			}
			certCacheMutex.Lock()
			defer certCacheMutex.Unlock()
			if cert, ok := certCache[host]; ok {
				return &cert, nil
			}
			cert, err := generateSelfSignedCert(host)
			if err != nil {
				return nil, err
			}
			certCache[host] = cert
			return &cert, nil
		},
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	}

	log.Printf("Starting server control plane on %s\n", controlAddr)
	listener, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		log.Fatalf("Failed to listen tls on control port %s: %v\n", controlAddr, err)
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept control connection: %v\n", err)
			continue
		}
		log.Printf("Accepted control connection from %s\n", conn.RemoteAddr())
		go handleControlConnection(conn)
	}
}
func handleControlConnection(conn net.Conn) {
	// Use Yamux for multiplexing over the control connection
	session, err := muxServer(conn, nil)
	if err != nil {
		log.Printf("Failed to create yamux server session: %v\n", err)
		conn.Close()
		return
	}
	defer session.Close()
	defer log.Printf("Control session closed for %s\n", conn.RemoteAddr())

	for {
		// Accept streams initiated by the client (for control messages)
		stream, err := session.Accept()
		if err != nil {
			log.Printf("Failed to accept stream from %s: %v\n", conn.RemoteAddr(), err)
			break // Session likely closed
		}

		// Handle control messages in a separate goroutine
		go handleControlStream(session, stream)
	}
}

func handleControlStream(session *Session, stream net.Conn) {
	defer stream.Close()

	// Read the request (e.g., "LISTEN <public_port>")
	buf := make([]byte, 128) // Adjust buffer size as needed
	n, err := stream.Read(buf)
	if err != nil {
		log.Printf("Failed to read from control stream: %v\n", err)
		return
	}

	request := string(buf[:n])
	parts := strings.Fields(request)

	if len(parts) == 2 && parts[0] == "LISTEN" {
		publicPort := parts[1]
		log.Printf("Received request to listen on public port %s from %s\n", publicPort, session.RemoteAddr())
		// Start listening on the requested public port in a goroutine
		go listenPublic(session, ":"+publicPort)
		// Optionally send confirmation back via the stream (omitted for simplicity)
	} else {
		log.Printf("Received unknown request on control stream: %s\n", request)
	}
}

func listenPublic(session *Session, publicAddr string) {
	publicListener, err := net.Listen("tcp", publicAddr)
	if err != nil {
		log.Printf("Failed to listen on public port %s: %v\n", publicAddr, err)
		// Optionally notify the client about the failure via a new stream (omitted)
		return
	}
	defer publicListener.Close()
	log.Printf("Server listening on public port %s for %s\n", publicAddr, session.RemoteAddr())

	for {
		publicConn, err := publicListener.Accept()
		if err != nil {
			// Check if the session is closed, if so, stop listening
			if session.IsClosed() {
				log.Printf("Session closed, stopping listener on %s\n", publicAddr)
				return
			}
			log.Printf("Failed to accept public connection on %s: %v\n", publicAddr, err)
			continue
		}
		log.Printf("Accepted public connection on %s from %s\n", publicAddr, publicConn.RemoteAddr())

		// Open a new stream to the client over the existing session
		proxyStream, err := session.Open()
		if err != nil {
			log.Printf("Failed to open yamux stream to client %s: %v\n", session.RemoteAddr(), err)
			publicConn.Close() // Close the public connection if we can't reach the client
			// If session is closed, stop accepting new connections
			if session.IsClosed() {
				log.Printf("Session closed, stopping listener on %s\n", publicAddr)
				return
			}
			continue
		}

		// Start proxying data between the public connection and the client stream
		log.Printf("Starting proxy between %s <-> yamux stream for %s\n", publicConn.RemoteAddr(), session.RemoteAddr())
		go proxy(publicConn, proxyStream)
	}
}

// --- Client Logic ---

func runClient(serverAddr, publicPort, localTargetAddr string) {
	log.Printf("Connecting to server %s\n", serverAddr)

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := tls.Dial("tcp", serverAddr, tlsConfig)
	if err != nil {
		log.Fatalf("Failed to connect to server %s: %v\n", serverAddr, err)
	}
	log.Printf("Connected to server %s\n", serverAddr)

	// Create yamux client session
	session, err := muxClient(conn, nil)
	if err != nil {
		log.Fatalf("Failed to create yamux client session: %v\n", err)
	}
	defer session.Close()
	log.Println("Yamux client session established")

	// Open a control stream to send the listen request
	controlStream, err := session.Open()
	if err != nil {
		log.Fatalf("Failed to open control stream: %v\n", err)
	}

	// Send the listen request
	request := fmt.Sprintf("LISTEN %s", publicPort)
	_, err = controlStream.Write([]byte(request))
	if err != nil {
		controlStream.Close()
		log.Fatalf("Failed to send LISTEN request: %v\n", err)
	}
	controlStream.Close() // Close the stream after sending
	log.Printf("Sent request to server: %s\n", request)

	// Wait for the server to open streams for incoming public connections
	log.Println("Waiting for incoming proxy connections from server...")
	for {
		proxyStream, err := session.Accept()
		if err != nil {
			log.Printf("Failed to accept stream from server: %v. Exiting.\n", err)
			break // Session likely closed
		}
		log.Printf("Accepted incoming proxy stream from server %s\n", session.RemoteAddr())

		// Handle the incoming proxy stream in a goroutine
		go handleProxyStream(proxyStream, localTargetAddr)
	}
}

func handleProxyStream(proxyStream net.Conn, localTargetAddr string) {
	log.Printf("Attempting to connect to local target %s\n", localTargetAddr)
	localConn, err := net.Dial("tcp", localTargetAddr)
	if err != nil {
		log.Printf("Failed to connect to local target %s: %v\n", localTargetAddr, err)
		proxyStream.Close() // Close the stream from the server if local connection fails
		return
	}
	log.Printf("Connected to local target %s\n", localTargetAddr)

	// Start proxying data between the server stream and the local connection
	log.Printf("Starting proxy between yamux stream <-> local %s\n", localTargetAddr)
	proxy(proxyStream, localConn)
}

func proxy(conn1 io.ReadWriteCloser, conn2 io.ReadWriteCloser) {
	var conn1Local, conn1Remote, conn2Local, conn2Remote string

	if nc1, ok := conn1.(net.Conn); ok {
		conn1Local = nc1.LocalAddr().String()
		conn1Remote = nc1.RemoteAddr().String()
	} else {
		conn1Local, conn1Remote = "unknown", "unknown"
	}

	if nc2, ok := conn2.(net.Conn); ok {
		conn2Local = nc2.LocalAddr().String()
		conn2Remote = nc2.RemoteAddr().String()
	} else {
		conn2Local, conn2Remote = "unknown", "unknown"
	}

	log.Printf("[%s <-> %s] and [%s <-> %s]", conn1Remote, conn1Local, conn2Local, conn2Remote)

	var wg sync.WaitGroup
	wg.Add(2)

	closer := func(c io.Closer) {
		// Ensure close is called only once, ignore errors as the other side might have closed already
		_ = c.Close()
	}

	go func() {
		defer wg.Done()
		defer closer(conn2) // Close conn2 if copying from conn1 finishes/errors
		_, err := io.Copy(conn1, conn2)
		if err != nil && err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
			log.Printf("Proxy error (conn2->conn1): %v\n", err)
		}
		// log.Printf("Proxy conn2->conn1 finished [%s <-> %s] and [%s <-> %s]", conn1Local, conn1Remote, conn2Local, conn2Remote)
	}()

	go func() {
		defer wg.Done()
		defer closer(conn1) // Close conn1 if copying from conn2 finishes/errors
		_, err := io.Copy(conn2, conn1)
		if err != nil && err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
			log.Printf("Proxy error (conn1->conn2): %v\n", err)
		}
		// log.Printf("Proxy conn1->conn2 finished [%s <-> %s] and [%s <-> %s]", conn1Local, conn1Remote, conn2Local, conn2Remote)
	}()

	wg.Wait()
	log.Println("Proxy finished for connection pair.")
}
