package tools

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"go-forward/mux"
	"io"
	"log"
	"net"
	"strings"
	"sync"
)

// --- Server Logic ---
func RunServer(controlAddr string, serverHost string) {
	addr := controlAddr
	if !strings.HasPrefix(addr, ":") {
		addr = ":" + addr
	}
	certPEM, keyPEM := GenerateSelfSignedCert(serverHost)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Fatalf("Failed to parse certificate: %v\n", err)
	}

	fmt.Printf("%s\n", base64.StdEncoding.EncodeToString([]byte(certPEM)))

	tlsConfig, err := NewServerTLSConfig(cert)
	if err != nil {
		log.Fatalf("Failed to create server TLS config: %v\n", err)
	}

	log.Printf("Starting server control plane on %s:%s \n", serverHost, controlAddr)
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
	session, err := mux.Server(conn, nil)
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

func handleControlStream(session *mux.Session, stream net.Conn) {
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

func listenPublic(session *mux.Session, publicAddr string) {
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
		go Proxy(publicConn, proxyStream)
	}
}

// --- Client Logic ---

func RunClient(serverAddr, publicPort, localTargetAddr string, cert string) {
	log.Printf("Connecting to server %s\n", serverAddr)

	caPool := x509.NewCertPool()
	certBytes, err := base64.StdEncoding.DecodeString(cert)
	if err != nil {
		log.Fatalf("failed to decode base64 cert: %v", err)
	}
	if !caPool.AppendCertsFromPEM(certBytes) {
		log.Fatal("failed to append CA cert")
	}

	tlsConfig := NewClientTLSConfig(caPool)

	conn, err := tls.Dial("tcp", serverAddr, tlsConfig)
	if err != nil {
		log.Fatalf("Failed to connect to server %s: %v\n", serverAddr, err)
	}
	log.Printf("Connected to server %s\n", serverAddr)

	// Create yamux client session
	session, err := mux.Client(conn, nil)
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
	Proxy(proxyStream, localConn)
}

func Proxy(conn1 io.ReadWriteCloser, conn2 io.ReadWriteCloser) {
	var conn1Local, conn1Remote, conn2Local, conn2Remote string

	if nc1, ok := conn1.(net.Conn); ok {
		conn1Local = nc1.LocalAddr().String()
		conn1Remote = nc1.RemoteAddr().String()
	}

	if nc2, ok := conn2.(net.Conn); ok {
		conn2Local = nc2.LocalAddr().String()
		conn2Remote = nc2.RemoteAddr().String()
	}

	log.Printf("[%s <-> %s] and [%s <-> %s]", conn1Remote, conn1Local, conn2Local, conn2Remote)

	var wg sync.WaitGroup
	wg.Add(2)

	closer := func(c io.Closer) { _ = c.Close() }

	go func() {
		defer wg.Done()
		defer closer(conn2)
		_, err := io.Copy(conn1, conn2)
		if err != nil && err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
			log.Printf("Proxy error (conn2->conn1): %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		defer closer(conn1)
		_, err := io.Copy(conn2, conn1)
		if err != nil && err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
			log.Printf("Proxy error (conn1->conn2): %v", err)
		}
	}()

	wg.Wait()
	log.Println("Proxy finished for connection pair.")
}
