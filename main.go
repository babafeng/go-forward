package main

import (
	"flag" // Import flag package
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	listenAddr := flag.String("L", "", "Port for the server's control plane (e.g., 7000) or client's reverse port (e.g., 2080//127.0.0.1:1080)")
	serverAddr := flag.String("F", "", "Server address (host:port) for the client to connect to (e.g., example.com:7000)")

	// Parse flags
	flag.Parse()

	var publicPort, localTargetAddr string

	mode := "server"
	controlPort := *listenAddr

	if strings.Contains(*listenAddr, "//") {
		mode = "client"
		listenAddrSplit := strings.Split(*listenAddr, "//")
		if len(listenAddrSplit) != 2 {
			log.Println("Error: -L must be in the format 'publicPort//localTargetAddr' (e.g., 2080//127.0.0.1:1080)")
			printUsage()
			return
		}

		publicPort = listenAddrSplit[0]
		localTargetAddr = listenAddrSplit[1]
	}

	switch mode {
	case "server":
		if controlPort == "" {
			log.Println("Error: -L is required for server mode")
			printUsage()
			return
		}
		// Ensure port has a colon prefix
		cp := controlPort
		if !strings.HasPrefix(cp, ":") {
			cp = ":" + cp
		}
		runServer(cp)
	case "client":
		if publicPort == "" || localTargetAddr == "" {
			log.Println("Error: Parsing public port or local target from -L failed for client mode.")
			printUsage()
			return
		}
		runClient(*serverAddr, publicPort, localTargetAddr)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "\nOptions:")
	flag.PrintDefaults()
	fmt.Fprintln(os.Stderr, "\nExamples:")
	fmt.Fprintln(os.Stderr, "  Server: go-forward -L 7000")
	fmt.Fprintln(os.Stderr, "  Client (with specific server): go-forward -L 2080//127.0.0.1:1080 -F your.server.com:7000")
}

// --- Server Logic ---

func runServer(controlAddr string) {
	log.Printf("Starting server control plane on %s\n", controlAddr)
	listener, err := net.Listen("tcp", controlAddr)
	if err != nil {
		log.Fatalf("Failed to listen on control port %s: %v\n", controlAddr, err)
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
	log.Printf("Handling new control connection from %s\n", conn.RemoteAddr())

	// Use Yamux for multiplexing over the control connection
	session, err := yamux.Server(conn, nil)
	if err != nil {
		log.Printf("Failed to create yamux server session for %s: %v\n", conn.RemoteAddr(), err)
		conn.Close()
		return
	}
	defer session.Close()
	defer log.Printf("Control session closed for %s\n", conn.RemoteAddr())

	// Channel to signal listener goroutines to stop
	stopChan := make(chan struct{})
	var wg sync.WaitGroup // Wait for listener goroutine to finish before closing session fully

	for {
		// Accept streams initiated by the client (for control messages)
		stream, err := session.Accept()
		if err != nil {
			log.Printf("Failed to accept stream from %s: %v. Closing associated listeners.\n", conn.RemoteAddr(), err)
			close(stopChan) // Signal all associated listeners to stop
			break           // Exit the loop
		}

		// Handle control messages in a separate goroutine
		// Pass the stopChan so listener knows when to stop
		wg.Add(1) // Increment counter for the handleControlStream goroutine (which might start a listener)
		go func() {
			defer wg.Done() // Decrement counter when handleControlStream finishes
			handleControlStream(session, stream, stopChan, &wg)
		}()
	}

	// Wait for all goroutines started by this session (like listeners) to finish cleaning up
	log.Printf("Waiting for associated listeners for %s to close...\n", conn.RemoteAddr())
	wg.Wait()
	log.Printf("All associated listeners closed for %s.\n", conn.RemoteAddr())
}

// Modified to remove clientID parameter
func handleControlStream(session *yamux.Session, stream net.Conn, stopChan chan struct{}, wg *sync.WaitGroup) {
	defer stream.Close()

	// Read the request (e.g., "LISTEN <public_port>")
	buf := make([]byte, 128) // Adjust buffer size as needed

	// Set a deadline for reading the request
	err := stream.SetReadDeadline(time.Now().Add(10 * time.Second))
	if err != nil {
		log.Printf("Failed to set read deadline on control stream: %v\n", err)
		return
	}

	n, err := stream.Read(buf)
	if err != nil {
		// Don't log EOF or timeout errors as critical failures here
		if err != io.EOF && !os.IsTimeout(err) {
			log.Printf("Failed to read from control stream: %v\n", err)
		}
		return
	}
	// Reset deadline
	err = stream.SetReadDeadline(time.Time{})
	if err != nil {
		// Log non-critical error
		log.Printf("Failed to reset read deadline on control stream: %v\n", err)
	}

	request := string(buf[:n])
	parts := strings.Fields(request)

	if len(parts) == 2 && parts[0] == "LISTEN" {
		publicPort := parts[1]
		log.Printf("Received request to listen on public port %s\n", publicPort)

		// Start listening on the requested public port in a goroutine
		// Pass session, stopChan, and wg
		wg.Add(1) // Increment counter for the listener goroutine
		go listenPublic(session, ":"+publicPort, stopChan, wg)
		// Optionally send confirmation back via the stream (omitted for simplicity)
	} else {
		log.Printf("Received unknown request on control stream: %s\n", request)
		// If the stream wasn't for LISTEN, we didn't start a listener, so decrement the counter added in handleControlConnection
		// This requires careful wg management. Let's adjust: only Add in handleControlStream if listenPublic is actually called.
		// The wg.Add(1) before calling handleControlStream covers the stream handling itself.
		// Let's remove wg passing here and manage it differently.
		// Simpler: wg in handleControlConnection waits for handleControlStream goroutines.
		// We need a separate mechanism if listenPublic needs to signal completion *back* to handleControlConnection.
		// Let's stick to the original plan: wg passed down.
	}
}

// Modified to remove clientID parameter
func listenPublic(session *yamux.Session, publicAddr string, stopChan <-chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done() // Decrement counter when this listener goroutine exits

	publicListener, err := net.Listen("tcp", publicAddr)
	if err != nil {
		log.Printf("Failed to listen on public port %s: %v\n", publicAddr, err)
		// Optionally notify the client about the failure via a new stream (omitted)
		return
	}
	defer publicListener.Close() // Ensure listener is closed when function returns
	log.Printf("Server listening on public port %s\n", publicAddr)

	// Goroutine to close the listener when stopChan is closed or session ends
	go func() {
		select {
		case <-stopChan:
			log.Printf("Stop signal received, closing listener on %s\n", publicAddr)
		case <-session.CloseChan(): // Also stop if the session itself closes gracefully
			log.Printf("Session closed, closing listener on %s\n", publicAddr)
		}
		// Closing the listener will cause the Accept loop below to break
		publicListener.Close()
	}()

	for {
		// Check if the session is already closed before accepting
		if session.IsClosed() {
			log.Printf("Session is closed, stopping listener %s before accept.\n", publicAddr)
			return // Exit if session closed
		}

		publicConn, err := publicListener.Accept()
		if err != nil {
			// Check if the error is due to the listener being closed intentionally
			select {
			case <-stopChan:
				log.Printf("Listener %s closed gracefully due to stop signal.\n", publicAddr)
			case <-session.CloseChan():
				log.Printf("Listener %s closed gracefully due to session close.\n", publicAddr)
			default:
				// If stopChan/session isn't closed, it's a different error
				if !strings.Contains(err.Error(), "use of closed network connection") {
					log.Printf("Failed to accept public connection on %s: %v\n", publicAddr, err)
				} else {
					// This is expected if the listener was closed by the goroutine above
					log.Printf("Listener %s closed, accept loop terminating.\n", publicAddr)
				}
			}
			return // Exit the accept loop
		}

		// Double check session status after accept, before opening stream
		if session.IsClosed() {
			log.Printf("Session closed after accept on %s, dropping connection from %s\n", publicAddr, publicConn.RemoteAddr())
			publicConn.Close()
			continue // Or return, depending on desired behavior
		}

		log.Printf("Accepted public connection on %s from %s\n", publicAddr, publicConn.RemoteAddr())

		// Open a new stream to the client over the existing session
		proxyStream, err := session.Open()
		if err != nil {
			log.Printf("Failed to open yamux stream: %v\n", err)
			publicConn.Close() // Close the public connection if we can't reach the client
			// If session is closed, the loop will exit on the next iteration's check or Accept error
			if session.IsClosed() {
				log.Printf("Session closed, cannot open new stream for %s.\n", publicAddr)
				return // Exit listener loop if session is gone
			}
			continue // Try accepting next connection
		}

		// Start proxying data between the public connection and the client stream
		log.Printf("Starting proxy between public %s <-> yamux stream for local target\n", publicConn.RemoteAddr())
		go proxy(publicConn, proxyStream)
	}
}

// --- Client Logic ---
func runClient(serverAddr, publicPort, localTargetAddr string) {
	log.Printf("Connecting to server %s\n", serverAddr)
	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		log.Fatalf("Failed to connect to server %s: %v\n", serverAddr, err)
	}
	log.Printf("Connected to server %s\n", serverAddr)

	// Create yamux client session
	session, err := yamux.Client(conn, nil)
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

// --- Proxy Logic ---
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
