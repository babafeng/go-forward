// WARNING: This is a highly simplified proof-of-concept Go implementation
// mirroring the basic Python example. It lacks many crucial features found
// in production tools like frp (security, reliability, error handling,
// multiplexing, UDP, HTTP proxying, etc.).
// DO NOT USE IN PRODUCTION ENVIRONMENTS. Use the official frp project instead.

package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

// --- Configuration ---
const (
	// Shared Ports
	defaultControlPort = 7000
	defaultDataPort    = 7001
	defaultPublicPort  = 6000

	// Client Specific
	defaultLocalHost = "127.0.0.1"
	defaultLocalPort = 8080

	bufferSize         = 4096
	heartbeatInterval  = 30 * time.Second
	connectionTimeout  = 10 * time.Second // Timeout for establishing connections
	ioTimeout          = 15 * time.Second // Timeout for idle I/O during piping or waiting
	retryDelay         = 10 * time.Second // Delay before client retries connection
	pendingDataTimeout = 15 * time.Second // How long server waits for client data conn
)

// --- Global Server State (Protected by Mutex) ---
var (
	serverControlConn net.Conn
	controlConnMutex  sync.Mutex
	// Maps a user connection to a channel that will receive the client's data connection
	pendingDataConns map[string]chan net.Conn // Key: userConn.RemoteAddr().String()
	pendingMutex     sync.Mutex
)

// --- Main Entry Point ---
func main() {
	mode := flag.String("mode", "", "Run mode: 'server' or 'client'")
	serverAddr := flag.String("server", "YOUR_PUBLIC_SERVER_IP", "Server address (required for client)") // Client needs this
	controlPort := flag.Int("cport", defaultControlPort, "Control port")
	dataPort := flag.Int("dport", defaultDataPort, "Data port")
	publicPort := flag.Int("pport", defaultPublicPort, "Public access port (server)")
	localHost := flag.String("lhost", defaultLocalHost, "Local service host (client)")
	localPort := flag.Int("lport", defaultLocalPort, "Local service port (client)")

	flag.Parse()

	if *mode == "" {
		log.Fatal("Error: -mode ('server' or 'client') is required")
	}

	// Setup context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle termination signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		log.Printf("Received signal: %v. Shutting down...", sig)
		cancel() // Trigger context cancellation
	}()

	// Initialize server state if needed
	if *mode == "server" {
		pendingDataConns = make(map[string]chan net.Conn)
	}

	log.Printf("Starting in %s mode", *mode)

	switch *mode {
	case "server":
		if err := runServer(ctx, *controlPort, *publicPort, *dataPort); err != nil {
			log.Fatalf("Server error: %v", err)
		}
	case "client":
		if *serverAddr == "YOUR_PUBLIC_SERVER_IP" || *serverAddr == "" {
			log.Fatal("Error: -server address is required for client mode")
		}
		runClient(ctx, *serverAddr, *controlPort, *dataPort, *localHost, *localPort)
	default:
		log.Fatalf("Invalid mode: %s", *mode)
	}

	log.Println("Shutdown complete.")
}

// --- Data Piping Utility ---
func pipeData(ctx context.Context, conn1, conn2 net.Conn, name1, name2 string) {
	var wg sync.WaitGroup
	wg.Add(2)

	closer := func(err error) {
		// Try closing both connections on any error or completion
		conn1.Close()
		conn2.Close()
		if err != nil && err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
			log.Printf("[Pipe %s<->%s] Error during copy: %v", name1, name2, err)
		}
	}

	copyData := func(dst net.Conn, src net.Conn, srcName, dstName string) {
		defer wg.Done()
		// Apply a deadline for copying to prevent leaks on idle connections
		if ioTimeout > 0 {
			src.SetReadDeadline(time.Now().Add(ioTimeout))
		}
		_, err := io.Copy(dst, src)
		if err != nil {
			// If it's just a timeout, renew it if context isn't done
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() && ctx.Err() == nil {
				if ioTimeout > 0 {
					src.SetReadDeadline(time.Now().Add(ioTimeout)) // Renew deadline
				}
				// Re-attempt copy or handle differently? For simplicity, we exit.
				log.Printf("[Pipe %s->%s] Read timeout, closing pipe direction.", srcName, dstName)
			} else {
				closer(err) // Close on non-timeout errors or if context is cancelled
			}
		} else {
			closer(nil) // Close on successful EOF
		}

	}

	log.Printf("[Pipe %s<->%s] Starting data transfer", name1, name2)
	go copyData(conn1, conn2, name2, name1) // Copy conn2 -> conn1
	go copyData(conn2, conn1, name1, name2) // Copy conn1 -> conn2

	wg.Wait() // Wait for both copy directions to finish
	log.Printf("[Pipe %s<->%s] Transfer finished", name1, name2)
}

// --- Server Implementation ---

func runServer(ctx context.Context, controlPort, publicPort, dataPort int) error {
	var wg sync.WaitGroup

	// Listener function
	listen := func(port int, handler func(context.Context, net.Conn)) error {
		addr := fmt.Sprintf("0.0.0.0:%d", port)
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("failed to listen on %s: %w", addr, err)
		}
		defer listener.Close()
		log.Printf("Server listening on %s", addr)

		// Goroutine to close listener when context is cancelled
		go func() {
			<-ctx.Done()
			listener.Close()
		}()

		// Accept loop
		for {
			conn, err := listener.Accept()
			if err != nil {
				// Check if the error is due to context cancellation / listener being closed
				select {
				case <-ctx.Done():
					log.Printf("Listener on port %d stopped due to context cancellation.", port)
					return nil
				default:
					log.Printf("Error accepting connection on port %d: %v", port, err)
					// Don't return, maybe temporary error? Or maybe check specific errors
					if opErr, ok := err.(*net.OpError); ok && !opErr.Temporary() {
						return fmt.Errorf("non-temporary accept error on port %d: %w", port, err)
					}
					continue // Try again on temporary errors
				}
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer c.Close() // Ensure connection is closed when handler exits
				handler(ctx, c)
			}(conn)
		}
	}

	// Start listeners concurrently
	errChan := make(chan error, 3) // Channel to collect errors from listeners

	go func() { errChan <- listen(controlPort, handleControlConnection) }()
	go func() { errChan <- listen(publicPort, handlePublicConnection) }()
	go func() { errChan <- listen(dataPort, handleDataConnection) }()

	// Wait for context cancellation or a listener error
	select {
	case <-ctx.Done():
		log.Println("Server context cancelled, waiting for connections to finish...")
		// Wait for active connections to finish (optional timeout)
		// wg.Wait() // Note: This might block shutdown indefinitely if connections hang
		return nil // Normal shutdown
	case err := <-errChan:
		// If one listener fails critically, trigger shutdown for others
		// cancel() // Trigger context cancellation via main() defer or explicitly here
		return err // Return the critical error
	}
}

func handleControlConnection(ctx context.Context, conn net.Conn) {
	addr := conn.RemoteAddr().String()
	log.Printf("[Server Ctrl] Control connection accepted from %s", addr)

	controlConnMutex.Lock()
	if serverControlConn != nil {
		log.Printf("[Server Ctrl] Another client tried to connect from %s. Closing old connection from %s.", addr, serverControlConn.RemoteAddr().String())
		serverControlConn.Close() // Close the previous one
	}
	serverControlConn = conn
	controlConnMutex.Unlock()

	defer func() {
		controlConnMutex.Lock()
		if serverControlConn == conn { // Make sure we are closing the one we reference
			serverControlConn = nil
			log.Printf("[Server Ctrl] Cleaned up control connection reference for %s", addr)
		}
		controlConnMutex.Unlock()
		conn.Close() // Ensure it's closed on exit
		log.Printf("[Server Ctrl] Control connection closed for %s", addr)
	}()

	reader := bufio.NewReader(conn)
	for {
		select {
		case <-ctx.Done():
			log.Printf("[Server Ctrl] Context cancelled, closing control conn %s", addr)
			return
		default:
			// Add read deadline to detect dead connections
			conn.SetReadDeadline(time.Now().Add(heartbeatInterval + ioTimeout))
			cmd, err := reader.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					log.Printf("[Server Ctrl] Control connection closed by client %s", addr)
				} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					log.Printf("[Server Ctrl] Control connection %s timed out waiting for command/ping.", addr)
				} else {
					log.Printf("[Server Ctrl] Error reading from control connection %s: %v", addr, err)
				}
				return // Exit handler
			}

			cmd = strings.TrimSpace(cmd)
			//log.Printf("[Server Ctrl] Received command from %s: %s", addr, cmd)
			if cmd == "PING" {
				//log.Printf("[Server Ctrl] Responding PONG to %s", addr)
				conn.SetWriteDeadline(time.Now().Add(ioTimeout))
				_, err := conn.Write([]byte("PONG\n"))
				if err != nil {
					log.Printf("[Server Ctrl] Error writing PONG to %s: %v", addr, err)
					return // Exit handler
				}
			} else if cmd != "" {
				log.Printf("[Server Ctrl] Received unknown command from %s: %s", addr, cmd)
			}
			// Reset read deadline after successful read
			conn.SetReadDeadline(time.Time{}) // Remove deadline or set to zero value
		}
	}
}

func handlePublicConnection(ctx context.Context, userConn net.Conn) {
	userAddr := userConn.RemoteAddr().String()
	log.Printf("[Server Public] Public connection accepted from %s", userAddr)

	controlConnMutex.Lock()
	ctrlConn := serverControlConn // Get current control connection
	controlConnMutex.Unlock()

	if ctrlConn == nil {
		log.Printf("[Server Public] No client control connection available for %s. Closing.", userAddr)
		userConn.Close()
		return
	}

	// Channel to wait for the client's data connection
	dataConnChan := make(chan net.Conn, 1) // Buffered channel size 1

	pendingMutex.Lock()
	pendingDataConns[userAddr] = dataConnChan // Register interest
	pendingMutex.Unlock()

	defer func() { // Cleanup pending entry
		pendingMutex.Lock()
		delete(pendingDataConns, userAddr)
		pendingMutex.Unlock()
		userConn.Close() // Ensure user conn is closed if pipe doesn't start
		log.Printf("[Server Public] Cleaned up pending state for %s", userAddr)
	}()

	// Notify the client via the control connection
	log.Printf("[Server Public] Notifying client about new connection from %s", userAddr)
	ctrlConn.SetWriteDeadline(time.Now().Add(ioTimeout))
	_, err := ctrlConn.Write([]byte("NEW_CONNECTION\n"))
	if err != nil {
		log.Printf("[Server Public] Failed to notify client for %s: %v", userAddr, err)
		return
	}

	// Wait for the client to establish the data connection
	log.Printf("[Server Public] Waiting for data connection from client for user %s...", userAddr)
	select {
	case clientDataConn, ok := <-dataConnChan:
		if !ok {
			log.Printf("[Server Public] Data connection channel closed unexpectedly for %s", userAddr)
			return
		}
		if clientDataConn == nil { // Should not happen with current logic, but check
			log.Printf("[Server Public] Received nil data connection for %s", userAddr)
			return
		}
		log.Printf("[Server Public] Received data connection %s for user %s. Starting pipe.",
			clientDataConn.RemoteAddr().String(), userAddr)
		// Start piping data between user and client's data connection
		pipeData(ctx, userConn, clientDataConn, fmt.Sprintf("user_%s", userAddr), "client_data") // Blocks until pipe finishes

	case <-time.After(pendingDataTimeout):
		log.Printf("[Server Public] Timed out waiting for client data connection for %s", userAddr)
		// Optionally notify client control connection? (More complex)

	case <-ctx.Done():
		log.Printf("[Server Public] Context cancelled while waiting for data connection for %s", userAddr)
	}
}

func handleDataConnection(ctx context.Context, clientDataConn net.Conn) {
	clientAddr := clientDataConn.RemoteAddr().String()
	log.Printf("[Server Data] Potential data connection accepted from %s", clientAddr)

	// This matching logic is simplistic and potentially racy.
	// A better approach would use unique IDs generated by the server
	// sent to the client, which the client includes when making the data conn.
	// For this example, we find the *first* pending channel.
	var targetChan chan net.Conn
	var userAddr string

	pendingMutex.Lock()
	// Iterate map to find a waiting channel (order isn't guaranteed)
	for addr, ch := range pendingDataConns {
		// Check if channel is still valid (not closed by timeout/cleanup)
		// We can't directly check if it's closed without reading,
		// so we rely on the fact handlePublicConnection cleans up on timeout.
		// Try a non-blocking send? No, just pass it. handlePublic will timeout if needed.
		userAddr = addr
		targetChan = ch
		break // Found one
	}
	if targetChan != nil {
		// Remove it immediately while still holding the lock to prevent reuse
		delete(pendingDataConns, userAddr)
	}
	pendingMutex.Unlock()

	if targetChan != nil {
		log.Printf("[Server Data] Matched data conn %s to pending user %s", clientAddr, userAddr)
		select {
		case targetChan <- clientDataConn:
			log.Printf("[Server Data] Sent data conn %s to handler for user %s", clientAddr, userAddr)
			// The handlePublicConnection goroutine will now take ownership of clientDataConn
			// Do not close clientDataConn here.
		case <-time.After(1 * time.Second): // Short timeout for channel send
			log.Printf("[Server Data] Failed to send data conn %s to handler (timeout) for user %s", clientAddr, userAddr)
			clientDataConn.Close()
		case <-ctx.Done():
			log.Printf("[Server Data] Context cancelled, closing data conn %s for user %s", clientAddr, userAddr)
			clientDataConn.Close()
		}
	} else {
		log.Printf("[Server Data] No pending user request found for data connection %s. Closing.", clientAddr)
		clientDataConn.Close()
	}
}

// --- Client Implementation ---

func runClient(ctx context.Context, serverAddr string, controlPort, dataPort int, localHost string, localPort int) {
	serverControlAddr := fmt.Sprintf("%s:%d", serverAddr, controlPort)
	serverDataAddr := fmt.Sprintf("%s:%d", serverAddr, dataPort)
	localServiceAddr := fmt.Sprintf("%s:%d", localHost, localPort)

	for {
		select {
		case <-ctx.Done():
			log.Println("[Client] Context cancelled, exiting client loop.")
			return
		default:
			log.Printf("[Client] Attempting to connect to server control port %s", serverControlAddr)
			controlConn, err := net.DialTimeout("tcp", serverControlAddr, connectionTimeout)
			if err != nil {
				log.Printf("[Client] Failed to connect to control port: %v. Retrying in %v...", err, retryDelay)
				select {
				case <-time.After(retryDelay):
					continue // Retry connection
				case <-ctx.Done():
					log.Println("[Client] Context cancelled during retry delay.")
					return
				}
			}

			log.Printf("[Client] Control connection established to %s", serverControlAddr)
			// Create a new context for this connection session, linked to the main context
			sessionCtx, sessionCancel := context.WithCancel(ctx)

			// Run command handler in a goroutine
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer sessionCancel() // Cancel session context when handler exits
				defer controlConn.Close()
				handleServerCommands(sessionCtx, controlConn, serverDataAddr, localServiceAddr)
				log.Println("[Client] Command handler goroutine finished.")
			}()

			// Wait for the session context to be cancelled (either by main ctx or handler exit)
			<-sessionCtx.Done()
			log.Println("[Client] Session finished. Cleaning up.")
			// Ensure connection is closed if handler didn't close it
			controlConn.Close()
			// Wait for the handler goroutine to fully finish
			wg.Wait()

			// Check if main context is cancelled before retrying
			if ctx.Err() != nil {
				log.Println("[Client] Main context cancelled, stopping retry loop.")
				return
			}

			log.Printf("[Client] Disconnected or handler finished. Retrying connection in %v...", retryDelay)
			select {
			case <-time.After(retryDelay):
				// Continue loop
			case <-ctx.Done():
				log.Println("[Client] Main context cancelled during post-session retry delay.")
				return
			}
		}
	}
}

func handleServerCommands(ctx context.Context, controlConn net.Conn, serverDataAddr, localServiceAddr string) {
	reader := bufio.NewReader(controlConn)
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("[Client Handler] Context cancelled.")
			return
		case <-ticker.C:
			// Send heartbeat
			// log.Println("[Client Handler] Sending PING")
			controlConn.SetWriteDeadline(time.Now().Add(ioTimeout))
			_, err := controlConn.Write([]byte("PING\n"))
			if err != nil {
				log.Printf("[Client Handler] Failed to send PING: %v", err)
				return // Exit handler, triggers reconnect in runClient
			}
		default:
			// Check for commands from server (with timeout)
			controlConn.SetReadDeadline(time.Now().Add(1 * time.Second)) // Short deadline for non-blocking check
			cmd, err := reader.ReadString('\n')

			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					// This is expected, just means no command received yet
					controlConn.SetReadDeadline(time.Time{}) // Clear deadline until next check/heartbeat
					continue                                 // Go back to select
				}
				if err == io.EOF {
					log.Println("[Client Handler] Server closed control connection.")
				} else {
					log.Printf("[Client Handler] Error reading control connection: %v", err)
				}
				return // Exit handler, triggers reconnect
			}
			controlConn.SetReadDeadline(time.Time{}) // Clear deadline after successful read

			cmd = strings.TrimSpace(cmd)
			// log.Printf("[Client Handler] Received command: %s", cmd)

			switch cmd {
			case "PONG":
				// log.Println("[Client Handler] Received PONG")
				// Heartbeat acknowledged
			case "NEW_CONNECTION":
				log.Println("[Client Handler] Received NEW_CONNECTION request.")
				// Handle in a new goroutine to avoid blocking command loop
				go handleNewConnectionRequest(ctx, serverDataAddr, localServiceAddr)
			case "":
				// Ignore empty lines potentially caused by extra newlines
			default:
				log.Printf("[Client Handler] Received unknown command: %s", cmd)
			}
		}
	}
}

func handleNewConnectionRequest(ctx context.Context, serverDataAddr, localServiceAddr string) {
	log.Printf("[Client NewConn] Dialing local service %s", localServiceAddr)
	localConn, err := net.DialTimeout("tcp", localServiceAddr, connectionTimeout)
	if err != nil {
		log.Printf("[Client NewConn] Failed to connect to local service %s: %v", localServiceAddr, err)
		// Maybe notify server control? (Simplistic: do nothing)
		return
	}
	defer localConn.Close()
	log.Printf("[Client NewConn] Connected to local service %s", localServiceAddr)

	log.Printf("[Client NewConn] Dialing server data port %s", serverDataAddr)
	serverDataConn, err := net.DialTimeout("tcp", serverDataAddr, connectionTimeout)
	if err != nil {
		log.Printf("[Client NewConn] Failed to connect to server data port %s: %v", serverDataAddr, err)
		return
	}
	defer serverDataConn.Close()
	log.Printf("[Client NewConn] Connected to server data port %s", serverDataAddr)

	// Start piping data
	log.Println("[Client NewConn] Starting data pipe")
	pipeData(ctx, serverDataConn, localConn, "server_data", fmt.Sprintf("local_%s", localServiceAddr))
	log.Println("[Client NewConn] Data pipe finished.")
}
