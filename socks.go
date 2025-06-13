package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync" // 新增导入
	"time"
)

// 限制并发连接数
var maxConcurrentConns = 100
var sem = make(chan struct{}, maxConcurrentConns)

// Modified signature to accept username and password
func local_socks_proxy(proxyListenAddr, username, password string) {
	// Address parsing is now done in main.go
	addr := proxyListenAddr

	if username != "" {
		log.Printf("Starting SOCKS5 proxy server on %s with authentication ENABLED\n", addr)
	} else {
		log.Printf("Starting SOCKS5 proxy server on %s with authentication DISABLED\n", addr)
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v\n", addr, err)
	}
	defer listener.Close()

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept client connection: %v\n", err)
			continue
		}
		log.Printf("Accepted SOCKS5 connection from %s\n", clientConn.RemoteAddr())
		select {
		case sem <- struct{}{}:
			go func() {
				defer func() {
					<-sem
				}()
				// Pass credentials to the handler
				handleSocks5Connection(clientConn, username, password)
			}()
		default:
			log.Printf("Too many concurrent connections, rejecting client %s\n", clientConn.RemoteAddr())
			clientConn.Close()
		}
	}
}

// 新增：使用 sync.Pool 复用缓冲区以降低内存分配次数
var bufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 512)
		return &b
	},
}

// Modified signature to accept username and password
func handleSocks5Connection(clientConn net.Conn, serverUser, serverPass string) {
	defer clientConn.Close()

	bufPtr := bufPool.Get().(*[]byte)
	defer bufPool.Put(bufPtr)
	buf := *bufPtr

	// --- 1. Method Selection ---
	// Read Version and NMETHODS
	// ... (same as before) ...
	n, err := clientConn.Read(buf[:2])
	if err != nil || n != 2 {
		log.Printf("Error reading SOCKS version/nmethods from %s: %v\n", clientConn.RemoteAddr(), err)
		return
	}
	ver := buf[0]
	nMethods := buf[1]
	if ver != 0x05 {
		log.Printf("Unsupported SOCKS version %d from %s\n", ver, clientConn.RemoteAddr())
		return
	}
	// ... (same read METHODS logic) ...
	if int(nMethods) > len(buf) {
		log.Printf("Too many methods requested by %s: %d\n", clientConn.RemoteAddr(), nMethods)
		return
	}
	n, err = io.ReadFull(clientConn, buf[:nMethods])
	if err != nil || n != int(nMethods) {
		log.Printf("Error reading SOCKS methods from %s: %v\n", clientConn.RemoteAddr(), err)
		return
	}

	// Determine selected method based on server config and client capabilities
	var selectedMethod byte = 0xFF // Default: No acceptable methods

	clientSupportsNoAuth := false
	clientSupportsUserPass := false
	for i := 0; i < int(nMethods); i++ {
		if buf[i] == 0x00 {
			clientSupportsNoAuth = true
		}
		if buf[i] == 0x02 {
			clientSupportsUserPass = true
		}
	}

	// Server requires auth
	if serverUser != "" {
		if clientSupportsUserPass {
			selectedMethod = 0x02
			log.Printf("Client %s supports User/Pass auth, selecting method 0x02\n", clientConn.RemoteAddr())
		} else {
			log.Printf("Client %s does not support required User/Pass auth\n", clientConn.RemoteAddr())
			// selectedMethod remains 0xFF
		}
	} else { // Server does not require auth
		if clientSupportsNoAuth {
			selectedMethod = 0x00
			log.Printf("Client %s supports No Auth, selecting method 0x00\n", clientConn.RemoteAddr())
		} else {
			log.Printf("Client %s does not support No Auth method (and server requires none)\n", clientConn.RemoteAddr())
			// selectedMethod remains 0xFF
		}
	}

	// Send server method selection
	_, err = clientConn.Write([]byte{0x05, selectedMethod})
	if err != nil {
		log.Printf("Error sending SOCKS method selection to %s: %v\n", clientConn.RemoteAddr(), err)
		return
	}

	// If no acceptable method, close connection
	if selectedMethod == 0xFF {
		log.Printf("No acceptable authentication method for client %s\n", clientConn.RemoteAddr())
		return
	}

	// --- 1.5. Authentication Sub-negotiation (if User/Pass selected) ---
	if selectedMethod == 0x02 {
		log.Printf("Performing User/Pass authentication for %s\n", clientConn.RemoteAddr())
		// Read username/password request (RFC 1929)
		// VER(1) ULEN(1) UNAME(ULEN) PLEN(1) PASSWD(PLEN)
		n, err = io.ReadFull(clientConn, buf[:2]) // Read VER, ULEN
		if err != nil || n != 2 {
			log.Printf("Auth error (reading ver/ulen) for %s: %v\n", clientConn.RemoteAddr(), err)
			return // Error or short read
		}
		authVer := buf[0]
		uLen := int(buf[1])
		if authVer != 0x01 { // Must be version 1 for username/password auth subnegotiation
			log.Printf("Invalid auth subnegotiation version %d for %s\n", authVer, clientConn.RemoteAddr())
			// Send failure response (using 0x01 for general failure, though spec doesn't define specific codes here)
			_, _ = clientConn.Write([]byte{0x01, 0x01})
			return
		}
		if uLen <= 0 || uLen > 255 {
			log.Printf("Invalid username length %d for %s\n", uLen, clientConn.RemoteAddr())
			_, _ = clientConn.Write([]byte{0x01, 0x01})
			return
		}

		// Read UNAME, PLEN
		n, err = io.ReadFull(clientConn, buf[:uLen+1]) // Read UNAME and PLEN
		if err != nil || n != (uLen+1) {
			log.Printf("Auth error (reading uname/plen) for %s: %v\n", clientConn.RemoteAddr(), err)
			return
		}
		clientUser := string(buf[:uLen])
		pLen := int(buf[uLen])
		if pLen <= 0 || pLen > 255 {
			log.Printf("Invalid password length %d for %s\n", pLen, clientConn.RemoteAddr())
			_, _ = clientConn.Write([]byte{0x01, 0x01})
			return
		}

		// Read PASSWD
		n, err = io.ReadFull(clientConn, buf[:pLen])
		if err != nil || n != pLen {
			log.Printf("Auth error (reading password) for %s: %v\n", clientConn.RemoteAddr(), err)
			return
		}
		clientPass := string(buf[:pLen])

		// Verify credentials
		authStatus := byte(0x01) // Default to failure
		if clientUser == serverUser && clientPass == serverPass {
			authStatus = 0x00 // Success
			log.Printf("Authentication successful for user '%s' from %s\n", clientUser, clientConn.RemoteAddr())
		} else {
			log.Printf("Authentication failed for user '%s' from %s\n", clientUser, clientConn.RemoteAddr())
		}

		// Send sub-negotiation response: VER(1) STATUS(1)
		_, err = clientConn.Write([]byte{0x01, authStatus})
		if err != nil {
			log.Printf("Error sending auth response to %s: %v\n", clientConn.RemoteAddr(), err)
			return
		}

		// If authentication failed, close connection
		if authStatus != 0x00 {
			return
		}
	}

	// --- 2. Request Processing ---
	// ... (rest of the function remains the same: read request, dial target, send reply, proxy data) ...
	// Read VER, CMD, RSV, ATYP
	n, err = io.ReadFull(clientConn, buf[:4])
	if err != nil || n != 4 {
		log.Printf("Error reading SOCKS request header from %s: %v\n", clientConn.RemoteAddr(), err)
		sendSocksReply(clientConn, 0x01, nil) // General SOCKS server failure
		return
	}
	// ... (rest of request processing, dialing, replying, proxying) ...
	ver = buf[0]
	cmd := buf[1]
	// rsv := buf[2] // Reserved, ignore
	atyp := buf[3]

	if ver != 0x05 {
		log.Printf("Invalid SOCKS version in request from %s: %d\n", clientConn.RemoteAddr(), ver)
		sendSocksReply(clientConn, 0x01, nil)
		return
	}

	if cmd != 0x01 { // Only support CONNECT command
		log.Printf("Unsupported SOCKS command %d from %s\n", cmd, clientConn.RemoteAddr())
		sendSocksReply(clientConn, 0x07, nil) // Command not supported
		return
	}

	var targetHost string
	var targetPort uint16

	// Read DST.ADDR
	switch atyp {
	case 0x01: // IPv4
		n, err = io.ReadFull(clientConn, buf[:4]) // Read 4 bytes for IPv4
		if err != nil || n != 4 {
			log.Printf("Error reading IPv4 address from %s: %v\n", clientConn.RemoteAddr(), err)
			sendSocksReply(clientConn, 0x01, nil)
			return
		}
		targetHost = net.IP(buf[:4]).String()
	case 0x03: // Domain Name
		n, err = io.ReadFull(clientConn, buf[:1]) // Read 1 byte for domain length
		if err != nil || n != 1 {
			log.Printf("Error reading domain length from %s: %v\n", clientConn.RemoteAddr(), err)
			sendSocksReply(clientConn, 0x01, nil)
			return
		}
		domainLen := int(buf[0])
		if domainLen > len(buf) { // Prevent reading too much
			log.Printf("Domain length too long from %s: %d\n", clientConn.RemoteAddr(), domainLen)
			sendSocksReply(clientConn, 0x01, nil)
			return
		}
		n, err = io.ReadFull(clientConn, buf[:domainLen]) // Read domain name
		if err != nil || n != domainLen {
			log.Printf("Error reading domain name from %s: %v\n", clientConn.RemoteAddr(), err)
			sendSocksReply(clientConn, 0x01, nil)
			return
		}
		targetHost = string(buf[:domainLen])
	case 0x04: // IPv6
		n, err = io.ReadFull(clientConn, buf[:16]) // Read 16 bytes for IPv6
		if err != nil || n != 16 {
			log.Printf("Error reading IPv6 address from %s: %v\n", clientConn.RemoteAddr(), err)
			sendSocksReply(clientConn, 0x01, nil)
			return
		}
		targetHost = net.IP(buf[:16]).String()
	default:
		log.Printf("Unsupported address type %d from %s\n", atyp, clientConn.RemoteAddr())
		sendSocksReply(clientConn, 0x0, nil) // Address type not supported
		return
	}

	// Read DST.PORT (2 bytes, network byte order)
	n, err = io.ReadFull(clientConn, buf[:2])
	if err != nil || n != 2 {
		log.Printf("Error reading target port from %s: %v\n", clientConn.RemoteAddr(), err)
		sendSocksReply(clientConn, 0x01, nil)
		return
	}
	targetPort = uint16(buf[0])<<8 | uint16(buf[1])

	// targetHost 变量此时包含域名（如果 atyp == 0x03）或 IP 地址
	targetAddr := net.JoinHostPort(targetHost, fmt.Sprintf("%d", targetPort)) // 用于 Dial 的地址

	// 调整日志格式以更清晰地显示主机信息
	var hostType string
	switch atyp {
	case 0x01:
		hostType = "IPv4"
	case 0x03:
		hostType = "Domain" // 明确是域名
	case 0x04:
		hostType = "IPv6"
	default:
		hostType = "Unknown"
	}
	// 注意：这里记录的 Host 是客户端实际发送过来的地址。
	// 如果客户端发送的是 IP 地址 (ATYP=0x01 或 0x04)，则 targetHost 将是 IP 地址。
	// 如果客户端发送的是域名 (ATYP=0x03)，则 targetHost 将是域名。
	log.Printf("SOCKS5 client %s requests connection to Host: [%s] (%s), Port: [%d] (Dial Addr: %s)\n",
		clientConn.RemoteAddr(),
		targetHost, // 这里会显示客户端发送的域名或 IP
		hostType,   // 显示客户端发送的类型
		targetPort,
		targetAddr) // 显示最终用于连接的地址

	// --- 3. Establish Target Connection ---
	targetConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second) // Add timeout
	if err != nil {
		log.Printf("Failed to connect to target %s for %s: %v\n", targetAddr, clientConn.RemoteAddr(), err)
		// Map network errors to SOCKS reply codes (simplified)
		replyCode := 0x01 // General SOCKS server failure
		if strings.Contains(err.Error(), "refused") {
			replyCode = 0x05 // Connection refused
		} else if strings.Contains(err.Error(), "network is unreachable") {
			replyCode = 0x03 // Network unreachable
		} else if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
			replyCode = 0x04 // Host unreachable (using for timeout)
		}
		sendSocksReply(clientConn, byte(replyCode), nil)
		return
	}
	defer targetConn.Close()
	log.Printf("Connected to target %s for %s\n", targetAddr, clientConn.RemoteAddr())

	// --- 4. Send Reply ---
	// Get the local address the target connection is using (might be needed for BIND, but send 0s for CONNECT)
	// For CONNECT, BND.ADDR and BND.PORT can be the server's address/port listening for the client,
	// or more commonly, just 0.0.0.0:0 if the info isn't readily available or needed.
	// We'll send 0.0.0.0:0 for simplicity.
	bindAddr := net.IPv4(0, 0, 0, 0)
	bindPort := 0

	err = sendSocksReply(clientConn, 0x00, &net.TCPAddr{IP: bindAddr, Port: bindPort})
	if err != nil {
		log.Printf("Error sending SOCKS success reply to %s: %v\n", clientConn.RemoteAddr(), err)
		return
	}

	// --- 5. Proxy Data ---
	log.Printf("Starting proxy between %s <-> %s\n", clientConn.RemoteAddr(), targetAddr)
	// Assuming proxy function is defined elsewhere (e.g., reverse.go)
	proxy(clientConn, targetConn)
	log.Printf("Proxy finished between %s <-> %s\n", clientConn.RemoteAddr(), targetAddr)
}

// sendSocksReply sends a SOCKS5 reply message.
// REP: Reply field code (see RFC 1928 Section 6)
// BND.ADDR, BND.PORT: The address and port the server bound to (can be nil for failures or 0.0.0.0:0 for success)
func sendSocksReply(conn net.Conn, rep byte, bindAddr *net.TCPAddr) error {
	reply := []byte{
		0x05, // VER
		rep,  // REP
		0x00, // RSV
	}

	addrBytes := []byte{0x00, 0x00, 0x00, 0x00} // Default: IPv4 0.0.0.0
	portBytes := []byte{0x00, 0x00}             // Default: Port 0
	atyp := byte(0x01)                          // Default: IPv4

	if bindAddr != nil && bindAddr.IP != nil {
		ipv4 := bindAddr.IP.To4()
		if ipv4 != nil {
			atyp = 0x01
			addrBytes = []byte(ipv4)
		} else {
			ipv6 := bindAddr.IP.To16()
			if ipv6 != nil {
				atyp = 0x04
				addrBytes = []byte(ipv6)
			} else {
				// Should not happen with net.TCPAddr, but handle defensively
				log.Printf("Warning: Could not determine bind address type for reply")
				rep = 0x01 // General failure if address is weird
			}
		}
		portBytes[0] = byte(bindAddr.Port >> 8)
		portBytes[1] = byte(bindAddr.Port & 0xFF)
	}

	reply = append(reply, atyp)
	reply = append(reply, addrBytes...)
	reply = append(reply, portBytes...)

	_, err := conn.Write(reply)
	return err
}
