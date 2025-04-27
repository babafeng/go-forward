package main

import (
	"bytes" // <-- 添加 bytes 包
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
	"golang.org/x/crypto/ssh" // <-- 添加 SSH 包
)

// --- 密钥占位符 ---
// !! 将下面的字符串替换为您实际的 PEM 格式密钥 !!

const serverPrivateKeyPEM = `
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDmbi7+kDZfMcdxwFMbcOYcOfs2T+qqk97YHaSxzqiWngAAAJAz90T6M/dE
+gAAAAtzc2gtZWQyNTUxOQAAACDmbi7+kDZfMcdxwFMbcOYcOfs2T+qqk97YHaSxzqiWng
AAAEBXCND8BR3Hg6wYZEc5Jzc4B42ar5ERdK/V9NoTE3IaXuZuLv6QNl8xx3HAUxtw5hw5
+zZP6qqT3tgdpLHOqJaeAAAACnJvb3RAQXBwbGUBAgM=
-----END OPENSSH PRIVATE KEY-----
`

const clientPrivateKeyPEM = `
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDmbi7+kDZfMcdxwFMbcOYcOfs2T+qqk97YHaSxzqiWngAAAJAz90T6M/dE
+gAAAAtzc2gtZWQyNTUxOQAAACDmbi7+kDZfMcdxwFMbcOYcOfs2T+qqk97YHaSxzqiWng
AAAEBXCND8BR3Hg6wYZEc5Jzc4B42ar5ERdK/V9NoTE3IaXuZuLv6QNl8xx3HAUxtw5hw5
+zZP6qqT3tgdpLHOqJaeAAAACnJvb3RAQXBwbGUBAgM=
-----END OPENSSH PRIVATE KEY-----
`

const authorizedClientKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOZuLv6QNl8xx3HAUxtw5hw5+zZP6qqT3tgdpLHOqJae root@Apple"

// --- SSH 认证逻辑 ---
// authenticateClient 验证客户端公钥是否与 authorizedClientKey 匹配
func authenticateClient(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	log.Printf("Client %s (%s) attempting auth with public key type %s fingerprint %s\n",
		conn.RemoteAddr(), conn.ClientVersion(), key.Type(), ssh.FingerprintSHA256(key))

	// 解析预期的授权公钥
	authorizedPubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedClientKey))
	if err != nil {
		log.Printf("ERROR: Failed to parse authorizedClientKey: %v", err)
		// 拒绝连接，因为服务器配置错误
		return nil, fmt.Errorf("internal server error: could not parse authorized key")
	}

	// 比较提供的密钥和授权的密钥
	if bytes.Equal(key.Marshal(), authorizedPubKey.Marshal()) {
		log.Printf("Client public key AUTHORIZED for %s\n", conn.RemoteAddr())
		// 可以选择性地设置权限
		// perms := &ssh.Permissions{
		//     CriticalOptions: map[string]string{
		//         "user": conn.User(),
		//     },
		// }
		// return perms, nil
		return nil, nil // 授权成功
	}

	log.Printf("Client public key REJECTED for %s\n", conn.RemoteAddr())
	return nil, fmt.Errorf("public key rejected")
}

// --- Server Logic ---
func runServer(controlAddr string) {
	addr := controlAddr
	if !strings.HasPrefix(addr, ":") {
		addr = ":" + addr
	}

	// 1. 解析服务器私钥 (使用 ParseRawPrivateKey)
	serverKey, err := ssh.ParseRawPrivateKey([]byte(serverPrivateKeyPEM)) // <--- 修改这里
	if err != nil {
		log.Fatalf("Failed to parse server private key: %v\nEnsure serverPrivateKeyPEM is correctly set and is in OpenSSH format.", err) // <--- 修改错误信息
	}
	serverSigner, err := ssh.NewSignerFromKey(serverKey) // <--- 从解析后的 key 创建 signer
	if err != nil {
		log.Fatalf("Failed to create signer from server private key: %v", err)
	}
	log.Println("Parsed server private key.")

	// 2. 配置 SSH 服务器 - 启用公钥认证
	sshConfig := &ssh.ServerConfig{
		PublicKeyCallback: authenticateClient, // <--- 设置公钥认证回调
	}
	sshConfig.AddHostKey(serverSigner)

	log.Printf("Starting server control plane on %s (SSH enabled, Public Key Auth required)\n", addr)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to listen on control port %s: %v\n", addr, err)
	}
	defer listener.Close()

	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			// ... existing error handling ...
			log.Printf("Failed to accept raw TCP connection: %v\n", err)
			continue
		}
		log.Printf("Accepted raw TCP connection from %s\n", tcpConn.RemoteAddr())

		// 启动 goroutine 处理单个连接的 SSH 握手和通道接受
		go func(conn net.Conn) {
			// 3. 执行 SSH 握手 (进行公钥认证)
			sshConn, chans, reqs, err := ssh.NewServerConn(conn, sshConfig)
			if err != nil {
				log.Printf("Failed SSH handshake/auth from %s: %v\n", conn.RemoteAddr(), err)
				conn.Close()
				return
			}
			// 认证成功
			log.Printf("SSH handshake and client authentication successful with %s (%s)\n",
				sshConn.RemoteAddr(), sshConn.ClientVersion()) // 简化日志，因为权限可能为 nil

			// 丢弃全局请求
			go ssh.DiscardRequests(reqs)

			// 4. 等待客户端打开 "yamux" 通道
			log.Printf("Waiting for 'yamux' channel from %s\n", sshConn.RemoteAddr())
			select {
			case newChannel := <-chans:
				if newChannel == nil {
					log.Printf("SSH connection closed before channel open from %s\n", sshConn.RemoteAddr())
					return
				}
				// 检查通道类型
				if newChannel.ChannelType() != "yamux" {
					log.Printf("Rejecting unexpected channel type '%s' from %s\n", newChannel.ChannelType(), sshConn.RemoteAddr())
					newChannel.Reject(ssh.UnknownChannelType, "expected 'yamux' channel")
					sshConn.Close()
					return
				}

				// 接受通道
				channel, requests, err := newChannel.Accept()
				if err != nil {
					log.Printf("Failed to accept 'yamux' channel from %s: %v\n", sshConn.RemoteAddr(), err)
					sshConn.Close()
					return
				}
				log.Printf("Accepted 'yamux' channel from %s\n", sshConn.RemoteAddr())
				go ssh.DiscardRequests(requests) // 丢弃此通道上的请求

				// 5. 将 SSH 通道传递给处理程序
				handleControlConnection(channel, sshConn.RemoteAddr()) // 传递 channel

			case <-time.After(30 * time.Second): // 添加超时
				log.Printf("Timeout waiting for 'yamux' channel from %s\n", sshConn.RemoteAddr())
				sshConn.Close()
			}
		}(tcpConn)
	}
}

// handleControlConnection 现在接受 ssh.Channel 和远端地址
func handleControlConnection(channel ssh.Channel, remoteAddr net.Addr) { // <--- 修改参数类型
	log.Printf("Handling new control connection via SSH channel from %s\n", remoteAddr)

	// 使用 Yamux 在 SSH 通道上进行多路复用
	session, err := yamux.Server(channel, nil) // <--- 使用 channel
	if err != nil {
		log.Printf("Failed to create yamux server session over SSH channel for %s: %v\n", remoteAddr, err)
		channel.Close()
		return
	}
	defer session.Close()
	defer log.Printf("Control session closed for %s\n", remoteAddr)

	// ... (内部逻辑与之前 SSH 版本相同, 使用 remoteAddr 记录日志) ...
	// Channel to signal listener goroutines to stop
	stopChan := make(chan struct{})
	var wg sync.WaitGroup // Wait for listener goroutine to finish before closing session fully

	for {
		// Accept streams initiated by the client (for control messages)
		stream, err := session.Accept()
		if err != nil {
			// 检查错误是否因为底层 SSH 通道关闭
			if err == io.EOF || strings.Contains(err.Error(), "session closed") || strings.Contains(err.Error(), "connection reset by peer") || strings.Contains(err.Error(), "broken pipe") || strings.Contains(err.Error(), "EOF") {
				log.Printf("Yamux session closed for %s, likely due to SSH channel closure. Closing associated listeners.\n", remoteAddr)
			} else {
				log.Printf("Failed to accept yamux stream from %s: %v. Closing associated listeners.\n", remoteAddr, err)
			}
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
	log.Printf("Waiting for associated listeners for %s to close...\n", remoteAddr)
	wg.Wait()
	log.Printf("All associated listeners closed for %s.\n", remoteAddr)
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
		listenPublic(session, ":"+publicPort, stopChan, wg)
		// Optionally send confirmation back via the stream (omitted for simplicity)
	} else {
		log.Printf("Received unknown request on control stream: %s\n", request)
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
	log.Printf("Connecting to server %s (SSH enabled)\n", serverAddr)

	// 0. 解析客户端私钥 (使用 ParseRawPrivateKey)
	clientKey, err := ssh.ParseRawPrivateKey([]byte(clientPrivateKeyPEM)) // <--- 修改这里
	if err != nil {
		log.Fatalf("Failed to parse client private key: %v\nEnsure clientPrivateKeyPEM is correctly set and is in OpenSSH format.", err) // <--- 修改错误信息
	}
	clientSigner, err := ssh.NewSignerFromKey(clientKey) // <--- 从解析后的 key 创建 signer
	if err != nil {
		log.Fatalf("Failed to create signer from client private key: %v", err)
	}
	log.Println("Parsed client private key.")

	// 1. 配置 SSH 客户端 - 提供公钥认证方法
	sshConfig := &ssh.ClientConfig{
		User: "yamux-client", // 用户名仍然需要
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(clientSigner), // <--- 提供公钥认证
		},
		// !! 警告: 生产环境中不安全 !!
		// 强烈建议替换为验证服务器公钥的回调
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	// 2. 建立 TCP 连接
	tcpConn, err := net.DialTimeout("tcp", serverAddr, sshConfig.Timeout)
	if err != nil {
		log.Fatalf("Failed to dial server %s: %v\n", serverAddr, err)
	}
	log.Printf("TCP connection established to %s\n", serverAddr)

	// 3. 执行 SSH 握手 (发送公钥进行认证)
	sshConn, chans, reqs, err := ssh.NewClientConn(tcpConn, serverAddr, sshConfig)
	if err != nil {
		log.Fatalf("Failed SSH handshake/auth with server %s: %v\n", serverAddr, err)
	}
	log.Printf("SSH handshake and authentication successful with %s (%s)\n", sshConn.RemoteAddr(), sshConn.ServerVersion())

	// 丢弃服务器可能发送的请求和通道
	go ssh.DiscardRequests(reqs)
	go func() {
		for newChannel := range chans {
			log.Printf("Rejecting unexpected SSH channel request from server %s", sshConn.RemoteAddr())
			if newChannel != nil {
				newChannel.Reject(ssh.UnknownChannelType, "channel type not supported")
			}
		}
	}()

	// 4. 打开 "yamux" SSH 通道
	log.Printf("Opening 'yamux' channel to server %s\n", sshConn.RemoteAddr())
	channel, requests, err := sshConn.OpenChannel("yamux", nil) // <--- 打开通道
	if err != nil {
		sshConn.Close()
		log.Fatalf("Failed to open 'yamux' channel: %v\n", err)
	}
	log.Printf("Opened 'yamux' channel successfully\n")
	go ssh.DiscardRequests(requests) // 丢弃此通道上的请求

	// 5. 在 SSH 通道上创建 Yamux 客户端会话
	session, err := yamux.Client(channel, nil) // <--- 使用 channel
	if err != nil {
		channel.Close()
		log.Fatalf("Failed to create yamux client session over SSH channel: %v\n", err)
	}
	defer session.Close()
	log.Println("Yamux client session established over SSH channel")

	// ... (后续逻辑与之前 SSH 版本相同: 打开控制流, 发送请求, 接受代理流) ...
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
			// 检查错误是否因为底层 SSH 通道关闭
			if err == io.EOF || strings.Contains(err.Error(), "session closed") || strings.Contains(err.Error(), "connection reset by peer") || strings.Contains(err.Error(), "broken pipe") || strings.Contains(err.Error(), "EOF") {
				log.Printf("Yamux session closed, likely due to SSH channel closure. Exiting.\n")
			} else {
				log.Printf("Failed to accept yamux stream from server: %v. Exiting.\n", err)
			}
			break // Session likely closed
		}
		log.Printf("Accepted incoming proxy stream from server %s\n", session.RemoteAddr()) // session.RemoteAddr() 现在是 SSH 通道的地址

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
