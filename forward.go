package main

import (
	"io"
	"log"
	"net"
	"strings"
)

func handleTCPForward(listenPort string, remoteAddr string) {
	localAddr := listenPort
	if !strings.Contains(localAddr, ":") { // Check if it's just a port number
		localAddr = ":" + localAddr // Prepend colon
	}

	log.Printf("Starting TCP forwarder: listening on %s, forwarding to %s\n", localAddr, remoteAddr) // Add log
	listener, err := net.Listen("tcp", localAddr)
	if err != nil {
		// Use Fatalf for critical startup errors
		log.Fatalf("Failed to listen on %s: %v", localAddr, err)
	}
	defer listener.Close()

	for {
		client, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		log.Printf("New TCP connection from %s", client.RemoteAddr())

		go func() {
			defer client.Close()
			remote, err := net.Dial("tcp", remoteAddr)
			if err != nil {
				log.Printf("Remote dial error: %v", err)
				return
			}
			defer remote.Close()
			log.Printf("Connected to remote %s", remoteAddr)

			go transfer(remote, client)
			transfer(client, remote)
		}()
	}
}

// 更新 transfer 函数，添加错误处理
func transfer(dst io.WriteCloser, src io.ReadCloser) {
	defer dst.Close()
	defer src.Close()

	srcConn, srcOk := src.(net.Conn)
	dstConn, dstOk := dst.(net.Conn)
	if srcOk && dstOk {
		log.Printf("Transfer: src=%s -> dst=%s", srcConn.RemoteAddr(), dstConn.RemoteAddr())
	}

	written, err := io.Copy(dst, src)
	if (err != nil) && !strings.Contains(err.Error(), "use of closed network connection") {
		log.Printf("Data transfer error: %v", err)
	}

	if srcOk && dstOk {
		log.Printf("Transferred %d bytes from %s to %s", written, srcConn.RemoteAddr(), dstConn.RemoteAddr())
	} else {
		log.Printf("Transferred %d bytes", written)
	}
}
