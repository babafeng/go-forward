package main

import (
	"fmt"
	"github.com/google/uuid"
	"io"
	"net"
	"sync"
	"time"
)

type Server struct {
	controlConn      net.Conn
	controlLock      sync.Mutex
	pendingDataConns map[string]chan net.Conn
	stopChan         chan struct{}
}

func NewServer() *Server {
	return &Server{
		pendingDataConns: make(map[string]chan net.Conn),
		stopChan:         make(chan struct{}),
	}
}

func (s *Server) Run() {
	controlListener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", serverAddr, controlPort))
	if err != nil {
		fmt.Printf("[Server] Failed to start control listener: %v\n", err)
		return
	}

	publicListener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", serverAddr, publicPort))
	if err != nil {
		fmt.Printf("[Server] Failed to start public listener: %v\n", err)
		return
	}

	dataListener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", serverAddr, dataPort))
	if err != nil {
		fmt.Printf("[Server] Failed to start data listener: %v\n", err)
		return
	}

	fmt.Printf("[Server] Listening on control port %d, public port %d, data port %d\n",
		controlPort, publicPort, dataPort)

	go s.acceptControl(controlListener)
	go s.acceptPublic(publicListener)
	go s.acceptData(dataListener)

	<-s.stopChan // 等待停止信号
}

// filepath: [server.go](http://_vscodecontentref_/0)
func (s *Server) acceptData(dataListener net.Listener) {
	for {
		conn, err := dataListener.Accept()
		if err != nil {
			fmt.Printf("[Server] Data accept error: %v\n", err)
			return
		}

		// 读取连接ID
		connID := make([]byte, 36)
		_, err = conn.Read(connID)
		if err != nil {
			fmt.Printf("[Server] Failed to read connection ID: %v\n", err)
			conn.Close()
			continue
		}

		connIDStr := string(connID)
		if ch, ok := s.pendingDataConns[connIDStr]; ok {
			ch <- conn
			delete(s.pendingDataConns, connIDStr)
		} else {
			fmt.Printf("[Server] No pending connection for ID: %s\n", connIDStr)
			conn.Close()
		}
	}
}

func (s *Server) acceptPublic(publicListener net.Listener) {
	for {
		conn, err := publicListener.Accept()
		if err != nil {
			fmt.Printf("[Server] Public accept error: %v\n", err)
			return
		}

		s.controlLock.Lock()
		if s.controlConn == nil {
			fmt.Println("[Server] No control connection available")
			conn.Close()
			s.controlLock.Unlock()
			continue
		}

		// 生成唯一的连接ID
		connID := generateUUID()
		ch := make(chan net.Conn)
		s.pendingDataConns[connID] = ch

		// 通知客户端新的连接请求
		_, err = s.controlConn.Write([]byte(connID))
		s.controlLock.Unlock()

		if err != nil {
			fmt.Printf("[Server] Failed to notify client: %v\n", err)
			conn.Close()
			continue
		}

		// 等待数据连接建立
		go func(publicConn net.Conn, connIDStr string) {
			select {
			case dataConn := <-ch:
				// 开始转发数据
				go forward(publicConn, dataConn)
				go forward(dataConn, publicConn)
			case <-time.After(10 * time.Second):
				fmt.Printf("[Server] Data connection timeout for ID: %s\n", connIDStr)
				delete(s.pendingDataConns, connIDStr)
				publicConn.Close()
			}
		}(conn, connID)
	}
}

func (s *Server) acceptControl(controlListener net.Listener) {
	for {
		conn, err := controlListener.Accept()
		if err != nil {
			fmt.Printf("[Server] Control accept error: %v\n", err)
			return
		}

		s.controlLock.Lock()
		if s.controlConn != nil {
			fmt.Println("[Server] Control connection already exists")
			conn.Close()
			s.controlLock.Unlock()
			continue
		}
		s.controlConn = conn
		s.controlLock.Unlock()

		fmt.Println("[Server] Control connection established")
	}
}

// 添加辅助函数
func forward(dst net.Conn, src net.Conn) {
	defer dst.Close()
	defer src.Close()
	io.Copy(dst, src)
}

func generateUUID() string {
	return uuid.New().String()
}
