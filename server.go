package main

import (
	"fmt"
	"net"
	"sync"
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

func (s *Server) acceptData(dataListener net.Listener) {
	panic("unimplemented")
}

func (s *Server) acceptPublic(publicListener net.Listener) {
	panic("unimplemented")
}

func (s *Server) acceptControl(controlListener net.Listener) {
	panic("unimplemented")
}

// ... 其他服务端方法实现 ...
