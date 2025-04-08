package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
)

const (
	ServerMode = "server"
	ClientMode = "client"
)

func main() {
	mode := flag.String("mode", "", "运行模式: 'server' 或 'client'")

	// --- Server 参数 ---
	publicListenAddr := flag.String("public", "0.0.0.0:7000", "[Server模式] 监听外部用户连接的地址")
	clientListenAddr := flag.String("listen", "0.0.0.0:7001", "[Server模式] 监听内网客户端连接的地址")

	// --- Client 参数 ---
	serverClientAddr := flag.String("server", "example.com:7001", "[Client模式] 连接公网服务器的客户端监听地址")
	localServiceAddr := flag.String("local", "127.0.0.1:1080", "[Client模式] 要暴露的内网服务地址")

	flag.Parse()

	if *mode == "" {
		fmt.Println("错误: 必须指定 -mode 参数 ('server' 或 'client')")
		flag.Usage()
		os.Exit(1)
	}

	log.Printf("启动模式: %s", *mode)

	switch *mode {
	case ServerMode:
		runServer(*publicListenAddr, *clientListenAddr)
	case ClientMode:
		runClient(*serverClientAddr, *localServiceAddr)
	default:
		fmt.Printf("错误: 无效的模式 '%s'\n", *mode)
		flag.Usage()
		os.Exit(1)
	}
}

// --- Server 端逻辑 ---
func runServer(publicAddr, clientAddr string) {
	log.Printf("服务器: 监听公共端口 %s", publicAddr)
	publicListener, err := net.Listen("tcp", publicAddr)
	if err != nil {
		log.Fatalf("服务器: 监听公共端口失败: %v", err)
	}
	defer publicListener.Close()

	log.Printf("服务器: 监听客户端端口 %s", clientAddr)
	clientListener, err := net.Listen("tcp", clientAddr)
	if err != nil {
		log.Fatalf("服务器: 监听客户端端口失败: %v", err)
	}
	defer clientListener.Close()

	log.Println("服务器: 等待连接...")

	for {
		// 1. 接受外部用户连接
		userConn, err := publicListener.Accept()
		if err != nil {
			log.Printf("服务器: 接受用户连接失败: %v", err)
			continue // 继续接受下一个
		}
		log.Printf("服务器: 接受到来自 %s 的用户连接", userConn.RemoteAddr())

		// 2. 等待并接受内网客户端连接 (为这个用户连接)
		// 注意：这种简单的配对方式在高并发下有问题，真正的frp用控制连接来协调
		log.Printf("服务器: 等待来自客户端的配对连接 (端口 %s)...", clientAddr)
		clientConn, err := clientListener.Accept()
		if err != nil {
			log.Printf("服务器: 接受客户端配对连接失败: %v", err)
			userConn.Close() // 关闭对应的用户连接
			continue         // 继续接受下一个用户连接
		}
		log.Printf("服务器: 接受到来自 %s 的客户端配对连接", clientConn.RemoteAddr())

		// 3. 开始转发
		log.Printf("服务器: 开始为 %s <-> %s 转发数据", userConn.RemoteAddr(), clientConn.RemoteAddr())
		go forwardTraffic(userConn, clientConn)
	}
}

// --- Client 端逻辑 ---
func runClient(serverAddr, localAddr string) {
	log.Printf("客户端: 将连接服务器 %s 并转发到本地服务 %s", serverAddr, localAddr)

	// 注意：这个简单的客户端不知道何时应该连接服务器的client端口
	// 它只是不断尝试建立连接对。实际的frp客户端会通过控制连接
	// 接收到服务器的指令后，才发起用于数据传输的连接。
	// 为了模拟，我们让客户端在需要时才连接，但这需要服务器端逻辑配合
	// 这里我们做一个简化：客户端循环连接，适用于服务器端简单配对逻辑
	for {
		log.Println("客户端: 尝试连接服务器和本地服务...")

		// 1. 连接公网服务器 (用于数据传输的端口)
		serverConn, err := net.Dial("tcp", serverAddr)
		if err != nil {
			log.Printf("客户端: 连接服务器 %s 失败: %v。稍后重试...", serverAddr, err)
			// 在实际应用中应该有退避策略
			// time.Sleep(5 * time.Second)
			continue
		}
		log.Printf("客户端: 成功连接到服务器 %s", serverAddr)

		// 2. 连接本地服务
		localConn, err := net.Dial("tcp", localAddr)
		if err != nil {
			log.Printf("客户端: 连接本地服务 %s 失败: %v", localAddr, err)
			serverConn.Close() // 关闭到服务器的连接
			continue
		}
		log.Printf("客户端: 成功连接到本地服务 %s", localAddr)

		// 3. 开始转发
		log.Printf("客户端: 开始为 %s <-> %s 转发数据", serverAddr, localAddr)
		// 这里也需要阻塞或者等待转发完成，否则循环会立即开始下一次连接尝试
		// forwardTraffic 会阻塞，直到其中一个连接关闭
		forwardTraffic(serverConn, localConn)
		log.Println("客户端: 转发结束，重新建立连接...")
	}

}

// --- 双向流量转发 ---
func forwardTraffic(conn1 net.Conn, conn2 net.Conn) {
	log.Printf("转发: 开始 %s <-> %s", conn1.RemoteAddr(), conn2.RemoteAddr())
	var wg sync.WaitGroup
	wg.Add(2)

	closer := func() {
		// 使用 sync.Once 确保只关闭一次
		var once sync.Once
		once.Do(func() {
			conn1.Close()
			conn2.Close()
			log.Printf("转发: 连接关闭 %s, %s", conn1.RemoteAddr(), conn2.RemoteAddr())
		})
	}

	// Goroutine 1: conn1 -> conn2
	go func() {
		defer wg.Done()
		defer closer() // 确保另一个连接也关闭
		written, err := io.Copy(conn2, conn1)
		if err != nil && err != io.EOF {
			// 忽略 "use of closed network connection" 错误，因为可能是对方先关闭
			if opErr, ok := err.(*net.OpError); !ok || opErr.Err.Error() != "use of closed network connection" {
				log.Printf("转发错误 (%s -> %s): %v", conn1.RemoteAddr(), conn2.RemoteAddr(), err)
			}
		}
		log.Printf("转发: %s -> %s 写入 %d 字节", conn1.RemoteAddr(), conn2.RemoteAddr(), written)
	}()

	// Goroutine 2: conn2 -> conn1
	go func() {
		defer wg.Done()
		defer closer() // 确保另一个连接也关闭
		written, err := io.Copy(conn1, conn2)
		if err != nil && err != io.EOF {
			if opErr, ok := err.(*net.OpError); !ok || opErr.Err.Error() != "use of closed network connection" {
				log.Printf("转发错误 (%s -> %s): %v", conn2.RemoteAddr(), conn1.RemoteAddr(), err)
			}
		}
		log.Printf("转发: %s -> %s 写入 %d 字节", conn2.RemoteAddr(), conn1.RemoteAddr(), written)
	}()

	wg.Wait() // 等待两个转发goroutine结束
	log.Printf("转发: 完成 %s <-> %s", conn1.RemoteAddr(), conn2.RemoteAddr())
}
