package main

import (
	"flag"
	"fmt"
	"os"
)

const (
	// 服务端配置
	serverAddr  = "0.0.0.0"
	controlPort = 7000
	publicPort  = 6000
	dataPort    = 7001

	// 客户端配置
	serverIP  = "home.3749.xin"
	localHost = "10.36.6.156"
	localPort = 28080

	// 通用配置
	bufferSize        = 4096
	heartbeatInterval = 30
)

func main() {
	mode := flag.String("mode", "", "运行模式: server 或 client")
	flag.Parse()

	if *mode == "" {
		fmt.Println("请指定运行模式: -mode server 或 -mode client")
		os.Exit(1)
	}

	switch *mode {
	case "server":
		server := NewServer()
		server.Run()
	case "client":
		client := NewClient()
		client.Run()
	default:
		fmt.Printf("未知的模式: %s\n", *mode)
		os.Exit(1)
	}
}
