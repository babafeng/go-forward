package main

import (
	"log"
	"net"
	"strconv" // Import strconv
	"strings"
	"sync" // Import sync
)

// Modified to accept ForwardConfig struct
func handleTCPForward(cfg ForwardConfig) {
	if cfg.IsRange {
		log.Printf("Starting TCP forwarder range: local %d-%d -> %s:%d-%d\n",
			cfg.LocalStartPort, cfg.LocalEndPort, cfg.TargetHost, cfg.TargetStartPort, cfg.TargetEndPort)

		var rangeWg sync.WaitGroup
		for localPort := cfg.LocalStartPort; localPort <= cfg.LocalEndPort; localPort++ {
			rangeWg.Add(1)
			// Launch a goroutine for each port in the local range
			go func(currentLocalPort int) {
				defer rangeWg.Done()
				listenAndForwardSinglePort(currentLocalPort, cfg)
			}(localPort)
		}
		rangeWg.Wait() // Wait for all listeners in the range to finish (they shouldn't normally)

	} else {
		// Single port forwarding logic (original logic)
		log.Printf("Starting TCP forwarder: listening on %s, forwarding to %s\n", cfg.ListenAddr, cfg.TargetAddr)
		listener, err := net.Listen("tcp", cfg.ListenAddr)
		if err != nil {
			log.Printf("Failed to listen on %s: %v", cfg.ListenAddr, err) // Use Printf, not Fatalf in goroutine
			return
		}
		defer listener.Close()

		for {
			client, err := listener.Accept()
			if (err != nil) && !strings.Contains(err.Error(), "use of closed network connection") {
				log.Printf("Accept error on %s: %v", cfg.ListenAddr, err)
				continue
			}
			log.Printf("New TCP connection from %s on %s", client.RemoteAddr(), cfg.ListenAddr)

			go func() {
				defer client.Close()
				remote, err := net.Dial("tcp", cfg.TargetAddr)
				if err != nil {
					log.Printf("Remote dial error (%s -> %s): %v", client.RemoteAddr(), cfg.TargetAddr, err)
					return
				}
				defer remote.Close()
				log.Printf("Forwarding %s -> %s", client.RemoteAddr(), cfg.TargetAddr)

				// Use the existing proxy/transfer function (assuming it's named 'proxy')
				// If it's named 'transfer', use that instead. Let's assume 'proxy'.
				proxy(client, remote) // Use the standard proxy function
			}()
		}
	}
}

// Handles listening on a single local port and forwarding to the calculated target port
func listenAndForwardSinglePort(localPort int, cfg ForwardConfig) {
	localListenAddr := ":" + strconv.Itoa(localPort)

	// Calculate corresponding target port
	portOffset := localPort - cfg.LocalStartPort
	targetPort := cfg.TargetStartPort + portOffset
	currentTargetAddr := net.JoinHostPort(cfg.TargetHost, strconv.Itoa(targetPort))

	listener, err := net.Listen("tcp", localListenAddr)
	if err != nil {
		log.Printf("Failed to listen on %s (range): %v", localListenAddr, err)
		return
	}
	defer listener.Close()
	log.Printf("Forwarder listening on %s, forwarding to %s", localListenAddr, currentTargetAddr)

	for {
		client, err := listener.Accept()
		if err != nil {
			if !strings.Contains(err.Error(), "use of closed network connection") {
				log.Printf("Accept error on %s (range): %v", localListenAddr, err)
			} else {
				log.Printf("Listener %s (range) closed.", localListenAddr)
				break
			}
			continue
		}
		log.Printf("New TCP connection from %s on %s (range)", client.RemoteAddr(), localListenAddr)

		go func() {
			defer client.Close()
			remote, err := net.Dial("tcp", currentTargetAddr)
			if err != nil {
				log.Printf("Remote dial error (%s -> %s): %v", client.RemoteAddr(), currentTargetAddr, err)
				return
			}
			defer remote.Close()
			proxy(client, remote)
		}()
	}
}
