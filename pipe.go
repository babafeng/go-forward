package main

import (
	"fmt"
	"io"
	"net"
	"sync"
)

type Pipe struct {
	sock1     net.Conn
	sock2     net.Conn
	name1     string
	name2     string
	stopChan  chan struct{}
	waitGroup sync.WaitGroup
}

func NewPipe(sock1, sock2 net.Conn, name1, name2 string) *Pipe {
	return &Pipe{
		sock1:     sock1,
		sock2:     sock2,
		name1:     name1,
		name2:     name2,
		stopChan:  make(chan struct{}),
	}
}

func (p *Pipe) Start() {
	p.waitGroup.Add(2)
	go p.transfer(p.sock1, p.sock2, p.name1, p.name2)
	go p.transfer(p.sock2, p.sock1, p.name2, p.name1)
}

func (p *Pipe) transfer(src, dst net.Conn, srcName, dstName string) {
	defer p.waitGroup.Done()
	buffer := make([]byte, bufferSize)

	for {
		select {
		case <-p.stopChan:
			return
		default:
			n, err := src.Read(buffer)
			if err != nil {
				if err != io.EOF {
					fmt.Printf("[Pipe] Error reading from %s: %v\n", srcName, err)
				}
				return
			}

			_, err = dst.Write(buffer[:n])
			if err != nil {
				fmt.Printf("[Pipe] Error writing to %s: %v\n", dstName, err)
				return
			}
		}
	}
}

func (p *Pipe) Stop() {
	close(p.stopChan)
	p.sock1.Close()
	p.sock2.Close()
	p.waitGroup.Wait()
}
