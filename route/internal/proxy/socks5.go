package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"log/slog"

	"go-forward/route/internal/router"
	"go-forward/route/internal/runtime"
)

// SOCKS5Server handles SOCKS5 proxy connections.
type SOCKS5Server struct {
	addr    string
	udpAddr string
	runtime *runtime.Store
	logger  *slog.Logger
	udpConn *net.UDPConn
}

// NewSOCKS5Server creates a SOCKS5 server instance.
func NewSOCKS5Server(addr string, store *runtime.Store, logger *slog.Logger) *SOCKS5Server {
	// UDP address is the same as TCP address (will use same port for UDP)
	udpAddr := addr
	return &SOCKS5Server{
		addr:    addr,
		udpAddr: udpAddr,
		runtime: store,
		logger:  logger,
	}
}

// Serve runs the SOCKS5 server until context cancellation.
func (s *SOCKS5Server) Serve(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("listen socks5: %w", err)
	}
	log.Printf("socks5 proxy listening: %s", s.addr)

	// Start UDP listener
	udpAddr, err := net.ResolveUDPAddr("udp", s.udpAddr)
	if err != nil {
		return fmt.Errorf("resolve udp addr: %w", err)
	}
	s.udpConn, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("listen udp: %w", err)
	}
	log.Printf("socks5 udp listening: %s", s.udpAddr)

	go func() {
		<-ctx.Done()
		_ = listener.Close()
		if s.udpConn != nil {
			_ = s.udpConn.Close()
		}
	}()

	// Start UDP handler
	go s.handleUDP(ctx)

	var tempDelay time.Duration
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if tempDelay > time.Second {
					tempDelay = time.Second
				}
				time.Sleep(tempDelay)
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept socks5: %w", err)
		}
		tempDelay = 0
		go s.handleConnection(ctx, conn)
	}
}

func (s *SOCKS5Server) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	remoteAddr := conn.RemoteAddr().String()

	if err := s.handleGreeting(reader, conn); err != nil {
		log.Printf("socks5 [%s] greeting failed: %v", remoteAddr, err)
		return
	}

	req, err := s.readRequest(reader, remoteAddr)
	if err != nil {
		log.Printf("socks5 [%s] read request failed: %v", remoteAddr, err)
		s.sendReply(conn, 0x01, "", 0)
		return
	}

	snapshot := s.runtime.Load()
	if snapshot == nil || snapshot.Router == nil {
		s.sendReply(conn, 0x01, "", 0)
		log.Printf("socks runtime missing")
		return
	}

	// Handle UDP ASSOCIATE
	if req.cmd == 0x03 {
		s.handleUDPAssociate(ctx, conn, req, snapshot, remoteAddr)
		return
	}

	domainLower := strings.ToLower(req.host)
	decision := snapshot.Router.Decide(domainLower)
	s.logDecision(req, decision)

	switch decision.Action {
	case router.ActionReject:
		s.sendReply(conn, 0x02, "", 0)
		return
	}

	target := net.JoinHostPort(req.host, req.port)
	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	targetConn, err := snapshot.Dialers.DialContext(dialCtx, upstreamName(decision), "tcp", target)
	if err != nil {
		log.Printf("socks dial failed: %s, %v", target, err)
		s.sendReply(conn, 0x05, "", 0)
		return
	}

	if err := s.sendReply(conn, 0x00, "", 0); err != nil {
		targetConn.Close()
		return
	}

	linkConns(conn, targetConn)
}

func (s *SOCKS5Server) handleGreeting(reader *bufio.Reader, conn net.Conn) error {
	version, err := reader.ReadByte()
	if err != nil {
		return err
	}
	if version != 0x05 {
		return fmt.Errorf("unsupported socks version %d", version)
	}
	methodsCount, err := reader.ReadByte()
	if err != nil {
		return err
	}
	methods := make([]byte, methodsCount)
	if _, err := io.ReadFull(reader, methods); err != nil {
		return err
	}
	// Only "no authentication" is supported.
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return err
	}
	return nil
}

func (s *SOCKS5Server) readRequest(reader *bufio.Reader, remoteAddr string) (*socksRequest, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	if header[0] != 0x05 {
		return nil, fmt.Errorf("invalid version %d", header[0])
	}

	cmd := header[1]
	addrType := header[3]

	// 先读取目标地址和端口,即使命令不支持也要读取以便记录日志
	var host string
	var port string

	switch addrType {
	case 0x01: // IPv4
		addr := make([]byte, 4)
		if _, err := io.ReadFull(reader, addr); err != nil {
			return nil, err
		}
		host = net.IP(addr).String()
	case 0x03: // domain name
		size, err := reader.ReadByte()
		if err != nil {
			return nil, err
		}
		domain := make([]byte, size)
		if _, err := io.ReadFull(reader, domain); err != nil {
			return nil, err
		}
		host = string(domain)
	case 0x04: // IPv6
		addr := make([]byte, 16)
		if _, err := io.ReadFull(reader, addr); err != nil {
			return nil, err
		}
		host = net.IP(addr).String()
	default:
		return nil, fmt.Errorf("address type %d not supported", addrType)
	}

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(reader, portBytes); err != nil {
		return nil, err
	}
	port = fmt.Sprintf("%d", binary.BigEndian.Uint16(portBytes))

	// 检查命令类型
	if cmd != 0x01 {
		cmdName := "UNKNOWN"
		switch cmd {
		case 0x01:
			cmdName = "CONNECT"
		case 0x02:
			cmdName = "BIND"
		case 0x03:
			cmdName = "UDP_ASSOCIATE"
		}
		return nil, fmt.Errorf("unsupported command %d (%s), target: %s:%s", cmd, cmdName, host, port)
	}

	return &socksRequest{host: host, port: port, atyp: addrType, cmd: cmd}, nil
}

func (s *SOCKS5Server) sendReply(conn net.Conn, rep byte, bindAddr string, bindPort uint16) error {
	response := []byte{0x05, rep, 0x00}
	if bindAddr == "" {
		response = append(response, 0x01)
		response = append(response, []byte{0, 0, 0, 0}...)
	} else {
		response = append(response, 0x03)
		response = append(response, byte(len(bindAddr)))
		response = append(response, []byte(bindAddr)...)
	}
	// Add port
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, bindPort)
	response = append(response, portBytes...)
	_, err := conn.Write(response)
	return err
}

func (s *SOCKS5Server) logDecision(req *socksRequest, decision router.Decision) {
	attrs := []any{
		slog.String("action", decision.Action.String()),
		slog.Bool("matched", decision.Matched),
	}
	upstream := "None"
	if decision.Proxy != "" {
		upstream = decision.Proxy
	}
	if decision.Rule != nil {
		attrs = append(attrs,
			slog.String("rule_type", decision.Rule.MatchTypeString()),
			slog.String("rule_value", decision.Rule.Value),
			slog.Int("rule_index", decision.Rule.Index),
		)
	}
	log.Printf("routing: %v socks5 --> %v %v", upstream, net.JoinHostPort(req.host, req.port), attrs)
}

type socksRequest struct {
	host string
	port string
	atyp byte
	cmd  byte
}

func (s *SOCKS5Server) handleUDPAssociate(ctx context.Context, conn net.Conn, req *socksRequest, snapshot *runtime.Snapshot, remoteAddr string) {
	// Get the UDP relay address (same host as TCP, same port for simplicity)
	host, _, _ := net.SplitHostPort(s.udpAddr)
	_, portStr, _ := net.SplitHostPort(s.udpAddr)
	port, _ := strconv.Atoi(portStr)

	log.Printf("socks5 [%s] UDP ASSOCIATE request, relay address: %s:%d", remoteAddr, host, port)

	// Send success reply with UDP relay address
	if err := s.sendReply(conn, 0x00, host, uint16(port)); err != nil {
		log.Printf("socks5 [%s] failed to send UDP ASSOCIATE reply: %v", remoteAddr, err)
		return
	}

	// Keep the TCP connection alive as long as UDP association is active
	// The association terminates when the TCP connection closes
	buf := make([]byte, 1)
	for {
		conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		_, err := conn.Read(buf)
		if err != nil {
			log.Printf("socks5 [%s] UDP ASSOCIATE connection closed", remoteAddr)
			return
		}
	}
}

func (s *SOCKS5Server) handleUDP(ctx context.Context) {
	buffer := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		s.udpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, clientAddr, err := s.udpConn.ReadFromUDP(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if !errors.Is(err, net.ErrClosed) {
				log.Printf("udp read error: %v", err)
			}
			return
		}

		go s.handleUDPPacket(ctx, buffer[:n], clientAddr)
	}
}

func (s *SOCKS5Server) handleUDPPacket(ctx context.Context, data []byte, clientAddr *net.UDPAddr) {
	// SOCKS5 UDP packet format:
	// +----+------+------+----------+----------+----------+
	// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
	// +----+------+------+----------+----------+----------+
	// | 2  |  1   |  1   | Variable |    2     | Variable |
	// +----+------+------+----------+----------+----------+

	if len(data) < 10 {
		log.Printf("udp packet too short: %d bytes", len(data))
		return
	}

	// Skip RSV (2 bytes) and FRAG (1 byte)
	frag := data[2]
	if frag != 0 {
		log.Printf("fragmented UDP packets not supported")
		return
	}

	addrType := data[3]
	var host string
	var dataOffset int

	switch addrType {
	case 0x01: // IPv4
		if len(data) < 10 {
			return
		}
		host = net.IP(data[4:8]).String()
		dataOffset = 10
	case 0x03: // Domain
		domainLen := int(data[4])
		if len(data) < 5+domainLen+2 {
			return
		}
		host = string(data[5 : 5+domainLen])
		dataOffset = 5 + domainLen + 2
	case 0x04: // IPv6
		if len(data) < 22 {
			return
		}
		host = net.IP(data[4:20]).String()
		dataOffset = 22
	default:
		log.Printf("unsupported address type: %d", addrType)
		return
	}

	port := binary.BigEndian.Uint16(data[dataOffset-2 : dataOffset])
	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	payload := data[dataOffset:]

	snapshot := s.runtime.Load()
	if snapshot == nil || snapshot.Router == nil {
		log.Printf("udp runtime missing")
		return
	}

	domainLower := strings.ToLower(host)
	decision := snapshot.Router.Decide(domainLower)

	if decision.Action == router.ActionReject {
		log.Printf("udp packet rejected: %s", target)
		return
	}

	log.Printf("udp relay: %s -> %s (%d bytes)", clientAddr, target, len(payload))

	// Dial target
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	targetConn, err := snapshot.Dialers.DialContext(dialCtx, upstreamName(decision), "udp", target)
	if err != nil {
		log.Printf("udp dial failed: %s, %v", target, err)
		return
	}
	defer targetConn.Close()

	// Send data to target
	if _, err := targetConn.Write(payload); err != nil {
		log.Printf("udp write failed: %v", err)
		return
	}

	// Read response
	targetConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	responseBuffer := make([]byte, 65535)
	n, err := targetConn.Read(responseBuffer)
	if err != nil {
		if !errors.Is(err, io.EOF) {
			log.Printf("udp read response failed: %v", err)
		}
		return
	}

	// Build SOCKS5 UDP response packet
	responsePacket := make([]byte, 0, n+dataOffset)
	responsePacket = append(responsePacket, 0, 0, 0) // RSV + FRAG
	responsePacket = append(responsePacket, addrType)

	switch addrType {
	case 0x01: // IPv4
		responsePacket = append(responsePacket, data[4:8]...)
	case 0x03: // Domain
		domainLen := int(data[4])
		responsePacket = append(responsePacket, data[4:5+domainLen]...)
	case 0x04: // IPv6
		responsePacket = append(responsePacket, data[4:20]...)
	}

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	responsePacket = append(responsePacket, portBytes...)
	responsePacket = append(responsePacket, responseBuffer[:n]...)

	// Send response back to client
	if _, err := s.udpConn.WriteToUDP(responsePacket, clientAddr); err != nil {
		log.Printf("udp write response failed: %v", err)
	}
}
