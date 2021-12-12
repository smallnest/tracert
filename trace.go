package tracert

import (
	//"bufio"

	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type Config struct {
	MaxTTL  int
	TOS     int
	Timeout time.Duration
}

var DefaultConfig = Config{
	MaxTTL:  30,
	Timeout: 3 * time.Second,
}

type TracertHop struct {
	Success bool
	Address string
	TTL     int
	RTT     time.Duration
}

type TraceRoute struct {
	config                *Config
	localIP, remoteIP     string
	localPort, remotePort int
	data                  []byte

	pConn *icmp.PacketConn

	sentDataLock sync.Mutex
	sentData     map[string]bool
}

func New(localIP, remoteIP string, localPort, remotePort int, data []byte, config *Config) *TraceRoute {
	if config == nil {
		config = &DefaultConfig
	}

	if data == nil {
		data = []byte("hello, this a msg from tracert")
	}

	return &TraceRoute{
		localIP:    localIP,
		remoteIP:   remoteIP,
		localPort:  localPort,
		remotePort: remotePort,
		data:       data,
		config:     config,
		sentData:   make(map[string]bool),
	}
}

func (tr *TraceRoute) Trace(ctx context.Context) ([]*TracertHop, error) {
	routers := make(chan string)

	go tr.handleReplies(routers)

	conn, err := net.ListenPacket("ip4:udp", tr.localIP)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	cc := conn.(*net.IPConn)
	cc.SetReadBuffer(20 * 1024 * 1024)
	cc.SetWriteBuffer(20 * 1024 * 1024)

	localIP := net.ParseIP(tr.localIP)
	remoteIP := net.ParseIP(tr.remoteIP)
	dstAddr := &net.IPAddr{IP: remoteIP}

	pkt := ipv4.NewPacketConn(conn)

	var results []*TracertHop
loop:
	for i := 1; i <= tr.config.MaxTTL; i++ {
		pkt.SetTTL(i)

		buffer, _ := encodeUDPPacket(localIP, remoteIP, uint16(tr.localPort), uint16(tr.remotePort), 64, tr.data)
		tr.sentDataLock.Lock()
		tr.sentData[string(buffer[:8])] = true
		tr.sentDataLock.Unlock()

		start := time.Now()
		_, err = conn.WriteTo(buffer, dstAddr) // write bytes through connected socket

		if err != nil {
			continue
		}

		var router string
		select {
		case <-ctx.Done():
			if len(results) > 0 {
				if results[len(results)-1].Address == "*" {
					break loop
				}
			}
			hop := &TracertHop{
				Success: false,
				Address: "*",
				TTL:     i,
			}
			results = append(results, hop)
			break loop
		case router = <-routers:
		}

		hop := &TracertHop{
			Success: router != "*",
			Address: router,
			TTL:     i,
			RTT:     time.Since(start),
		}
		results = append(results, hop)

		if router == tr.remoteIP {
			break loop
		}
	}

	if tr.pConn != nil {
		tr.pConn.Close()
	}

	return results, nil
}

func findLastSuccess(remoteIP string, hops []*TracertHop) string {
	if len(hops) == 0 {
		return ""
	}

	last := len(hops) - 1

	for i := last; i >= 0; i-- {
		if hops[i].Success && hops[i].Address == remoteIP {
			return hops[i].Address
		}
		if !hops[i].Success {
			continue
		}

		return hops[i].Address
	}

	return "*"
}

func (tr *TraceRoute) handleReplies(routers chan string) {
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return
	}
	tr.pConn = c

	for {
		c.SetReadDeadline(time.Now().Add(tr.config.Timeout))

		rb := make([]byte, 1500)
		readed, peer, err := c.ReadFrom(rb)

		if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
			return
		}

		if readed <= 0 {
			routers <- "*"
			continue
		}

		message, err := icmp.ParseMessage(1, rb[:readed])
		if err != nil {
			routers <- "*"
			continue
		}

		switch message.Type {
		case ipv4.ICMPTypeTimeExceeded:
			if _, ok := message.Body.(*icmp.TimeExceeded); ok {
				b := message.Body.(*icmp.TimeExceeded).Data
				header, err := ipv4.ParseHeader(b[:20])
				if err != nil {
					continue
				}

				if header.Src.String() != tr.localIP || header.Dst.String() != tr.remoteIP {
					continue
				}
				tr.sentDataLock.Lock()
				if !tr.sentData[string(b[20:28])] {
					tr.sentDataLock.Unlock()
					continue
				}

				tr.sentDataLock.Unlock()
			}

			routers <- peer.String()
		case ipv4.ICMPTypeDestinationUnreachable:
			b := message.Body.(*icmp.DstUnreach).Data
			header, err := ipv4.ParseHeader(b[:20])
			if err != nil {
				continue
			}

			if header.Src.String() != tr.localIP || header.Dst.String() != tr.remoteIP {
				continue
			}
			tr.sentDataLock.Lock()
			if !tr.sentData[string(b[20:28])] {
				tr.sentDataLock.Unlock()
				continue
			}

			tr.sentDataLock.Unlock()

			routers <- peer.String()
		default:
			continue
		}
	}
}
