package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DataDog/tcptracer-bpf/pkg/tracer"
	"github.com/stretchr/testify/assert"
)

var payloadSizes = []int{2 << 5, 2 << 8, 2 << 10, 2 << 12, 2 << 14, 2 << 15}

func TestTCPSendAndReceiveWithBPF(t *testing.T) {
	ClientMessageSize := 2 << 8
	ServerMessageSize := 2 << 15

	// Enable BPF-based network tracer
	tr, err := tracer.NewTracer(tracer.DefaultConfig)
	if err != nil {
		t.Fatal(err)
	}
	tr.Start()
	defer tr.Stop()

	// Create TCP Server which sends back ServerMessageSize bytes
	server := NewServer(func(c net.Conn) {
		r := bufio.NewReader(c)
		r.ReadBytes(byte('\n'))
		c.Write(genPayload(ServerMessageSize))
		c.Close()
	})
	doneChan := make(chan struct{})
	server.Run(doneChan)

	c, err := net.DialTimeout("tcp", server.address, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Write ClientMessageSize to server, and read response
	if _, err = c.Write(genPayload(ClientMessageSize)); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(c)
	r.ReadBytes(byte('\n'))

	// Iterate through active connections until we find connection created above, and confirm send + recv counts
	connectionFound := false
	connections, err := tr.GetActiveConnections()
	if err != nil {
		t.Fatal(err)
	}

	for _, conn := range connections.Conns {
		localAddr := fmt.Sprintf("%s:%d", conn.Source, conn.SPort)
		remoteAddr := fmt.Sprintf("%s:%d", conn.Dest, conn.DPort)
		if localAddr == c.LocalAddr().String() && remoteAddr == c.RemoteAddr().String() {
			connectionFound = true
			assert.Equal(t, ClientMessageSize, int(conn.SendBytes))
			assert.Equal(t, ServerMessageSize, int(conn.RecvBytes))
		}
	}

	assert.True(t, connectionFound)

	doneChan <- struct{}{}
}

func runBenchtests(b *testing.B, prefix string, f func(p int) func(*testing.B)) {
	for _, p := range payloadSizes {
		name := strings.TrimSpace(strings.Join([]string{prefix, strconv.Itoa(p), "bytes"}, " "))
		b.Run(name, f(p))
	}
}

func BenchmarkTCPEcho(b *testing.B) {
	runBenchtests(b, "", benchEchoTCP)

	// Enable BPF-based network tracer
	t, err := tracer.NewTracer(tracer.DefaultConfig)
	if err != nil {
		b.Fatal(err)
	}
	t.Start()
	defer t.Stop()

	runBenchtests(b, "eBPF", benchEchoTCP)
}

func BenchmarkTCPSend(b *testing.B) {
	runBenchtests(b, "", benchSendTCP)

	// Enable BPF-based network tracer
	t, err := tracer.NewTracer(tracer.DefaultConfig)
	if err != nil {
		b.Fatal(err)
	}
	t.Start()
	defer t.Stop()

	runBenchtests(b, "eBPF", benchSendTCP)
}

func benchEchoTCP(size int) func(b *testing.B) {
	payload := genPayload(size)
	echoOnMessage := func(c net.Conn) {
		r := bufio.NewReader(c)
		for {
			buf, err := r.ReadBytes(byte('\n'))
			if err == io.EOF {
				c.Close()
				return
			}
			c.Write(buf)
		}
	}

	return func(b *testing.B) {
		end := make(chan struct{})
		server := NewServer(echoOnMessage)
		server.Run(end)

		c, err := net.DialTimeout("tcp", server.address, 50*time.Millisecond)
		if err != nil {
			b.Fatal(err)
		}
		defer c.Close()
		r := bufio.NewReader(c)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			c.Write(payload)
			buf, err := r.ReadBytes(byte('\n'))

			if err != nil || len(buf) != len(payload) || !bytes.Equal(payload, buf) {
				b.Fatalf("Sizes: %d, %d. Equal: %v. Error: %s", len(buf), len(payload), bytes.Equal(payload, buf), err)
			}
		}
		b.StopTimer()

		end <- struct{}{}
	}
}

func benchSendTCP(size int) func(b *testing.B) {
	payload := genPayload(size)
	dropOnMessage := func(c net.Conn) {
		r := bufio.NewReader(c)
		for { // Drop all payloads received
			_, err := r.Discard(r.Buffered() + 1)
			if err == io.EOF {
				c.Close()
				return
			}
		}
	}

	return func(b *testing.B) {
		end := make(chan struct{})
		server := NewServer(dropOnMessage)
		server.Run(end)

		c, err := net.DialTimeout("tcp", server.address, 50*time.Millisecond)
		if err != nil {
			b.Fatal(err)
		}
		defer c.Close()

		b.ResetTimer()
		for i := 0; i < b.N; i++ { // Send-heavy workload
			_, err := c.Write(payload)
			if err != nil {
				b.Fatal(err)
			}
		}
		b.StopTimer()

		end <- struct{}{}
	}
}

func NewServer(onMessage func(c net.Conn)) *Server {
	return &Server{
		address:   "127.0.0.1:0",
		onMessage: onMessage,
	}
}

func (s *Server) Run(done chan struct{}) {
	ln, err := net.Listen("tcp", s.address)
	if err != nil {
		fmt.Println(err)
		return
	}
	s.address = ln.Addr().String()

	go func() {
		<-done
		ln.Close()
	}()

	go func() {
		for {
			if conn, err := ln.Accept(); err != nil {
				return
			} else {
				s.onMessage(conn)
			}
		}
	}()
}

type Server struct {
	address   string
	onMessage func(c net.Conn)
}

var letterBytes = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func genPayload(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		if i == n-1 {
			b[i] = '\n'
		} else {
			b[i] = letterBytes[rand.Intn(len(letterBytes))]
		}
	}
	return b
}
