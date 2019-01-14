package tracer

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/common"
	"io"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"os"
)

var (
	clientMessageSize     = 2 << 8
	clientMessageFileSize = 44
	serverMessageSize     = 2 << 14
	payloadSizesTCP       = []int{2 << 5, 2 << 8, 2 << 10, 2 << 12, 2 << 14, 2 << 15}
	payloadSizesUDP       = []int{2 << 5, 2 << 8, 2 << 12, 2 << 14}
)

func TestTCPSendAndReceive(t *testing.T) {
	// Enable BPF-based network tracer
	tr, err := NewTracer(MakeTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	tr.Start()
	defer tr.Stop()

	// Create TCP Server which sends back serverMessageSize bytes
	server := common.NewTCPServer(func(c net.Conn) {
		r := bufio.NewReader(c)
		r.ReadBytes(byte('\n'))
		c.Write(genPayload(serverMessageSize))
		r.ReadBytes(byte('\n'))
		c.Close()
	})
	doneChan := make(chan struct{})
	server.Run(doneChan)

	// Connect to server
	c, err := net.DialTimeout("tcp", server.Address, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Write clientMessageSize to server, and read response
	if _, err = c.Write(genPayload(clientMessageSize)); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(c)
	r.ReadBytes(byte('\n'))

	// Iterate through active connections until we find connection created above, and confirm send + recv counts
	connections, err := tr.GetConnections()
	if err != nil {
		t.Fatal(err)
	}

	// One direction
	conn1, ok := findConnection(c.LocalAddr(), c.RemoteAddr(), connections)
	assert.True(t, ok)
	assert.Equal(t, clientMessageSize, int(conn1.SendBytes))
	assert.Equal(t, serverMessageSize, int(conn1.RecvBytes))
	assert.Equal(t, conn1.Direction, common.OUTGOING)
	assert.Equal(t, conn1.State, common.ACTIVE)

	conn2, ok := findConnection(c.RemoteAddr(), c.LocalAddr(), connections)
	assert.True(t, ok)
	assert.Equal(t, clientMessageSize, int(conn2.RecvBytes))
	assert.Equal(t, serverMessageSize, int(conn2.SendBytes))
	assert.Equal(t, conn2.Direction, common.INCOMING)
	assert.Equal(t, conn2.State, common.ACTIVE)

	// Write clientMessageSize to server, to shut down the connection
	if _, err = c.Write(genPayload(0)); err != nil {
		t.Fatal(err)
	}

	doneChan <- struct{}{}
}

func TestTCPSendPage(t *testing.T) {
	// Enable BPF-based network tracer
	tr, err := NewTracer(MakeTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	tr.Start()
	defer tr.Stop()

	// Create TCP Server which sends back serverMessageSize bytes
	server := common.NewTCPServer(func(c net.Conn) {
		r := bufio.NewReader(c)
		r.ReadBytes(byte('\n'))
		c.Write(genPayload(serverMessageSize))
		r.ReadBytes(byte('\n'))
		c.Close()
	})
	doneChan := make(chan struct{})
	server.Run(doneChan)

	fmt.Printf("Addr: %s", server.Address)
	tcpAddr, err := net.ResolveTCPAddr("tcp4", server.Address)
	// Connect to server
	c, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Write filedata directly to socket, this triggers tcp_sendpage kernel call
	file, err := os.Open("./testdata.txt")
	if err != nil {
		t.Fatal(err)
	}
	lr := &io.LimitedReader{N: int64(clientMessageFileSize), R: file}
	_, err = c.ReadFrom(lr)
	if err != nil {
		t.Fatal(err)
	}

	r := bufio.NewReader(c)
	r.ReadBytes(byte('\n'))

	// Iterate through active connections until we find connection created above, and confirm send + recv counts
	connections, err := tr.GetConnections()
	if err != nil {
		t.Fatal(err)
	}

	// One direction
	conn1, ok := findConnection(c.LocalAddr(), c.RemoteAddr(), connections)
	assert.True(t, ok)
	assert.Equal(t, clientMessageFileSize, int(conn1.SendBytes))
	assert.Equal(t, serverMessageSize, int(conn1.RecvBytes))
	assert.Equal(t, conn1.Direction, common.OUTGOING)
	assert.Equal(t, conn1.State, common.ACTIVE)

	conn2, ok := findConnection(c.RemoteAddr(), c.LocalAddr(), connections)
	assert.True(t, ok)
	assert.Equal(t, clientMessageFileSize, int(conn2.RecvBytes))
	assert.Equal(t, serverMessageSize, int(conn2.SendBytes))
	assert.Equal(t, conn2.Direction, common.INCOMING)
	assert.Equal(t, conn2.State, common.ACTIVE)

	// Write clientMessageSize to server, to shut down the connection
	if _, err = c.Write(genPayload(0)); err != nil {
		t.Fatal(err)
	}

	doneChan <- struct{}{}
}

func TestMaxConnectionsIsUsed(t *testing.T) {
	// Enable BPF-based network tracer
	conf := MakeTestConfig()
	conf.MaxConnections = 1
	tr, err := NewTracer(conf)
	if err != nil {
		t.Fatal(err)
	}
	tr.Start()
	defer tr.Stop()

	// Create TCP Server which sends back serverMessageSize bytes
	server := common.NewTCPServer(func(c net.Conn) {
		r := bufio.NewReader(c)
		r.ReadBytes(byte('\n'))
		c.Write(genPayload(serverMessageSize))
		r.ReadBytes(byte('\n'))
		c.Close()
	})
	doneChan := make(chan struct{})
	server.Run(doneChan)

	// Connect to server
	c, err := net.DialTimeout("tcp", server.Address, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Write some data 1
	if _, err = c.Write(genPayload(clientMessageSize)); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(c)
	r.ReadBytes(byte('\n'))

	// Create TCP Server which sends back serverMessageSize bytes
	server2 := common.NewTCPServer(func(c net.Conn) {
		r := bufio.NewReader(c)
		r.ReadBytes(byte('\n'))
		c.Write(genPayload(serverMessageSize))
		r.ReadBytes(byte('\n'))
		c.Close()
	})
	doneChan2 := make(chan struct{})
	server2.Run(doneChan2)

	// Connect again
	c2, err := net.DialTimeout("tcp", server2.Address, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()

	// Write some data 2
	if _, err = c2.Write(genPayload(clientMessageSize)); err != nil {
		t.Fatal(err)
	}
	r2 := bufio.NewReader(c2)
	r2.ReadBytes(byte('\n'))

	// Iterate through active connections until we find connection created above, and confirm send + recv counts
	connections, err := tr.GetConnections()
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, len(connections.Conns), 1)

	// Write clientMessageSize to server, to shut down the connection
	if _, err = c.Write(genPayload(0)); err != nil {
		t.Fatal(err)
	}

	// Write clientMessageSize to server, to shut down the connection
	if _, err = c2.Write(genPayload(0)); err != nil {
		t.Fatal(err)
	}

	doneChan <- struct{}{}
	doneChan2 <- struct{}{}
}

func TestTCPNoDataNoConnection(t *testing.T) {
	// Enable BPF-based network tracer
	tr, err := NewTracer(MakeTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	tr.Start()
	defer tr.Stop()

	connectChan := make(chan struct{})

	// Create TCP Server which sends back serverMessageSize bytes
	server := common.NewTCPServer(func(c net.Conn) {
		connectChan <- struct{}{}
		r := bufio.NewReader(c)
		r.ReadBytes(byte('\n'))
		c.Close()
	})
	doneChan := make(chan struct{})
	server.Run(doneChan)

	// Connect to server
	c, err := net.DialTimeout("tcp", server.Address, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Waddressit for the connection to be established
	<-connectChan
	// Iterate through active connections until we find connection created above, and confirm send + recv counts
	connections, err := tr.GetConnections()
	if err != nil {
		t.Fatal(err)
	}

	// One direction
	_, ok := findConnection(c.LocalAddr(), c.RemoteAddr(), connections)
	assert.False(t, ok)

	_, ok = findConnection(c.RemoteAddr(), c.LocalAddr(), connections)
	assert.False(t, ok)

	// Write to server to shut down the connection
	if _, err = c.Write(genPayload(0)); err != nil {
		t.Fatal(err)
	}
	doneChan <- struct{}{}
}

// TODO: Seems flaky at times
func TestListenBeforeTraceStartResultInConnectionWhenAccepted(t *testing.T) {

	// Create TCP Server which sends back serverMessageSize bytes
	server := common.NewTCPServer(func(c net.Conn) {
		r := bufio.NewReader(c)
		r.ReadBytes(byte('\n'))
		c.Write(genPayload(serverMessageSize))
		r.ReadBytes(byte('\n'))
		c.Close()
	})
	doneChan := make(chan struct{})
	server.Run(doneChan)

	// Enable BPF-based network tracer
	tr, err := NewTracer(MakeTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	tr.Start()
	defer tr.Stop()

	// Connect to server
	c, err := net.DialTimeout("tcp", server.Address, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Write clientMessageSize to server, and read response
	if _, err = c.Write(genPayload(clientMessageSize)); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(c)
	r.ReadBytes(byte('\n'))

	// Iterate through active connections until we find connection created above, and confirm send + recv counts
	connections, err := tr.GetConnections()
	if err != nil {
		t.Fatal(err)
	}

	// sleeping to wait for connections
	time.Sleep(100 * time.Millisecond)

	// One direction
	conn1, ok := findConnection(c.LocalAddr(), c.RemoteAddr(), connections)
	assert.True(t, ok)
	assert.Equal(t, clientMessageSize, int(conn1.SendBytes))
	assert.Equal(t, serverMessageSize, int(conn1.RecvBytes))
	assert.Equal(t, conn1.Direction, common.OUTGOING)
	assert.Equal(t, conn1.State, common.ACTIVE)

	conn2, ok := findConnection(c.RemoteAddr(), c.LocalAddr(), connections)
	assert.True(t, ok)
	assert.Equal(t, clientMessageSize, int(conn2.RecvBytes))
	assert.Equal(t, serverMessageSize, int(conn2.SendBytes))
	assert.Equal(t, conn2.Direction, common.INCOMING)
	assert.Equal(t, conn2.State, common.ACTIVE)

	// Write clientMessageSize to server, to shut down the connection
	if _, err = c.Write(genPayload(0)); err != nil {
		t.Fatal(err)
	}

	doneChan <- struct{}{}
}

func TestReportInFlightTCPConnectionWithMetrics(t *testing.T) {
	// Create TCP Server which sends back serverMessageSize bytes
	server := common.NewTCPServer(func(c net.Conn) {
		r := bufio.NewReader(c)
		r.ReadBytes(byte('\n'))
		c.Write(genPayload(serverMessageSize))
		r.ReadBytes(byte('\n'))
		c.Close()
	})
	doneChan := make(chan struct{})
	server.Run(doneChan)

	// Connect to server
	c, err := net.DialTimeout("tcp", server.Address, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Connection established, setup tracer
	tr, err := NewTracer(MakeTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	tr.Start()
	defer tr.Stop()

	// Write clientMessageSize to server, and read response
	if _, err = c.Write(genPayload(clientMessageSize)); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(c)
	r.ReadBytes(byte('\n'))

	// Iterate through active connections until we find connection created above, and confirm send + recv counts
	connections, err := tr.GetConnections()
	if err != nil {
		t.Fatal(err)
	}

	// One direction
	conn1, ok := findConnection(c.LocalAddr(), c.RemoteAddr(), connections)
	assert.True(t, ok)
	assert.Equal(t, clientMessageSize, int(conn1.SendBytes))
	assert.Equal(t, serverMessageSize, int(conn1.RecvBytes))
	assert.Equal(t, conn1.Direction, common.UNKNOWN)
	assert.Equal(t, conn1.State, common.ACTIVE)

	conn2, ok := findConnection(c.RemoteAddr(), c.LocalAddr(), connections)
	assert.True(t, ok)
	assert.Equal(t, clientMessageSize, int(conn2.RecvBytes))
	assert.Equal(t, serverMessageSize, int(conn2.SendBytes))
	assert.Equal(t, conn2.Direction, common.INCOMING)
	assert.Equal(t, conn2.State, common.ACTIVE)

	// Write clientMessageSize to server, to shut down the connection
	if _, err = c.Write(genPayload(0)); err != nil {
		t.Fatal(err)
	}

	doneChan <- struct{}{}
}

func TestCloseInFlightTCPConnectionWithEBPFWithData(t *testing.T) {
	// Create TCP Server which sends back serverMessageSize bytes
	server := common.NewTCPServer(func(c net.Conn) {
		r := bufio.NewReader(c)
		r.ReadBytes(byte('\n'))
		c.Write(genPayload(serverMessageSize))
		c.Close()
	})
	doneChan := make(chan struct{})
	server.Run(doneChan)

	// Connect to server
	c, err := net.DialTimeout("tcp", server.Address, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}

	// Connection established, now setup tracer
	tr, err := NewTracer(MakeTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	tr.Start()
	defer tr.Stop()

	// Write clientMessageSize to server, and read response
	if _, err = c.Write(genPayload(clientMessageSize)); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(c)
	r.ReadBytes(byte('\n'))

	// Explicitly close this TCP connection
	c.Close()

	// First run, should contain the closed connection
	connections, err := tr.GetConnections()
	if err != nil {
		t.Fatal(err)
	}

	conn1, ok := findConnection(c.LocalAddr(), c.RemoteAddr(), connections)
	assert.True(t, ok)
	assert.Equal(t, conn1.State, common.ACTIVE_CLOSED)

	conn2, ok := findConnection(c.RemoteAddr(), c.LocalAddr(), connections)
	assert.True(t, ok)
	assert.Equal(t, conn2.State, common.ACTIVE_CLOSED)

	// Second run, connection should be cleaned up
	connections, err = tr.GetConnections()
	if err != nil {
		t.Fatal(err)
	}

	// Confirm that we could not find connection created above
	_, ok = findConnection(c.LocalAddr(), c.RemoteAddr(), connections)
	assert.False(t, ok)

	doneChan <- struct{}{}
}

func TestInFlightDirectionListenAllInterfaces(t *testing.T) {
	connectChan := make(chan struct{})
	closeChan := make(chan struct{})
	closedChan := make(chan struct{})

	// Create TCP Server which sends back serverMessageSize bytes
	server := common.NewTCPServerAllPorts(func(c net.Conn) {
		connectChan <- struct{}{}
		<-closeChan
		c.Close()
		closedChan <- struct{}{}
	})
	doneChan := make(chan struct{})
	server.Run(doneChan)

	// Connect to server
	c, err := net.DialTimeout("tcp", server.Address, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Wait for the connection to be established
	<-connectChan

	// Enable BPF-based network tracer
	tr, err := NewTracer(MakeTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	tr.Start()
	defer tr.Stop()

	closeChan <- struct{}{}
	<-closedChan

	c.Close()

	// Iterate through active connections until we find connection created above, and confirm send + recv counts
	connections, err := tr.GetConnections()
	if err != nil {
		t.Fatal(err)
	}

	// One direction
	conn1, ok := findConnection(c.LocalAddr(), c.RemoteAddr(), connections)
	assert.True(t, ok)
	assert.Equal(t, 0, int(conn1.SendBytes))
	assert.Equal(t, 0, int(conn1.RecvBytes))
	assert.Equal(t, conn1.Direction, common.UNKNOWN)
	assert.Equal(t, conn1.State, common.ACTIVE_CLOSED)

	conn2, ok := findConnection(c.RemoteAddr(), c.LocalAddr(), connections)
	assert.True(t, ok)
	assert.Equal(t, 0, int(conn2.RecvBytes))
	assert.Equal(t, 0, int(conn2.SendBytes))
	assert.Equal(t, conn2.Direction, common.INCOMING)
	assert.Equal(t, conn2.State, common.ACTIVE_CLOSED)

	doneChan <- struct{}{}
}

func TestCloseInFlightTCPConnectionNoData(t *testing.T) {
	connectChan := make(chan struct{})
	closeChan := make(chan struct{})
	closedChan := make(chan struct{})

	// Create TCP Server which sends back serverMessageSize bytes
	server := common.NewTCPServer(func(c net.Conn) {
		connectChan <- struct{}{}
		<-closeChan
		c.Close()
		closedChan <- struct{}{}
	})
	doneChan := make(chan struct{})
	server.Run(doneChan)

	// Connect to server
	c, err := net.DialTimeout("tcp", server.Address, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Wait for the connection to be established
	<-connectChan

	// Enable BPF-based network tracer
	tr, err := NewTracer(MakeTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	tr.Start()
	defer tr.Stop()

	closeChan <- struct{}{}
	<-closedChan

	c.Close()

	// Iterate through active connections until we find connection created above, and confirm send + recv counts
	connections, err := tr.GetConnections()
	if err != nil {
		t.Fatal(err)
	}

	// One direction
	conn1, ok := findConnection(c.LocalAddr(), c.RemoteAddr(), connections)
	assert.True(t, ok)
	assert.Equal(t, 0, int(conn1.SendBytes))
	assert.Equal(t, 0, int(conn1.RecvBytes))
	assert.Equal(t, conn1.Direction, common.UNKNOWN)
	assert.Equal(t, conn1.State, common.ACTIVE_CLOSED)

	conn2, ok := findConnection(c.RemoteAddr(), c.LocalAddr(), connections)
	assert.True(t, ok)
	assert.Equal(t, 0, int(conn2.RecvBytes))
	assert.Equal(t, 0, int(conn2.SendBytes))
	assert.Equal(t, conn2.Direction, common.INCOMING)
	assert.Equal(t, conn2.State, common.ACTIVE_CLOSED)

	doneChan <- struct{}{}
}

func TestTCPClosedConnectionsAreFirstReportedAndThenCleanedUp(t *testing.T) {
	// Enable BPF-based network tracer
	tr, err := NewTracer(MakeTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	tr.Start()
	defer tr.Stop()

	// Create TCP Server which sends back serverMessageSize bytes
	server := common.NewTCPServer(func(c net.Conn) {
		r := bufio.NewReader(c)
		r.ReadBytes(byte('\n'))
		c.Write(genPayload(serverMessageSize))
		c.Close()
	})
	doneChan := make(chan struct{})
	server.Run(doneChan)

	// Connect to server
	c, err := net.DialTimeout("tcp", server.Address, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}

	// Write clientMessageSize to server, and read response
	if _, err = c.Write(genPayload(clientMessageSize)); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(c)
	r.ReadBytes(byte('\n'))

	// Explicitly close this TCP connection
	c.Close()

	// First run, should contain the closed connection
	connections, err := tr.GetConnections()
	if err != nil {
		t.Fatal(err)
	}

	conn, ok := findConnection(c.LocalAddr(), c.RemoteAddr(), connections)
	assert.True(t, ok)
	assert.Equal(t, conn.State, common.ACTIVE_CLOSED)

	conn2, ok := findConnection(c.RemoteAddr(), c.LocalAddr(), connections)
	assert.True(t, ok)
	assert.Equal(t, conn2.State, common.ACTIVE_CLOSED)

	// Second run, connection should be cleaned up
	connections, err = tr.GetConnections()
	if err != nil {
		t.Fatal(err)
	}

	// Confirm that we could not find connection created above
	_, ok = findConnection(c.LocalAddr(), c.RemoteAddr(), connections)
	assert.False(t, ok)

	doneChan <- struct{}{}
}

func TestFailedConnectionShouldNotBeReported(t *testing.T) {
	// Connection established, now setup tracer
	tr, err := NewTracer(MakeTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	tr.Start()
	defer tr.Stop()

	// Connect to non-existing server (we assume port 81 to not be open
	_, err = net.DialTimeout("tcp", "127.0.0.1:81", 50*time.Millisecond)
	assert.NotNil(t, err)
	fmt.Printf("Err %s\n", err)

	// First run, should contain the closed connection
	connections, err := tr.GetConnections()
	if err != nil {
		t.Fatal(err)
	}

	_, ok := findConnectionWithRemote("127.0.0.1:81", connections)
	assert.False(t, ok)
}

func TestUDPSendAndReceive(t *testing.T) {
	// Enable BPF-based network tracer
	tr, err := NewTracer(MakeTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	tr.Start()
	defer tr.Stop()

	// Create UDP Server which sends back serverMessageSize bytes
	server := common.NewUDPServer(func(b []byte, n int) []byte {
		return genPayload(serverMessageSize)
	})

	doneChan := make(chan struct{})
	server.Run(doneChan, clientMessageSize)

	// Connect to server
	c, err := net.DialTimeout("udp", server.Address, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Write clientMessageSize to server, and read response
	if _, err = c.Write(genPayload(clientMessageSize)); err != nil {
		t.Fatal(err)
	}

	c.Read(make([]byte, serverMessageSize))

	// Iterate through common.ACTIVE connections until we find connection created above, and confirm send + recv counts
	connections, err := tr.GetConnections()
	if err != nil {
		t.Fatal(err)
	}

	conn, ok := findConnection(c.LocalAddr(), c.RemoteAddr(), connections)
	assert.True(t, ok)
	assert.Equal(t, clientMessageSize, int(conn.SendBytes))
	assert.Equal(t, serverMessageSize, int(conn.RecvBytes))
	assert.Equal(t, common.UNKNOWN, conn.Direction)
	assert.Equal(t, common.ACTIVE, conn.State)

	doneChan <- struct{}{}
}

func findConnection(l, r net.Addr, c *common.Connections) (*common.ConnectionStats, bool) {
	fmt.Println("Looking for conn")
	for _, conn := range c.Conns {
		fmt.Println("conn", conn)
		localAddr := fmt.Sprintf("%s:%d", conn.Local, conn.LocalPort)
		remoteAddr := fmt.Sprintf("%s:%d", conn.Remote, conn.RemotePort)
		if localAddr == l.String() && remoteAddr == r.String() {
			return &conn, true
		}
	}
	return nil, false
}

func findConnectionWithRemote(r string, c *common.Connections) (*common.ConnectionStats, bool) {
	fmt.Println("Looking for conn")
	for _, conn := range c.Conns {
		fmt.Println("conn", conn)
		remoteAddr := fmt.Sprintf("%s:%d", conn.Remote, conn.RemotePort)
		if remoteAddr == r {
			return &conn, true
		}
	}
	return nil, false
}

func runBenchtests(b *testing.B, payloads []int, prefix string, f func(p int) func(*testing.B)) {
	for _, p := range payloads {
		name := strings.TrimSpace(strings.Join([]string{prefix, strconv.Itoa(p), "bytes"}, " "))
		b.Run(name, f(p))
	}
}

func BenchmarkUDPEcho(b *testing.B) {
	runBenchtests(b, payloadSizesUDP, "", benchEchoUDP)

	// Enable BPF-based network tracer
	t, err := NewTracer(MakeTestConfig())
	if err != nil {
		b.Fatal(err)
	}
	t.Start()
	defer t.Stop()

	runBenchtests(b, payloadSizesUDP, "eBPF", benchEchoUDP)
}

func benchEchoUDP(size int) func(b *testing.B) {
	payload := genPayload(size)
	echoOnMessage := func(b []byte, n int) []byte {
		resp := make([]byte, len(b))
		copy(resp, b)
		return resp
	}

	return func(b *testing.B) {
		end := make(chan struct{})
		server := common.NewUDPServer(echoOnMessage)
		server.Run(end, size)

		c, err := net.DialTimeout("udp", server.Address, 50*time.Millisecond)
		if err != nil {
			b.Fatal(err)
		}
		defer c.Close()
		r := bufio.NewReader(c)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			c.Write(payload)
			buf := make([]byte, size)
			n, err := r.Read(buf)

			if err != nil || n != len(payload) || !bytes.Equal(payload, buf) {
				b.Fatalf("Sizes: %d, %d. Equal: %v. Error: %s", len(buf), len(payload), bytes.Equal(payload, buf), err)
			}
		}
		b.StopTimer()

		end <- struct{}{}
	}
}

func BenchmarkTCPEcho(b *testing.B) {
	runBenchtests(b, payloadSizesTCP, "", benchEchoTCP)

	// Enable BPF-based network tracer
	t, err := NewTracer(MakeTestConfig())
	if err != nil {
		b.Fatal(err)
	}
	t.Start()
	defer t.Stop()

	runBenchtests(b, payloadSizesTCP, "eBPF", benchEchoTCP)
}

func BenchmarkTCPSend(b *testing.B) {
	runBenchtests(b, payloadSizesTCP, "", benchSendTCP)

	// Enable BPF-based network tracer
	t, err := NewTracer(MakeTestConfig())
	if err != nil {
		b.Fatal(err)
	}
	t.Start()
	defer t.Stop()

	runBenchtests(b, payloadSizesTCP, "eBPF", benchSendTCP)
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
		server := common.NewTCPServer(echoOnMessage)
		server.Run(end)

		c, err := net.DialTimeout("tcp", server.Address, 50*time.Millisecond)
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
		server := common.NewTCPServer(dropOnMessage)
		server.Run(end)

		c, err := net.DialTimeout("tcp", server.Address, 50*time.Millisecond)
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
