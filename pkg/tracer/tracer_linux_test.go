// +build linux_bpf

package tracer

import (
	"bufio"
	"fmt"
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/common"
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/config"
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/network"
	logger "github.com/cihub/seelog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"
	"time"
)

const CheckMessageSize = true

func TestMain(m *testing.M) {
	testLogger, err := logger.LoggerFromConfigAsFile("seelog-tests.xml")
	if err != nil {
		panic(err)
	}
	err = logger.ReplaceLogger(testLogger)
	if err != nil {
		panic(err)
	}
	defer logger.Flush()
	os.Exit(m.Run())
}

func MakeTestConfig() *config.Config {
	c := config.MakeDefaultConfig()
	c.ProcRoot = common.TestRoot()
	return c
}

func TestTCPSendAndReceiveWithNamespaces(t *testing.T) {
	// Enable network tracer
	tr, err := NewTracer(MakeTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	tr.Start()
	defer tr.Stop()

	// Create TCP Server which sends back serverMessageSize bytes
	server := network.NewTCPServer(func(c net.Conn) {
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
	assert.NotNil(t, conn1)
	if CheckMessageSize {
		assert.Equal(t, clientMessageSize, int(conn1.SendBytes))
		assert.Equal(t, serverMessageSize, int(conn1.RecvBytes))
	}
	assert.Equal(t, conn1.Direction, common.OUTGOING)
	assert.Equal(t, conn1.State, common.ACTIVE)

	conn2, ok := findConnection(c.RemoteAddr(), c.LocalAddr(), connections)
	assert.True(t, ok)
	assert.NotNil(t, conn2)
	if CheckMessageSize {
		assert.Equal(t, clientMessageSize, int(conn2.RecvBytes))
		assert.Equal(t, serverMessageSize, int(conn2.SendBytes))
	}
	assert.Equal(t, conn2.Direction, common.INCOMING)
	assert.Equal(t, conn2.State, common.ACTIVE)

	// assert that localhost connections both have the same namespace
	assert.NotNil(t, conn1.NetworkNamespace)
	assert.NotNil(t, conn2.NetworkNamespace)
	assert.Equal(t, conn1.NetworkNamespace, conn2.NetworkNamespace)

	// Write clientMessageSize to server, to shut down the connection
	if _, err = c.Write(genPayload(0)); err != nil {
		t.Fatal(err)
	}

	doneChan <- struct{}{}
}

func TestReportInFlightTCPConnectionWithMetrics(t *testing.T) {
	// Create TCP Server which sends back serverMessageSize bytes
	server := network.NewTCPServer(func(c net.Conn) {
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
	if CheckMessageSize {
		assert.Equal(t, clientMessageSize, int(conn1.SendBytes))
		assert.Equal(t, serverMessageSize, int(conn1.RecvBytes))
	}
	assert.Equal(t, conn1.Direction, common.UNKNOWN)
	assert.Equal(t, conn1.State, common.ACTIVE)

	conn2, ok := findConnection(c.RemoteAddr(), c.LocalAddr(), connections)
	assert.True(t, ok)
	if CheckMessageSize {
		assert.Equal(t, clientMessageSize, int(conn2.RecvBytes))
		assert.Equal(t, serverMessageSize, int(conn2.SendBytes))
	}
	assert.Equal(t, conn2.Direction, common.INCOMING)
	assert.Equal(t, conn2.State, common.ACTIVE)

	// assert that localhost connections both have the same namespace and that it's not nil
	assert.Equal(t, conn1.NetworkNamespace, conn2.NetworkNamespace)
	assert.NotNil(t, conn1.NetworkNamespace)
	assert.NotNil(t, conn2.NetworkNamespace)

	// Write clientMessageSize to server, to shut down the connection
	if _, err = c.Write(genPayload(0)); err != nil {
		t.Fatal(err)
	}

	doneChan <- struct{}{}
}

func TestCloseInFlightTCPConnectionWithEBPFWithData(t *testing.T) {
	// Create TCP Server which sends back serverMessageSize bytes
	server := network.NewTCPServer(func(c net.Conn) {
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
	server := network.NewTCPServerAllPorts(func(c net.Conn) {
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

	// Enable network tracer
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
	if CheckMessageSize {
		assert.Equal(t, 0, int(conn1.SendBytes))
		assert.Equal(t, 0, int(conn1.RecvBytes))
	}
	assert.Equal(t, conn1.Direction, common.UNKNOWN)
	assert.Equal(t, conn1.State, common.ACTIVE_CLOSED)

	conn2, ok := findConnection(c.RemoteAddr(), c.LocalAddr(), connections)
	assert.True(t, ok)
	if CheckMessageSize {
		assert.Equal(t, 0, int(conn2.RecvBytes))
		assert.Equal(t, 0, int(conn2.SendBytes))
	}
	assert.Equal(t, conn2.Direction, common.INCOMING)
	assert.Equal(t, conn2.State, common.ACTIVE_CLOSED)

	doneChan <- struct{}{}
}

func TestCloseInFlightTCPConnectionNoData(t *testing.T) {
	connectChan := make(chan struct{})
	closeChan := make(chan struct{})
	closedChan := make(chan struct{})

	// Create TCP Server which sends back serverMessageSize bytes
	server := network.NewTCPServer(func(c net.Conn) {
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

	// Enable network tracer
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
	if CheckMessageSize {
		assert.Equal(t, 0, int(conn1.SendBytes))
		assert.Equal(t, 0, int(conn1.RecvBytes))
	}
	assert.Equal(t, conn1.Direction, common.UNKNOWN)
	assert.Equal(t, conn1.State, common.ACTIVE_CLOSED)

	conn2, ok := findConnection(c.RemoteAddr(), c.LocalAddr(), connections)
	assert.True(t, ok)
	if CheckMessageSize {
		assert.Equal(t, 0, int(conn2.RecvBytes))
		assert.Equal(t, 0, int(conn2.SendBytes))
	}
	assert.Equal(t, conn2.Direction, common.INCOMING)
	assert.Equal(t, conn2.State, common.ACTIVE_CLOSED)

	doneChan <- struct{}{}
}

func TestTCPClosedConnectionsAreFirstReportedAndThenCleanedUp(t *testing.T) {
	// Enable network tracer
	tr, err := NewTracer(MakeTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	tr.Start()
	defer tr.Stop()

	// Create TCP Server which sends back serverMessageSize bytes
	server := network.NewTCPServer(func(c net.Conn) {
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

func TestUDPSendAndReceive(t *testing.T) {
	// Enable network tracer
	tr, err := NewTracer(MakeTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	tr.Start()
	defer tr.Stop()

	// Create UDP Server which sends back serverMessageSize bytes
	server := network.NewUDPServer(func(b []byte, n int) []byte {
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
	if CheckMessageSize {
		assert.Equal(t, clientMessageSize, int(conn.SendBytes))
		assert.Equal(t, serverMessageSize, int(conn.RecvBytes))
	}
	assert.Equal(t, common.UNKNOWN, conn.Direction)
	assert.Equal(t, common.ACTIVE, conn.State)

	doneChan <- struct{}{}
}

func TestHTTPRequestLog(t *testing.T) {
	tr, err := NewTracer(MakeTestConfig())
	assert.NoError(t, err)
	assert.NoError(t, tr.Start())
	defer tr.Stop()

	time.Sleep(2 * time.Second)

	testServer := createTestHTTPServer()

	getServerStats := func() ([]map[string]string, error) {
		conns, err := tr.GetConnections()
		if err != nil {
			return nil, err
		}
		labels := make([]map[string]string, 0)
		for i := range conns.Conns {
			for mi := range conns.Conns[i].Metrics {
				labels = append(labels, conns.Conns[i].Metrics[mi].Labels)
			}
		}
		return labels, nil
	}

	assertHttpStats := func(expected []map[string]string) {
		require.Eventually(t, func() bool {
			stats, err := getServerStats()
			assert.NoError(t, err)
			sort.Slice(stats, func(i, j int) bool {
				return strings.Compare(stats[i]["code"], stats[j]["code"]) < 0
			})
			return assert.Equal(t, expected, stats)
		}, 6*time.Second, 300*time.Millisecond)
	}

	// perform test calls to HTTP server that should be caught by BPF the tracer
	statusCode, respText := runGETRequest(t, testServer, "/")
	assert.Equal(t, 200, statusCode)
	assert.Equal(t, "OK", respText)
	assertHttpStats([]map[string]string{
		{"code": "2xx", "type": "http_response_time"},
	})

	// perform test calls to HTTP server that should be caught by BPF the tracer
	statusCode, respText = runGETRequest(t, testServer, "/notfound")
	assert.Equal(t, 404, statusCode)
	assert.Equal(t, "Not found", respText)
	assertHttpStats([]map[string]string{
		{"code": "2xx", "type": "http_response_time"},
		{"code": "4xx", "type": "http_response_time"},
	})
}

func runGETRequest(t *testing.T, srv *httptest.Server, path string) (int, string) {
	fmt.Printf("Address: %s\n", srv.Listener.Addr().String())
	resp, err := srv.Client().Get("http://" + srv.Listener.Addr().String() + path)
	assert.NoError(t, err)
	respBytes, err := ioutil.ReadAll(resp.Body)
	assert.NoError(t, resp.Body.Close())
	assert.NoError(t, err)
	return resp.StatusCode, string(respBytes)
}

func createTestHTTPServer() *httptest.Server {
	handler := http.NewServeMux()
	handler.Handle("/", http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(200)
		_, _ = writer.Write([]byte("OK"))
	}))
	handler.Handle("/notfound", http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(404)
		_, _ = writer.Write([]byte("Not found"))
	}))
	handler.Handle("/error", http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(500)
		_, _ = writer.Write([]byte("Internal error"))
	}))
	return httptest.NewServer(handler)
}

func TestTCPSendPage(t *testing.T) {
	// Enable network tracer
	tr, err := NewTracer(MakeTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	tr.Start()
	defer tr.Stop()

	// Create TCP Server which sends back serverMessageSize bytes
	server := network.NewTCPServer(func(c net.Conn) {
		r := bufio.NewReader(c)
		r.ReadBytes(byte('\n'))
		c.Write(genPayload(serverMessageSize))
		r.ReadBytes(byte('\n'))
		c.Close()
	})
	doneChan := make(chan struct{})
	server.Run(doneChan)

	fmt.Printf("Addr: %s\n", server.Address)
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
	if CheckMessageSize {
		assert.Equal(t, clientMessageFileSize, int(conn1.SendBytes))
		assert.Equal(t, serverMessageSize, int(conn1.RecvBytes))
	}
	assert.Equal(t, conn1.Direction, common.OUTGOING)
	assert.Equal(t, conn1.State, common.ACTIVE)

	conn2, ok := findConnection(c.RemoteAddr(), c.LocalAddr(), connections)
	assert.True(t, ok)
	if CheckMessageSize {
		assert.Equal(t, clientMessageFileSize, int(conn2.RecvBytes))
		assert.Equal(t, serverMessageSize, int(conn2.SendBytes))
	}
	assert.Equal(t, conn2.Direction, common.INCOMING)
	assert.Equal(t, conn2.State, common.ACTIVE)

	// Write clientMessageSize to server, to shut down the connection
	if _, err = c.Write(genPayload(0)); err != nil {
		t.Fatal(err)
	}

	doneChan <- struct{}{}
}
