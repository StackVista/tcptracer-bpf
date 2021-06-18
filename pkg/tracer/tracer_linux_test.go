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
	"strconv"
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

	time.Sleep(50 * time.Millisecond)

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

func TestHTTPRequestLogSingleRequest(t *testing.T) {
	tr, err := NewTracer(MakeTestConfig())
	assert.NoError(t, err)
	assert.NoError(t, tr.Start())
	defer tr.Stop()

	testServer, port := createTestHTTPServer()

	httpT := httpLogTest{
		test:       t,
		tracer:     tr,
		server:     testServer,
		client:     testServer.Client(),
		serverPort: port,
	}

	// perform test calls to HTTP server that should be caught by BPF the tracer
	statusCode, respText := httpT.runGETRequest("/")
	assert.Equal(t, 200, statusCode)
	assert.Equal(t, "OK", respText)
	httpT.testHttpStats([]httpStat{
		{StatusCode: 200, MaxResponseTimeMillis: TestHttpServerRootLatency.Milliseconds()},
	})

	// perform test calls to HTTP server that should be caught by BPF the tracer
	httpT.runGETRequest("/error")
	statusCode, respText = httpT.runGETRequest("/notfound")
	assert.Equal(t, 404, statusCode)
	assert.Equal(t, "Not found", respText)
	httpT.testHttpStats([]httpStat{
		{StatusCode: 404, MaxResponseTimeMillis: TestHttpServerNotfoundLatency.Milliseconds()},
		{StatusCode: 500, MaxResponseTimeMillis: TestHttpServerErrorLatency.Milliseconds()},
	})
}

func TestHTTPRequestLogForExistingConnection(t *testing.T) {

	testServer, port := createTestHTTPServer()

	client := &http.Client{Transport: &http.Transport{
		MaxConnsPerHost:     1,
		MaxIdleConns:        1,
		MaxIdleConnsPerHost: 1,
	}}

	httpT := httpLogTest{
		test:       t,
		server:     testServer,
		client:     client,
		serverPort: port,
	}
	// perform first request to establish the only connection
	httpT.runGETRequest("/")

	tr, err := NewTracer(MakeTestConfig())
	assert.NoError(t, err)
	assert.NoError(t, tr.Start())
	defer tr.Stop()
	httpT.tracer = tr

	// perform test calls to HTTP server that should be caught by BPF the tracer
	statusCode, respText := httpT.runGETRequest("/error")
	assert.Equal(t, 500, statusCode)
	assert.Equal(t, "Internal error", respText)
	httpT.testHttpStats([]httpStat{
		{StatusCode: 500, MaxResponseTimeMillis: TestHttpServerErrorLatency.Milliseconds()},
	})
}

func TestHTTPRequestLogDelayBetweenTwoRequestIsNotCounted(t *testing.T) {

	testServer, port := createTestHTTPServer()

	client := &http.Client{Transport: &http.Transport{
		MaxConnsPerHost:     1,
		MaxIdleConns:        1,
		MaxIdleConnsPerHost: 1,
	}}

	httpT := httpLogTest{
		test:       t,
		server:     testServer,
		client:     client,
		serverPort: port,
	}

	tr, err := NewTracer(MakeTestConfig())
	assert.NoError(t, err)
	assert.NoError(t, tr.Start())
	defer tr.Stop()
	httpT.tracer = tr

	// perform test calls to HTTP server that should be caught by BPF the tracer
	statusCode, _ := httpT.runGETRequest("/")
	assert.Equal(t, 200, statusCode)
	httpT.testHttpStats([]httpStat{
		{StatusCode: 200, MaxResponseTimeMillis: TestHttpServerRootLatency.Milliseconds()},
	})

	// sleep for some time to ensure latency is measured only between request and response
	time.Sleep(1 * time.Second)

	// perform test calls to HTTP server that should be caught by BPF the tracer
	statusCode, _ = httpT.runGETRequest("/notfound")
	assert.Equal(t, 404, statusCode)
	httpT.testHttpStats([]httpStat{
		{StatusCode: 404, MaxResponseTimeMillis: TestHttpServerNotfoundLatency.Milliseconds()},
	})
}

func TestProtocolInspectionDisabled(t *testing.T) {
	testConfig := MakeTestConfig()
	testConfig.EnableProtocolInspection = false
	tr, err := NewTracer(testConfig)
	assert.NoError(t, err)
	assert.NoError(t, tr.Start())
	defer tr.Stop()

	testServer, port := createTestHTTPServer()

	httpT := httpLogTest{
		test:       t,
		tracer:     tr,
		server:     testServer,
		client:     testServer.Client(),
		serverPort: port,
	}

	// perform test calls to HTTP server that should be ignored by ebpf tracker
	assertGetRequestStatusCode(t, httpT, "/", 200)
	assertGetRequestStatusCode(t, httpT, "/", 200)
	assertGetRequestStatusCode(t, httpT, "/error", 500)
	assertGetRequestStatusCode(t, httpT, "/notfound", 404)
	httpT.testHttpStats([]httpStat{})
}

func assertGetRequestStatusCode(t *testing.T, httpT httpLogTest, path string, expectedCode int) {
	statusCode, _ := httpT.runGETRequest(path)
	assert.Equal(t, expectedCode, statusCode)
}

type httpLogTest struct {
	test       *testing.T
	server     *httptest.Server
	client     *http.Client
	tracer     Tracer
	serverPort uint16
}

type httpStat struct {
	StatusCode            int
	MaxResponseTimeMillis int64
}

func (ht httpLogTest) getHttpStats() ([]httpStat, error) {
	conns, err := ht.tracer.GetConnections()
	if err != nil {
		return nil, err
	}
	stats := make([]httpStat, 0)
	for i := range conns.Conns {
		conn := conns.Conns[i]
		if conn.LocalPort != ht.serverPort && conn.RemotePort != ht.serverPort {
			continue
		}
		for mi := range conns.Conns[i].Metrics {
			metric := conns.Conns[i].Metrics[mi]
			maxRespTime, err := metric.Value.Histogram.DDSketch.GetMaxValue()
			assert.NoError(ht.test, err)
			statusCode, _ := strconv.Atoi(metric.Tags[common.HTTPStatusCodeTagName])
			stats = append(stats, httpStat{StatusCode: statusCode, MaxResponseTimeMillis: int64(maxRespTime * 1000)})
		}
	}
	sort.Slice(stats, func(i, j int) bool {
		return stats[i].StatusCode < stats[j].StatusCode
	})
	return stats, nil
}

const ToleranceMillis = 250

func (ht httpLogTest) testHttpStats(expected []httpStat) {
	require.Eventually(ht.test, func() bool {
		stats, err := ht.getHttpStats()
		assert.NoError(ht.test, err)
		assert.Equal(ht.test, len(expected), len(stats), "Returned different set stats")
		if len(expected) == len(stats) {
			success := true
			for i := range expected {
				success = success && assert.Equal(ht.test, expected[i].StatusCode, stats[i].StatusCode)
				success = success && assert.InDelta(ht.test, expected[i].MaxResponseTimeMillis, stats[i].MaxResponseTimeMillis, ToleranceMillis)
			}
			return success
		} else {
			return assert.Equal(ht.test, expected, stats, "Returned different set stats")
		}
	}, 6*time.Second, 300*time.Millisecond)
}

func (ht httpLogTest) runGETRequest(path string) (int, string) {
	fmt.Printf("Address: %s\n", ht.server.Listener.Addr().String())
	resp, err := ht.client.Get("http://" + ht.server.Listener.Addr().String() + path)
	assert.NoError(ht.test, err)
	respBytes, err := ioutil.ReadAll(resp.Body)
	assert.NoError(ht.test, resp.Body.Close())
	assert.NoError(ht.test, err)
	return resp.StatusCode, string(respBytes)
}

const TestHttpServerRootLatency = 1 * time.Second
const TestHttpServerNotfoundLatency = 1 * time.Second
const TestHttpServerErrorLatency = 1 * time.Second

// createTestHTTPServer returns created http server and the port it is listening on
func createTestHTTPServer() (*httptest.Server, uint16) {
	handler := http.NewServeMux()
	handler.Handle("/", http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		<-time.After(TestHttpServerRootLatency)
		writer.WriteHeader(200)
		_, _ = writer.Write([]byte("OK"))
	}))
	handler.Handle("/notfound", http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		<-time.After(TestHttpServerNotfoundLatency)
		writer.WriteHeader(404)
		_, _ = writer.Write([]byte("Not found"))
	}))
	handler.Handle("/error", http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		<-time.After(TestHttpServerErrorLatency)
		writer.WriteHeader(500)
		_, _ = writer.Write([]byte("Internal error"))
	}))
	newServer := httptest.NewServer(handler)
	boundAddr := newServer.Listener.Addr().String()
	colonIndex := strings.LastIndex(boundAddr, ":")
	boundPort, _ := strconv.Atoi(boundAddr[colonIndex+1:])
	return newServer, uint16(boundPort)
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
