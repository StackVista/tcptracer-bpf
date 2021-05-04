// +build linux_bpf

package tracer

import (
	"bytes"
	"fmt"
	"github.com/golang/protobuf/proto"
	"sync"
	"syscall"
	"unsafe"

	"github.com/DataDog/sketches-go/ddsketch"
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/common"
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/config"
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/procspy"

	logger "github.com/cihub/seelog"

	bpflib "github.com/iovisor/gobpf/elf"
)

/*
#include "../../tcptracer-bpf.h"
*/
import "C"

type HttpCode = int

type HttpStatusCodeGroup = string

const (
	Http_1xx HttpStatusCodeGroup = "1xx"
	Http_2xx HttpStatusCodeGroup = "2xx"
	Http_3xx HttpStatusCodeGroup = "3xx"
	Http_4xx HttpStatusCodeGroup = "4xx"
	Http_5xx HttpStatusCodeGroup = "5xx"
)

type ConnInsight struct {
	ApplicationProtocol string
	HttpMetrics         map[HttpStatusCodeGroup]*ddsketch.DDSketch
}

type LinuxTracer struct {
	m      *bpflib.Module
	config *config.Config
	// In flight connections are the connections that already existed before the EBPF module was loaded.
	// These connections are stored with a key without direction, to make it possible to merge with undirected
	// metric stats
	inFlightTCP map[string]*common.ConnectionStats

	// Contains events used to get an insight about the connections
	// See `maps/perf_events` in `tcptracer-maps.h`
	perfEventsBytes   chan []byte
	perfEventsLostLog chan uint64
	perfMap           *bpflib.PerfMap

	tcpConnInsights     map[common.ConnTupleV4]ConnInsight // TODO gonna leak
	tcpConnInsightsLock sync.RWMutex
	onPerfEvent         func(event common.PerfEvent)
	stopCh              chan bool
}

var (
	DebugFsPath      = "/sys/kernel/debug"
	DebugFsMagic     = int64(0x64626720) //http://man7.org/linux/man-pages/man2/statfs.2.html
	PerfEventsBuffer = 100
)

func MakeTracer(config *config.Config) (Tracer, error) {

	m, err := loadBPFModule()
	if err != nil {
		return nil, err
	}

	sectionParams := make(map[string]bpflib.SectionParams)
	sectionParams["maps/"+common.PerfEvents] = bpflib.SectionParams{
		PerfRingBufferPageCount: 256,
	}
	err = m.Load(sectionParams)
	if err != nil {
		return nil, err
	}

	// TODO: Only enable kprobes for traffic collection defined in config
	err = m.EnableKprobes(common.MaxActive)
	if err != nil {
		err = m.Close()
		if err != nil {
			return nil, logger.Error(err.Error())
		}
	}

	if err := initialize(m); err != nil {
		return nil, logger.Errorf("failed to init module: %s", err)
	}

	logger.Info("Starting tracepipe")
	RunTracepipe()

	perfEventsBytes := make(chan []byte, PerfEventsBuffer)
	perfEventsLostLog := make(chan uint64, PerfEventsBuffer)

	perfMap, err := bpflib.InitPerfMap(m, common.PerfEvents, perfEventsBytes, perfEventsLostLog)
	if err != nil {
		return nil, err
	}

	inFlightTCP := make(map[string]*common.ConnectionStats)

	// TODO: Improve performance by detaching unnecessary kprobes, once offsets have been figured out in initialize()
	tracer := &LinuxTracer{
		m:                   m,
		config:              config,
		inFlightTCP:         inFlightTCP,
		perfMap:             perfMap,
		perfEventsBytes:     perfEventsBytes,
		perfEventsLostLog:   perfEventsLostLog,
		tcpConnInsights:     make(map[common.ConnTupleV4]ConnInsight),
		tcpConnInsightsLock: sync.RWMutex{},
		stopCh:              make(chan bool),
	}

	// Get data from /proc AFTER ebpf has been initialized. This makes sure that we do not miss any
	// connections on the host. Some may be duplicate, but the mergin of inFlight end EBPF will sort this out
	if config.BackfillFromProc {
		err = tracer.getProcConnections()
		if err != nil {
			return nil, err
		}
	}

	return tracer, nil
}

// CheckTracerSupport returns whether or not the current kernel version supports tracer functionality
func CheckTracerSupport() (bool, error) {
	currentKernelCode, err := bpflib.CurrentKernelVersion()
	if err != nil {
		return false, err
	}

	if currentKernelCode < common.MinRequiredKernelCode {
		return false, logger.Errorf("incompatible linux version. at least %d required, got %d", common.MinRequiredKernelCode, currentKernelCode)
	}

	if err = ensureDebugFsMounted(); err != nil {
		return false, err
	}

	return true, nil
}

// We use debugfs interface to work with kprobes (kernel tracing) and we must ensure debugfs is mounted.
// On Amazon Linux due to a bug https://forums.aws.amazon.com/thread.jspa?messageID=753257
// debugfs is not automatically mounted and we try to mount ourselves
func ensureDebugFsMounted() error {
	if ok, err := isDebugFsMounted(); err == nil {
		if ok {
			logger.Debug("debugfs already mounted")
			return nil
		} else {
			err := syscall.Mount("debugfs", DebugFsPath, "debugfs", 0, "")
			if err != nil {
				// http://man7.org/linux/man-pages/man2/mount.2.html#ERRORS
				switch err {
				case syscall.EBUSY:
					logger.Info("debugfs already mounted")
				case syscall.EPERM:
					return logger.Error("no permissions to mount debugfs!")
				default:
					// http://www-numi.fnal.gov/offline_software/srt_public_context/WebDocs/Errors/unix_system_errors.html
					return logger.Errorf("debugfs mount error: %d - %v\n", err, err)
				}
			} else {
				logger.Info("debugfs successfully mounted")
			}
			return nil
		}
	} else {
		return logger.Errorf("cannot check debugfs mount: %v\n", err)
	}
}

func isDebugFsMounted() (bool, error) {
	var data syscall.Statfs_t
	if err := syscall.Statfs(DebugFsPath, &data); err != nil {
		return false, fmt.Errorf("cannot statfs %q: %v", DebugFsPath, err)
	}
	return data.Type == DebugFsMagic, nil
}

func (t *LinuxTracer) Start() error {

	go func() {
	EvLoop:
		for {
			select {
			case payload := <-t.perfEventsBytes:
				perfEvent := perfEvent(payload)
				logger.Tracef("received perf event: %v (bytes [%d]%v)", perfEvent, len(payload), payload)
				t.dispatchPerfEvent(perfEvent)
				break
			case lost := <-t.perfEventsLostLog:
				logger.Infof("Lost %d", lost)
				break
			case <-t.stopCh:
				break EvLoop
			}
		}
	}()

	t.perfMap.PollStart()

	return nil
}

func (t *LinuxTracer) Stop() {
	logger.Info("Stopping linux network tracer")
	t.stopCh <- true
	t.perfMap.PollStop()
	err := t.m.Close()
	if err != nil {
		logger.Error(err.Error())
	}
}

func (t *LinuxTracer) GetConnections() (*common.Connections, error) {

	err := t.updateInFlightTCPWithEBPF()
	if err != nil {
		return nil, err
	}

	tcpConns := t.getTcpConnectionsFromInFlight()

	tcpConns = t.enrichTcpConns(tcpConns)

	udpConns, err := t.getEbpfUDPConnections()
	if err != nil {
		return nil, err
	}

	return &common.Connections{Conns: append(tcpConns, udpConns...)}, nil
}

// Linux Tracer internal functions
func (t *LinuxTracer) getProcConnections() error {
	procWalker := procspy.NewWalker(t.config.ProcRoot)
	scanner := procspy.NewSyncConnectionScanner(procWalker, t.config.ProcRoot, true)
	defer scanner.Stop()
	conns, err := scanner.Connections()

	if err != nil {
		return logger.Errorf("failed load existing connections: %s", err)
	}

	// No set in go, so we use a map... identify using connectionstats key from local port
	// Listening ports on specific interfaces
	listeningOnSpecificInterfaces := make(map[string]bool)
	listeningPortsOnAllInterfaces := make(map[uint16]bool)

	var connections []struct {
		common.ConnectionStats
		string
	}

	buffer := new(bytes.Buffer)

	// Collect the data and listening ports
	for conn := conns.Next(); conn != nil; conn = conns.Next() {
		connWithStats := connStatsFromProcSpy(conn)
		localKey, err := connWithStats.WithOnlyLocal().ByteKey(buffer)

		if conn.Proc.PID == 0 {
			continue
		}

		if err != nil {
			return logger.Errorf("failed to write to byte buffer: %s", err)
		}

		if conn.Listening {
			if conn.LocalAddress.IsUnspecified() {
				listeningPortsOnAllInterfaces[conn.LocalPort] = true
			} else {
				listeningOnSpecificInterfaces[string(localKey)] = true
			}
		} else {
			connections = append(connections, struct {
				common.ConnectionStats
				string
			}{connWithStats, string(localKey)})
		}
	}

	// Set the direction based on listening ports and add to inFlightTCP connections
	for _, connAndKey := range connections {
		conn := connAndKey.ConnectionStats
		if _, exists := listeningOnSpecificInterfaces[connAndKey.string]; exists {
			conn.Direction = common.INCOMING
		}

		if _, exists := listeningPortsOnAllInterfaces[conn.LocalPort]; exists {
			conn.Direction = common.INCOMING
		}

		// We drop the direction to enable merging with undirected metrics
		connKey, err := conn.WithUnknownDirection().ByteKey(buffer)

		if err != nil {
			return logger.Errorf("failed to write to byte buffer: %s", err)
		}

		t.addInFlight(string(connKey), conn)
	}

	return nil
}

func (t *LinuxTracer) getTcpConnectionsFromInFlight() []common.ConnectionStats {
	conns := make([]common.ConnectionStats, 0)

	for key, conn := range t.inFlightTCP {
		conns = append(conns, *conn)
		// Closed connection we only report once. After reporting,
		// they get removed from inFlight
		if conn.State == common.ACTIVE_CLOSED || conn.State == common.CLOSED {
			delete(t.inFlightTCP, key)
		}
	}

	return conns
}

// Get connection observations from EBPF and update inFlightTCP connections with that information
func (t *LinuxTracer) updateInFlightTCPWithEBPF() error {
	ebpf_conns, err := t.getEbpfTCPConnections()
	if err != nil {
		return err
	}

	buffer := new(bytes.Buffer)

	for _, conn := range ebpf_conns {
		// We drop the direction to enable merging with undirected metrics
		connKey, err := conn.WithUnknownDirection().ByteKey(buffer)

		if err != nil {
			return logger.Errorf("failed to write to byte buffer: %s", err)
		}

		// We are not interested in connections which are still initializing
		if conn.State == common.INITIALIZING {
			continue
		}

		if conn.Direction != common.UNKNOWN && conn.State != common.CLOSED {
			// If we already know the direction, we do not need previous in-flight connections and can just put this in, EBPF knows all
			t.addInFlight(string(connKey), conn)
		} else {
			// We had no direction, lets merge the info with what we learned from /proc
			if inFlight, exists := t.inFlightTCP[string(connKey)]; exists {
				inFlight.RecvBytes = conn.RecvBytes
				inFlight.SendBytes = conn.SendBytes
				inFlight.State = conn.State
				// If we observe just a close, we know it was active before (its in inFlight). So we make it ACTIVE_CLOSED
				if conn.State == common.CLOSED {
					inFlight.State = common.ACTIVE_CLOSED
				}
			}
		}
	}

	return nil
}

func (t *LinuxTracer) addInFlight(key string, conn common.ConnectionStats) {
	if len(t.inFlightTCP) >= t.config.MaxConnections {
		logger.Warnf("Exceeded maximum connections %d", t.config.MaxConnections)
		return
	}
	t.inFlightTCP[key] = &conn
}

func (t *LinuxTracer) getEbpfTCPConnections() ([]common.ConnectionStats, error) {
	conns := make([]common.ConnectionStats, 0)
	if t.config.CollectTCPConns {
		v4, err := t.getTCPv4Connections()
		if err != nil {
			return nil, err
		}
		v6, err := t.getTCPv6Connections()
		if err != nil {
			return nil, err
		}
		conns = append(conns, append(v4, v6...)...)
	}
	return conns, nil
}

func (t *LinuxTracer) getEbpfUDPConnections() ([]common.ConnectionStats, error) {
	conns := make([]common.ConnectionStats, 0)
	if t.config.CollectUDPConns {
		v4, err := t.getUDPv4Connections()
		if err != nil {
			return nil, err
		}
		v6, err := t.getUDPv6Connections()
		if err != nil {
			return nil, err
		}
		conns = append(conns, append(v4, v6...)...)
	}
	return conns, nil
}

func (t *LinuxTracer) getUDPv4Connections() ([]common.ConnectionStats, error) {
	mp, err := t.getMap(common.V4UDPMapName)
	if err != nil {
		return nil, err
	}

	tsMp, err := t.getMap(common.LatestTimestampMapName)
	if err != nil {
		return nil, err
	}

	var latestTime int64
	err = t.m.LookupElement(tsMp, unsafe.Pointer(&zero), unsafe.Pointer(&latestTime))
	if err != nil { // If we can't find latest timestamp, there probably hasn't been any UDP messages yet
		return nil, nil
	}

	// Iterate through all key-value pairs in map
	key, nextKey, connStats := &ConnTupleV4{}, &ConnTupleV4{}, &ConnStatsWithTimestamp{}
	active := make([]common.ConnectionStats, 0)
	expired := make([]*ConnTupleV4, 0)
	for {
		hasNext, _ := t.m.LookupNextElement(mp, unsafe.Pointer(key), unsafe.Pointer(nextKey), unsafe.Pointer(connStats))
		if !hasNext {
			break
		} else if connStats.isExpired(latestTime, t.config.UDPConnTimeout.Nanoseconds()) {
			expired = append(expired, nextKey.copy())
		} else {
			active = append(active, connStatsFromUDPv4(nextKey, connStats))
		}
		key = nextKey
	}

	// Remove expired entries
	for i := range expired {
		t.m.DeleteElement(mp, unsafe.Pointer(expired[i]))
	}
	return active, nil
}

func (t *LinuxTracer) getUDPv6Connections() ([]common.ConnectionStats, error) {
	mp, err := t.getMap(common.V6UDPMapName)
	if err != nil {
		return nil, err
	}

	tsMp, err := t.getMap(common.LatestTimestampMapName)
	if err != nil {
		return nil, err
	}

	var latestTime int64
	err = t.m.LookupElement(tsMp, unsafe.Pointer(&zero), unsafe.Pointer(&latestTime))
	if err != nil { // If we can't find latest timestamp, there probably hasn't been any UDP messages yet
		return nil, nil
	}

	// Iterate through all key-value pairs in map
	key, nextKey, connStats := &ConnTupleV6{}, &ConnTupleV6{}, &ConnStatsWithTimestamp{}
	active := make([]common.ConnectionStats, 0)
	expired := make([]*ConnTupleV6, 0)
	for {
		hasNext, _ := t.m.LookupNextElement(mp, unsafe.Pointer(key), unsafe.Pointer(nextKey), unsafe.Pointer(connStats))
		if !hasNext {
			break
		} else if connStats.isExpired(latestTime, t.config.UDPConnTimeout.Nanoseconds()) {
			expired = append(expired, nextKey.copy())
		} else {
			active = append(active, connStatsFromUDPv6(nextKey, connStats))
		}
		key = nextKey
	}

	// Remove expired entries
	for i := range expired {
		t.m.DeleteElement(mp, unsafe.Pointer(expired[i]))
	}
	return active, nil
}

func (t *LinuxTracer) getTCPv4Connections() ([]common.ConnectionStats, error) {
	mp, err := t.getMap(common.V4TCPMapName)
	if err != nil {
		return nil, err
	}

	// Iterate through all key-value pairs in map
	key, nextKey, connStats := &ConnTupleV4{}, &ConnTupleV4{}, &ConnStats{}
	conns := make([]common.ConnectionStats, 0)
	closed := make([]*ConnTupleV4, 0)
	for {
		hasNext, _ := t.m.LookupNextElement(mp, unsafe.Pointer(key), unsafe.Pointer(nextKey), unsafe.Pointer(connStats))
		if !hasNext {
			break
		} else {
			stats := connStatsFromTCPv4(nextKey, connStats)
			conns = append(conns, stats)
			if stats.State == common.ACTIVE_CLOSED || stats.State == common.CLOSED {
				closed = append(closed, nextKey.copy())
			}
			key = nextKey
		}
	}

	// Remove closed entries
	for i := range closed {
		t.m.DeleteElement(mp, unsafe.Pointer(closed[i]))
	}
	return conns, nil
}

func (t *LinuxTracer) getTCPv6Connections() ([]common.ConnectionStats, error) {
	mp, err := t.getMap(common.V6TCPMapName)
	if err != nil {
		return nil, err
	}

	// Iterate through all key-value pairs in map
	key, nextKey, connStats := &ConnTupleV6{}, &ConnTupleV6{}, &ConnStats{}
	conns := make([]common.ConnectionStats, 0)
	closed := make([]*ConnTupleV6, 0)
	for {
		hasNext, _ := t.m.LookupNextElement(mp, unsafe.Pointer(key), unsafe.Pointer(nextKey), unsafe.Pointer(connStats))
		if !hasNext {
			break
		} else {
			stats := connStatsFromTCPv6(nextKey, connStats)
			conns = append(conns, stats)
			if stats.State == common.ACTIVE_CLOSED || stats.State == common.CLOSED {
				closed = append(closed, nextKey.copy())
			}
			key = nextKey
		}
	}

	// Remove closed entries
	for i := range closed {
		t.m.DeleteElement(mp, unsafe.Pointer(closed[i]))
	}
	return conns, nil
}

func (t *LinuxTracer) getMap(mapName string) (*bpflib.Map, error) {
	mp := t.m.Map(mapName)
	if mp == nil {
		return nil, logger.Errorf("no map with name %s", mapName)
	}
	return mp, nil
}

func (t *LinuxTracer) dispatchPerfEvent(event common.PerfEvent) {
	if event.HTTPResponse != nil {
		logger.Tracef("http response: %v", event.HTTPResponse)
		httpRes := event.HTTPResponse

		t.tcpConnInsightsLock.Lock()
		defer t.tcpConnInsightsLock.Unlock()
		conn, ok := t.tcpConnInsights[httpRes.Connection]
		httpProtocol := "http"
		if !ok {
			conn = ConnInsight{
				ApplicationProtocol: httpProtocol,
				HttpMetrics:         make(map[HttpStatusCodeGroup]*ddsketch.DDSketch),
			}
		}
		conn.ApplicationProtocol = httpProtocol

		var httpStatusGroup HttpStatusCodeGroup
		if httpRes.StatusCode >= 100 && httpRes.StatusCode < 200 {
			httpStatusGroup = Http_1xx
		} else if httpRes.StatusCode >= 200 && httpRes.StatusCode < 300 {
			httpStatusGroup = Http_2xx
		} else if httpRes.StatusCode >= 300 && httpRes.StatusCode < 400 {
			httpStatusGroup = Http_3xx
		} else if httpRes.StatusCode >= 400 && httpRes.StatusCode < 500 {
			httpStatusGroup = Http_4xx
		} else if httpRes.StatusCode >= 500 && httpRes.StatusCode < 600 {
			httpStatusGroup = Http_5xx
		} else {
			logger.Tracef("incorrect status code")
			return
		}

		latencyCounter, ok := conn.HttpMetrics[httpStatusGroup]
		if !ok {
			var err error
			latencyCounter, err = ddsketch.NewDefaultDDSketch(0.001)
			if err != nil {
				logger.Errorf("can't create dd sketch")
			}
			conn.HttpMetrics[httpStatusGroup] = latencyCounter
		}
		err := latencyCounter.Add(httpRes.ResponseTime.Seconds())
		if err != nil {
			logger.Errorf("can't count")
		}
		t.tcpConnInsights[httpRes.Connection] = conn

	} else if event.MySQLGreeting != nil {
		logger.Tracef("mysql greeting: %v", event.MySQLGreeting)
		mysqlGreeting := event.MySQLGreeting

		conn, ok := t.tcpConnInsights[mysqlGreeting.Connection]
		if !ok {
			conn = ConnInsight{
				ApplicationProtocol: "mysql",
				HttpMetrics:         make(map[HttpStatusCodeGroup]*ddsketch.DDSketch),
			}
		}
		conn.ApplicationProtocol = "mysql"
		t.tcpConnInsights[mysqlGreeting.Connection] = conn
	} else if event.Error != nil {
		logger.Infof("perf events error: %v", event.Error)
	}
}

func (t *LinuxTracer) enrichTcpConns(conns []common.ConnectionStats) []common.ConnectionStats {
	logger.Infof("enrich tcp connections")
	for i := range conns {
		conn := conns[i]
		t.tcpConnInsightsLock.RLock()
		connection := conn.GetConnection()
		connInsight, ok := t.tcpConnInsights[connection]
		t.tcpConnInsightsLock.RUnlock()
		if ok {
			logger.Infof("enriched %v with %v", connection, connInsight)
			if connInsight.ApplicationProtocol != "" {
				conn.ApplicationProtocol = connInsight.ApplicationProtocol
			}
			for statusCode, metric := range connInsight.HttpMetrics {
				metricSketchBytes, err := proto.Marshal(metric.ToProto())
				if err != nil {
					logger.Errorf("can't encode metric sketch for %v http_code=%d: %v", conn, statusCode, err)
					continue
				}
				conn.Metrics = append(conn.Metrics, common.Metric{
					Labels:   map[string]string{"type": "http_response_time", "code": statusCode},
					DDSketch: metricSketchBytes,
				})
			}
			connInsight.HttpMetrics = make(map[HttpStatusCodeGroup]*ddsketch.DDSketch)
			t.tcpConnInsightsLock.Lock()
			t.tcpConnInsights[connection] = connInsight
			t.tcpConnInsightsLock.Unlock()
		}
		conns[i] = conn
	}
	return conns
}

func initialize(m *bpflib.Module) error {
	if err := guess(m); err != nil {
		return logger.Errorf("error guessing offsets: %v", err)
	}
	return nil
}

func loadBPFModule() (*bpflib.Module, error) {
	buf, err := Asset("tcptracer-ebpf.o")
	if err != nil {
		return nil, logger.Errorf("couldn't find asset: %s", err)
	}

	m := bpflib.NewModuleFromReader(bytes.NewReader(buf))
	if m == nil {
		return nil, logger.Errorf("BPF not supported")
	}
	return m, nil
}
