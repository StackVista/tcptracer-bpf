// +build linux_bpf

package tracer

import (
	"bytes"
	"fmt"
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/common"
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/procspy"
	"unsafe"

	bpflib "github.com/iovisor/gobpf/elf"
)

/*
#include "../../tcptracer-bpf.h"
*/
import "C"

const (
	v4UDPMapName           = "udp_stats_ipv4"
	v6UDPMapName           = "udp_stats_ipv6"
	v4TCPMapName           = "tcp_stats_ipv4"
	v6TCPMapName           = "tcp_stats_ipv6"
	latestTimestampMapName = "latest_ts"
)

var (
	// Feature versions sourced from: https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md
	// Minimum kernel version -> max(3.15 - eBPF,
	//                               3.18 - tables/maps,
	//                               4.1 - kprobes,
	//                               4.3 - perf events)
	// 	                      -> 4.3
	minRequiredKernelCode = common.LinuxKernelVersionCode(4, 3, 0)
)

type Tracer struct {
	m      *bpflib.Module
	config *Config
	// In flight connections are the connections that already existed before the EBPF module was loaded.
	// These connections are stored with a key without direction, to make it possible to merge with undirected
	// metric stats
	inFlightTCP map[string]*ConnectionStats
}

// maxActive configures the maximum number of instances of the kretprobe-probed functions handled simultaneously.
// This value should be enough for typical workloads (e.g. some amount of processes blocked on the accept syscall).
const maxActive = 128

// IsTracerSupportedByOS returns whether or not the current kernel version supports tracer functionality
func IsTracerSupportedByOS() (bool, error) {
	currentKernelCode, err := bpflib.CurrentKernelVersion()
	if err != nil {
		return false, err
	}

	if currentKernelCode < minRequiredKernelCode {
		return false, fmt.Errorf("incompatible linux version. at least %d required, got %d", minRequiredKernelCode, currentKernelCode)
	}
	return true, nil
}

func NewTracer(config *Config) (*Tracer, error) {
	m, err := loadBPFModule()
	if err != nil {
		return nil, err
	}

	err = m.Load(nil)
	if err != nil {
		return nil, err
	}

	// TODO: Only enable kprobes for traffic collection defined in config
	err = m.EnableKprobes(maxActive)
	if err != nil {
		return nil, err
	}

	if err := initialize(m); err != nil {
		return nil, fmt.Errorf("failed to init module: %s", err)
	}

	// TODO: Improve performance by detaching unnecessary kprobes, once offsets have been figured out in initialize()
	tracer := &Tracer{m: m, config: config, inFlightTCP: make(map[string]*ConnectionStats)}

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

func (t *Tracer) Start() error {
	return nil
}

func (t *Tracer) Stop() {
	t.m.Close()
}

func (t *Tracer) getProcConnections() error {
	procWalker := procspy.NewWalker(t.config.ProcRoot)
	scanner := procspy.NewSyncConnectionScanner(procWalker, t.config.ProcRoot, true)
	defer scanner.Stop()
	conns, err := scanner.Connections()

	if err != nil {
		return fmt.Errorf("failed load existing connections: %s", err)
	}

	// No set in go, so we use a map... identify using connectionstats key from local port
	listeningPorts := make(map[string]bool)
	var connections []struct {
		ConnectionStats
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
			return fmt.Errorf("failed to write to byte buffer: %s", err)
		}

		if conn.Listening {
			listeningPorts[string(localKey)] = true
		} else {
			connections = append(connections, struct {
				ConnectionStats
				string
			}{connWithStats, string(localKey)})
		}
	}

	// Set the direction based on listening ports and add to inFlightTCP connections
	for _, connAndKey := range connections {
		conn := connAndKey.ConnectionStats
		if _, exists := listeningPorts[connAndKey.string]; exists {
			conn.Direction = INCOMING
		}

		// We drop the direction to enable merging with undirected metrics
		connKey, err := conn.WithUnknownDirection().ByteKey(buffer)

		if err != nil {
			return fmt.Errorf("failed to write to byte buffer: %s", err)
		}

		t.addInFlight(string(connKey), conn)
	}

	return nil
}

func (t *Tracer) GetConnections() (*Connections, error) {
	err := t.updateInFlightTCPWithEBPF()
	if err != nil {
		return nil, err
	}

	tcpConns := t.getTcpConnectionsFromInFlight()

	udpConns, err := t.getEbpfUDPConnections()
	if err != nil {
		return nil, err
	}

	return &Connections{Conns: append(tcpConns, udpConns...)}, nil
}

func (t *Tracer) getTcpConnectionsFromInFlight() []ConnectionStats {
	conns := make([]ConnectionStats, 0)

	for key, conn := range t.inFlightTCP {
		conns = append(conns, *conn)
		// Closed connection we only report once. After reporting,
		// they get removed from inFlight
		if conn.State == ACTIVE_CLOSED || conn.State == CLOSED {
			delete(t.inFlightTCP, key)
		}
	}

	return conns
}

// Get connection observations from EBPF and update inFlightTCP connections with that information
func (t *Tracer) updateInFlightTCPWithEBPF() error {
	ebpf_conns, err := t.getEbpfTCPConnections()
	if err != nil {
		return err
	}

	buffer := new(bytes.Buffer)

	for _, conn := range ebpf_conns {
		// We drop the direction to enable merging with undirected metrics
		connKey, err := conn.WithUnknownDirection().ByteKey(buffer)

		if err != nil {
			return fmt.Errorf("failed to write to byte buffer: %s", err)
		}

		// We are not interested in connections which are still initializing
		if conn.State == INITIALIZING {
			continue
		}

		if conn.Direction != UNKNOWN && conn.State != CLOSED {
			// If we already know the direction, we do not need previous in-flight connections and can just put this in, EBPF knows all
			t.addInFlight(string(connKey), conn)
		} else {
			// We had no direction, lets merge the info with what we learned from /proc
			if inFlight, exists := t.inFlightTCP[string(connKey)]; exists {
				inFlight.RecvBytes = conn.RecvBytes
				inFlight.SendBytes = conn.SendBytes
				inFlight.State = conn.State
				// If we observe just a close, we know it was active before (its in inFlight). So we make it ACTIVE_CLOSED
				if conn.State == CLOSED {
					inFlight.State = ACTIVE_CLOSED
				}
			}
		}
	}

	return nil
}

func (t *Tracer) addInFlight(key string, conn ConnectionStats) {
	if len(t.inFlightTCP) >= t.config.MaxConnections {
		return
	}
	t.inFlightTCP[key] = &conn
}

func (t *Tracer) getEbpfTCPConnections() ([]ConnectionStats, error) {
	conns := make([]ConnectionStats, 0)
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

func (t *Tracer) getEbpfUDPConnections() ([]ConnectionStats, error) {
	conns := make([]ConnectionStats, 0)
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

func (t *Tracer) getUDPv4Connections() ([]ConnectionStats, error) {
	mp, err := t.getMap(v4UDPMapName)
	if err != nil {
		return nil, err
	}

	tsMp, err := t.getMap(latestTimestampMapName)
	if err != nil {
		return nil, err
	}

	var latestTime int64
	err = t.m.LookupElement(tsMp, unsafe.Pointer(&zero), unsafe.Pointer(&latestTime))
	if err != nil { // If we can't find latest timestamp, there probably hasn't been any UDP messages yet
		return nil, nil
	}

	// Iterate through all key-value pairs in map
	key, nextKey, stats := &ConnTupleV4{}, &ConnTupleV4{}, &ConnStatsWithTimestamp{}
	active := make([]ConnectionStats, 0)
	expired := make([]*ConnTupleV4, 0)
	for {
		hasNext, _ := t.m.LookupNextElement(mp, unsafe.Pointer(key), unsafe.Pointer(nextKey), unsafe.Pointer(stats))
		if !hasNext {
			break
		} else if stats.isExpired(latestTime, t.config.UDPConnTimeout.Nanoseconds()) {
			expired = append(expired, nextKey.copy())
		} else {
			active = append(active, connStatsFromUDPv4(nextKey, stats))
		}
		key = nextKey
	}

	// Remove expired entries
	for i := range expired {
		t.m.DeleteElement(mp, unsafe.Pointer(expired[i]))
	}
	return active, nil
}

func (t *Tracer) getUDPv6Connections() ([]ConnectionStats, error) {
	mp, err := t.getMap(v6UDPMapName)
	if err != nil {
		return nil, err
	}

	tsMp, err := t.getMap(latestTimestampMapName)
	if err != nil {
		return nil, err
	}

	var latestTime int64
	err = t.m.LookupElement(tsMp, unsafe.Pointer(&zero), unsafe.Pointer(&latestTime))
	if err != nil { // If we can't find latest timestamp, there probably hasn't been any UDP messages yet
		return nil, nil
	}

	// Iterate through all key-value pairs in map
	key, nextKey, stats := &ConnTupleV6{}, &ConnTupleV6{}, &ConnStatsWithTimestamp{}
	active := make([]ConnectionStats, 0)
	expired := make([]*ConnTupleV6, 0)
	for {
		hasNext, _ := t.m.LookupNextElement(mp, unsafe.Pointer(key), unsafe.Pointer(nextKey), unsafe.Pointer(stats))
		if !hasNext {
			break
		} else if stats.isExpired(latestTime, t.config.UDPConnTimeout.Nanoseconds()) {
			expired = append(expired, nextKey.copy())
		} else {
			active = append(active, connStatsFromUDPv6(nextKey, stats))
		}
		key = nextKey
	}

	// Remove expired entries
	for i := range expired {
		t.m.DeleteElement(mp, unsafe.Pointer(expired[i]))
	}
	return active, nil
}

func (t *Tracer) getTCPv4Connections() ([]ConnectionStats, error) {
	mp, err := t.getMap(v4TCPMapName)
	if err != nil {
		return nil, err
	}

	// Iterate through all key-value pairs in map
	key, nextKey, val := &ConnTupleV4{}, &ConnTupleV4{}, &ConnStats{}
	conns := make([]ConnectionStats, 0)
	closed := make([]*ConnTupleV4, 0)
	for {
		hasNext, _ := t.m.LookupNextElement(mp, unsafe.Pointer(key), unsafe.Pointer(nextKey), unsafe.Pointer(val))
		if !hasNext {
			break
		} else {
			stats := connStatsFromTCPv4(nextKey, val)
			conns = append(conns, stats)
			if stats.State == ACTIVE_CLOSED || stats.State == CLOSED {
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

func (t *Tracer) getTCPv6Connections() ([]ConnectionStats, error) {
	mp, err := t.getMap(v6TCPMapName)
	if err != nil {
		return nil, err
	}

	// Iterate through all key-value pairs in map
	key, nextKey, val := &ConnTupleV6{}, &ConnTupleV6{}, &ConnStats{}
	conns := make([]ConnectionStats, 0)
	closed := make([]*ConnTupleV6, 0)
	for {
		hasNext, _ := t.m.LookupNextElement(mp, unsafe.Pointer(key), unsafe.Pointer(nextKey), unsafe.Pointer(val))
		if !hasNext {
			break
		} else {
			stats := connStatsFromTCPv6(nextKey, val)
			conns = append(conns, stats)
			if stats.State == ACTIVE_CLOSED || stats.State == CLOSED {
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

func (t *Tracer) getMap(mapName string) (*bpflib.Map, error) {
	mp := t.m.Map(mapName)
	if mp == nil {
		return nil, fmt.Errorf("no map with name %s", mapName)
	}
	return mp, nil
}

func initialize(m *bpflib.Module) error {
	if err := guess(m); err != nil {
		return fmt.Errorf("error guessing offsets: %v", err)
	}
	return nil
}

func loadBPFModule() (*bpflib.Module, error) {
	buf, err := Asset("tcptracer-ebpf.o")
	if err != nil {
		return nil, fmt.Errorf("couldn't find asset: %s", err)
	}

	m := bpflib.NewModuleFromReader(bytes.NewReader(buf))
	if m == nil {
		return nil, fmt.Errorf("BPF not supported")
	}
	return m, nil
}
