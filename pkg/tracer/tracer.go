// +build linux_bpf

package tracer

import (
	"bytes"
	"fmt"
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
	minRequiredKernelCode = linuxKernelVersionCode(4, 3, 0)
)

type Tracer struct {
	m      *bpflib.Module
	config *Config
}

// maxActive configures the maximum number of instances of the kretprobe-probed functions handled simultaneously.
// This value should be enough for typical workloads (e.g. some amount of processes blocked on the accept syscall).
const maxActive = 128

// CurrentKernelVersion exposes calculated kernel version - exposed in LINUX_VERSION_CODE format
// That is, for kernel "a.b.c", the version number will be (a<<16 + b<<8 + c)
func CurrentKernelVersion() (uint32, error) {
	return bpflib.CurrentKernelVersion()
}

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
	return &Tracer{m: m, config: config}, nil
}

func (t *Tracer) Start() error {
	return nil
}

func (t *Tracer) Stop() {
	t.m.Close()
}

func (t *Tracer) GetConnections() (*Connections, error) {
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
	return &Connections{Conns: conns}, nil
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
			if stats.State == CLOSED {
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
			if stats.State == CLOSED {
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
