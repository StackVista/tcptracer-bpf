// +build linux

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
	tcpV4StatsMapName = "tcp_stats_ipv4"
	tcpV6StatsMapName = "tcp_stats_ipv6"
)

var (
	// Feature versions sourced from: https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md
	// Minimum kernel version -> max(3.15 - eBPF, 3.18 - tables/maps,
	//                               4.1 - kprobes, 4.3 - perf events)
	// 	                      -> 4.3
	minRequiredKernelCode = linuxKernelVersionCode(4, 3, 0)
)

type Tracer struct {
	m           *bpflib.Module
	perfMapIPV4 *bpflib.PerfMap
	perfMapIPV6 *bpflib.PerfMap
	stopChan    chan struct{}
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

func NewTracer() (*Tracer, error) {
	m, err := loadBPFModule()
	if err != nil {
		return nil, err
	}

	err = m.Load(nil)
	if err != nil {
		return nil, err
	}

	err = m.EnableKprobes(maxActive)
	if err != nil {
		return nil, err
	}

	if err := initialize(m); err != nil {
		return nil, fmt.Errorf("failed to init module: %s", err)
	}

	// TODO: Improve performance by detaching unnecessary kprobes, once offsets have been figured out in initialize()

	return &Tracer{m: m}, nil
}

func NewEventTracer(cb Callback) (*Tracer, error) {
	m, err := loadBPFModule()
	if err != nil {
		return nil, err
	}

	sectionParams := make(map[string]bpflib.SectionParams)
	sectionParams["maps/tcp_event_ipv4"] = bpflib.SectionParams{PerfRingBufferPageCount: 256}
	err = m.Load(sectionParams)
	if err != nil {
		return nil, err
	}

	err = m.EnableKprobes(maxActive)
	if err != nil {
		return nil, err
	}

	channelV4, channelV6 := make(chan []byte), make(chan []byte)
	lostChanV4, lostChanV6 := make(chan uint64), make(chan uint64)

	perfMapIPV4, err := initializePerfMap(m, "tcp_event_ipv4", channelV4, lostChanV4)
	if err != nil {
		return nil, fmt.Errorf("failed to init perf map for IPv4 events: %s", err)
	}

	perfMapIPV6, err := initializePerfMap(m, "tcp_event_ipv6", channelV6, lostChanV6)
	if err != nil {
		return nil, fmt.Errorf("failed to init perf map for IPv6 events: %s", err)
	}

	perfMapIPV4.SetTimestampFunc(tcpV4Timestamp)
	perfMapIPV6.SetTimestampFunc(tcpV6Timestamp)

	stopChan := make(chan struct{})
	go func() {
		defer perfMapIPV4.PollStop()
		defer perfMapIPV6.PollStop()

		for {
			select {
			case <-stopChan:
				return
			case data, ok := <-channelV4:
				if ok {
					cb.TCPEventV4(tcpV4ToGo(&data))
				}
			case data, ok := <-channelV6:
				if ok {
					cb.TCPEventV6(tcpV6ToGo(&data))
				}
			case lost, ok := <-lostChanV4:
				if ok {
					cb.LostV4(lost)
				}
			case lost, ok := <-lostChanV6:
				if ok {
					cb.LostV6(lost)
				}
			}
		}
	}()

	return &Tracer{
		m:           m,
		stopChan:    stopChan,
		perfMapIPV4: perfMapIPV4,
		perfMapIPV6: perfMapIPV6,
	}, nil
}

func (t *Tracer) Start() error {
	if t.perfMapIPV4 != nil {
		t.perfMapIPV4.PollStart()
		t.perfMapIPV6.PollStart()
	}
	return nil
}

func (t *Tracer) Stop() {
	if t.stopChan != nil {
		t.stopChan <- struct{}{}
	}
	t.m.Close()
}

func (t *Tracer) GetActiveConnections() ([]ConnectionStats, error) {
	v4, err := t.getTCPv4Connections()
	if err != nil {
		return nil, err
	}
	v6, err := t.getTCPv6Connections()
	if err != nil {
		return nil, err
	}
	return append(v4, v6...), nil
}

func (t *Tracer) getTCPv4Connections() ([]ConnectionStats, error) {
	mp := t.m.Map(tcpV4StatsMapName)
	if mp == nil {
		return nil, fmt.Errorf("no map with name %s", tcpV4StatsMapName)
	}

	// Iterate through all key-value pairs in map
	key, nextKey, val := &TCPTupleV4{}, &TCPTupleV4{}, &TCPConnStats{}
	conns := make([]ConnectionStats, 0)
	for {
		hasNext, _ := t.m.LookupNextElement(mp, unsafe.Pointer(key), unsafe.Pointer(nextKey), unsafe.Pointer(val))
		if !hasNext {
			break
		} else {
			conns = append(conns, connStatsFromTCPv4(nextKey, val))
			key = nextKey
		}
	}

	return conns, nil
}

func (t *Tracer) getTCPv6Connections() ([]ConnectionStats, error) {
	mp := t.m.Map(tcpV6StatsMapName)
	if mp == nil {
		return nil, fmt.Errorf("no map with name %s", tcpV6StatsMapName)
	}

	// Iterate through all key-value pairs in map
	key, nextKey, val := &TCPTupleV6{}, &TCPTupleV6{}, &TCPConnStats{}
	conns := make([]ConnectionStats, 0)
	for {
		hasNext, _ := t.m.LookupNextElement(mp, unsafe.Pointer(key), unsafe.Pointer(nextKey), unsafe.Pointer(val))
		if !hasNext {
			break
		} else {
			conns = append(conns, connStatsFromTCPv6(nextKey, val))
			key = nextKey
		}
	}

	return conns, nil
}

func (t *Tracer) AddFdInstallWatcher(pid uint32) (err error) {
	var one uint32 = 1
	mapFdInstall := t.m.Map("fdinstall_pids")
	err = t.m.UpdateElement(mapFdInstall, unsafe.Pointer(&pid), unsafe.Pointer(&one), 0)
	return err
}

func (t *Tracer) RemoveFdInstallWatcher(pid uint32) (err error) {
	mapFdInstall := t.m.Map("fdinstall_pids")
	err = t.m.DeleteElement(mapFdInstall, unsafe.Pointer(&pid))
	return err
}

func initialize(m *bpflib.Module) error {
	if err := guess(m); err != nil {
		return fmt.Errorf("error guessing offsets: %v", err)
	}
	return nil
}

func initializePerfMap(module *bpflib.Module, eventMapName string, eChan chan []byte, lChan chan uint64) (*bpflib.PerfMap, error) {
	if err := initialize(module); err != nil {
		return nil, fmt.Errorf("error guessing offsets: %v", err)
	}

	pm, err := bpflib.InitPerfMap(module, eventMapName, eChan, lChan)
	if err != nil {
		return nil, fmt.Errorf("error initializing perf map for %q: %v", eventMapName, err)
	}

	return pm, nil
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
