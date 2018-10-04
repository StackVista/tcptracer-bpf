// +build linux_bpf

package tracer

import (
	"bytes"
	"fmt"
	"syscall"
	"unsafe"

	bpflib "github.com/iovisor/gobpf/elf"
)

/*
#include "../../tcptracer-bpf.h"
*/
import "C"

const (
	statsMapName = "connections"
)

var (
	// Feature versions sourced from: https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md
	// Minimum kernel version -> max(3.15 - eBPF,
	//                               3.18 - tables/maps)
	// 	                      -> 3.18
	minRequiredKernelCode = linuxKernelVersionCode(3, 18, 0)
)

type Tracer struct {
	m      *bpflib.Module
	config *Config
}

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

	t := &Tracer{m: m, config: config}
	if err := t.initialize(); err != nil {
		return nil, fmt.Errorf("failed to init module: %s", err)
	}

	return t, nil
}

func (t *Tracer) Start() error {
	return nil
}

func (t *Tracer) Stop() {
	t.m.Close()
}

func (t *Tracer) GetActiveConnections() (*Connections, error) {
	conns, err := t.getConnections()
	if err != nil {
		return nil, err
	}

	return &Connections{Conns: conns}, nil
}

func (t *Tracer) getConnections() ([]ConnectionStats, error) {
	mp, err := t.getMap(statsMapName)
	if err != nil {
		return nil, err
	}

	// Iterate through all key-value pairs in map
	key, nextKey, val := &ConnKey{}, &ConnKey{}, &ConnLeaf{}
	conns := make([]ConnectionStats, 0)
	keys := make([]*ConnKey, 0)
	for {
		hasNext, _ := t.m.LookupNextElement(mp, unsafe.Pointer(key), unsafe.Pointer(nextKey), unsafe.Pointer(val))
		if !hasNext {
			break
		} else {
			conns = append(conns, formatConnStats(nextKey, val))

			// We already read the connection data so we can now remove it
			err := t.m.DeleteElement(mp, unsafe.Pointer(nextKey))
			if err != nil {
				fmt.Printf("Warning couldn't delete key %+v: %s\n", key, err)
			}

			keys = append(keys, nextKey)
			key = nextKey
		}
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

func (t *Tracer) initialize() error {
	filter := t.m.SocketFilter("socket_tracer")

	if t.config.CollectTCPConns {
		tcp, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
		if err != nil {
			return fmt.Errorf("Couldn't create tcp socket: %s", err)
		}

		err = bpflib.AttachSocketFilter(filter, int(tcp))
		if err != nil {
			return fmt.Errorf("Coudln't bind socket filter to the tcp socket: %s", err)
		}
		fmt.Println("TCP loaded")
	}

	if t.config.CollectUDPConns {
		udp, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_UDP)
		if err != nil {
			return fmt.Errorf("Couldn't create udp socket: %s", err)
		}

		err = bpflib.AttachSocketFilter(filter, int(udp))
		if err != nil {
			return fmt.Errorf("Coudln't bind socket filter to the udp socket: %s", err)
		}
		fmt.Println("UDP loaded")
	}

	// TODO detach the filters when they are done

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
