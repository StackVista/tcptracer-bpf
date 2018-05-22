// +build linux

package tracer

import (
	"bytes"
	"fmt"
	"unsafe"

	bpflib "github.com/iovisor/gobpf/elf"
	"time"
	"os/exec"
)

/*
#include "../../tcptracer-bpf.h"
*/
import "C"

const (
	tcpV4StatsMapName = "tcp_stats_ipv4"
)

type Tracer struct {
	m           *bpflib.Module
	stopChan    chan struct{}
}

// maxActive configures the maximum number of instances of the kretprobe-probed functions
// that can be handled simultaneously.
// This value should be enough to handle typical workloads (for example, some
// amount of processes blocked on the accept syscall).
const maxActive = 128

func NewTracer(cb Callback) (*Tracer, error) {
	var out bytes.Buffer
	cmd := exec.Command("uname","-r")
	cmd.Stdout = &out
	cmd.Run()
	fmt.Printf("Kernel: %s", out.String())

	buf, err := Asset("tcptracer-ebpf.o")
	if err != nil {
		return nil, fmt.Errorf("couldn't find asset: %s", err)
	}
	reader := bytes.NewReader(buf)

	m := bpflib.NewModuleFromReader(reader)
	if m == nil {
		return nil, fmt.Errorf("BPF not supported")
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

	stopChan := make(chan struct{})
	go func() {
		for {
			select {
			case <-stopChan:
				// On stop, stopChan will be closed but the other channels will
				// also be closed shortly after. The select{} has no priorities,
				// therefore, the "ok" value must be checked below.
				return
			}
		}
	}()

	return &Tracer{
		m:           m,
		stopChan:    stopChan,
	}, nil
}

func (t *Tracer) Start() error {
	// TODO: Remove this debugging output
	printConns := func() {
		conns, err := t.GetActiveConnections()
		if err != nil {
			fmt.Println(err)
		}
		for _, c := range conns {
			fmt.Println(c)
		}
	}

	go func() {  // Go through map immediately, and then again every 5 seconds
		tick := time.NewTicker(5 * time.Second)
		printConns()
		for {
			select {
			case <-tick.C:
				printConns()
			case <-t.stopChan:
				tick.Stop()
				return
			}
		}
	}()

	return nil
}

func (t *Tracer) Stop() {
	close(t.stopChan)
	t.m.Close()
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

func (t *Tracer) GetActiveConnections() ([]ConnectionStats, error) {
	// TODO: Also lookup active TCP v6 connections
	return t.lookupActiveTCPv4Connections()
}

func (t *Tracer) lookupActiveTCPv4Connections() ([]ConnectionStats, error) {
	mp := t.m.Map("tcp_stats_ipv4")
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
			conns = append(conns, connectionStatsFromTCPv4(nextKey, val))
			key = nextKey
		}
	}

	return conns, nil
}


