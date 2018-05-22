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

	stopChan := make(chan struct{})

	if err := initializeIPv4(m, stopChan); err != nil {
		return nil, fmt.Errorf("failed to init table parser for IPv4 send & recieve stats: %s", err)
	}

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

func (t *Tracer) Start() {
	// No-op at the moment
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

func initialize(m *bpflib.Module, mapName string, stopChan chan struct{}) error {
	fmt.Printf("Initializing watcher for kprobe: %s\n", mapName)

	if err := guess(m); err != nil {
		return fmt.Errorf("error guessing offsets: %v", err)
	}

	mp := m.Map(mapName)
	if mp == nil {
		return fmt.Errorf("no map with name %s", mapName)
	}

	iterateMap := func() { // Iterate through all key-value pairs in map
		key, nextKey := &TCPTupleV4{}, &TCPTupleV4{}
		stats := &TCPConnStats{}
		for {
			hasNext, _ := m.LookupNextElement(mp, unsafe.Pointer(key), unsafe.Pointer(nextKey), unsafe.Pointer(stats))
			if !hasNext {
				break
			} else {
				// TODO: Consider using bpf_ktime_get_ns() to store timestamp and deleting keys that haven't been seen in a while?
				// TODO: Send this data through channel instead of printing it here
				fmt.Printf("%s - event: %s, %d bytes sent, %d bytes recieved \n", mapName, nextKey, stats.send_bytes, stats.recv_bytes)
				key = nextKey
			}
		}
	}

	go func() {  // Go through map immediately, and then again every 5 seconds
		tick := time.NewTicker(5 * time.Second)
		iterateMap()
		for {
			select {
			case <-tick.C:
				iterateMap()
			case <-stopChan:
				tick.Stop()
				return
			}
		}
	}()

	return nil
}

func initializeIPv4(module *bpflib.Module, stopChan chan struct{}) error {
	return initialize(module, "tcp_stats_ipv4", stopChan)
}

func (t *Tracer) GetActiveConnections() ([]ConnectionStats, error) {
	// TODO: Search ip {v4,v6} maps for active connection stats and output
	return []ConnectionStats{}, nil
}

