// +build linux_bpf

package tracer

import (
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/common"
	"runtime"
	"testing"
	"unsafe"
)

func TestEnsureGuessingFromConnectingSide(t *testing.T) {
	module, err := loadBPFModule()
	if err != nil {
		t.Fatal(err)
	}

	err = module.Load(nil)
	if err != nil {
		t.Fatal(err)
	}

	// TODO: Only enable kprobes for traffic collection defined in config
	err = module.EnableKprobes(common.MaxActive)
	if err != nil {
		module.Close()
		if err != nil {
			t.Fatal(err)
		}
	}

	currentNetns, err := ownNetNS()
	if err != nil {
		t.Fatal(err)
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// if guessBench null tracer is initialized
	bench, err := setupGuess(module, currentNetns)
	if err != nil || bench == nil {
		t.Fatal(err)
	}

	stop := bench.stopServer
	defer close(stop)
	expected := bench.expectedClientConnection
	mp := bench.statusBpfMap
	status := bench.status

	var maxRetries = 100
	for status.state != stateReady {
		if err := makeNewClientConnection(status, expected, stop); err != nil {
			t.Fatal(err)
		}

		if err := checkAndUpdateCurrentOffset(module, mp, status, expected, &maxRetries); err != nil {
			t.Fatal(err)
		}

		if status.what == guessSport {
			break
		}
	}

	if err := makeNewClientConnection(status, expected, stop); err != nil {
		t.Fatal(err)
	}

	if err := module.LookupElement(mp, unsafe.Pointer(&zero), unsafe.Pointer(status)); err != nil {
		t.Fatal(err)
	}

	for status.state != stateChecked {
		//do nothing, until ebpf processed the event

		if err := module.LookupElement(mp, unsafe.Pointer(&zero), unsafe.Pointer(status)); err != nil {
			t.Fatal(err)
		}
	}

	defer module.Close()
	if err != nil {
		t.Fatal(err)
	}

	// the tcptracer_status should report only connecting events from _connect_ probes
	for i, v := range status.calling_probes {
		if i < len(status.calling_probes)-1 && v != status.calling_probes[i+1] {
			t.Log(status.calling_probes)
			t.Fail()
		}
	}

}