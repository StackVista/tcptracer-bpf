package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/DataDog/tcptracer-bpf/pkg/tracer"
)

var watchFdInstallPids string

type tcpEventTracer struct {
	lastTimestampV4 uint64
	lastTimestampV6 uint64
}

func (t *tcpEventTracer) TCPEventV4(e tracer.TcpV4) {
	if e.Type == tracer.EventFdInstall {
		fmt.Printf("%v cpu#%d %s %v %s %v\n",
			e.Timestamp, e.CPU, e.Type, e.Pid, e.Comm, e.Fd)
	} else {
		fmt.Printf("%v cpu#%d %s %v %s %v:%v %v:%v %v\n",
			e.Timestamp, e.CPU, e.Type, e.Pid, e.Comm, e.SAddr, e.SPort, e.DAddr, e.DPort, e.NetNS)
	}

	if t.lastTimestampV4 > e.Timestamp {
		fmt.Printf("ERROR: late event!\n")
		os.Exit(1)
	}

	t.lastTimestampV4 = e.Timestamp
}

func (t *tcpEventTracer) TCPEventV6(e tracer.TcpV6) {
	fmt.Printf("%v cpu#%d %s %v %s %v:%v %v:%v %v\n",
		e.Timestamp, e.CPU, e.Type, e.Pid, e.Comm, e.SAddr, e.SPort, e.DAddr, e.DPort, e.NetNS)

	if t.lastTimestampV6 > e.Timestamp {
		fmt.Printf("ERROR: late event!\n")
		os.Exit(1)
	}

	t.lastTimestampV6 = e.Timestamp
}

func (t *tcpEventTracer) LostV4(count uint64) {
	fmt.Printf("ERROR: lost %d events!\n", count)
	os.Exit(1)
}

func (t *tcpEventTracer) LostV6(count uint64) {
	fmt.Printf("ERROR: lost %d events!\n", count)
	os.Exit(1)
}

func init() {
	flag.Parse()
}

func main() {
	if flag.NArg() > 1 {
		flag.Usage()
		os.Exit(1)
	}

	t, err := tracer.NewEventTracer(&tcpEventTracer{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	t.Start()

	fmt.Printf("Ready\n")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	<-sig
	t.Stop()
}
