package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/DataDog/tcptracer-bpf/pkg/tracer"
)

var watchFdInstallPids string

func init() {
	flag.StringVar(&watchFdInstallPids, "monitor-fdinstall-pids", "", "a comma-separated list of pids that need to be monitored for fdinstall events")

	flag.Parse()
}

func main() {
	if flag.NArg() > 1 {
		flag.Usage()
		os.Exit(1)
	}

	t, err := tracer.NewTracer()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	t.Start()

	for _, p := range strings.Split(watchFdInstallPids, ",") {
		if p == "" {
			continue
		}

		pid, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid pid: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Monitor fdinstall events for pid %d\n", pid)
		t.AddFdInstallWatcher(uint32(pid))
	}

	fmt.Printf("Ready\n")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	printConns := func(now time.Time) {
		fmt.Printf("-- %s --\n", now)
		conns, err := t.GetActiveConnections()
		if err != nil {
			fmt.Println(err)
		}
		for _, c := range conns {
			fmt.Println(c)
		}
	}

	stopChan := make(chan struct{})
	go func() {
		// Print active connections immediately, and then again every 5 seconds
		tick := time.NewTicker(5 * time.Second)
		printConns(time.Now())
		for {
			select {
			case now := <-tick.C:
				printConns(now)
			case <-stopChan:
				tick.Stop()
				return
			}
		}
	}()

	<-sig
	stopChan <- struct{}{}

	t.Stop()
}
