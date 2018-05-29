package main

import (
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/DataDog/tcptracer-bpf/pkg/tracer"
)

func main() {
	t, err := tracer.NewTracer()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	t.Start()

	fmt.Printf("Initialization complete. Starting nettop\n")

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
