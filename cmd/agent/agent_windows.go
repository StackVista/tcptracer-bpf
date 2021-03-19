package main

import (
	"fmt"
	"github.com/StackVista/tcptracer-bpf/pkg/tracer"
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/config"
)

func main() {
	tracerConfig := config.MakeDefaultConfig()
	t, err := tracer.NewTracer(tracerConfig)
	if err != nil {
		fmt.Println(err)
	}

	conns, err := t.GetConnections()

	for _, c := range conns.Conns {
		fmt.Println(c.String())
	}
}
