package main

import (
	"fmt"

	"github.com/DataDog/tcptracer-bpf/agent/config"
	"github.com/DataDog/tcptracer-bpf/pkg/tracer"
)

type NetworkTracer struct {
	cfg *config.Config

	supported bool
	tracer    *tracer.Tracer
}

func CreateNetworkTracer(cfg *config.Config) (*NetworkTracer, error) {
	var err error

	nt := &NetworkTracer{}

	// Checking whether the current OS + kernel version is supported by the tracer
	if nt.supported, err = tracer.IsTracerSupportedByOS(); err == tracer.ErrNotImplemented {
		return nil, fmt.Errorf("operating is unsupported for BPF tracing")
	} else if err != nil {
		return nil, err
	}

	t, err := tracer.NewTracer(tracer.DefaultConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create network tracer: %s", err)
	}

	nt.tracer = t
	nt.cfg = cfg

	// TODO: Setup UDS + TCP endpoints

	return nt, nil
}

func (nt *NetworkTracer) Run() {
	nt.tracer.Start()
	// TODO: Enable UDS + TCP endpoints
}

func (nt *NetworkTracer) Close() {
	// TODO: Disable UDS + TCP endpoints
	nt.tracer.Stop()
}
