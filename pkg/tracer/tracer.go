package tracer

import (
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/common"
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/config"
	"github.com/prometheus/client_golang/prometheus"
)

type Tracer interface {
	Start() error
	Stop()
	GetConnections() (*common.Connections, error)
	GetMetrics() prometheus.Gatherer
}

// Generic New Tracer function
func NewTracer(config *config.Config) (Tracer, error) {
	// Ensures that each tracer implements a MakeTracer function
	return MakeTracer(config)
}

// Generic IsSupported function
func IsTracerSupportedByOS() (bool, error) {
	// Ensures that each tracer implements a CheckTracerSupport function
	return CheckTracerSupport()
}
