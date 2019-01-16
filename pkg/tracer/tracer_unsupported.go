// +build !linux_bpf,!windows

package tracer

import (
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/common"
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/config"
)

func CurrentKernelVersion() (uint32, error) {
	return 0, common.ErrNotImplemented
}

func IsTracerSupportedByOS() (bool, error) {
	return false, common.ErrNotImplemented
}

type Tracer struct{}

func NewTracer(config *config.Config) (*Tracer, error) {
	return nil, common.ErrNotImplemented
}

func NewEventTracer(cb Callback) (*Tracer, error) {
	return nil, common.ErrNotImplemented
}

func (t *Tracer) Start() {}

func (t *Tracer) Stop() {}

func (t *Tracer) GetConnections() (*common.Connections, error) {
	return nil, common.ErrNotImplemented
}
