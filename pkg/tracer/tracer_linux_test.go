// +build linux_bpf

package tracer

import (
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/common"
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/config"
)

const CheckMessageSize = true

func MakeTestConfig() *config.Config {
	c := config.MakeDefaultConfig()
	c.ProcRoot = common.TestRoot()
	return c
}