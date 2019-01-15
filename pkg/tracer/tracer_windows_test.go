package tracer

import (
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/config"
)

const CheckMessageSize = false

func MakeTestConfig() *config.Config {
	c := config.MakeDefaultConfig()
	return c
}
