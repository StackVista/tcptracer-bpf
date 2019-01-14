package tracer

import (
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/config"
)

func MakeTestConfig() *config.Config {
	c := config.MakeDefaultConfig()
	return c
}