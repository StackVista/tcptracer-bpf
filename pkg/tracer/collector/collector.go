package collector

import "github.com/StackVista/tcptracer-bpf/pkg/tracer/common"

type Collector interface {
	GetTCPv4Connections() ([]*common.ConnectionStats, error)
	GetTCPv6Connections() ([]*common.ConnectionStats, error)
	GetUDPv4Connections() ([]*common.ConnectionStats, error)
	GetUDPv6Connections() ([]*common.ConnectionStats, error)
}
