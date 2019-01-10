package tracer

import (
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/collector"
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/common"
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/config"
)

type Tracer struct {
	collector.Collector
	TracerConfig *config.Config
}

func NewTracer(config *config.Config) (*Tracer, error) {
	tracer := &Tracer{
		Collector:    collector.MakeNetstatCollector(),
		TracerConfig: config,
	}

	return tracer, nil
}

func (t *Tracer) GetTCPConnections() ([]*common.ConnectionStats, error) {
	return t.GetTCPv4Connections()

}

func (t *Tracer) GetUDPConnections() ([]*common.ConnectionStats, error) {
	return t.GetUDPv4Connections()
}

func (t *Tracer) GetConnections() (*common.Connections, error) {
	tcpConns := make([]common.ConnectionStats, 0)
	udpConns := make([]common.ConnectionStats, 0)

	if t.TracerConfig.CollectTCPConns {
		conns, err := t.GetTCPConnections()
		if err != nil {
			return nil, err
		}
		for _, conn := range conns {
			tcpConns = append(tcpConns, *conn)
		}
	}

	if t.TracerConfig.CollectUDPConns {
		conns, err := t.GetUDPConnections()
		if err != nil {
			return nil, err
		}
		for _, conn := range conns {
			udpConns = append(udpConns, *conn)
		}
	}

	return &common.Connections{Conns: append(tcpConns, udpConns...)}, nil
}
