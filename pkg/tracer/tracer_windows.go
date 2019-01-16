package tracer

import (
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/collector"
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/common"
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/config"
	log "github.com/cihub/seelog"
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

func (t *Tracer) Start() error {
	return nil
}

func (t *Tracer) Stop() {}

func (t *Tracer) GetTCPConnections() ([]*common.ConnectionStats, error) {
	v4conns, err := t.GetTCPv4Connections()
	if err != nil {
		return nil, err
	}

	v6conns, err := t.GetTCPv6Connections()
	if err != nil {
		return nil, err
	}

	return append(v4conns, v6conns...), nil
}

func (t *Tracer) GetUDPConnections() ([]*common.ConnectionStats, error) {
	v4conns, err := t.GetUDPv4Connections()
	if err != nil {
		return nil, err
	}

	v6conns, err := t.GetUDPv6Connections()
	if err != nil {
		return nil, err
	}

	return append(v4conns, v6conns...), nil
}

func (t *Tracer) GetConnections() (*common.Connections, error) {
	var conns []*common.ConnectionStats

	if t.TracerConfig.CollectTCPConns {
		tcpConns, err := t.GetTCPConnections()
		if err != nil {
			return nil, err
		}
		conns = append(conns, tcpConns...)
	}

	if t.TracerConfig.CollectUDPConns {
		udpConns, err := t.GetUDPConnections()
		if err != nil {
			return nil, err
		}
		conns = append(conns, udpConns...)
	}

	connectionStats := make([]common.ConnectionStats, 0)

	for _, conn := range conns {
		if len(connectionStats) >= t.TracerConfig.MaxConnections {
			log.Warnf("Exceeded maximum connections %d", t.TracerConfig.MaxConnections)
			break
		}
		connectionStats = append(connectionStats, *conn)
	}

	return &common.Connections{Conns: connectionStats}, nil
}
