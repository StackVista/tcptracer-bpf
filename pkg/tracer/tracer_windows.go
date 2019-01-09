package tracer

import (
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/common"
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/config"
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/collector"
	"log"
)

type Tracer struct {
	TracerConfig *config.Config
	// In flight connections are the connections that already existed before the EBPF module was loaded.
	// These connections are stored with a key without direction, to make it possible to merge with undirected
	// metric stats
	NetworkConnectionStats map[string]*common.ConnectionStats
	ConnectionCollector collector.Collector
}

func NewTracer(config *Config) (*Tracer, error) {
	tracer := &Tracer{
		TracerConfig: config,
		NetworkConnectionStats: make(map[string]*common.ConnectionStats),
		ConnectionCollector: collector.MakeNetstatCollector(),
	}

	return tracer, nil
}

func (t *Tracer) GetTCPConnections() ([]*common.ConnectionStats, error) {
	return t.ConnectionCollector.GetTCPv4Connections()

}

func (t *Tracer) GetUDPConnections() ([]*common.ConnectionStats, error) {
	return t.ConnectionCollector.GetUDPv4Connections()
}

func (t *Tracer) GetConnections() (*common.Connections, error) {
	tcpConns := make([]common.ConnectionStats, 0)
	udpConns := make([]common.ConnectionStats, 0)

	if t.TracerConfig.CollectTCPConns {
		conns, err := t.GetTCPConnections()
		if err != nil {
			log.Fatal(err)
			return nil, err
		}
		for _, conn := range conns {
			tcpConns = append(tcpConns, *conn)
		}
	}

	if t.TracerConfig.CollectUDPConns {
		conns, err := t.GetUDPConnections()
		if err != nil {
			log.Fatal(err)
			return nil, err
		}
		for _, conn := range conns {
			udpConns = append(udpConns, *conn)
		}
	}

	return &common.Connections{Conns: append(tcpConns, udpConns...) }, nil

}
