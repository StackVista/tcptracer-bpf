package collector

import (
	winnetstat "github.com/pytimer/win-netstat"

	"github.com/StackVista/tcptracer-bpf/pkg/tracer/common"
)

// Connection collector interface. Can be mocked for testing.
type NetstatConnectionCollector interface {
	getConnections(kind string) ([]winnetstat.NetStat, error)
}

type NetstatCollector struct {
	NetstatConnectionCollector
}

// Default connection collector, that is used in the application.
type DefaultNetstatConnectionCollector struct {}

func (context DefaultNetstatConnectionCollector) getConnections(kind string) ([]winnetstat.NetStat, error) {
	return winnetstat.Connections(kind)
}

// MakeNetstatCollector to create the default Netstat Collector
func MakeNetstatCollector() *NetstatCollector {
	return &NetstatCollector{DefaultNetstatConnectionCollector{}}
}

func (collector NetstatCollector) GetTCPv4Connections() ([]*common.ConnectionStats, error) {
	return collector.getNetstatConnections("tcp4", common.TCP, common.AF_INET)
}

func (collector NetstatCollector) GetTCPv6Connections() ([]*common.ConnectionStats, error) {
	return collector.getNetstatConnections("tcp6", common.TCP, common.AF_INET6)
}

func (collector NetstatCollector) GetUDPv4Connections() ([]*common.ConnectionStats, error) {
	return collector.getNetstatConnections("udp4", common.UDP, common.AF_INET)
}

func (collector NetstatCollector) GetUDPv6Connections() ([]*common.ConnectionStats, error) {
	return collector.getNetstatConnections("udp6", common.UDP, common.AF_INET6)
}

func (collector NetstatCollector) getNetstatConnections(kind string, connectionType common.ConnectionType, connectionFamily common.ConnectionFamily) ([]*common.ConnectionStats, error) {
	var connectionStats = make([]*common.ConnectionStats, 0)

	conns, err := collector.getConnections(kind)
	if err != nil {
		return nil, err
	}

	for _, conn := range conns {
		connection := toConnectionStats(conn, connectionType, connectionFamily)
		connectionStats = append(connectionStats, connection)
	}

	return connectionStats, nil
}

// Helper function to convert the netstat connection to a connection stats type
func toConnectionStats(conn winnetstat.NetStat, connectionType common.ConnectionType, connectionFamily common.ConnectionFamily) *common.ConnectionStats {
	state, direction := extractStateDirection(conn.State)

	if connectionType == common.UDP {
		direction = common.UNKNOWN
	}

	return &common.ConnectionStats{
		Pid:        uint32(conn.OwningPid),
		Type:       connectionType,
		Family:     connectionFamily,
		Local:      conn.LocalAddr,
		Remote:     conn.RemoteAddr,
		LocalPort:  conn.LocalPort,
		RemotePort: conn.RemotePort,
		Direction:  direction,
		State:      state,
		SendBytes:  0,
		RecvBytes:  0,
	}
}

// Helper function to extract the State and Direction from the netstat connection status
func extractStateDirection(status string) (state common.State, direction common.Direction) {
	switch status {
	case "LISTEN":
		return common.ACTIVE, common.INCOMING
	case "ESTABLISHED":
		return common.ACTIVE, common.OUTGOING
	case "CLOSE_WAIT", "TIME_WAIT":
		return common.ACTIVE_CLOSED, common.UNKNOWN
	default:
		return common.ACTIVE, common.UNKNOWN
	}
}
