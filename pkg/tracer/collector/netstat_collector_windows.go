package collector

import (
	"fmt"
	winnetstat "github.com/pytimer/win-netstat"

	"github.com/StackVista/tcptracer-bpf/pkg/tracer/common"
)

type NetstatCollector struct {}

func MakeNetstatCollector() *NetstatCollector {
	return &NetstatCollector{}
}

func (nsCol NetstatCollector) GetTCPv4Connections() ([]*common.ConnectionStats, error) {
	return getNetstatConnections("tcp4", common.TCP, common.AF_INET)
}

func (nsCol NetstatCollector) GetTCPv6Connections() ([]*common.ConnectionStats, error) {
	return getNetstatConnections("tcp6", common.TCP, common.AF_INET6)
}

func (nsCol NetstatCollector) GetUDPv4Connections() ([]*common.ConnectionStats, error) {
	return getNetstatConnections("udp4", common.UDP, common.AF_INET)
}

func (nsCol NetstatCollector) GetUDPv6Connections() ([]*common.ConnectionStats, error) {
	return getNetstatConnections("udp6", common.UDP, common.AF_INET6)
}

func getNetstatConnections(kind string, connectionType common.ConnectionType, connectionFamily common.ConnectionFamily) ([]*common.ConnectionStats, error) {
	var connectionStats = make([]*common.ConnectionStatsm, 0)

	conns, err := winnetstat.Connections("udp6")
	if err != nil {
		return nil, err
	}

	for _, conn := range conns {
		connection := netstatToConnection(conn, connectionType, connectionFamily)
		connectionStats = append(connectionStats, connection)
		fmt.Println(connection.String())
	}

	return connectionStats, nil
}

func netstatToConnection(conn winnetstat.NetStat, connectionType common.ConnectionType, connectionFamily common.ConnectionFamily) *common.ConnectionStats {
	state, direction := connectionStatusToStateDirection(conn.State)

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

func connectionStatusToStateDirection(status string) (state common.State, direction common.Direction){
	switch status {
	case "LISTEN":
		return common.ACTIVE, common.INCOMING
	case "ESTABLISHED":
		return common.ACTIVE, common.OUTGOING
	default:
		return common.ACTIVE, common.UNKNOWN
	}
}