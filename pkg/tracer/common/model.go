package common

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/DataDog/sketches-go/ddsketch"
	"github.com/DataDog/sketches-go/ddsketch/pb/sketchpb"
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/network"
	"github.com/golang/protobuf/proto"
)

type ConnectionType uint8

const (
	TCP ConnectionType = 0
	UDP ConnectionType = 1
)

func (c ConnectionType) String() string {
	if c == TCP {
		return "TCP"
	}
	return "UDP"
}

const (
	AF_INET  ConnectionFamily = 0
	AF_INET6 ConnectionFamily = 1
)

type ConnectionFamily uint8

const (
	UNKNOWN  Direction = 0
	OUTGOING Direction = 1
	INCOMING Direction = 2
)

type Direction uint8

func (d Direction) String() string {
	if d == UNKNOWN {
		return "UNKNOWN"
	}
	if d == OUTGOING {
		return "OUTGOING"
	}
	return "INCOMING"
}

const (
	INITIALIZING  State = 0
	ACTIVE        State = 1
	ACTIVE_CLOSED State = 2
	CLOSED        State = 3
)

type State uint8

func (s State) String() string {
	if s == INITIALIZING {
		return "INITIALIZING"
	} else if s == ACTIVE {
		return "ACTIVE"
	} else if s == ACTIVE_CLOSED {
		return "ACTIVE_CLOSED"
	}
	return "CLOSED"
}

//easyjson:json
type Connections struct {
	Conns []ConnectionStats `json:"connections"`
}

//easyjson:json
type ConnectionStats struct {
	Pid    uint32           `json:"pid"`
	Type   ConnectionType   `json:"type"`
	Family ConnectionFamily `json:"family"`

	// Local & Remote represented as a string to handle both IPv4 & IPv6
	Local            string    `json:"local"`
	Remote           string    `json:"remote"`
	LocalPort        uint16    `json:"lport"`
	RemotePort       uint16    `json:"rport"`
	Direction        Direction `json:"direction"`
	State            State     `json:"state"`
	NetworkNamespace string    `json:"network_namespace"`

	SendBytes uint64 `json:"send_bytes"`
	RecvBytes uint64 `json:"recv_bytes"`

	ApplicationProtocol string             `json:"app_proto"`
	Metrics             []ConnectionMetric `json:"metrics"`
}

type MetricName string

const (
	// HTTPResponseTime is for the metric that is sent with a connection
	HTTPResponseTime MetricName = "http_response_time_seconds"

	// HTTPRequestsPerSecond is for the metric that is sent with a connection
	HTTPRequestsPerSecond MetricName = "http_requests_per_second"

	// HTTPStatusCodeTagName Status Code tag name
	HTTPStatusCodeTagName = "code"
)

//easyjson:json
type ConnectionMetric struct {
	Name  MetricName            `json:"name"`
	Tags  map[string]string     `json:"tags"`
	Value ConnectionMetricValue `json:"value"`
}

type ConnectionMetricValue struct {
	Histogram *Histogram `json:"ddsketch"`
}

type Histogram struct {
	DDSketch *ddsketch.DDSketch
}

func (m *Histogram) UnmarshalJSON(data []byte) error {
	var ddbytes []byte
	err := json.Unmarshal(data, &ddbytes)
	if err != nil {
		return err
	}
	var sketchPb sketchpb.DDSketch
	err = proto.Unmarshal(ddbytes, &sketchPb)
	if err != nil {
		return err
	}
	ddSketch, err := ddsketch.FromProto(&sketchPb)
	if err != nil {
		return err
	}
	m.DDSketch = ddSketch
	return nil
}

func (m *Histogram) MarshalJSON() ([]byte, error) {
	encoded, err := proto.Marshal(m.DDSketch.ToProto())
	if err != nil {
		return nil, err
	}
	return json.Marshal(encoded)
}

type ConnTupleV4 struct {
	Laddr string
	Lport uint16
	Raddr string
	Rport uint16
	Pid   uint16
}

func (ct *ConnTupleV4) Matches(stats *ConnectionStats) bool {
	return stats.Pid == uint32(ct.Pid) &&
		stats.Local == ct.Laddr && stats.Remote == ct.Raddr &&
		stats.LocalPort == ct.Lport && stats.RemotePort == ct.Rport
}

type HTTPResponse struct {
	Connection   ConnTupleV4
	StatusCode   int
	ResponseTime time.Duration
}

type MySQLGreeting struct {
	Connection      ConnTupleV4
	ProtocolVersion int
}

type PerfEvent struct {
	HTTPResponse  *HTTPResponse
	MySQLGreeting *MySQLGreeting
	Timestamp     time.Time
}

func (c ConnectionStats) GetConnection() ConnTupleV4 {
	return ConnTupleV4{
		Laddr: c.Local,
		Lport: c.LocalPort,
		Raddr: c.Remote,
		Rport: c.RemotePort,
		Pid:   0,
	}
}

func (c ConnectionStats) WithOnlyLocal() ConnectionStats {
	return ConnectionStats{
		Pid:              c.Pid,
		Type:             c.Type,
		Family:           c.Family,
		Local:            c.Local,
		Remote:           "",
		LocalPort:        c.LocalPort,
		RemotePort:       0,
		Direction:        UNKNOWN,
		State:            ACTIVE,
		NetworkNamespace: c.NetworkNamespace,
		SendBytes:        0,
		RecvBytes:        0,
	}
}

func (c ConnectionStats) WithUnknownDirection() ConnectionStats {
	return ConnectionStats{
		Pid:              c.Pid,
		Type:             c.Type,
		Family:           c.Family,
		Local:            c.Local,
		Remote:           c.Remote,
		LocalPort:        c.LocalPort,
		RemotePort:       c.RemotePort,
		Direction:        UNKNOWN,
		State:            c.State,
		NetworkNamespace: c.NetworkNamespace,
		SendBytes:        c.SendBytes,
		RecvBytes:        c.RecvBytes,
	}
}

func (c ConnectionStats) Copy() ConnectionStats {
	return ConnectionStats{
		Pid:              c.Pid,
		Type:             c.Type,
		Family:           c.Family,
		Local:            c.Local,
		Remote:           c.Remote,
		LocalPort:        c.LocalPort,
		RemotePort:       c.RemotePort,
		Direction:        c.Direction,
		State:            c.State,
		NetworkNamespace: c.NetworkNamespace,
		SendBytes:        c.SendBytes,
		RecvBytes:        c.RecvBytes,
	}
}

func (c ConnectionStats) String() string {
	if len(strings.TrimSpace(c.NetworkNamespace)) != 0 {
		return fmt.Sprintf("[%s] [PID: %d] [%v:%d ⇄ %v:%d] direction=%s state=%s netns=%s protocol=%s [%d bytes sent ↑ %d bytes received ↓]",
			c.Type, c.Pid, c.Local, c.LocalPort, c.Remote, c.RemotePort, c.Direction, c.State, c.NetworkNamespace, c.ApplicationProtocol, c.SendBytes, c.RecvBytes)
	} else {
		return fmt.Sprintf("[%s] [PID: %d] [%v:%d ⇄ %v:%d] direction=%s state=%s protocol=%s  [%d bytes sent ↑ %d bytes received ↓]",
			c.Type, c.Pid, c.Local, c.LocalPort, c.Remote, c.RemotePort, c.Direction, c.State, c.ApplicationProtocol, c.SendBytes, c.RecvBytes)
	}
}

func (c ConnectionStats) ByteKey(buffer *bytes.Buffer) ([]byte, error) {
	buffer.Reset()
	// Byte-packing to improve creation speed
	// PID (32 bits) + LocalPort (16 bits) + RemotePort (16 bits) = 64 bits
	p0 := uint64(c.Pid)<<32 | uint64(c.LocalPort)<<16 | uint64(c.RemotePort)
	if err := binary.Write(buffer, binary.LittleEndian, p0); err != nil {
		return nil, err
	}
	if _, err := buffer.WriteString(c.Local); err != nil {
		return nil, err
	}
	// Family (8 bits) + Type (8 bits) + Direction (8 bits) = 32 bits
	p1 := uint32(c.Direction)<<16 | uint32(c.Family)<<8 | uint32(c.Type)
	if err := binary.Write(buffer, binary.LittleEndian, p1); err != nil {
		return nil, err
	}
	if _, err := buffer.WriteString(c.Remote); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// enriches the connection stats with namespace if it's a localhost connection
func (c ConnectionStats) WithNamespace(namespace string) ConnectionStats {
	// check for local connections, add namespace for connection
	networkScanner := network.MakeLocalNetworkScanner()
	if networkScanner.ContainsIP(c.Local) && networkScanner.ContainsIP(c.Remote) {
		c.NetworkNamespace = namespace
	}

	return c
}

func V4IPString(addr uint32) string {
	addrbuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(addrbuf, addr)
	return net.IPv4(addrbuf[0], addrbuf[1], addrbuf[2], addrbuf[3]).String()
}

func V6IPString(addr_h, addr_l uint64) string {
	addrbuf := make([]byte, 16)
	binary.LittleEndian.PutUint64(addrbuf, addr_h)
	binary.LittleEndian.PutUint64(addrbuf[8:], addr_l)
	return net.IP(addrbuf).String()
}
