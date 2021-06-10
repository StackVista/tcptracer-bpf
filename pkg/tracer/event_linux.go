// +build linux_bpf

package tracer

import (
	"errors"
	"fmt"
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/common"
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/procspy"
	"strconv"
	"time"
	"unsafe"
)

/*
#include "../../tcptracer-bpf.h"
*/
import "C"

/*  struct_ipv4_tuple_t
__u32 laddr;
__u32 raddr;
__u16 lport;
__u16 rport;
__u32 netns;
__u32 pid;
*/
type ConnTupleV4 C.struct_ipv4_tuple_t

func (t *ConnTupleV4) copy() *ConnTupleV4 {
	return &ConnTupleV4{
		laddr: t.laddr,
		raddr: t.raddr,
		lport: t.lport,
		rport: t.rport,
		netns: t.netns,
		pid:   t.pid,
	}
}

/* struct_ipv6_tuple_t
__u64 laddr_h;
__u64 laddr_l;
__u64 raddr_h;
__u64 raddr_l;
__u16 lport;
__u16 rport;
__u32 netns;
__u32 pid;
*/
type ConnTupleV6 C.struct_ipv6_tuple_t

func (t *ConnTupleV6) copy() *ConnTupleV6 {
	return &ConnTupleV6{
		laddr_h: t.laddr_h,
		laddr_l: t.laddr_l,
		raddr_h: t.raddr_h,
		raddr_l: t.raddr_l,
		lport:   t.lport,
		rport:   t.rport,
		netns:   t.netns,
		pid:     t.pid,
	}
}

type ConnTupleStruct C.struct_connections

func (t *ConnTupleStruct) copy() *ConnTupleStruct {
	return &ConnTupleStruct{
		ipv4_connection: t.ipv4_connection,
		ipv6_connection: t.ipv6_connection,
	}
}

/* struct conn_stats_t
__u64 send_bytes;
__u64 recv_bytes;
__u32 direction;
__u32 state;
*/
type ConnStats C.struct_conn_stats_t

/* struct conn_stats_ts_t
__u64 send_bytes;
__u64 recv_bytes;
__u64 timestamp;
*/
type ConnStatsWithTimestamp C.struct_conn_stats_ts_t

type PerfEvent C.struct_perf_event
type PerfEventPayload C.union_event_payload
type EventHTTPResponse C.struct_event_http_response
type EventMYSQLGreeting C.struct_event_mysql_greeting
type IPConnections C.struct_connections
type IPV4Connection C.struct_ipv4_tuple_t
type IPV6Connection C.struct_ipv6_tuple_t


func (cs *ConnStatsWithTimestamp) isExpired(latestTime int64, timeout int64) bool {
	return latestTime-int64(cs.timestamp) > timeout
}

func httpResponseEventV4(eventC *EventHTTPResponse, timestamp time.Time) *common.PerfEvent {
	connections_raw := (*IPConnections)(unsafe.Pointer(&eventC.connection))
	connection := ipConnectionV4(connections_raw)
	return &common.PerfEvent{
		Timestamp: timestamp,
		HTTPResponse: &common.HTTPResponse{
			Connection: common.ConnStruct{
				IPV4Connection: common.ConnTuple{
					Laddr: common.V4IPString(uint32(connection.laddr)),
					Lport: uint16(connection.lport),
					Raddr: common.V4IPString(uint32(connection.raddr)),
					Rport: uint16(connection.rport),
					Pid:   uint16(connection.pid),
				},
			},
			StatusCode:   int(eventC.status_code),
			ResponseTime: time.Duration(int(eventC.response_time)) * time.Microsecond,
		},
	}
}

func mysqlGreetingEventV4(eventC *EventMYSQLGreeting, timestamp time.Time) *common.PerfEvent {
	connections_raw := (*IPConnections)(unsafe.Pointer(&eventC.connection))
	connection := ipConnectionV4(connections_raw)
	return &common.PerfEvent{
		Timestamp: timestamp,
		MySQLGreeting: &common.MySQLGreeting{
			Connection: common.ConnStruct{
				IPV4Connection: common.ConnTuple{
					Laddr: common.V4IPString(uint32(connection.laddr)),
					Lport: uint16(connection.lport),
					Raddr: common.V4IPString(uint32(connection.raddr)),
					Rport: uint16(connection.rport),
					Pid:   uint16(connection.pid),
				},
			},
			ProtocolVersion: int(uint16(eventC.protocol_version)),
		},
	}
}

func httpResponseEventV6(eventC *EventHTTPResponse, timestamp time.Time) *common.PerfEvent {
	connections_raw := (*IPConnections)(unsafe.Pointer(&eventC.connection))
	connection := ipConnectionV6(connections_raw)
	return &common.PerfEvent{
		Timestamp: timestamp,
		HTTPResponse: &common.HTTPResponse{
			Connection: common.ConnStruct{
				IPV6Connection: common.ConnTuple{
					Laddr: common.V6IPString(uint64(connection.laddr_h), uint64(connection.laddr_l)),
					Lport: uint16(connection.lport),
					Raddr: common.V6IPString(uint64(connection.raddr_h), uint64(connection.raddr_l)),
					Rport: uint16(connection.rport),
					Pid:   uint16(connection.pid),
				},
			},
			StatusCode:   int(eventC.status_code),
			ResponseTime: time.Duration(int(eventC.response_time)) * time.Microsecond,
		},
	}
}

func mysqlGreetingEventV6(eventC *EventMYSQLGreeting, timestamp time.Time) *common.PerfEvent {
	connections_raw := (*IPConnections)(unsafe.Pointer(&eventC.connection))
	connection := ipConnectionV6(connections_raw)
	return &common.PerfEvent{
		Timestamp: timestamp,
		MySQLGreeting: &common.MySQLGreeting{
			Connection: common.ConnStruct{
				IPV6Connection: common.ConnTuple{
					Laddr: common.V6IPString(uint64(connection.laddr_h), uint64(connection.laddr_l)),
					Lport: uint16(connection.lport),
					Raddr: common.V6IPString(uint64(connection.raddr_h), uint64(connection.raddr_l)),
					Rport: uint16(connection.rport),
					Pid:   uint16(connection.pid),
				},
			},
			ProtocolVersion: int(uint16(eventC.protocol_version)),
		},
	}
}

func ipConnectionV4(eventC *IPConnections) *IPV4Connection {
	ipv4Connection := eventC.ipv4_connection;
	return (*IPV4Connection)(unsafe.Pointer(&ipv4Connection))
}

func ipConnectionV6(eventC *IPConnections) *IPV6Connection {
	ipv6Connection := eventC.ipv6_connection;
	return (*IPV6Connection)(unsafe.Pointer(&ipv6Connection))
}

func perfEvent(data []byte) (*common.PerfEvent, error) {
	eventC := (*PerfEvent)(unsafe.Pointer(&data[0]))
	timestamp := time.Now()
	eventPayload := eventC.payload
	eventType := int(uint16(eventC.event_type))
	switch eventType {
	case 1:
		return httpResponseEventV4((*EventHTTPResponse)(unsafe.Pointer(&eventPayload)), timestamp), nil
	case 2:
		return mysqlGreetingEventV4((*EventMYSQLGreeting)(unsafe.Pointer(&eventPayload)), timestamp), nil
	case 3:
		return httpResponseEventV6((*EventHTTPResponse)(unsafe.Pointer(&eventPayload)), timestamp), nil
	case 4:
		return mysqlGreetingEventV6((*EventMYSQLGreeting)(unsafe.Pointer(&eventPayload)), timestamp), nil
	default:
		return nil, errors.New(fmt.Sprintf("Unknown event type %v", eventType))
	}
}

func connStatsFromTCPv4(t *ConnTupleV4, s *ConnStats) common.ConnectionStats {
	return common.ConnectionStats{
		Pid:        uint32(t.pid),
		Type:       common.TCP,
		Family:     common.AF_INET,
		Local:      common.V4IPString(uint32(t.laddr)),
		Remote:     common.V4IPString(uint32(t.raddr)),
		LocalPort:  uint16(t.lport),
		RemotePort: uint16(t.rport),
		Direction:  common.Direction(s.direction),
		State:      common.State(s.state),
		SendBytes:  uint64(s.send_bytes),
		RecvBytes:  uint64(s.recv_bytes),
	}.WithNamespace(fmt.Sprint(t.netns))
}

func connStatsFromTCPv6(t *ConnTupleV6, s *ConnStats) common.ConnectionStats {
	return common.ConnectionStats{
		Pid:        uint32(t.pid),
		Type:       common.TCP,
		Family:     common.AF_INET6,
		Local:      common.V6IPString(uint64(t.laddr_h), uint64(t.laddr_l)),
		Remote:     common.V6IPString(uint64(t.raddr_h), uint64(t.raddr_l)),
		LocalPort:  uint16(t.lport),
		RemotePort: uint16(t.rport),
		Direction:  common.Direction(s.direction),
		State:      common.State(s.state),
		SendBytes:  uint64(s.send_bytes),
		RecvBytes:  uint64(s.recv_bytes),
	}.WithNamespace(fmt.Sprint(t.netns))
}

func connStatsFromUDPv4(t *ConnTupleV4, s *ConnStatsWithTimestamp) common.ConnectionStats {
	return common.ConnectionStats{
		Pid:        uint32(t.pid),
		Type:       common.UDP,
		Family:     common.AF_INET,
		Local:      common.V4IPString(uint32(t.laddr)),
		Remote:     common.V4IPString(uint32(t.raddr)),
		LocalPort:  uint16(t.lport),
		RemotePort: uint16(t.rport),
		Direction:  common.UNKNOWN,
		State:      common.ACTIVE,
		SendBytes:  uint64(s.send_bytes),
		RecvBytes:  uint64(s.recv_bytes),
	}.WithNamespace(fmt.Sprint(t.netns))
}

func connStatsFromUDPv6(t *ConnTupleV6, s *ConnStatsWithTimestamp) common.ConnectionStats {
	return common.ConnectionStats{
		Pid:        uint32(t.pid),
		Type:       common.UDP,
		Family:     common.AF_INET6,
		Local:      common.V6IPString(uint64(t.laddr_h), uint64(t.laddr_l)),
		Remote:     common.V6IPString(uint64(t.raddr_h), uint64(t.raddr_l)),
		LocalPort:  uint16(t.lport),
		RemotePort: uint16(t.rport),
		Direction:  common.UNKNOWN,
		State:      common.ACTIVE,
		SendBytes:  uint64(s.send_bytes),
		RecvBytes:  uint64(s.recv_bytes),
	}.WithNamespace(fmt.Sprint(t.netns))
}

func connStatsFromProcSpy(t *procspy.Connection) common.ConnectionStats {
	var family = common.AF_INET
	if t.LocalAddress.To4() == nil {
		family = common.AF_INET6
	}

	return common.ConnectionStats{
		Pid:        uint32(t.Proc.PID),
		Type:       common.TCP,
		Family:     family,
		Local:      t.LocalAddress.To16().String(),
		Remote:     t.RemoteAddress.To16().String(),
		LocalPort:  t.LocalPort,
		RemotePort: t.RemotePort,
		Direction:  common.UNKNOWN,
		State:      common.ACTIVE,
		SendBytes:  0,
		RecvBytes:  0,
	}.WithNamespace(strconv.FormatUint(t.Proc.NetNamespaceID, 10))
}
