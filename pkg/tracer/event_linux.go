// +build linux_bpf

package tracer

import (
	"errors"
	"fmt"
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/common"
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/procspy"
	logger "github.com/cihub/seelog"
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
type IPConnection C.union_connections
type IPV4Connection C.struct_ipv4_tuple_t
type IPV6Connection C.struct_ipv6_tuple_t


func (cs *ConnStatsWithTimestamp) isExpired(latestTime int64, timeout int64) bool {
	return latestTime-int64(cs.timestamp) > timeout
}

func getConnDetails(eventType int, eventC *PerfEvent) (string, string, uint16, uint16, uint16) {
	var laddr, raddr string
	var lport, rport, pid uint16
	connection_raw := (*IPConnection)(unsafe.Pointer(&eventC.connection))
	if eventType == 1 || eventType == 2 {
		connection := ipConnectionV4(connection_raw)
		logger.Tracef("ipv4: %v", connection)
		laddr = common.V4IPString(uint32(connection.laddr))
		raddr = common.V4IPString(uint32(connection.raddr))
		lport = uint16(connection.lport)
		rport = uint16(connection.rport)
		pid = uint16(connection.pid)
	} else {
		connection := ipConnectionV6(connection_raw)
		logger.Tracef("ipv6: %v", connection)
		laddr = common.V6IPString(uint64(connection.laddr_h), uint64(connection.laddr_l))
		raddr = common.V6IPString(uint64(connection.raddr_h), uint64(connection.raddr_l))
		lport = uint16(connection.lport)
		rport = uint16(connection.rport)
		pid = uint16(connection.pid)
	}
	return laddr, raddr, lport, rport, pid
}

func httpResponseEvent(eventType int, eventC *PerfEvent, timestamp time.Time) *common.PerfEvent {
	eventHttpResponse := (*EventHTTPResponse)(unsafe.Pointer(&eventC.payload))

	laddr, raddr, lport, rport, pid := getConnDetails(eventType, eventC)

	return &common.PerfEvent{
		Timestamp: timestamp,
		HTTPResponse: &common.HTTPResponse{
			StatusCode:   int(eventHttpResponse.status_code),
			ResponseTime: time.Duration(int(eventHttpResponse.response_time)) * time.Microsecond,
		},
		Connection: &common.ConnTuple{
			Laddr: laddr,
			Lport: lport,
			Raddr: raddr,
			Rport: rport,
			Pid:   pid,
		},
	}
}

func mysqlGreetingEvent(eventType int, eventC *PerfEvent, timestamp time.Time) *common.PerfEvent {
	mySqlGreeting := (*EventMYSQLGreeting)(unsafe.Pointer(&eventC.payload))

	laddr, raddr, lport, rport, pid := getConnDetails(eventType, eventC)

	return &common.PerfEvent{
		Timestamp: timestamp,
		MySQLGreeting: &common.MySQLGreeting{
			ProtocolVersion: int(uint16(mySqlGreeting.protocol_version)),
		},
		Connection: &common.ConnTuple{
			Laddr: laddr,
			Lport: lport,
			Raddr: raddr,
			Rport: rport,
			Pid:   pid,
		},
	}
}

func ipConnectionV4(eventC *IPConnection) *IPV4Connection {
	ipv4Connection := *eventC;
	return (*IPV4Connection)(unsafe.Pointer(&ipv4Connection))
}

func ipConnectionV6(eventC *IPConnection) *IPV6Connection {
	ipv6Connection := *eventC;
	return (*IPV6Connection)(unsafe.Pointer(&ipv6Connection))
}

func perfEvent(data []byte) (*common.PerfEvent, error) {
	eventC := (*PerfEvent)(unsafe.Pointer(&data[0]))
	timestamp := time.Now()
	eventType := int(uint16(eventC.event_type))
	switch eventType {
	case 1:
		return httpResponseEvent(eventType, eventC, timestamp), nil
	case 2:
		return mysqlGreetingEvent(eventType, eventC, timestamp), nil
	case 3:
		return httpResponseEvent(eventType, eventC, timestamp), nil
	case 4:
		return mysqlGreetingEvent(eventType, eventC, timestamp), nil
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
