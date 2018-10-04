// +build linux_bpf

package tracer

import (
	"encoding/binary"
	"net"
)

/*
#include "../../tcptracer-bpf.h"
*/
import "C"

/* struct_Key
u32 src_ip;
u32 dst_ip;
*/
type ConnKey C.struct_Key

/* struct_Leaf
u64 pkts;
u64 bytes;
*/
type ConnLeaf C.struct_Leaf

/*  struct_ipv4_tuple_t
__u32 saddr;
__u32 daddr;
__u16 sport;
__u16 dport;
__u32 netns;
__u32 pid;
*/
type ConnTupleV4 C.struct_ipv4_tuple_t

func (t *ConnTupleV4) copy() *ConnTupleV4 {
	return &ConnTupleV4{
		saddr: t.saddr,
		daddr: t.daddr,
		sport: t.sport,
		dport: t.dport,
		netns: t.netns,
		pid:   t.pid,
	}
}

/* struct_ipv6_tuple_t
__u64 saddr_h;
__u64 saddr_l;
__u64 daddr_h;
__u64 daddr_l;
__u16 sport;
__u16 dport;
__u32 netns;
__u32 pid;
*/
type ConnTupleV6 C.struct_ipv6_tuple_t

func (t *ConnTupleV6) copy() *ConnTupleV6 {
	return &ConnTupleV6{
		saddr_h: t.saddr_h,
		saddr_l: t.saddr_l,
		daddr_h: t.daddr_h,
		daddr_l: t.daddr_l,
		sport:   t.sport,
		dport:   t.dport,
		netns:   t.netns,
		pid:     t.pid,
	}
}

/* struct conn_stats_t
__u64 send_bytes;
__u64 recv_bytes;
*/
type ConnStats C.struct_conn_stats_t

/* struct conn_stats_ts_t
__u64 send_bytes;
__u64 recv_bytes;
__u64 timestamp;
*/
type ConnStatsWithTimestamp C.struct_conn_stats_ts_t

func (cs *ConnStatsWithTimestamp) isExpired(latestTime int64, timeout int64) bool {
	return latestTime-int64(cs.timestamp) > timeout
}

var protocolType = map[uint32]ConnectionType{
	0x06: TCP,
	0x11: UDP,
}

func connStatsFromTCPv4(t *ConnKey, s *ConnLeaf) ConnectionStats {
	return ConnectionStats{
		Pid:       0,
		Type:      protocolType[uint32(t.protocol)],
		Family:    AF_INET,
		Source:    v4IPString(uint32(t.src_ip)),
		Dest:      v4IPString(uint32(t.dst_ip)),
		SPort:     uint16(t.src_port),
		DPort:     uint16(t.dst_port),
		SendBytes: uint64(s.bytes),
		RecvBytes: uint64(0),
	}
}

func connStatsFromTCPv6(t *ConnTupleV6, s *ConnStats) ConnectionStats {
	return ConnectionStats{
		Pid:       uint32(t.pid),
		Type:      TCP,
		Family:    AF_INET6,
		Source:    v6IPString(uint64(t.saddr_h), uint64(t.saddr_l)),
		Dest:      v6IPString(uint64(t.daddr_h), uint64(t.daddr_l)),
		SPort:     uint16(t.sport),
		DPort:     uint16(t.dport),
		SendBytes: uint64(s.send_bytes),
		RecvBytes: uint64(s.recv_bytes),
	}
}

func connStatsFromUDPv4(t *ConnTupleV4, s *ConnStatsWithTimestamp) ConnectionStats {
	return ConnectionStats{
		Pid:       uint32(t.pid),
		Type:      UDP,
		Family:    AF_INET,
		Source:    v4IPString(uint32(t.saddr)),
		Dest:      v4IPString(uint32(t.daddr)),
		SPort:     uint16(t.sport),
		DPort:     uint16(t.dport),
		SendBytes: uint64(s.send_bytes),
		RecvBytes: uint64(s.recv_bytes),
	}
}

func connStatsFromUDPv6(t *ConnTupleV6, s *ConnStatsWithTimestamp) ConnectionStats {
	return ConnectionStats{
		Pid:       uint32(t.pid),
		Type:      UDP,
		Family:    AF_INET6,
		Source:    v6IPString(uint64(t.saddr_h), uint64(t.saddr_l)),
		Dest:      v6IPString(uint64(t.daddr_h), uint64(t.daddr_l)),
		SPort:     uint16(t.sport),
		DPort:     uint16(t.dport),
		SendBytes: uint64(s.send_bytes),
		RecvBytes: uint64(s.recv_bytes),
	}
}

func v4IPString(addr uint32) string {
	addrbuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(addrbuf, uint32(addr))
	return net.IPv4(addrbuf[0], addrbuf[1], addrbuf[2], addrbuf[3]).String()
}

func v6IPString(addr_h, addr_l uint64) string {
	addrbuf := make([]byte, 16)
	binary.LittleEndian.PutUint64(addrbuf, uint64(addr_h))
	binary.LittleEndian.PutUint64(addrbuf[8:], uint64(addr_l))
	return net.IP(addrbuf).String()
}
