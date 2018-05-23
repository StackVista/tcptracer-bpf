package tracer

import (
	"encoding/binary"
	"fmt"
	"net"
)

/*
#include "../../tcptracer-bpf.h"
*/
import "C"

/*  struct_ipv4_tuple_t
__u32 saddr;
__u32 daddr;
__u16 sport;
__u16 dport;
__u32 netns;
__u32 pid;
*/
type TCPTupleV4 C.struct_ipv4_tuple_t

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
type TCPTupleV6 C.struct_ipv6_tuple_t

/* struct tcp_conn_stats_t
__u64 send_bytes;
__u64 recv_bytes;
*/
type TCPConnStats C.struct_tcp_conn_stats_t

type ConnectionStats struct {
	Pid uint32

	Source string // Represented as a string for now to handle both IPv4 & IPv6
	Dest   string
	SPort  uint16
	DPort  uint16

	SendBytes uint64
	RecvBytes uint64
}

func (c ConnectionStats) String() string {
	return fmt.Sprintf("ConnectionStats [PID: %d - %v:%d → %v:%d] %d bytes send, %d bytes recieved",
		c.Pid, c.Source, c.SPort, c.Dest, c.DPort, c.SendBytes, c.RecvBytes)
}

func connStatsFromTCPv4(t *TCPTupleV4, s *TCPConnStats) ConnectionStats {
	saddrbuf := make([]byte, 4)
	daddrbuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(saddrbuf, uint32(t.saddr))
	binary.LittleEndian.PutUint32(daddrbuf, uint32(t.daddr))

	return ConnectionStats{
		Pid:       uint32(t.pid),
		Source:    net.IPv4(saddrbuf[0], saddrbuf[1], saddrbuf[2], saddrbuf[3]).String(),
		Dest:      net.IPv4(daddrbuf[0], daddrbuf[1], daddrbuf[2], daddrbuf[3]).String(),
		SPort:     uint16(t.sport),
		DPort:     uint16(t.dport),
		SendBytes: uint64(s.send_bytes),
		RecvBytes: uint64(s.recv_bytes),
	}
}

func connStatsFromTCPv6(t *TCPTupleV6, s *TCPConnStats) ConnectionStats {
	saddrbuf := make([]byte, 16)
	daddrbuf := make([]byte, 16)
	binary.LittleEndian.PutUint64(saddrbuf, uint64(t.saddr_h))
	binary.LittleEndian.PutUint64(saddrbuf[8:], uint64(t.saddr_l))
	binary.LittleEndian.PutUint64(daddrbuf, uint64(t.daddr_h))
	binary.LittleEndian.PutUint64(daddrbuf[8:], uint64(t.daddr_l))

	return ConnectionStats{
		Pid:       uint32(t.pid),
		Source:    net.IP(saddrbuf).String(),
		Dest:      net.IP(daddrbuf).String(),
		SPort:     uint16(t.sport),
		DPort:     uint16(t.dport),
		SendBytes: uint64(s.send_bytes),
		RecvBytes: uint64(s.recv_bytes),
	}
}
