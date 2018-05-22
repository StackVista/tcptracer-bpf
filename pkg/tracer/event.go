package tracer

import (
	"encoding/binary"
	"net"
	"fmt"
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

func (t TCPTupleV4) String() string {
	saddrbuf := make([]byte, 4)
	daddrbuf := make([]byte, 4)

	binary.LittleEndian.PutUint32(saddrbuf, uint32(t.saddr))
	binary.LittleEndian.PutUint32(daddrbuf, uint32(t.daddr))

	source := net.IPv4(saddrbuf[0], saddrbuf[1], saddrbuf[2], saddrbuf[3])
	dest := net.IPv4(daddrbuf[0], daddrbuf[1], daddrbuf[2], daddrbuf[3])

	pid := uint32(t.pid)
	return fmt.Sprintf("[PID: %d - %v:%d -> %v:%d]", pid, source, t.sport, dest, t.dport)
}
