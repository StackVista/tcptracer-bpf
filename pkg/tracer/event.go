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

var protocolType = map[uint32]ConnectionType{
	0x06: TCP,
	0x11: UDP,
}

func formatConnStats(t *ConnKey, s *ConnLeaf) ConnectionStats {
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

func v4IPString(addr uint32) string {
	addrbuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(addrbuf, uint32(addr))
	return net.IPv4(addrbuf[0], addrbuf[1], addrbuf[2], addrbuf[3]).String()
}
