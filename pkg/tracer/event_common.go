package tracer

import (
	"bytes"
	"encoding/binary"
	"fmt"
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

type ConnectionStats struct {
	Pid    uint32
	Type   ConnectionType
	Family ConnectionFamily

	Source string // Represented as a string for now to handle both IPv4 & IPv6
	Dest   string
	SPort  uint16
	DPort  uint16

	SendBytes uint64
	RecvBytes uint64
}

func (c ConnectionStats) String() string {
	return fmt.Sprintf("[%s] [PID: %d] [%v:%d ⇄ %v:%d] %d bytes sent, %d bytes received",
		c.Type, c.Pid, c.Source, c.SPort, c.Dest, c.DPort, c.SendBytes, c.RecvBytes)
}

func (c ConnectionStats) ByteKey(buffer *bytes.Buffer) ([]byte, error) {
	buffer.Reset()
	// Byte-packing to improve creation speed
	// PID (32 bits) + SPort (16 bits) + DPort (16 bits) = 64 bits
	p0 := uint64(c.Pid)<<32 | uint64(c.SPort)<<16 | uint64(c.DPort)
	if err := binary.Write(buffer, binary.LittleEndian, p0); err != nil {
		return nil, err
	}
	if _, err := buffer.WriteString(c.Source); err != nil {
		return nil, err
	}
	// Family (8 bits) + Type (8 bits) = 16 bits
	p1 := uint16(c.Family)<<8 | uint16(c.Type)
	if err := binary.Write(buffer, binary.LittleEndian, p1); err != nil {
		return nil, err
	}
	if _, err := buffer.WriteString(c.Dest); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}