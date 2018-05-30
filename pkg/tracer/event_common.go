package tracer

import (
	"fmt"
	"net"
)

type ConnectionType uint32

const (
	TCP ConnectionType = 0
	UDP ConnectionType = 1
)

const (
	AF_INET  ConnectionFamily = 0
	AF_INET6 ConnectionFamily = 1
)

type ConnectionFamily uint32

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
	return fmt.Sprintf("ConnectionStats [PID: %d - %v:%d → %v:%d] %d bytes send, %d bytes recieved",
		c.Pid, c.Source, c.SPort, c.Dest, c.DPort, c.SendBytes, c.RecvBytes)
}

type EventType uint32

// These constants should be in sync with the equivalent definitions in the ebpf program.
const (
	EventConnect   EventType = 1
	EventAccept              = 2
	EventClose               = 3
	EventFdInstall           = 4
)

func (e EventType) String() string {
	switch e {
	case EventConnect:
		return "connect"
	case EventAccept:
		return "accept"
	case EventClose:
		return "close"
	case EventFdInstall:
		return "fdinstall"
	default:
		return "unknown"
	}
}

// TcpV4 represents a TCP event (connect, accept or close) on IPv4
type TcpV4 struct {
	Timestamp uint64    // Monotonic timestamp
	CPU       uint64    // CPU index
	Type      EventType // connect, accept or close
	Pid       uint32    // Process ID, who triggered the event
	Comm      string    // The process command (as in /proc/$pid/comm)
	SAddr     net.IP    // Local IP address
	DAddr     net.IP    // Remote IP address
	SPort     uint16    // Local TCP port
	DPort     uint16    // Remote TCP port
	NetNS     uint32    // Network namespace ID (as in /proc/$pid/ns/net)
	Fd        uint32    // File descriptor for fd_install events
}

// TcpV6 represents a TCP event (connect, accept or close) on IPv6
type TcpV6 struct {
	Timestamp uint64    // Monotonic timestamp
	CPU       uint64    // CPU index
	Type      EventType // connect, accept or close
	Pid       uint32    // Process ID, who triggered the event
	Comm      string    // The process command (as in /proc/$pid/comm)
	SAddr     net.IP    // Local IP address
	DAddr     net.IP    // Remote IP address
	SPort     uint16    // Local TCP port
	DPort     uint16    // Remote TCP port
	NetNS     uint32    // Network namespace ID (as in /proc/$pid/ns/net)
	Fd        uint32    // File descriptor for fd_install events
}
