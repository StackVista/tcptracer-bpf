package tracer

import "time"

type Config struct {
	// CollectTCPConns specifies whether the tracer should collect traffic statistics for TCP connections
	CollectTCPConns bool
	// CollectUDPConns specifies whether the tracer should collect traffic statistics for UDP connections
	CollectUDPConns bool
	// BackfillFromProc enables using /proc to find connections which were already active when the tracer started
	BackfillFromProc bool
	// Location of /proc
	ProcRoot string
	// Mximum connections we keep track of
	MaxConnections int
	// UDPConnTimeout determines the length of traffic inactivity between two (IP, port)-pairs before declaring a UDP
	// connection as inactive.
	// Note: As UDP traffic is technically "connection-less", for tracking, we consider a UDP connection to be traffic
	//       between a source and destination IP and port.
	UDPConnTimeout time.Duration
}

// DefaultConfig enables traffic collection for all connection types
var DefaultConfig = &Config{
	CollectTCPConns: true,
	CollectUDPConns: true,
	BackfillFromProc: true,
	ProcRoot: "/proc",
	MaxConnections: 10000,
	UDPConnTimeout:  30 * time.Second,
}
