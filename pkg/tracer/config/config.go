package config

import "time"

type CommonConfig struct {
	// CollectTCPConns specifies whether the tracer should collect traffic statistics for TCP connections
	CollectTCPConns bool
	// CollectUDPConns specifies whether the tracer should collect traffic statistics for UDP connections
	CollectUDPConns bool
	// Mximum connections we keep track of
	MaxConnections int
	// UDPConnTimeout determines the length of traffic inactivity between two (IP, port)-pairs before declaring a UDP
	// connection as inactive.
	// Note: As UDP traffic is technically "connection-less", for tracking, we consider a UDP connection to be traffic
	//       between a source and destination IP and port.
	UDPConnTimeout time.Duration
}

var DefaultCommonConfig = &CommonConfig{
	CollectTCPConns:  true,
	CollectUDPConns:  true,
	MaxConnections:   10000,
	UDPConnTimeout:   30 * time.Second,
}