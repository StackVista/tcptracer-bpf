package config

import "time"

type CommonConfig struct {
	// CollectTCPConns specifies whether the tracer should collect traffic statistics for TCP connections
	CollectTCPConns bool
	// CollectUDPConns specifies whether the tracer should collect traffic statistics for UDP connections
	CollectUDPConns bool
	// Maximum connections we keep track of
	MaxConnections int
	// UDPConnTimeout determines the length of traffic inactivity between two (IP, port)-pairs before declaring a UDP
	// connection as inactive.
	// Note: As UDP traffic is technically "connection-less", for tracking, we consider a UDP connection to be traffic
	//       between a source and destination IP and port.
	UDPConnTimeout time.Duration
	// Boolean flag to set whether connections should be dropped if no data is transferred.
	FilterInactiveConnections bool
	// Specifies targeted percentile's precision, the more precision - the more measurements we should keep
	// hence more memory is needed and more data will be transferred
	HttpMetricPrecision float64
	// Enable reading and logging bpf_trace_printk from a running eBPF program
	EnableTracepipeLogging bool
}

var DefaultCommonConfig = &CommonConfig{
	CollectTCPConns:           true,
	CollectUDPConns:           true,
	MaxConnections:            10000,
	UDPConnTimeout:            30 * time.Second,
	FilterInactiveConnections: true,
	HttpMetricPrecision:       0.01,
	EnableTracepipeLogging:    false,
}

func MakeCommonConfig() *CommonConfig {
	return &CommonConfig{
		CollectTCPConns:           true,
		CollectUDPConns:           true,
		MaxConnections:            10000,
		UDPConnTimeout:            30 * time.Second,
		FilterInactiveConnections: true,
		HttpMetricPrecision:       0.01,
		EnableTracepipeLogging:    false,
	}
}
