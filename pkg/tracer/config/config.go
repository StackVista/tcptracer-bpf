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
	// HttpMetricConfig contains settings related to aggregation of http metrics
	HttpMetricConfig HttpMetricConfig
	// Enable reading and logging bpf_trace_printk from a running eBPF program
	EnableTracepipeLogging bool
}

type HttpMetricConfig struct {
	// SketchType specifies which algorithm to use to collapse measurements
	SketchType MetricSketchType
	// MaxNumBins is the maximum number of bins of the ddSketch we use to store percentiles.]
	MaxNumBins int
	// Accuracy is the value accuracy we have on the percentiles.
	// for example, we can say that p99 is 100ms +- 1ms
	Accuracy float64
}

type MetricSketchType string

const (
	// Unbounded offers constant-time insertion and whose size grows indefinitely
	Unbounded MetricSketchType = "unbounded"
	// CollapsingLowest offers constant-time insertion and whose size grows until the maximum number of bins is reached, at which point bins with lowest indices are collapsed
	CollapsingLowest MetricSketchType = "collapsing_lowest_dense"
	// CollapsingHighest offers constant-time insertion and whose size grows until the maximum number of bins is reached, at which point bins with highest indices are collapsed
	CollapsingHighest MetricSketchType = "collapsing_highest_dense"
)

var DefaultCommonConfig = &CommonConfig{
	CollectTCPConns:           true,
	CollectUDPConns:           true,
	MaxConnections:            10000,
	UDPConnTimeout:            30 * time.Second,
	FilterInactiveConnections: true,
	HttpMetricConfig: HttpMetricConfig{
		SketchType: CollapsingLowest,
		Accuracy:   0.01,
		MaxNumBins: 1024,
	},
	EnableTracepipeLogging: false,
}

func MakeCommonConfig() *CommonConfig {
	return &CommonConfig{
		CollectTCPConns:           true,
		CollectUDPConns:           true,
		MaxConnections:            10000,
		UDPConnTimeout:            30 * time.Second,
		FilterInactiveConnections: true,
		HttpMetricConfig: HttpMetricConfig{
			SketchType: CollapsingLowest,
			Accuracy:   0.01,
			MaxNumBins: 1024,
		},
		EnableTracepipeLogging: false,
	}
}
