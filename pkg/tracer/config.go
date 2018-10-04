package tracer

type Config struct {
	// CollectTCPConns specifies whether the tracer should collect traffic statistics for TCP connections
	CollectTCPConns bool
	// CollectUDPConns specifies whether the tracer should collect traffic statistics for UDP connections
	CollectUDPConns bool
}

// DefaultConfig enables traffic collection for all connection types
var DefaultConfig = &Config{
	CollectTCPConns: true,
	CollectUDPConns: true,
}
