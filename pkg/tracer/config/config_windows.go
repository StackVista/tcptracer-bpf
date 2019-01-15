package config

type Config struct {
	CommonConfig
}

// DefaultConfig enables traffic collection for all connection types
var DefaultConfig = &Config{
	CommonConfig: CommonConfig{
		CollectTCPConns:           DefaultCommonConfig.CollectTCPConns,
		CollectUDPConns:           DefaultCommonConfig.CollectUDPConns,
		MaxConnections:            DefaultCommonConfig.MaxConnections,
		UDPConnTimeout:            DefaultCommonConfig.UDPConnTimeout,
		FilterInactiveConnections: false,
	},
}

func MakeDefaultConfig() *Config {
	defaultCommonConfig := *MakeCommonConfig()
	return &Config{
		CommonConfig: CommonConfig{
			CollectTCPConns:           defaultCommonConfig.CollectTCPConns,
			CollectUDPConns:           defaultCommonConfig.CollectUDPConns,
			MaxConnections:            defaultCommonConfig.MaxConnections,
			UDPConnTimeout:            defaultCommonConfig.UDPConnTimeout,
			FilterInactiveConnections: false,
		},
	}
}
