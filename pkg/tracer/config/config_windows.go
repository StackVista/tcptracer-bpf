package config

type Config struct {
	CommonConfig
}

// DefaultConfig enables traffic collection for all connection types
var DefaultConfig = &Config{
	CommonConfig: *DefaultCommonConfig,
}