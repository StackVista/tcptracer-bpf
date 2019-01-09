// +build !linux_bpf,!windows

package config

type Config struct {}

// DefaultConfig enables traffic collection for all connection types
var DefaultConfig = &Config{}
