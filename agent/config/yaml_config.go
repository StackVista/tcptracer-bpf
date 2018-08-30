package config

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v2"
)

// YamlConfig is a structure used for marshaling the datadog.yaml configuration
// available in Agent versions >= 6
type YamlConfig struct {
	LogToConsole bool   `yaml:"log_to_console"`
	LogLevel     string `yaml:"log_level"`
	Process      struct {
		// A string indicating the enabled state of the network tracer.
		NetworkTracingEnabled string `yaml:"network_tracing_enabled"`
		// The full path to the file where process-agent logs will be written.
		LogFile string `yaml:"log_file"`
		// The full path to the location of the unix socket where network traces will be accessed
		UnixSocketPath string `yaml:"nettracer_socket"`
	} `yaml:"process_config"`
}

// NewYamlIfExists returns a new YamlConfig if the given configPath is exists.
func NewYamlIfExists(configPath string) (*YamlConfig, error) {
	yamlConf := YamlConfig{}
	if pathExists(configPath) {
		lines, err := readLines(configPath)
		if err != nil {
			return nil, fmt.Errorf("read error: %s", err)
		}
		if err = yaml.Unmarshal([]byte(strings.Join(lines, "\n")), &yamlConf); err != nil {
			return nil, fmt.Errorf("parse error: %s", err)
		}
		return &yamlConf, nil
	}
	return nil, nil
}

func mergeYamlConfig(agentConf *Config, yc *YamlConfig) (*Config, error) {
	if enabled, err := isAffirmative(yc.Process.NetworkTracingEnabled); err != nil {
		agentConf.Enabled = enabled
	}

	if socketPath := yc.Process.UnixSocketPath; socketPath != "" {
		agentConf.UnixSocketPath = socketPath
	}

	if yc.LogToConsole {
		agentConf.LogToConsole = true
	}
	if yc.Process.LogFile != "" {
		agentConf.LogFile = yc.Process.LogFile
	}

	// Pull additional parameters from the global config file.
	agentConf.LogLevel = yc.LogLevel

	return agentConf, nil
}

// pathExists returns a boolean indicating if the given path exists on the file system.
func pathExists(filename string) bool {
	if _, err := os.Stat(filename); err == nil {
		return true
	}
	return false
}

// readLines reads contents from a file and splits them by new lines.
func readLines(filename string) ([]string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return []string{""}, err
	}
	defer f.Close()

	var ret []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		ret = append(ret, scanner.Text())
	}
	return ret, scanner.Err()
}
