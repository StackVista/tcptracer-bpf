package main

import (
	"bytes"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/DataDog/datadog-agent/pkg/pidfile"
	"github.com/DataDog/tcptracer-bpf/agent/config"

	log "github.com/cihub/seelog"
)

// Flag values
var opts struct {
	yamlConfigPath string
	iniConfigPath  string

	pidFilePath string
	debug       bool
	version     bool
}

// Version info sourced from build flags
var (
	GoVersion string
	Version   string
	GitCommit string
	GitBranch string
	BuildDate string
)

func main() {
	// Parse flags
	flag.StringVar(&opts.yamlConfigPath, "yamlConfig", "/etc/datadog-agent/datadog.yaml", "Path to datadog config formatted as YAML")
	flag.StringVar(&opts.iniConfigPath, "iniConfig", "/etc/dd-agent/datadog.conf", "Path to datadog config formatted as INI")
	flag.StringVar(&opts.pidFilePath, "pid", "", "Path to set pidfile for process")
	flag.BoolVar(&opts.version, "version", false, "Print the version and exit")
	flag.Parse()

	// Set up a default config before parsing config so we log errors nicely.
	// The default will be stdout since we can't assume any file is writeable.
	if err := config.NewLoggerLevel("info", "", true); err != nil {
		panic(err)
	}

	// --version
	if opts.version {
		fmt.Println(versionString())
		os.Exit(0)
	}

	// --pid
	if opts.pidFilePath != "" {
		if err := pidfile.WritePID(opts.pidFilePath); err != nil {
			log.Errorf("Error while writing PID file, exiting: %v", err)
			os.Exit(1)
		}

		log.Infof("pid '%d' written to pid file '%s'", os.Getpid(), opts.pidFilePath)

		defer func() {
			os.Remove(opts.pidFilePath)
		}()
	}

	// Parsing INI and/or YAML config files
	cfg := parseConfig()

	// Run a profile server.
	go func() {
		http.ListenAndServe("localhost:6062", nil)
	}()

	nt, err := CreateNetworkTracer(cfg)
	if err != nil {
		log.Criticalf("failed to create network tracer: %s", err)
		os.Exit(1)
	}

	go nt.Run()

	log.Infof("network tracer started")

	// Handles signals, which tells us whether we should exit.
	e := make(chan bool)
	go handleSignals(e)
	<-e

	nt.Close()
	log.Flush()
}

func handleSignals(exit chan bool) {
	sigIn := make(chan os.Signal, 100)
	signal.Notify(sigIn)
	// unix only in all likelihood;  but we don't care.
	for sig := range sigIn {
		switch sig {
		case syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL, syscall.SIGQUIT:
			log.Criticalf("Caught signal '%s'; terminating.", sig)
			close(exit)
		default:
			log.Warnf("Caught signal %s; continuing/ignoring.", sig)
		}
	}
}

// versionString returns the version information filled in at build time
func versionString() string {
	addString := func(buf *bytes.Buffer, s, arg string) {
		if arg != "" {
			fmt.Fprintf(buf, s, arg)
		}
	}

	var buf bytes.Buffer
	addString(&buf, "Version: %s\n", Version)
	addString(&buf, "Git hash: %s\n", GitCommit)
	addString(&buf, "Git branch: %s\n", GitBranch)
	addString(&buf, "Build date: %s\n", BuildDate)
	addString(&buf, "Go Version: %s\n", GoVersion)
	return buf.String()
}

func parseConfig() *config.Config {
	iniConfig, err := config.NewIfExists(opts.iniConfigPath) // --iniConfig
	if err != nil {
		log.Criticalf("Error reading INI formatted config: %s", err)
		os.Exit(1)
	}

	yamlConf, err := config.NewYamlIfExists(opts.yamlConfigPath) // --yamlConfig
	if err != nil {
		log.Criticalf("Error reading YAML formatted config: %s", err)
		os.Exit(1)
	}

	cfg, err := config.NewConfig(iniConfig, yamlConf)
	if err != nil {
		log.Criticalf("Error parsing config: %s", err)
		os.Exit(1)
	}
	return cfg
}
