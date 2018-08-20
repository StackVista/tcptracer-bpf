package net

import (
	"fmt"
	"net"
	"os"

	log "github.com/cihub/seelog"

	"github.com/DataDog/tcptracer-bpf/agent/config"
)

// Unix Domain Socket Listener
type UDSListener struct {
	conn       net.Listener
	socketPath string
}

// NewUDSListener returns an idle UDSListener Statsd listener
func NewUDSListener(cfg *config.Config) (*UDSListener, error) {
	if len(cfg.UnixSocketPath) == 0 {
		return nil, fmt.Errorf("nettracer-uds: empty socket path provided")
	}

	addr, err := net.ResolveUnixAddr("unix", cfg.UnixSocketPath)
	if err != nil {
		return nil, fmt.Errorf("nettracer-uds: can't ResolveUnixAddr: %v", err)
	}

	conn, err := net.Listen("unix", addr.Name)
	if err != nil {
		return nil, fmt.Errorf("can't listen: %s", err)
	}

	if err := os.Chmod(cfg.UnixSocketPath, 0722); err != nil {
		return nil, fmt.Errorf("can't set the socket at write only: %s", err)
	}

	listener := &UDSListener{
		conn:       conn,
		socketPath: cfg.UnixSocketPath,
	}

	log.Debugf("nettracer-uds: %s successfully initialized", conn.Addr())
	return listener, nil
}

func (l *UDSListener) GetListener() net.Listener {
	return l.conn
}

// Stop closes the UDSListener connection and stops listening
func (l *UDSListener) Stop() {
	l.conn.Close()

	// Socket cleanup on exit
	if err := os.Remove(l.socketPath); err != nil {
		log.Infof("nettracer-uds: error removing socket file: %s", err)
	}
}
