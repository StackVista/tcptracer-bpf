package tracer

import (
	"fmt"
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/common"
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/config"
	logger "github.com/cihub/seelog"
	"net"
)

type Tracer interface {
	Start() error
	Stop()
	GetConnections() (*common.Connections, error)
}

// Generic New Tracer function
func NewTracer(config *config.Config) (Tracer, error) {
	// Ensures that each tracer implements a MakeTracer function
	return MakeTracer(config)
}

// Generic IsSupported function
func IsTracerSupportedByOS() (bool, error) {
	// Ensures that each tracer implements a CheckTracerSupport function
	return CheckTracerSupport()
}

func ipLocal(ip string) bool {
	ips, err := getLocalIPs()
	if err != nil {
		logger.Error(fmt.Sprintf("Error getting local ips: %s", err.Error()))
		return false
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		logger.Error(fmt.Sprintf("Error occured parsing ip [%s]", ip))
		return false
	}
	return containsIp(ips, parsedIP)

}

func getLocalIPs() ([]net.IP, error) {
	ipnets, err := GetLocalNetworks()
	if err != nil {
		logger.Error(fmt.Sprintf("Error getting local ips: %s", err.Error()))
		return nil, err
	}
	ips := []net.IP{}
	for _, ipnet := range ipnets {
		ips = append(ips, ipnet.IP)
	}
	return ips, nil
}

func containsIp(list []net.IP, ip net.IP) bool {
	for _, v := range list {
		if v.Equal(ip) {
			return true
		}
	}
	return false
}

// GetLocalNetworks returns all the local networks.
func GetLocalNetworks() ([]*net.IPNet, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	return ipv4Nets(addrs), nil
}

func ipv4Nets(addrs []net.Addr) []*net.IPNet {
	nets := []*net.IPNet{}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			nets = append(nets, ipnet)
		}
	}
	return nets
}
