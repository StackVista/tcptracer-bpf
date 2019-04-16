package tracer

import (
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/common"
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/config"
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
		// log error panic(fmt.Sprintf("Error occured: %v", err))
		return false
	}

	parsedIP, _, err := net.ParseCIDR(ip)
	if err != nil {
		// log error panic(fmt.Sprintf("Error occured: %v", err))
		return false
	}
	return containsIp(ips, parsedIP)

}

func getLocalIPs() ([]net.IP, error) {
	ipnets, err := GetLocalNetworks()
	if err != nil {
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