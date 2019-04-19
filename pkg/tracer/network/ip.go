package network

import (
	"fmt"
	logger "github.com/cihub/seelog"
	"net"
)

func IsIPLocal(ip string) bool {
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
	networks, err := getLocalNetworks()
	if err != nil {
		logger.Error(fmt.Sprintf("Error getting local ips: %s", err.Error()))
		return nil, err
	}
	ips := make([]net.IP, 0)
	for _, ipNet := range networks {
		ips = append(ips, ipNet.IP)
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

// getLocalNetworks returns all the local networks.
func getLocalNetworks() ([]*net.IPNet, error) {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	return getIPNetworks(addresses), nil
}

func getIPNetworks(addresses []net.Addr) []*net.IPNet {
	networks := make([]*net.IPNet, 0)
	for _, address := range addresses {
		if ipNet, ok := address.(*net.IPNet); ok && ipNet.IP.To4() != nil {
			networks = append(networks, ipNet)
		}
	}
	return networks
}
