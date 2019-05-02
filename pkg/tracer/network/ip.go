package network

import (
	"fmt"
	logger "github.com/cihub/seelog"
	"net"
)

type NetScanner interface {
	getNetworks() ([]*net.IPNet, error)
	ContainsIP(ip string) bool
}

func MakeLocalNetworkScanner() NetScanner {
	return &LocalNetworkScanner{}
}

type LocalNetworkScanner struct {}

// checks whether the local network scanner contains the given IP
func (lns *LocalNetworkScanner) ContainsIP(ip string) bool {
	networks, err := lns.getNetworks()
	if err != nil {
		logger.Error(fmt.Sprintf("Error getting local networks: %s", err.Error()))
		return false
	}

	return containsIp(networks, ip)
}

// getNetworks returns all the local networks.
func (lns *LocalNetworkScanner) getNetworks() ([]*net.IPNet, error) {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}

	networks := make([]*net.IPNet, 0)
	for _, address := range addresses {
		if ipNet, ok := address.(*net.IPNet); ok && ipNet.IP.To4() != nil {
			networks = append(networks, ipNet)
		}
	}
	return networks, nil
}

// Test network scanner
func MakeTestNetworkScanner(networks []*net.IPNet) NetScanner {
	return &TestNetworkScanner{testNetworks: networks}
}


type TestNetworkScanner struct {
	testNetworks []*net.IPNet
}

// checks whether the local network scanner contains the given IP
func (tns *TestNetworkScanner) ContainsIP(ip string) bool {
	networks, err := tns.getNetworks()
	if err != nil {
		logger.Error(fmt.Sprintf("Error getting local networks: %s", err.Error()))
		return false
	}

	return containsIp(networks, ip)
}

// getNetworks returns all the local networks.
func (tns *TestNetworkScanner) getNetworks() ([]*net.IPNet, error) {
	return tns.testNetworks, nil
}

// Generic function for all network scanners to check whether ip is contained in ipnet's
func containsIp(list []*net.IPNet, ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		logger.Error(fmt.Sprintf("Error occured parsing ip [%s]", ip))
		return false
	}

	for _, v := range list {
		if v.Contains(parsedIP) {
			return true
		}
	}
	return false
}
