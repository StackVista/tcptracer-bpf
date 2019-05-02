package network

import (
	"github.com/stretchr/testify/assert"
	"net"
	"testing"
)

func TestIPContainedInNetwork(t *testing.T) {

	for _, tc := range []struct {
		name     string
		ip       string
		testNetworks []*net.IPNet
		expected bool
	}{
		{
			name:     "should contain ip in the 127.0.x.x range",
			ip:       "127.0.0.1",
			testNetworks: []*net.IPNet{
				{IP: net.IPv4(127, 0, 0, 1), Mask: net.IPv4Mask(255, 255, 0, 0)},
				{IP: net.IPv4(172, 17, 0, 1), Mask: net.IPv4Mask(255, 255, 0, 0)},
			},
			expected: true,
		},
		{
			name:     "should not contain ip in the 216.58.x.x range",
			ip:       "216.58.211.110",
			testNetworks: []*net.IPNet{
				{IP: net.IPv4(127, 0, 0, 1), Mask: net.IPv4Mask(255, 255, 0, 0)},
				{IP: net.IPv4(172, 17, 0, 1), Mask: net.IPv4Mask(255, 255, 0, 0)},
				{IP: net.IPv4(216, 52, 0, 1), Mask: net.IPv4Mask(255, 255, 0, 0)},
			},
			expected: false,
		},
		{
			name:     "should contain ip in the 216.58.x.x range",
			ip:       "216.58.211.110",
			testNetworks: []*net.IPNet{
				{IP: net.IPv4(127, 0, 0, 1), Mask: net.IPv4Mask(255, 255, 0, 0)},
				{IP: net.IPv4(172, 17, 0, 1), Mask: net.IPv4Mask(255, 255, 0, 0)},
				{IP: net.IPv4(216, 58, 0, 1), Mask: net.IPv4Mask(255, 255, 0, 0)},
			},
			expected: true,
		},
		{
			name:     "should contain ip in the 172.17.x.x range",
			ip:       "172.17.0.4",
			testNetworks: []*net.IPNet{
				{IP: net.IPv4(127, 0, 0, 1), Mask: net.IPv4Mask(255, 255, 0, 0)},
				{IP: net.IPv4(172, 17, 0, 1), Mask: net.IPv4Mask(255, 255, 0, 0)},
			},
			expected: true,
		},
		{
			name:     "should not contain ip in the 172.18.x.x range",
			ip:       "172.18.0.1",
			testNetworks: []*net.IPNet{
				{IP: net.IPv4(127, 0, 0, 1), Mask: net.IPv4Mask(255, 255, 0, 0)},
				{IP: net.IPv4(172, 17, 0, 1), Mask: net.IPv4Mask(255, 255, 0, 0)},
			},
			expected: false,
		},
		{
			name:     "should contain ip in the 172.18.x.x range",
			ip:       "172.18.0.1",
			testNetworks: []*net.IPNet{
				{IP: net.IPv4(127, 0, 0, 1), Mask: net.IPv4Mask(255, 255, 0, 0)},
				{IP: net.IPv4(172, 17, 0, 1), Mask: net.IPv4Mask(255, 255, 0, 0)},
				{IP: net.IPv4(172, 18, 0, 1), Mask: net.IPv4Mask(255, 255, 0, 0)},
			},
			expected: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			networkScanner := MakeTestNetworkScanner(tc.testNetworks)
			ipLocal := networkScanner.ContainsIP(tc.ip)
			assert.Equal(t, tc.expected, ipLocal, "Test: [%s], expected IsIPLocal to return: %d, actually returned: %d", tc.name, tc.expected, ipLocal)
		})
	}
}
