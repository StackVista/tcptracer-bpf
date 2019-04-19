package network

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestIsIPLocal(t *testing.T) {

	for _, tc := range []struct {
		name     string
		ip       string
		expected bool
	}{
		{
			name:     "localhost ip",
			ip:       "127.0.0.1",
			expected: true,
		},
		{
			name:     "Non-local ip (google)",
			ip:       "216.58.211.110",
			expected: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ipLocal := IsIPLocal(tc.ip)
			assert.Equal(t, tc.expected, ipLocal, "Test: [%s], expected IsIPLocal to return: %d, actually returned: %d", tc.name, tc.expected, ipLocal)
		})
	}
}
