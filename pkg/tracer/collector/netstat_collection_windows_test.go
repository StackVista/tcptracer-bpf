package collector

import (
	"fmt"
	"github.com/pytimer/win-netstat"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"strings"
	"testing"
)

func MockNetstatCollector() *NetstatCollector {
	collector := new(MockedNetstatCollector)
	collector.On("getConnections", mock.Anything).Return(Connections, nil)
	return &NetstatCollector{collector}
}

func TestExample(t *testing.T) {
	actual := strings.ToUpper("Hello")
	expected := "HELLO"

	collector := MockNetstatCollector()

	conns, err := collector.getConnections("TCP")
	if err != nil {
		println(err)
	}

	for _, conn := range conns {
		fmt.Printf("%s %d %s\n", conn.LocalAddr, conn.LocalPort, conn.State)
	}

	assert.Equal(t, expected, actual)
}

type MockedNetstatCollector struct {
	mock.Mock
}

func (mock *MockedNetstatCollector) getConnections(kind string) ([]winnetstat.NetStat, error) {
	args := mock.Called(kind)
	return args.Get(0).([]winnetstat.NetStat), args.Error(1)
}

var Connections = []winnetstat.NetStat{
	winnetstat.NetStat{
		LocalAddr:  "127.0.0.1",
		LocalPort:  8080,
		RemoteAddr: "192.168.2.111",
		RemotePort: 8080,
		OwningPid:  10,
		State:      "LISTEN",
	},
	winnetstat.NetStat{
		LocalAddr:  "127.0.0.1",
		LocalPort:  5050,
		RemoteAddr: "192.168.2.25",
		RemotePort: 0,
		OwningPid:  11,
		State:      "LISTEN",
	},
	winnetstat.NetStat{
		LocalAddr:  "192.168.2.20",
		LocalPort:  7070,
		RemoteAddr: "192.168.2.100",
		RemotePort: 11253,
		OwningPid:  12,
		State:      "LISTEN",
	},
	winnetstat.NetStat{
		LocalAddr:  "192.168.2.30",
		LocalPort:  11252,
		RemoteAddr: "192.168.2.31",
		RemotePort: 8081,
		OwningPid:  13,
		State:      "ESTABLISHED",
	},
	winnetstat.NetStat{
		LocalAddr:  "192.168.2.32",
		LocalPort:  11256,
		RemoteAddr: "192.168.2.33",
		RemotePort: 8082,
		OwningPid:  14,
		State:      "ESTABLISHED",
	},
	winnetstat.NetStat{
		LocalAddr:  "192.168.2.40",
		LocalPort:  9000,
		RemoteAddr: "192.168.2.50",
		RemotePort: 8086,
		OwningPid:  15,
		State:      "CLOSE_WAIT",
	},
}