package tracer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	testConn = ConnectionStats{
		Pid:        123,
		Type:       1,
		Family:     0,
		Local:      "192.168.0.1",
		Remote:     "192.168.0.103",
		LocalPort:  123,
		RemotePort: 35000,
		SendBytes:  123123,
		RecvBytes:  312312,
	}
)

func BenchmarkUniqueConnKeyString(b *testing.B) {
	c := testConn
	for n := 0; n < b.N; n++ {
		fmt.Sprintf("%d-%d-%d-%s-%d-%s-%d", c.Pid, c.Type, c.Family, c.Local, c.LocalPort, c.Remote, c.RemotePort)
	}
}

func BenchmarkUniqueConnKeyByteBuffer(b *testing.B) {
	c := testConn
	buf := new(bytes.Buffer)
	for n := 0; n < b.N; n++ {
		buf.Reset()
		buf.WriteString(c.Local)
		buf.WriteString(c.Remote)
		binary.Write(buf, binary.LittleEndian, c.Pid)
		binary.Write(buf, binary.LittleEndian, c.Type)
		binary.Write(buf, binary.LittleEndian, c.Family)
		binary.Write(buf, binary.LittleEndian, c.LocalPort)
		binary.Write(buf, binary.LittleEndian, c.RemotePort)
		buf.Bytes()
	}
}

func BenchmarkUniqueConnKeyByteBufferPacked(b *testing.B) {
	c := testConn
	buf := new(bytes.Buffer)
	for n := 0; n < b.N; n++ {
		buf.Reset()
		// PID (32 bits) + LocalPort (16 bits) + RemotePort (16 bits) = 64 bits
		p0 := uint64(c.Pid)<<32 | uint64(c.LocalPort)<<16 | uint64(c.RemotePort)
		binary.Write(buf, binary.LittleEndian, p0)
		buf.WriteString(c.Local)
		// Family (8 bits) + Type (8 bits) = 16 bits
		p1 := uint16(c.Family)<<8 | uint16(c.Type)
		binary.Write(buf, binary.LittleEndian, p1)
		buf.WriteString(c.Remote)
		buf.Bytes()
	}
}

func TestConnStatsByteKey(t *testing.T) {
	buf := new(bytes.Buffer)
	for _, test := range []struct {
		a ConnectionStats
		b ConnectionStats
	}{
		{
			a: ConnectionStats{Pid: 1},
			b: ConnectionStats{},
		},
		{
			a: ConnectionStats{Family: 1},
			b: ConnectionStats{},
		},
		{
			a: ConnectionStats{Type: 1},
			b: ConnectionStats{},
		},
		{
			a: ConnectionStats{Local: "hello"},
			b: ConnectionStats{},
		},
		{
			a: ConnectionStats{Remote: "goodbye"},
			b: ConnectionStats{},
		},
		{
			a: ConnectionStats{LocalPort: 1},
			b: ConnectionStats{},
		},
		{
			a: ConnectionStats{RemotePort: 1},
			b: ConnectionStats{},
		},
		{
			a: ConnectionStats{Direction: INCOMING},
			b: ConnectionStats{},
		},
		{
			a: ConnectionStats{Direction: OUTGOING},
			b: ConnectionStats{},
		},
		{
			a: ConnectionStats{Pid: 1, Family: 0, Type: 1, Local: "a"},
			b: ConnectionStats{Pid: 1, Family: 0, Type: 1, Local: "b"},
		},
		{
			a: ConnectionStats{Pid: 1, Remote: "b", Family: 0, Type: 1, Local: "a"},
			b: ConnectionStats{Pid: 1, Remote: "a", Family: 0, Type: 1, Local: "b"},
		},
		{
			a: ConnectionStats{Pid: 1, Remote: "", Family: 0, Type: 1, Local: "a"},
			b: ConnectionStats{Pid: 1, Remote: "a", Family: 0, Type: 1, Local: ""},
		},
		{
			a: ConnectionStats{Pid: 1, Remote: "b", Family: 0, Type: 1},
			b: ConnectionStats{Pid: 1, Family: 0, Type: 1, Local: "b"},
		},
		{
			a: ConnectionStats{Pid: 1, Remote: "b", Family: 1},
			b: ConnectionStats{Pid: 1, Remote: "b", Type: 1},
		},
		{
			a: ConnectionStats{Pid: 1, Remote: "b", Type: 0, LocalPort: 3},
			b: ConnectionStats{Pid: 1, Remote: "b", Type: 0, RemotePort: 3},
		},
	} {
		var keyA, keyB string
		if b, err := test.a.ByteKey(buf); assert.NoError(t, err) {
			keyA = string(b)
		}
		if b, err := test.b.ByteKey(buf); assert.NoError(t, err) {
			keyB = string(b)
		}
		assert.NotEqual(t, keyA, keyB)
	}
}
