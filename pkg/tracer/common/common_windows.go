//+build !linux_bpf

package common

import (
	"errors"
)

var (
	ErrNotImplemented = errors.New("BPF-based network tracing not implemented on non-linux systems")
)

func LinuxKernelVersionCode(major, minor, patch uint32) uint32 {
	return 0
}

func CurrentKernelVersion() (uint32, error) {
	return 0, ErrNotImplemented
}
