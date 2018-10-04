package tracer

import (
	"errors"
)

var (
	ErrNotImplemented = errors.New("BPF-based network tracing not implemented on non-linux systems")
)

// KERNEL_VERSION(a,b,c) = (a << 16) + (b << 8) + (c)
// Per https://github.com/torvalds/linux/blob/master/Makefile#L1187
func linuxKernelVersionCode(major, minor, patch uint32) uint32 {
	return (major << 16) + (minor << 8) + patch
}
