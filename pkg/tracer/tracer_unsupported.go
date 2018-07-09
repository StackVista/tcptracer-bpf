// +build !linux_bpf

package tracer

func CurrentKernelVersion() (uint32, error) {
	return 0, ErrNotImplemented
}

func IsTracerSupportedByOS() (bool, error) {
	return false, ErrNotImplemented
}

type Tracer struct{}

func NewTracer(config Config) (*Tracer, error) {
	return nil, ErrNotImplemented
}

func NewEventTracer(cb Callback) (*Tracer, error) {
	return nil, ErrNotImplemented
}

func (t *Tracer) Start() {}

func (t *Tracer) Stop() {}

func (t *Tracer) AddFdInstallWatcher(pid uint32) (err error) {
	return ErrNotImplemented
}

func (t *Tracer) RemoveFdInstallWatcher(pid uint32) (err error) {
	return ErrNotImplemented
}

func (t *Tracer) GetActiveConnections() ([]ConnectionStats, error) {
	return nil, ErrNotImplemented
}
