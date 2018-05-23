// +build !linux

package tracer

type Tracer struct{}

func TracerAsset() ([]byte, error) {
	return nil, ErrNotImplemented
}

func NewTracer() (*Tracer, error) {
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
