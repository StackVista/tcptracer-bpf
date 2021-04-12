module github.com/StackVista/tcptracer-bpf

go 1.15

require (
	github.com/DataDog/sketches-go v1.0.0
	github.com/cihub/seelog v0.0.0-20170130134532-f561c5e57575
	github.com/iovisor/gobpf v0.1.1
	github.com/mailru/easyjson v0.7.7
	github.com/prometheus/client_golang v1.9.0
	github.com/prometheus/common v0.15.0
	github.com/pytimer/win-netstat v0.0.0-20180710031115-efa1aff6aafc
	github.com/stretchr/testify v1.7.0
)

replace github.com/iovisor/gobpf => github.com/StackVista/gobpf v0.1.2-fixbuf
