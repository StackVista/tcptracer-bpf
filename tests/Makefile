.phony: all build

all: build

build:
	go build -tags 'linux_bpf' -o nettop nettop.go

build-in-docker:
	sudo docker build -t "stackvista/tcptracer-bpf-ci" . -f Dockerfile-nettop
	sudo docker run \
		-v $(GOPATH)/src/github.com/StackVista/tcptracer-bpf:/go/src/github.com/StackVista/tcptracer-bpf \
		--env GOPATH=/go \
		stackvista/tcptracer-bpf-ci \
		sh -c 'cd /go/src/github.com/StackVista/tcptracer-bpf/tests && make'
	sudo chown $(shell id -u):$(shell id -u) ./nettop
