.phony: all build

# If you can use docker without being root, you can do "make SUDO="
SUDO=$(shell docker info >/dev/null 2>&1 || echo "sudo -E")

all: build

build:
	go build -tags 'linux_bpf' -o nettop nettop.go

build-in-docker:
	$(SUDO) docker build -t "stackvista/tcptracer-bpf-ci" . -f Dockerfile-nettop
	$(SUDO) docker run \
		-v $(GOPATH)/src/github.com/StackVista/tcptracer-bpf:/go/src/github.com/StackVista/tcptracer-bpf \
		--env GOPATH=/go \
		stackvista/tcptracer-bpf-ci \
		sh -c 'cd /go/src/github.com/StackVista/tcptracer-bpf/tests && make'
	$(SUDO) chown $(shell id -u):$(shell id -u) ./nettop
