# TODO: Move this to a Rakefile, for consistency with the other agent
DEBUG=1
UID=$(shell id -u)
PWD=$(shell pwd)

DOCKER_FILE?=Dockerfile
DOCKER_IMAGE?=stackstate/tcptracer-bpf-builder

# If you can use docker without being root, you can do "make SUDO="
SUDO=$(shell docker info >/dev/null 2>&1 || echo "sudo -E")

# Agent configuration variables
NS = main
COMMIT = $(shell git rev-parse --short HEAD)
BRANCH = $(shell git rev-parse --abbrev-ref HEAD)
DATE = $(shell date +%FT%T%z)
GO_VER = $(shell go version)
# If not set, set AGENT_VERSION to 0.99.0
AGENT_VERSION ?= 0.99.0

# Go build parameters
GO_TAGS = linux_bpf

LDFLAGS = -X '$(NS).Version=$(AGENT_VERSION)'
LDFLAGS += -X '$(NS).BuildDate=$(DATE)'
LDFLAGS += -X '$(NS).GitCommit=$(COMMIT)'
LDFLAGS += -X '$(NS).GitBranch=$(BRANCH)'
LDFLAGS += -X '$(NS).GoVersion=$(GO_VER)'

# Optionally allow static builds
ifeq ($(NETWORK_AGENT_STATIC), true)
	# Required because of getaddrinfo
	GO_TAGS += netgo
	LDFLAGS += -linkmode external -extldflags '-static'
	# CC = '/usr/local/musl/bin/musl-gcc' # TODO: Get musl-based static builds working for network-tracer
endif

# Generate and install eBPF program via gobindata
all: install-generated-go test

build-docker-image:
	$(SUDO) docker build -t $(DOCKER_IMAGE) -f $(DOCKER_FILE) .

build-ebpf-object:
	$(SUDO) docker run -t --rm -e DEBUG=$(DEBUG) \
		-e CIRCLE_BUILD_URL=$(CIRCLE_BUILD_URL) \
		-v $(PWD):/src:ro \
		-v $(PWD)/ebpf:/dist/ \
		--workdir=/src \
		$(DOCKER_IMAGE) \
		make DEST_DIR=/dist -f ebpf.mk build
	$(SUDO) chown -R $(UID):$(UID) ebpf

build-ebpf-object-local:
	make -f ebpf.mk build

build-ebpf-object-ci:
	make DEST_DIR=./ebpf -f ebpf.mk build

install-generated-go: build-ebpf-object
	cp ebpf/tcptracer-ebpf.go pkg/tracer/tcptracer-ebpf.go

install-generated-local-go: build-ebpf-object-local
	cp ebpf/tcptracer-ebpf.go pkg/tracer/tcptracer-ebpf.go

delete-docker-image:
	$(SUDO) docker rmi -f $(DOCKER_IMAGE)

lint:
	./tools/lint -ignorespelling "agre " -ignorespelling "AGRE " .
	./tools/shell-lint .

# Build & run dockerized `nettop` command for testing 
# $ make all run-nettop
run-nettop:
	$(SUDO) docker build -t "tcptracer-bpf-dd-nettop" . -f Dockerfile
	$(SUDO) docker run \
		--net=host \
		--cap-add=SYS_ADMIN \
		--privileged \
		-v /sys/kernel/debug:/sys/kernel/debug \
		tcptracer-bpf-dd-nettop

# Build nettop - utility for testing
build-nettop-local:
	go build -a -tags 'linux_bpf' -o nettop github.com/StackVista/tcptracer-bpf/cmd/nettop
	chmod +x nettop

build-nettop:
	$(SUDO) docker build -t "stackvista/tcptracer-bpf-ci" . -f ../Dockerfile
	$(SUDO) docker run \
		-v $(GOPATH)/src/github.com/StackVista/tcptracer-bpf:/go/src/github.com/StackVista/tcptracer-bpf \
		--env GOPATH=/go \
		stackvista/tcptracer-bpf-ci \
		sh -c 'cd /go/src/github.com/StackVista/tcptracer-bpf/tests && make'


# Build network-tracer agent: runs eBPF program and exposes connections via /connections over UDS
build-network-tracer:
	go build -a -o network-tracer -tags '$(GO_TAGS)' -ldflags "$(LDFLAGS)" github.com/StackVista/tcptracer-bpf/cmd/agent

# easyjson code generation
codegen:
	go get -u github.com/mailru/easyjson/...
	easyjson pkg/tracer/common/model.go

test:
	go list ./... | grep -v vendor | sudo -E PATH=${PATH} xargs go test -count=1 -tags 'linux_bpf'

linux-ci-test: build-ebpf-object-ci
	go list ./... | grep -v vendor | sudo -E PATH=${PATH} xargs go test -count=1 -tags 'linux_bpf'
