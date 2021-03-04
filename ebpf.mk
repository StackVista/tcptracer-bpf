SHELL=/bin/bash -o pipefail
DEST_DIR?=./ebpf

ifeq ($(shell lsb_release -i -s),Ubuntu)
    LINUX_HEADERS=/usr/src/linux-headers-$(shell uname -r)
else
    LINUX_HEADERS=$(shell rpm -q kernel-devel --last | head -n 1 | awk -F'kernel-devel-' '{print "/usr/src/kernels/"$$2}' | cut -d " " -f 1)
endif

build:
	@sudo mkdir -p "$(DEST_DIR)"
	clang -D__KERNEL__ -D__ASM_SYSREG_H -D__BPF_TRACING__ \
		-DCIRCLE_BUILD_URL=\"$(CIRCLE_BUILD_URL)\" \
		-DDEBUG=1 \
		-Wno-unused-value \
		-DKBUILD_MODNAME='"bpftrace"' \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Wunused \
		-Wall \
		-Werror \
		-O2 -emit-llvm -c tcptracer-bpf.c \
		$(foreach path,$(LINUX_HEADERS), -I $(path)/arch/x86/include -I $(path)/arch/x86/include/generated -I $(path)/include -I $(path)/include/generated/uapi -I $(path)/arch/x86/include/uapi -I $(path)/include/uapi) \
		-o - | llc -march=bpf -filetype=obj -o "${DEST_DIR}/tcptracer-ebpf.o"
	go-bindata -pkg tracer -prefix "${DEST_DIR}/" -modtime 1 -o "${DEST_DIR}/tcptracer-ebpf.go" "${DEST_DIR}/tcptracer-ebpf.o"
