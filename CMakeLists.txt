cmake_minimum_required(VERSION 3.17)
project(tcptracer_bpf C)

set(CMAKE_C_STANDARD 11)

add_definitions(-D__KERNEL__ -D__ASM_SYSREG_H -D__BPF_TRACING__)

include_directories(.
        linux/linux-5.4/include
        linux/linux-5.4/include/uapi
        linux/linux-5.4/arch/x86/include
        linux/linux-5.4/arch/x86/include/uapi)


add_executable(tcptracer_bpf
        bpf_helpers.h
        tcptracer-bpf.c
        tcptracer-bpf.h tcptracer-maps.h)
