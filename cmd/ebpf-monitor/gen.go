package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf -type so_event bpf ../../bpf/main.bpf.c -- -I../../bpf/headers
