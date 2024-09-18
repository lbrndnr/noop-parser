#!/bin/bash
set -x
set -e

DIR="/sys/fs/bpf/parser"

bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./vmlinux.h

clang -O2 -g -Wall -target bpf -c parser.bpf.c -o parser.o "$@"

sudo bpftool prog loadall parser.o ${DIR}

MAP_ID=$(sudo bpftool prog show pinned ${DIR}/sock_ops | grep -o -E 'map_ids [0-9]+' | awk '{print $2}')
sudo bpftool map pin id ${MAP_ID} ${DIR}/sock_map

sudo bpftool cgroup attach /sys/fs/cgroup/ sock_ops pinned ${DIR}/sock_ops
sudo bpftool prog attach pinned ${DIR}/stream_parser stream_parser pinned ${DIR}/sock_map
sudo bpftool prog attach pinned ${DIR}/stream_verdict stream_verdict pinned ${DIR}/sock_map
