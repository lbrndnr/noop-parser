#!/bin/bash
set -x
set -e

DIR="/sys/fs/bpf/parser"

sudo bpftool prog detach pinned ${DIR}/stream_verdict stream_verdict pinned ${DIR}/sock_map
sudo bpftool prog detach pinned ${DIR}/stream_parser stream_parser pinned ${DIR}/sock_map
sudo bpftool cgroup detach /sys/fs/cgroup/ sock_ops pinned ${DIR}/sock_ops

sudo rm -r /sys/fs/bpf/parser