#!/bin/bash
make clean
docker build . -t ebpf-vershitifier
docker run --interactive \
	-t \
	--privileged \
	--userns=host \
	--pid=host \
	-v /sys/kernel/debug:/sys/kernel/debug \
	-v /sys/fs/cgroup:/sys/fs/cgroup \
	-v /sys/fs/bpf:/sys/fs/bpf \
	ebpf-vershitifier
