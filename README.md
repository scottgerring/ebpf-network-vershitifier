# eBPF Network Vershitifier

![network quality](https://img.shields.io/badge/network_quality-vershitfied-blue)
[![Build](https://github.com/scottgerring/ebpf-network-vershitifier/actions/workflows/ci.yaml/badge.svg)](https://github.com/scottgerring/ebpf-network-vershitifier/actions/workflows/ci.yaml)

Fancy [25 gigabit](https://www.init7.net/en/internet/why-init7/) symmetric fiber getting you down? Impossibly low latency and packet loss providing an unacceptable advantage to your professional Starcraft career? Envious of Wilson next door's literal [wet string DSL connection](https://www.revk.uk/2017/12/its-official-adsl-works-over-wet-string.html)? 

Try our **eBPF Network Vershitifier**! With one simple* CLI tool, you can easily target
any binary on your Linux system for unexpected packet loss. We support *all* percentages
between 0% and 100%. 

# What?
This repo contains a simple [ebpf-go](https://github.com/cilium/ebpf) application that randomly
drops packets for targeted processes using the eBPF [TC filters](https://docs.cilium.io/en/stable/bpf/progtypes/#tc-traffic-control). The TC action `TC_ACT_STOLEN` is used to pretend to the caller 
that the packet was processed successfully, which makes the packet loss induced look the same as if it's dropped somewhere on the wire.

eBPF probes attached to `sys_execve` are used to discover instances of
our targeted application as they are launched. Next, a probe is attached
to `BPF_CGROUP_INET_SOCK_CREATE` to discover sockets created by the given
processes, and mark them for packet loss by setting a socket cookie on 
the socket.

## Usage
You specify both which process to drop packets for, and what percentage of traffic to drop:

```bash
> sudo ./vershitifier -command ping -interface enp67s0 -drop 50 
2024/06/20 17:09:57 Attaching to interface enp67s0
2024/06/20 17:09:57 Started up. Dropping 50% of traffic for ping 
```

You can also run a simple demo in a docker container:

```bash
./docker-run.sh
```

## Arch install
If you want to hack on this and you happen to be using Arch Linux, you'll need the following bits:

```bash
pacman -S base-devel
pacman -S go
pacman -S llvm
pacman -S clang
pacman -S linux-headers

# Fix systemd madness
ln -sf ../run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
```
