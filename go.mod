module vershitifier

go 1.21.6

// Waiting for newer release than 0.12.3, pinned to commit hash in the meantime
// https://github.com/cilium/ebpf/discussions/1327
require github.com/cilium/ebpf v0.13.2

require (
	github.com/vishvananda/netlink v1.1.0 // indirect
	github.com/vishvananda/netns v0.0.0-20191106174202-0a2b9b5464df // indirect
	golang.org/x/exp v0.0.0-20230224173230-c95f2b4c22f2 // indirect
	golang.org/x/sys v0.15.0 // indirect
)
