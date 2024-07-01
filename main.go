// Attach probes to openSSL3 SSL_read and SSL_write
//
//go:build amd64

package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type new_process_t bpf probes.c -- -I../headers

func loadObjects(obj interface{}, opts *ebpf.CollectionOptions, targetApp string, dropPercent uint8) error {
	spec, err := loadBpf()
	if err != nil {
		return err
	}

	strBytes := []byte(targetApp)
	paddedBytes := make([]byte, 1024)
	copy(paddedBytes, strBytes)

	err = spec.RewriteConstants(map[string]interface{}{
		"target_app":      paddedBytes,
		"drop_percentage": uint8(dropPercent),
	})
	if err != nil {
		log.Fatal("Couldn't rewrite constants: ", err)
	}
	return spec.LoadAndAssign(obj, opts)
}

func main() {

	interfaceName := flag.String("interface", "", "Interface to attach the TC filter to")
	commandName := flag.String("command", "", "Command name to target for process monitoring")
	dropPercent := flag.Uint64("drop", 50, "Percent of traffic to drop")
	flag.Parse()

	if *dropPercent > 100 {
		fmt.Printf("Drop percentage %d > 100\n", *dropPercent)
		os.Exit(1)
	}

	// Check that both flags are provided
	if *interfaceName == "" || *commandName == "" {
		fmt.Println("Both -interface and -command flags are required.")
		flag.Usage()
		os.Exit(1)
	}

	targetedComm := *commandName
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadObjects(&objs, nil, targetedComm, uint8(*dropPercent)); err != nil {
		log.Fatalf("loading objects: %s", err)
	}

	defer objs.Close()

	// Get the first-mounted cgroupv2 path.
	cgroupPath, err := detectCgroupPath()
	if err != nil {
		log.Fatalf("Failed detecting cgroup path: %s", err)
	}

	// Attach the execve kprobe
	// We use this to find PIDs of our targeted process name
	execve, err := link.Kprobe("sys_execve", objs.KprobeSysExecve, nil)
	if err != nil {
		log.Fatalf("Failed attaching execve probe: %s", err)
	}
	defer execve.Close()

	execveret, err := link.Kretprobe("sys_execve", objs.KretprobeSysExecve, nil)
	if err != nil {
		log.Fatalf("Failed attaching execve probe: %s", err)
	}
	defer execveret.Close()

	// Attach socket create program
	// We use this to mark sockets created by a given PID
	sockCreate, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetSockCreate,
		Program: objs.CreateSocket,
	})
	if err != nil {
		log.Fatalf("Failed attaching sockCreate program: %s", err)
	}
	defer sockCreate.Close()

	// Attach the TC filter
	// We use this to drop traffic
	tc_filter, err := attachFilter(*interfaceName, objs.TcFilterTraffic)
	if err != nil {
		log.Fatalf("Failed attaching TC filter: %s", err)
	}
	// This doesn't work
	defer netlink.FilterDel(tc_filter)

	log.Printf("Started up. Dropping %d%% of traffic for %s \n", *dropPercent, targetedComm)

	go func() {
		// Read loop reporting the total amount of times the kernel
		// function was entered, once per second.
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		previousPassed, previousDropped := uint64(0), uint64(0)
		for range ticker.C {
			var passedPackets uint64
			if err := objs.PacketCount.Lookup(uint32(0), &passedPackets); err != nil {
				log.Fatalf("reading map: %v", err)
			}
			var droppedPackets uint64
			if err := objs.PacketCount.Lookup(uint32(1), &droppedPackets); err != nil {
				log.Fatalf("reading map: %v", err)
			}

			if (previousPassed != passedPackets) || (previousDropped != droppedPackets) {
				log.Printf("Passed %d Dropped %d\n", passedPackets, droppedPackets)
			}

			previousPassed = passedPackets
			previousDropped = droppedPackets
		}
	}()

	rd, err := ringbuf.NewReader(objs.NewProcessEvents)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()
	go func() {
		var event bpfNewProcessT
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Println("Received signal, exiting..")
					return
				}
				log.Printf("reading from reader: %s", err)
				continue
			}

			// Parse the ringbuf event entry into a bpfEvent structure.
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("parsing ringbuf event: %s", err)
				continue
			}

			child := unix.ByteSliceToString(event.ChildComm[:])
			if child == targetedComm {
				log.Printf("Process Launched: pid: %d parent: %s child: %s ", event.Pid, unix.ByteSliceToString(event.ParentComm[:]), child)
			}
		}
	}()

	// Close the reader when the process receives a signal, which will exit
	// the read loop.
	<-stopper

	log.Println("Cleaning up")
}

func attachFilter(attachTo string, program *ebpf.Program) (netlink.Filter, error) {
	log.Printf("Attaching to interface %s", attachTo)

	devID, err := net.InterfaceByName(attachTo)
	if err != nil {
		return nil, fmt.Errorf("could not get interface ID: %w", err)
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: devID.Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},

		QdiscType: "clsact",
	}

	err = netlink.QdiscReplace(qdisc)
	if err != nil {
		return nil, fmt.Errorf("could not get replace qdisc: %w", err)
	}

	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: devID.Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           program.FD(),
		Name:         program.String(),
		DirectAction: true,
	}

	if err := netlink.FilterReplace(filter); err != nil {
		return nil, fmt.Errorf("failed to replace tc filter: %w", err)
	}

	return filter, nil
}

// detectCgroupPath returns the first-found mount point of type cgroup2
// and stores it in the cgroupPath global variable.
func detectCgroupPath() (string, error) {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		// example fields: cgroup2 /sys/fs/cgroup/unified cgroup2 rw,nosuid,nodev,noexec,relatime 0 0
		fields := strings.Split(scanner.Text(), " ")
		if len(fields) >= 3 && fields[2] == "cgroup2" {
			return fields[1], nil
		}
	}

	return "", errors.New("cgroup2 not mounted")
}
