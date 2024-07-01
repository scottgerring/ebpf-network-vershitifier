//go:build ignore

#include <linux/if_ether.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// You actually need this!
char __license[] SEC("license") = "Dual MIT/GPL";

#define TC_ACT_UNSPEC -1   // Use default action configured by tc
#define TC_ACT_OK 0        // allow packet to procede
#define TC_ACT_SHOT 2      // drop the packet
#define TC_ACT_STOLEN 4	   // drop the packet but pretend it was successful (NET_XMIT_SUCCESS)

// Maximum length of a task comm
#define TASK_COMM_LENGTH 1024

// A struct and map we use to track processes we have discovered
// We use this to pass from the execve kprobe to the corresponding
// kretprobe
struct new_process_t {
	__u32 pid;
	__u32 ppid;
	__u32 uid;
	__u8 parent_comm[TASK_COMM_LENGTH];	
	__u8 child_comm[TASK_COMM_LENGTH];
}; 
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct new_process_t);
} execve_data SEC(".maps");

// An additional map for nwe_process_t. We use this to pass
// discovered processes back out to user space for logging purposes. 
// This is populated by the kretprobe once we've got all the info
// about the process.
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} new_process_events SEC(".maps");
// Force emitting struct event into the ELF.
const struct new_process_t *unused __attribute__((unused));

// A map we use to processes we should interfere with the traffic of. 
// Populate this in the kretprobe/execve, and we use it in our socket 
// creation handler to decide which sockets to flag. 
struct {
 __uint(type, BPF_MAP_TYPE_HASH);
 __uint(max_entries, 1024);
 __type(key, __u32);
 __type(value, __u32);
} processes_to_track SEC(".maps");

// A map we used to pass the number of packets that have gone by 
// for targeted processes that we either dropped or passed along. 
// We can then log this out to the console nicely in user space. 
#define PASSED_PACKETS_OFFSET 0
#define DROPPED_PACKETS_OFFSET 1
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 2);
} packet_count SEC(".maps");

/**
 * We use a pair of execve handlers - one on the kprobe and one on
 * the kretprobe - to discover new processes. execve is called by 
 * a process to replace its content with another executable, typically
 * after forking. This means that _before_ the syscall is invoked, the
 * comm is the parent process name, and _after_ the syscall is invoked,
 * the comm is the newly launched process. 
 * 
 * By capturing both sides of the invocation we can work out who's invoking
 * what, and if its a comm we are monitoring, add it to our processes_to_track
 * map so that its sockets get flagged as they are created.
*/
SEC("kprobe/sys_execve")
int kprobe_sys_execve(struct pt_regs *ctx) {

	// per-cpu map to path context over to our ret probe
	__u32 map_id = 0;
	struct new_process_t* map_value = bpf_map_lookup_elem(&execve_data, &map_id);
	if (!map_value) {
		return 0; 
	}

	// Get the easy bits
	map_value->pid = bpf_get_current_pid_tgid() >> 32;
	map_value->uid = bpf_get_current_uid_gid() & 0xffffffff;

	// Read the comm into it
    bpf_get_current_comm(&map_value->parent_comm, sizeof(map_value->parent_comm));

    return 0;
}

volatile const char target_app[1024];
volatile const char target_app[] = "curl";
volatile const __u32 target_app_size;
volatile const __u32 target_app_size = 5;
volatile const __u8 drop_percentage = 0;

/**
 * Catches the completion of an execve call, using it to flag processes we should
 * track based on their name. See the documentation in the equivilent kprobe for
 * details. 
*/
SEC("kretprobe/sys_ret_execve")
int kretprobe_sys_execve(struct pt_regs *ctx) {
	// Pick up the data from the kprobe 
	__u32 map_id = 0;
	struct new_process_t* map_value = bpf_map_lookup_elem(&execve_data, &map_id);
	if (!map_value) {
		return 0; 
	}

	// Read the comm into it
    bpf_get_current_comm(&map_value->child_comm, sizeof(map_value->parent_comm));

	// Submit it back to userspace
	struct new_process_t* output_process = bpf_ringbuf_reserve(&new_process_events, sizeof(struct new_process_t), 0);
	if (!output_process) {
	 		return 0;
	}	

	output_process->pid = map_value->pid;
	output_process->ppid = map_value->ppid;
	output_process->uid = map_value->uid;
	
	for (int i = 0; i < TASK_COMM_LENGTH; i++) {
		output_process->child_comm[i] = map_value->child_comm[i];
	}
	for (int i = 0; i < TASK_COMM_LENGTH; i++) {
		output_process->parent_comm[i] = map_value->parent_comm[i];
	}
	bpf_ringbuf_submit(output_process, 0);

	int did_match = 1;
	for (int i = 0; i < target_app_size; i++) {
		if (map_value->child_comm[i] != target_app[i]) {
			did_match = 0;
		}
	}
	
	if (did_match == 1) {
		const char fmt_str[] = "Found a target comm";
		__u32 one = 1;
		bpf_map_update_elem(&processes_to_track, &map_value->pid, &one, BPF_ANY);
		bpf_trace_printk(fmt_str, sizeof(fmt_str));
	}


    return 0;
}




/**
 * Capture the creation of new sockets. If the process that creates the socket
 * is one that we are interfering with the traffic of, we mark the socket with
 * our magic number. This lets us pick up packets associated with the socket
 * later on in the TC filter. 
*/
SEC("cgroup/sock_create")
int create_socket(struct bpf_sock* info) {

	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	// is this process in our targeted process map? If it is, mark
	__u32* val = bpf_map_lookup_elem(&processes_to_track, &pid);
	if (!val || *val == 0) {
		return 1;
	}

	const char fmt_str[] = "sock_create pid=%d, dst_port=%d";
	bpf_trace_printk(fmt_str, sizeof(fmt_str), pid, info->dst_port);

	info->mark = 123;

	return 1;
}


// Records a packet in the output packet counting map. We use
// this to display stats in userspace. 
void record_one_packet(__u32 offset) {
	__u64 one = 1;
	__u64 *count = bpf_map_lookup_elem(&packet_count, &offset);
	if (!count) {
		bpf_map_update_elem(&packet_count, &offset, &one, BPF_ANY);
	} else {
		__sync_fetch_and_add(count, 1);
	}
}

/**
 * The TC filter we use to drop a fraction of traffic associated
 * with our targeted program. At this point, we can't see the process
 * information anymore, but we can check if the associated socket
 * has our mark applied to it. 
 * 
 * Based on this, we randomly drop some fraction of the traffic through
 * the socket, using TC_ACT_STOLEN - this means that the packet appears
 * to have successfully moved through the kernel to the sender, and will
 * appear as close as possible to network loss. 
*/
SEC("tc/filter_traffic")
int tc_filter_traffic(struct __sk_buff *skb) {

    void *data_end = (void *)(unsigned long long)skb->data_end;
    void *data = (void *)(unsigned long long)skb->data;
    struct ethhdr *eth = data;

    if (data + sizeof(struct ethhdr) > data_end)
        return TC_ACT_OK;

    __u64 cookie;
    cookie = bpf_get_socket_cookie(skb);

	// Drop out if we've not got a mark
	if (skb->mark == 0) 
		return TC_ACT_OK;

	// If we've got a mark, randomly drop it
	__u64 one = 1;
	if (skb->mark == 123) {
		__u32 rand = bpf_get_prandom_u32();
		
		// 50% drop rate
		if (rand % 100 <= drop_percentage) {
			// Update stats
			record_one_packet(DROPPED_PACKETS_OFFSET);

			// And drop it
			return TC_ACT_STOLEN;
		}
		else {
			// Update stats
			record_one_packet(PASSED_PACKETS_OFFSET);

			// Pass it
			return TC_ACT_OK;
		}
	}

	// Marked but not with our mark, pass it
	return TC_ACT_OK;


}
