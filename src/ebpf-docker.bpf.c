#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "structs.h"

char LICENSE[] SEC("license") = "GPL";

#define DEMO_BLOCK_PROCESS_1                                    \
    if (                                                        \
        !__builtin_memcmp(event.docker.name, "demo-ebpf", 9) && \
        !__builtin_memcmp(event.path, "/usr/bin/whoami", 15))   \
    {                                                           \
        ret = -1;                                               \
    }

#define DEMO_BLOCK_PROCESS_2                                  \
    if (                                                      \
        !__builtin_memcmp(event.path, "/usr/bin/wget", 13) && \
        event.uid != 0 && event.uid < 1000)                   \
    {                                                         \
        ret = -1;                                             \
    }

#define DEMO_BLOCK_NETWORK_1                                    \
    if (                                                        \
        !__builtin_memcmp(event.docker.name, "demo-ebpf", 9) && \
        !__builtin_memcmp(event.dip, "8.8.8.8", 7))             \
    {                                                           \
        ret = -1;                                               \
    }

#define DEMO_BLOCK_NETWORK_2                            \
    if ((event.dport == 4444 || event.dport == 1337) && \
        event.uid >= 1000)                              \
    {                                                   \
        ret = -1;                                       \
    }

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF); // Ring buffer to store events
    __uint(max_entries, 256 * 1024);    // Max count of buffered events
} rb_process SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF); // Ring buffer to store events
    __uint(max_entries, 256 * 1024);    // Max count of buffered events
} rb_network SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);   // Hashmap to map cgroup ID to docker context
    __uint(max_entries, 2048);         // Max count of containers
    __type(key, u64);                  // Cgroup ID
    __type(value, struct meta_docker); // Docker context
} map_cgroups SEC(".maps");

SEC("lsm/bprm_check_security")
int BPF_PROG(process_handler, struct linux_binprm *bprm, int ret)
{
    if (ret != 0)
    {
        return ret;
    }

    // Allocating event struct
    struct event_proc event;
    __builtin_memset(&event, 0, sizeof(event));
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // Filling available process-related fields
    // Looks like ARGV is not available in bprm_check_security
    // https://stackoverflow.com/questions/65881204/get-argv-from-bprm-check-security-in-linux-kernel-is-the-documentation-wrong
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() >> 32;
    event.ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_probe_read_str(event.path, sizeof(event.path), bprm->filename);

    // Filling container-related fields if in docker container
    u64 cgroup = bpf_get_current_cgroup_id();
    struct meta_docker *p = (struct meta_docker *)bpf_map_lookup_elem(&map_cgroups, &cgroup);
    if (p)
    {
        event.docker = *p;
    }

    // Edit the defined macro to change what to block
    DEMO_BLOCK_PROCESS_1
    DEMO_BLOCK_PROCESS_2
    event.allowed = !ret;

    // Uncomment if you need debugging to /sys/kernel/debug/tracing/trace_pipe
    // bpf_printk("PROCESS: [allowed=%i][uid=%u][pid=%u][ppid=%u][path=%s][cgroup=%lu][container=%s]",
    //            event.allowed, event.uid, event.pid, event.ppid, event.path, cgroup, event.docker.name);

    // Push processed event to ring buffer
    bpf_ringbuf_output(&rb_process, &event, sizeof(event), 0);
    return ret;
}

SEC("lsm/socket_connect")
int BPF_PROG(network_handler, struct socket *sock, struct sockaddr *address, int addrlen, int ret)
{
    if (ret != 0)
    {
        return ret;
    }

    // Only IPv4 connections (AF_INET)
    if (address->sa_family != 2)
    {
        return 0;
    }

    struct event_net event;
    __builtin_memset(&event, 0, sizeof(event));
    struct sockaddr_in *addr = (struct sockaddr_in *)address;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // Filling available process-related fields
    // Can't get ARGV and executable path here
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() >> 32;
    event.ppid = BPF_CORE_READ(task, real_parent, tgid);

    // Parse big-endian destination IP to dot-decimal notation
    u32 raw_ip = __builtin_bswap32(addr->sin_addr.s_addr);
    u8 size = 0;
    for (int i = 0; i < 4; i++)
    {
        if (i > 0)
        {
            event.dip[size++] = '.';
        }
        u8 octet = (raw_ip >> (8 * (3 - i))) & 0xFF;
        if (octet >= 100)
        {
            event.dip[size++] = '0' + (octet / 100);
            event.dip[size++] = '0' + (octet % 100 / 10);
            event.dip[size++] = '0' + (octet % 10);
        }
        else if (octet >= 10)
        {
            event.dip[size++] = '0' + (octet / 10);
            event.dip[size++] = '0' + (octet % 10);
        }
        else
        {
            event.dip[size++] = '0' + octet;
        }
    }
    event.dip[size] = '\0';
    event.dport = __builtin_bswap16(addr->sin_port);

    // Mapping socket type to a transport protocol
    if (sock->type == 1)
    {
        __builtin_memcpy(&event.tp, "tcp", 4);
    }
    else if (sock->type == 2)
    {
        __builtin_memcpy(&event.tp, "udp", 4);
    }
    else
    {
        __builtin_memcpy(&event.tp, "raw", 4);
    }

    // Filling container-related fields if in docker container
    u64 cgroup = bpf_get_current_cgroup_id();
    struct meta_docker *p = (struct meta_docker *)bpf_map_lookup_elem(&map_cgroups, &cgroup);
    if (p)
    {
        event.docker = *p;
    }

    // Edit the defined macro to change what to block
    DEMO_BLOCK_NETWORK_1
    DEMO_BLOCK_NETWORK_2
    event.allowed = !ret;

    // Uncomment if you need debugging to /sys/kernel/debug/tracing/trace_pipe
    // bpf_printk("NETWORK: [allowed=%i][uid=%u][pid=%u][ppid=%u][tp=%s][dip=%s][dport=%u][cgroup=%lu][container=%s]",
    //            event.allowed, event.uid, event.pid, event.ppid, event.tp, event.dip, event.dport, cgroup, event.docker.name);

    // Push network event to ring buffer
    bpf_ringbuf_output(&rb_network, &event, sizeof(event), 0);
    return ret;
}