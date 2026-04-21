#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#ifndef AF_INET
#define AF_INET 2
#endif

enum event_kind {
    EVENT_KIND_EXEC = 1,
    EVENT_KIND_CONNECT = 2,
};

enum event_action {
    EVENT_ACTION_OBSERVE = 0,
    EVENT_ACTION_ALLOW = 1,
    EVENT_ACTION_BLOCK = 2,
};

struct event_t {
    __u64 ts_ns;
    __u32 pid;
    __u32 uid;
    __u8 kind;
    __u8 action;
    __u16 pad;
    __u32 ipv4_be;
    __u16 port_be;
    __u16 pad2;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} EVENTS SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} BLOCKED_IPV4 SEC(".maps");

static __always_inline void fill_common(struct event_t *evt, __u8 kind, __u8 action)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();

    evt->ts_ns = bpf_ktime_get_ns();
    evt->pid = (__u32)(pid_tgid >> 32);
    evt->uid = (__u32)uid_gid;
    evt->kind = kind;
    evt->action = action;
    evt->pad = 0;
    evt->ipv4_be = 0;
    evt->port_be = 0;
    evt->pad2 = 0;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
}

SEC("tracepoint/syscalls/sys_enter_execve")
int observe_execve(void *ctx)
{
    struct event_t evt = {};
    fill_common(&evt, EVENT_KIND_EXEC, EVENT_ACTION_OBSERVE);
    bpf_ringbuf_output(&EVENTS, &evt, sizeof(evt), 0);
    return 0;
}

struct sockaddr_in___local {
    __u16 sin_family;
    __u16 sin_port;
    __u32 sin_addr_s_addr;
    unsigned char sin_zero[8];
};

SEC("lsm/socket_connect")
int BPF_PROG(enforce_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen, int ret)
{
    struct sockaddr_in___local s4 = {};
    __u8 *blocked;

    if (ret != 0) {
        return ret;
    }
    if (addrlen < sizeof(struct sockaddr_in___local)) {
        return 0;
    }

    if (bpf_probe_read_user(&s4, sizeof(s4), address) != 0) {
        if (bpf_probe_read_kernel(&s4, sizeof(s4), address) != 0) {
            return 0;
        }
    }

    if (s4.sin_family != AF_INET) {
        return 0;
    }

    blocked = bpf_map_lookup_elem(&BLOCKED_IPV4, &s4.sin_addr_s_addr);
    if (!blocked) {
        return 0;
    }

    struct event_t evt = {};
    fill_common(&evt, EVENT_KIND_CONNECT, EVENT_ACTION_BLOCK);
    evt.ipv4_be = s4.sin_addr_s_addr;
    evt.port_be = s4.sin_port;
    bpf_ringbuf_output(&EVENTS, &evt, sizeof(evt), 0);
    return -EPERM;
}
