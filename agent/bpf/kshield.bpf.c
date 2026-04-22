#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/in.h>
#include <linux/ptrace.h>
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
    EVENT_KIND_FILE_OPEN = 3,
    EVENT_KIND_PTRACE = 4,
    EVENT_KIND_MODULE_LOAD = 5,
    EVENT_KIND_BIND = 6,
};

enum event_action {
    EVENT_ACTION_OBSERVE = 0,
    EVENT_ACTION_ALLOW = 1,
    EVENT_ACTION_BLOCK = 2,
};

struct event_t {
    __u64 ts_ns;
    __u64 arg0;
    __u64 arg1;
    __u32 ipv4_be;
    __u32 pid;
    __u32 uid;
    __u16 port_be;
    __u8 kind;
    __u8 action;
    char comm[16];
    char subject[96];
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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u16);
    __type(value, __u8);
} BLOCKED_BIND_PORTS SEC(".maps");

static __always_inline void fill_common(struct event_t *evt, __u8 kind, __u8 action)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();

    evt->ts_ns = bpf_ktime_get_ns();
    evt->arg0 = 0;
    evt->arg1 = 0;
    evt->ipv4_be = 0;
    evt->pid = (__u32)(pid_tgid >> 32);
    evt->uid = (__u32)uid_gid;
    evt->port_be = 0;
    evt->kind = kind;
    evt->action = action;
    __builtin_memset(evt->subject, 0, sizeof(evt->subject));
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
}

static __always_inline void submit_string_event(__u8 kind, const char *user_ptr)
{
    struct event_t evt = {};
    fill_common(&evt, kind, EVENT_ACTION_OBSERVE);
    if (user_ptr) {
        bpf_probe_read_user_str(&evt.subject, sizeof(evt.subject), user_ptr);
    }
    bpf_ringbuf_output(&EVENTS, &evt, sizeof(evt), 0);
}

SEC("kprobe/__x64_sys_execve")
int BPF_KPROBE(observe_execve, const char *filename)
{
    submit_string_event(EVENT_KIND_EXEC, filename);
    return 0;
}

SEC("kprobe/__x64_sys_openat")
int BPF_KPROBE(observe_openat, int dfd, const char *filename)
{
    submit_string_event(EVENT_KIND_FILE_OPEN, filename);
    return 0;
}

SEC("kprobe/__x64_sys_openat2")
int BPF_KPROBE(observe_openat2, int dfd, const char *filename)
{
    submit_string_event(EVENT_KIND_FILE_OPEN, filename);
    return 0;
}

SEC("kprobe/__x64_sys_ptrace")
int BPF_KPROBE(observe_ptrace, long request, long target_pid)
{
    struct event_t evt = {};
    fill_common(&evt, EVENT_KIND_PTRACE, EVENT_ACTION_OBSERVE);
    evt.arg0 = (__u64)request;
    evt.arg1 = (__u64)target_pid;
    bpf_ringbuf_output(&EVENTS, &evt, sizeof(evt), 0);
    return 0;
}

SEC("kprobe/__x64_sys_init_module")
int BPF_KPROBE(observe_init_module, void *module_image, unsigned long len, const char *uargs)
{
    struct event_t evt = {};
    fill_common(&evt, EVENT_KIND_MODULE_LOAD, EVENT_ACTION_OBSERVE);
    evt.arg0 = (__u64)len;
    if (uargs) {
        bpf_probe_read_user_str(&evt.subject, sizeof(evt.subject), uargs);
    }
    bpf_ringbuf_output(&EVENTS, &evt, sizeof(evt), 0);
    return 0;
}

SEC("kprobe/__x64_sys_finit_module")
int BPF_KPROBE(observe_finit_module, int fd, const char *uargs, int flags)
{
    struct event_t evt = {};
    fill_common(&evt, EVENT_KIND_MODULE_LOAD, EVENT_ACTION_OBSERVE);
    evt.arg0 = (__u64)fd;
    evt.arg1 = (__u64)flags;
    if (uargs) {
        bpf_probe_read_user_str(&evt.subject, sizeof(evt.subject), uargs);
    }
    bpf_ringbuf_output(&EVENTS, &evt, sizeof(evt), 0);
    return 0;
}

struct sockaddr_in___local {
    __u16 sin_family;
    __u16 sin_port;
    __u32 sin_addr_s_addr;
    unsigned char sin_zero[8];
};

static __always_inline int read_sockaddr(struct sockaddr *address, struct sockaddr_in___local *s4)
{
    if (bpf_probe_read_user(s4, sizeof(*s4), address) == 0) {
        return 0;
    }
    if (bpf_probe_read_kernel(s4, sizeof(*s4), address) == 0) {
        return 0;
    }
    return -1;
}

SEC("lsm/socket_connect")
int BPF_PROG(enforce_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen, int ret)
{
    struct sockaddr_in___local s4 = {};
    __u8 *blocked;
    struct event_t evt = {};

    if (ret != 0) {
        return ret;
    }
    if (addrlen < sizeof(s4)) {
        return 0;
    }
    if (read_sockaddr(address, &s4) != 0) {
        return 0;
    }
    if (s4.sin_family != AF_INET) {
        return 0;
    }

    fill_common(&evt, EVENT_KIND_CONNECT, EVENT_ACTION_ALLOW);
    evt.ipv4_be = s4.sin_addr_s_addr;
    evt.port_be = s4.sin_port;

    blocked = bpf_map_lookup_elem(&BLOCKED_IPV4, &s4.sin_addr_s_addr);
    if (!blocked) {
        bpf_ringbuf_output(&EVENTS, &evt, sizeof(evt), 0);
        return 0;
    }

    evt.action = EVENT_ACTION_BLOCK;
    bpf_ringbuf_output(&EVENTS, &evt, sizeof(evt), 0);
    return -EPERM;
}

SEC("lsm/socket_bind")
int BPF_PROG(enforce_socket_bind, struct socket *sock, struct sockaddr *address, int addrlen, int ret)
{
    struct sockaddr_in___local s4 = {};
    __u16 host_port;
    __u16 port_key;
    __u8 *blocked;
    struct event_t evt = {};

    if (ret != 0) {
        return ret;
    }
    if (addrlen < sizeof(s4)) {
        return 0;
    }
    if (read_sockaddr(address, &s4) != 0) {
        return 0;
    }
    if (s4.sin_family != AF_INET) {
        return 0;
    }

    fill_common(&evt, EVENT_KIND_BIND, EVENT_ACTION_ALLOW);
    evt.ipv4_be = s4.sin_addr_s_addr;
    evt.port_be = s4.sin_port;

    host_port = __builtin_bswap16(s4.sin_port);
    port_key = host_port;
    blocked = bpf_map_lookup_elem(&BLOCKED_BIND_PORTS, &port_key);
    if (!blocked) {
        bpf_ringbuf_output(&EVENTS, &evt, sizeof(evt), 0);
        return 0;
    }

    evt.action = EVENT_ACTION_BLOCK;
    bpf_ringbuf_output(&EVENTS, &evt, sizeof(evt), 0);
    return -EPERM;
}
