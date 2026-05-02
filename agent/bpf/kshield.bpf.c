#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/in.h>
#include <linux/ptrace.h>
#include <linux/socket.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#ifndef BPF_PRESERVE_ACCESS_INDEX
#if defined(__clang__) && __has_attribute(preserve_access_index)
#define BPF_PRESERVE_ACCESS_INDEX __attribute__((preserve_access_index))
#else
#define BPF_PRESERVE_ACCESS_INDEX
#endif
#endif

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
    EVENT_KIND_SETUID = 7,
    EVENT_KIND_MOUNT = 8,
    EVENT_KIND_BPF = 9,
    EVENT_KIND_FILE_WRITE = 10,
    EVENT_KIND_MMAP = 11,
    EVENT_KIND_MPROTECT = 12,
    EVENT_KIND_FORK = 13,
    EVENT_KIND_EXIT = 14,
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

struct trace_event_raw_sys_enter {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __s32 common_pid;
    __s64 id;
    __u64 args[6];
};

struct trace_event_raw_sched_process_fork {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __s32 common_pid;
    __u32 __data_loc_parent_comm;
    __s32 parent_pid;
    __u32 __data_loc_child_comm;
    __s32 child_pid;
};

struct trace_event_raw_sched_process_template {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __s32 common_pid;
};

struct string_key_t {
    char value[96];
};

struct qstr___local {
    const unsigned char *name;
} BPF_PRESERVE_ACCESS_INDEX;

struct dentry___local {
    struct qstr___local d_name;
} BPF_PRESERVE_ACCESS_INDEX;

struct path___local {
    struct dentry___local *dentry;
} BPF_PRESERVE_ACCESS_INDEX;

struct file___local {
    struct path___local f_path;
} BPF_PRESERVE_ACCESS_INDEX;

struct linux_binprm___local {
    const char *filename;
} BPF_PRESERVE_ACCESS_INDEX;

struct task_struct___local {
    int pid;
} BPF_PRESERVE_ACCESS_INDEX;

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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct string_key_t);
    __type(value, __u8);
} BLOCKED_EXEC_PATHS SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct string_key_t);
    __type(value, __u8);
} PROTECTED_WRITE_TARGETS SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u8);
    __type(value, __u8);
} DENY_PTRACE SEC(".maps");

#ifndef MAY_WRITE
#define MAY_WRITE 0x00000002
#endif

#ifndef MAY_APPEND
#define MAY_APPEND 0x00000008
#endif

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

static __always_inline int fill_key_from_kernel(struct string_key_t *key, const char *kernel_ptr)
{
    if (!kernel_ptr) {
        return -1;
    }
    return bpf_probe_read_kernel_str(&key->value, sizeof(key->value), kernel_ptr) > 0 ? 0 : -1;
}

static __always_inline void copy_key_to_subject(struct event_t *evt, const struct string_key_t *key)
{
    __builtin_memcpy(&evt->subject, &key->value, sizeof(evt->subject));
}

static __always_inline int current_comm_is_agent(void)
{
    char comm[16] = {};

    bpf_get_current_comm(&comm, sizeof(comm));
    return comm[0] == 'k' && comm[1] == 's' && comm[2] == 'h' &&
           comm[3] == 'i' && comm[4] == 'e' && comm[5] == 'l' &&
           comm[6] == 'd' && comm[7] == '-' && comm[8] == 'a' &&
           comm[9] == 'g' && comm[10] == 'e' && comm[11] == 'n' &&
           comm[12] == 't' && comm[13] == '\0';
}

SEC("tracepoint/syscalls/sys_enter_execve")
int observe_execve(struct trace_event_raw_sys_enter *ctx)
{
    const char *filename = (const char *)ctx->args[0];
    submit_string_event(EVENT_KIND_EXEC, filename);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int observe_openat(struct trace_event_raw_sys_enter *ctx)
{
    const char *filename = (const char *)ctx->args[1];
    submit_string_event(EVENT_KIND_FILE_OPEN, filename);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int observe_openat2(struct trace_event_raw_sys_enter *ctx)
{
    const char *filename = (const char *)ctx->args[1];
    submit_string_event(EVENT_KIND_FILE_OPEN, filename);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setuid")
int observe_setuid(struct trace_event_raw_sys_enter *ctx)
{
    struct event_t evt = {};
    fill_common(&evt, EVENT_KIND_SETUID, EVENT_ACTION_OBSERVE);
    evt.arg0 = ctx->args[0];
    bpf_ringbuf_output(&EVENTS, &evt, sizeof(evt), 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mount")
int observe_mount(struct trace_event_raw_sys_enter *ctx)
{
    struct event_t evt = {};
    fill_common(&evt, EVENT_KIND_MOUNT, EVENT_ACTION_OBSERVE);
    evt.arg0 = ctx->args[3];
    if (ctx->args[1]) {
        bpf_probe_read_user_str(&evt.subject, sizeof(evt.subject), (const char *)ctx->args[1]);
    }
    bpf_ringbuf_output(&EVENTS, &evt, sizeof(evt), 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_bpf")
int observe_bpf(struct trace_event_raw_sys_enter *ctx)
{
    struct event_t evt = {};
    fill_common(&evt, EVENT_KIND_BPF, EVENT_ACTION_OBSERVE);
    evt.arg0 = ctx->args[0];
    evt.arg1 = ctx->args[2];
    bpf_ringbuf_output(&EVENTS, &evt, sizeof(evt), 0);
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

SEC("lsm/ptrace_access_check")
int BPF_PROG(enforce_ptrace_access, struct task_struct *child, unsigned int mode, int ret)
{
    __u8 key = 0;
    __u8 *blocked;
    struct event_t evt = {};

    if (ret != 0) {
        return ret;
    }
    if (current_comm_is_agent()) {
        return 0;
    }

    blocked = bpf_map_lookup_elem(&DENY_PTRACE, &key);
    if (!blocked) {
        return 0;
    }

    fill_common(&evt, EVENT_KIND_PTRACE, EVENT_ACTION_BLOCK);
    evt.arg0 = (__u64)mode;
    evt.arg1 = (__u64)BPF_CORE_READ((struct task_struct___local *)child, pid);
    bpf_ringbuf_output(&EVENTS, &evt, sizeof(evt), 0);
    return -EPERM;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(enforce_bprm_check, struct linux_binprm *bprm, int ret)
{
    const char *filename;
    struct string_key_t key = {};
    __u8 *blocked;
    struct event_t evt = {};

    if (ret != 0) {
        return ret;
    }

    filename = BPF_CORE_READ((struct linux_binprm___local *)bprm, filename);
    if (fill_key_from_kernel(&key, filename) != 0) {
        return 0;
    }

    blocked = bpf_map_lookup_elem(&BLOCKED_EXEC_PATHS, &key);
    if (!blocked) {
        return 0;
    }

    fill_common(&evt, EVENT_KIND_EXEC, EVENT_ACTION_BLOCK);
    copy_key_to_subject(&evt, &key);
    bpf_ringbuf_output(&EVENTS, &evt, sizeof(evt), 0);
    return -EPERM;
}

SEC("lsm/file_permission")
int BPF_PROG(enforce_file_permission, struct file *file, int mask, int ret)
{
    struct dentry___local *dentry;
    const unsigned char *name;
    struct string_key_t key = {};
    __u8 *blocked;
    struct event_t evt = {};

    if (ret != 0) {
        return ret;
    }
    if (!(mask & (MAY_WRITE | MAY_APPEND))) {
        return 0;
    }

    dentry = BPF_CORE_READ((struct file___local *)file, f_path.dentry);
    name = BPF_CORE_READ((struct dentry___local *)dentry, d_name.name);
    if (fill_key_from_kernel(&key, (const char *)name) != 0) {
        return 0;
    }

    blocked = bpf_map_lookup_elem(&PROTECTED_WRITE_TARGETS, &key);
    if (!blocked) {
        return 0;
    }

    fill_common(&evt, EVENT_KIND_FILE_WRITE, EVENT_ACTION_BLOCK);
    evt.arg0 = (__u64)mask;
    copy_key_to_subject(&evt, &key);
    bpf_ringbuf_output(&EVENTS, &evt, sizeof(evt), 0);
    return -EPERM;
}

SEC("tracepoint/syscalls/sys_enter_mmap")
int observe_mmap(struct trace_event_raw_sys_enter *ctx)
{
    __u64 prot  = ctx->args[2];
    __u64 flags = ctx->args[3];
    
    // Only capture anonymous executable mmaps to prevent overwhelming the agent
    if ((flags & 0x20) && (prot & 0x4)) {
        struct event_t evt = {};
        fill_common(&evt, EVENT_KIND_MMAP, EVENT_ACTION_OBSERVE);
        evt.arg0 = prot;
        evt.arg1 = flags;
        bpf_ringbuf_output(&EVENTS, &evt, sizeof(evt), 0);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mprotect")
int observe_mprotect(struct trace_event_raw_sys_enter *ctx)
{
    __u64 prot = ctx->args[2];
    
    // Only capture executable mprotect to prevent overwhelming the agent
    if (prot & 0x4) {
        struct event_t evt = {};
        fill_common(&evt, EVENT_KIND_MPROTECT, EVENT_ACTION_OBSERVE);
        evt.arg0 = prot;
        bpf_ringbuf_output(&EVENTS, &evt, sizeof(evt), 0);
    }
    return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int observe_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    struct event_t evt = {};
    fill_common(&evt, EVENT_KIND_FORK, EVENT_ACTION_OBSERVE);
    evt.arg0 = (__u64)ctx->parent_pid;
    evt.arg1 = (__u64)ctx->child_pid;
    bpf_ringbuf_output(&EVENTS, &evt, sizeof(evt), 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int observe_exit(struct trace_event_raw_sched_process_template *ctx)
{
    struct event_t evt = {};
    fill_common(&evt, EVENT_KIND_EXIT, EVENT_ACTION_OBSERVE);
    bpf_ringbuf_output(&EVENTS, &evt, sizeof(evt), 0);
    return 0;
}
