//go:build ignore
#include "../headers/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define PF_KTHREAD 0x00200000

struct enter_data_t {
    char filename[256];
    u64 flags;
    u64 count;
};

struct so_event {
    u64 timestamp;
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[64];
    char syscall[32];
    char filename[256];
    s64 fd;
    u64 flags;
    s64 ret;
    u32 dest_ip;
    u32 dest_ipv6[4];
    u16 dest_port;
    u16 sa_family;
    u64 count;
    s64 bytes_rw;
};

const struct so_event *__unused __attribute__((unused));

// --- MAPS ---
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct so_event);
} event_heap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, struct enter_data_t);
} open_data SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, struct enter_data_t);
} write_data SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, struct enter_data_t);
} read_data SEC(".maps");

// -------------------------------------------------------------------------
// OPTIMIZED FILTERING LOGIC
// -------------------------------------------------------------------------

// Filter based on Process Name (Comm) - Called EARLY
static __always_inline int should_drop_comm(char *c) {
    // 1. Self-Protection (Infinite Loop prevention)
    if (c[0]=='e' && c[1]=='b' && c[2]=='p' && c[3]=='f' && c[4]=='-') return 1;

    // 2. Noisy System Daemons
    // "systemd-*"
    if (c[0]=='s' && c[1]=='y' && c[2]=='s' && c[3]=='t' && c[4]=='e' && c[5]=='m' && c[6]=='d') return 1;
    // "node_exporter"
    if (c[0]=='n' && c[1]=='o' && c[2]=='d' && c[3]=='e' && c[4]=='_') return 1;
    // "snapd"
    if (c[0]=='s' && c[1]=='n' && c[2]=='a' && c[3]=='p' && c[4]=='d') return 1;

    // 3. Smart kworker filter
    // Only drop if it is ACTUALLY a kernel thread (PF_KTHREAD). 
    // Keeps malware named "kworker".
    if (c[0]=='k' && c[1]=='w' && c[2]=='o' && c[3]=='r' && c[4]=='k') {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        u32 flags = 0;
        BPF_CORE_READ_INTO(&flags, task, flags);
        if (flags & PF_KTHREAD) return 1;
    }

    return 0;
}

// Filter based on File/Path - Called LATE (in submit)
static __always_inline int should_drop_file(struct so_event *e) {
    char *f = e->filename;
    char *sys = e->syscall;

    if (f[0] == 0) return 0;

    // SECURITY FIX: Never filter files if the syscall is 'execve'.
    // We want to know if someone executes a binary in /tmp, /usr/lib, or /var/log.
    if (sys[0] == 'e' && sys[1] == 'x' && sys[2] == 'e' && sys[3] == 'c') {
        return 0;
    }

    // 1. Library Paths (High Volume Noise)
    // Only drop these for non-exec events (like openat/read)
    if (f[0]=='/' && f[1]=='u' && f[2]=='s' && f[3]=='r' && f[4]=='/' && 
        f[5]=='l' && f[6]=='i' && f[7]=='b') return 1; // /usr/lib
    
    if (f[0]=='/' && f[1]=='l' && f[2]=='i' && f[3]=='b') return 1; // /lib

    // 2. Pseudo Filesystems (Always noisy)
    if (f[0]=='/' && f[1]=='s' && f[2]=='y' && f[3]=='s' && f[4]=='/') return 1; // /sys
    if (f[0]=='/' && f[1]=='p' && f[2]=='r' && f[3]=='o' && f[4]=='c') return 1; // /proc

    // 3. Noisy Devices
    if (f[0]=='/' && f[1]=='d' && f[2]=='e' && f[3]=='v' && f[4]=='/') {
        if (f[5]=='n' && f[6]=='u' && f[7]=='l' && f[8]=='l') return 1;
        if (f[5]=='u' && f[6]=='r' && f[7]=='a' && f[8]=='n') return 1;
        if (f[5]=='z' && f[6]=='e' && f[7]=='r' && f[8]=='o') return 1;
        // /dev/pts (Terminal noise)
        if (f[5]=='p' && f[6]=='t' && f[7]=='s' && f[8]=='/') return 1;
    }

    // 4. Runtime state
    if (f[0]=='/' && f[1]=='r' && f[2]=='u' && f[3]=='n' && f[4]=='/') return 1; // /run

    return 0;
}

// --- HELPERS ---

static __always_inline struct so_event* init_event() {
    u32 zero = 0;
    struct so_event *event = bpf_map_lookup_elem(&event_heap, &zero);
    if (!event) return NULL;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // STAGE 1 FILTER: Filter by Process Name ONLY
    if (should_drop_comm(event->comm)) return NULL;

    event->uid = bpf_get_current_uid_gid();
    event->timestamp = bpf_ktime_get_ns();
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    BPF_CORE_READ_INTO(&event->ppid, task, real_parent, tgid);
    
    // Clear fields
    event->filename[0] = 0;
    event->dest_ip = 0;
    event->dest_port = 0;
    event->sa_family = 0;
    event->count = 0;
    event->bytes_rw = 0;
    __builtin_memset(event->dest_ipv6, 0, sizeof(event->dest_ipv6));

    return event;
}

static __always_inline void submit(void *ctx, struct so_event *event) {
    // STAGE 2 FILTER: Filter by File Path (Context Aware)
    if (should_drop_file(event)) return;
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
}

// --- ARG STRUCTS ---
struct args_execve { struct trace_entry ent; long int id; const char * filename; const char *const * argv; const char *const * envp; };
struct args_openat { struct trace_entry ent; long int id; long int dfd; const char * filename; long int flags; long int mode; };
struct open_how_local { u64 flags; u64 mode; u64 resolve; };
struct args_openat2 { struct trace_entry ent; long int id; long int dfd; const char * filename; struct open_how_local * how; size_t size; };
struct args_write { struct trace_entry ent; long int id; long int fd; const char * buf; size_t count; };
struct args_read { struct trace_entry ent; long int id; long int fd; char * buf; size_t count; };
struct args_unlinkat { struct trace_entry ent; long int id; long int dfd; const char * pathname; int flag; };
struct args_connect { struct trace_entry ent; long int id; long int fd; struct sockaddr * uservaddr; int addrlen; };
struct args_exit { struct trace_entry ent; long int id; long int ret; };

// --- PROBES ---

SEC("tp/syscalls/sys_enter_execve")
int sys_enter_execve(struct args_execve *ctx) {
    struct so_event *event = init_event();
    if (!event) return 0;
    __builtin_memcpy(event->syscall, "execve", 7);
    bpf_probe_read_user_str(&event->filename, sizeof(event->filename), ctx->filename);
    submit(ctx, event);
    return 0;
}

SEC("tp/syscalls/sys_enter_openat")
int sys_enter_openat(struct args_openat *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct enter_data_t data = {};
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), ctx->filename);
    data.flags = ctx->flags;
    bpf_map_update_elem(&open_data, &id, &data, BPF_ANY);
    return 0;
}

SEC("tp/syscalls/sys_enter_openat2")
int sys_enter_openat2(struct args_openat2 *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct enter_data_t data = {};
    struct open_how_local how = {};
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), ctx->filename);
    bpf_probe_read_user(&how, sizeof(struct open_how_local), ctx->how);
    data.flags = how.flags;
    bpf_map_update_elem(&open_data, &id, &data, BPF_ANY);
    return 0;
}

SEC("tp/syscalls/sys_exit_openat")
int sys_exit_openat(struct args_exit *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct enter_data_t *data = bpf_map_lookup_elem(&open_data, &id);
    if (!data) return 0;
    struct so_event *event = init_event();
    if (event) {
        __builtin_memcpy(event->syscall, "openat", 7);
        __builtin_memcpy(event->filename, data->filename, sizeof(event->filename));
        event->flags = data->flags;
        event->ret = ctx->ret;
        submit(ctx, event);
    }
    bpf_map_delete_elem(&open_data, &id);
    return 0;
}

SEC("tp/syscalls/sys_exit_openat2")
int sys_exit_openat2(struct args_exit *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct enter_data_t *data = bpf_map_lookup_elem(&open_data, &id);
    if (!data) return 0;
    struct so_event *event = init_event();
    if (event) {
        __builtin_memcpy(event->syscall, "openat2", 8);
        __builtin_memcpy(event->filename, data->filename, sizeof(event->filename));
        event->flags = data->flags;
        event->ret = ctx->ret;
        submit(ctx, event);
    }
    bpf_map_delete_elem(&open_data, &id);
    return 0;
}

SEC("tp/syscalls/sys_enter_write")
int sys_enter_write(struct args_write *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct enter_data_t data = {};
    data.flags = ctx->fd;
    data.count = ctx->count;
    bpf_map_update_elem(&write_data, &id, &data, BPF_ANY);
    return 0;
}

SEC("tp/syscalls/sys_exit_write")
int sys_exit_write(struct args_exit *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct enter_data_t *data = bpf_map_lookup_elem(&write_data, &id);
    if (!data) return 0;
    if (ctx->ret < 0) { bpf_map_delete_elem(&write_data, &id); return 0; }
    struct so_event *event = init_event();
    if (event) {
        __builtin_memcpy(event->syscall, "write", 6);
        event->fd = data->flags;
        event->count = data->count;
        event->bytes_rw = ctx->ret;
        event->ret = ctx->ret;
        submit(ctx, event);
    }
    bpf_map_delete_elem(&write_data, &id);
    return 0;
}

SEC("tp/syscalls/sys_enter_read")
int sys_enter_read(struct args_read *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct enter_data_t data = {};
    data.flags = ctx->fd;
    data.count = ctx->count;
    bpf_map_update_elem(&read_data, &id, &data, BPF_ANY);
    return 0;
}

SEC("tp/syscalls/sys_exit_read")
int sys_exit_read(struct args_exit *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct enter_data_t *data = bpf_map_lookup_elem(&read_data, &id);
    if (!data) return 0;
    if (ctx->ret < 4) { bpf_map_delete_elem(&read_data, &id); return 0; } // Filter small reads
    struct so_event *event = init_event();
    if (event) {
        __builtin_memcpy(event->syscall, "read", 5);
        event->fd = data->flags;
        event->count = data->count;
        event->bytes_rw = ctx->ret;
        event->ret = ctx->ret;
        submit(ctx, event);
    }
    bpf_map_delete_elem(&read_data, &id);
    return 0;
}

SEC("tp/syscalls/sys_enter_unlinkat")
int sys_enter_unlinkat(struct args_unlinkat *ctx) {
    struct so_event *event = init_event();
    if (!event) return 0;
    __builtin_memcpy(event->syscall, "unlinkat", 9);
    bpf_probe_read_user_str(&event->filename, sizeof(event->filename), ctx->pathname);
    submit(ctx, event);
    return 0;
}

SEC("tp/syscalls/sys_enter_vfork")
int sys_enter_vfork(void *ctx) {
    struct so_event *event = init_event();
    if (!event) return 0;
    __builtin_memcpy(event->syscall, "vfork", 6);
    submit(ctx, event);
    return 0;
}

SEC("tp/syscalls/sys_enter_connect")
int sys_enter_connect(struct args_connect *ctx) {
    struct so_event *event = init_event();
    if (!event) return 0;
    __builtin_memcpy(event->syscall, "connect", 8);
    event->fd = ctx->fd;
    u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), ctx->uservaddr);
    event->sa_family = family;
    if (family == 2) {
        struct sockaddr_in addr = {};
        bpf_probe_read_user(&addr, sizeof(addr), ctx->uservaddr);
        event->dest_ip = bpf_ntohl(addr.sin_addr.s_addr);
        event->dest_port = bpf_ntohs(addr.sin_port);
    } else if (family == 10) {
        struct sockaddr_in6 addr = {};
        bpf_probe_read_user(&addr, sizeof(addr), ctx->uservaddr);
        event->dest_port = bpf_ntohs(addr.sin6_port);
        bpf_probe_read_user(&event->dest_ipv6, sizeof(event->dest_ipv6), &addr.sin6_addr);
    }
    submit(ctx, event);
    return 0;
}

SEC("tp/syscalls/sys_enter_clone")
int sys_enter_clone(void *ctx) {
    struct so_event *event = init_event();
    if (!event) return 0;
    __builtin_memcpy(event->syscall, "clone", 6);
    submit(ctx, event);
    return 0;
}

SEC("tp/syscalls/sys_enter_clone3")
int sys_enter_clone3(void *ctx) {
    struct so_event *event = init_event();
    if (!event) return 0;
    __builtin_memcpy(event->syscall, "clone3", 7);
    submit(ctx, event);
    return 0;
}