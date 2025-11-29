# eBPF Kernel Programs

This directory contains the eBPF (Extended Berkeley Packet Filter) programs that run in kernel space to monitor system calls with minimal overhead.

## Overview

The eBPF programs hook into kernel tracepoints to capture system call events in real-time. Events are filtered and enriched in kernel space before being passed to user space, minimizing performance impact.

## Files

- **main.bpf.c** - Main eBPF program with syscall tracepoint hooks and filtering logic
- **headers/vmlinux.h** - Kernel type definitions (BTF-generated)

## Monitored System Calls

### Process Execution
- `execve` - Execute program
- `clone` / `clone3` - Create child process
- `vfork` - Create child process (optimized)

### File Operations
- `openat` / `openat2` - Open files
- `read` - Read from file descriptors
- `write` - Write to file descriptors
- `unlinkat` - Delete files

### Network Operations
- `connect` - Network connections (IPv4 and IPv6)

## Architecture

### Event Flow

```
Kernel Tracepoint
      |
      v
+-----------------------+
| eBPF Program Entry    |
| - Initialize event    |
| - Filter by process   |   <-- Stage 1: Process-based filtering
+-----------------------+
      |
      v
+-----------------------+
| Enrich Event Data     |
| - Read syscall args   |
| - Parse structures    |
| - Format data         |
+-----------------------+
      |
      v
+-----------------------+
| Filter by Context     |   <-- Stage 2: Context-aware filtering
| - Check file paths    |
| - Skip noise          |
+-----------------------+
      |
      v
+-----------------------+
| Submit to Perf Buffer |
+-----------------------+
      |
      v
    User Space
```

### Data Structures

#### so_event
Main event structure passed to user space:

```c
struct so_event {
    u64 timestamp;          // Kernel timestamp (nanoseconds)
    u32 pid;                // Process ID
    u32 ppid;               // Parent process ID
    u32 uid;                // User ID
    char comm[64];          // Process name
    char syscall[32];       // System call name
    char filename[256];     // File path (if applicable)
    s64 fd;                 // File descriptor
    u64 flags;              // Syscall flags
    s64 ret;                // Return value
    u32 dest_ip;            // Destination IP (IPv4)
    u32 dest_ipv6[4];       // Destination IP (IPv6)
    u16 dest_port;          // Destination port
    u16 sa_family;          // Socket address family
    u64 count;              // Byte count for read/write
    s64 bytes_rw;           // Actual bytes read/written
};
```

#### enter_data_t
Temporary storage for enter/exit syscall correlation:

```c
struct enter_data_t {
    char filename[256];     // Filename from sys_enter
    u64 flags;              // Flags from sys_enter
    u64 count;              // Count from sys_enter
};
```

### eBPF Maps

**events** - Perf event array for passing events to user space
- Type: BPF_MAP_TYPE_PERF_EVENT_ARRAY
- Purpose: High-performance event queue

**event_heap** - Per-CPU event storage
- Type: BPF_MAP_TYPE_PERCPU_ARRAY
- Size: 1 entry per CPU
- Purpose: Avoid stack allocation for large structures

**open_data** - Track openat/openat2 syscalls
- Type: BPF_MAP_TYPE_HASH
- Max entries: 10,240
- Purpose: Correlate sys_enter and sys_exit for file opens

**write_data** - Track write syscalls
- Type: BPF_MAP_TYPE_HASH
- Max entries: 10,240
- Purpose: Correlate sys_enter_write with sys_exit_write

**read_data** - Track read syscalls
- Type: BPF_MAP_TYPE_HASH
- Max entries: 10,240
- Purpose: Correlate sys_enter_read with sys_exit_read

## Filtering Logic

### Two-Stage Filtering

The eBPF programs implement a two-stage filtering system to reduce noise while preserving security-relevant events.

#### Stage 1: Process-Based Filtering (Early)

Filters applied immediately in `init_event()` based on process name:

**Self-Protection**
- Drops events from `ebpf-*` processes to prevent infinite loops

**Noisy System Daemons**
- `systemd-*` - System management
- `node_exporter` - Metrics collection
- `snapd` - Snap package manager

**Smart Kernel Thread Filter**
- Checks `kworker*` processes
- Only drops if PF_KTHREAD flag is set (actual kernel threads)
- Preserves malware masquerading as kernel workers

Example:
```c
static __always_inline int should_drop_comm(char *c) {
    // Self-protection
    if (c[0]=='e' && c[1]=='b' && c[2]=='p' && c[3]=='f' && c[4]=='-')
        return 1;

    // Systemd daemons
    if (c[0]=='s' && c[1]=='y' && c[2]=='s' && c[3]=='t' && c[4]=='e'
        && c[5]=='m' && c[6]=='d')
        return 1;

    // Smart kworker filter
    if (c[0]=='k' && c[1]=='w' && c[2]=='o' && c[3]=='r' && c[4]=='k') {
        struct task_struct *task = bpf_get_current_task();
        u32 flags;
        BPF_CORE_READ_INTO(&flags, task, flags);
        if (flags & PF_KTHREAD) return 1;  // Real kernel thread
    }

    return 0;
}
```

#### Stage 2: Context-Aware Filtering (Late)

Filters applied in `submit()` after event enrichment, based on file paths and syscall context:

**Security-First Design**
- NEVER filters `execve` syscalls (malware may execute from /tmp, /var/log, etc.)
- Only filters non-exec file operations (openat, read, write)

**High-Volume Noise**
- `/usr/lib*` - Shared libraries (except execve)
- `/lib*` - System libraries
- `/sys/` - Kernel pseudo-filesystem
- `/proc/` - Process filesystem
- `/dev/null`, `/dev/zero`, `/dev/urandom` - Standard devices
- `/dev/pts/*` - Terminal devices
- `/run/` - Runtime state

Example:
```c
static __always_inline int should_drop_file(struct so_event *e) {
    char *f = e->filename;
    char *sys = e->syscall;

    if (f[0] == 0) return 0;  // No filename

    // SECURITY: Never filter execve
    if (sys[0] == 'e' && sys[1] == 'x' && sys[2] == 'e' && sys[3] == 'c') {
        return 0;
    }

    // Filter library paths for non-exec
    if (f[0]=='/' && f[1]=='u' && f[2]=='s' && f[3]=='r' && f[4]=='/' &&
        f[5]=='l' && f[6]=='i' && f[7]=='b')
        return 1;

    // Filter pseudo-filesystems
    if (f[0]=='/' && f[1]=='s' && f[2]=='y' && f[3]=='s' && f[4]=='/')
        return 1;

    return 0;
}
```

## Hook Implementation

### Simple Hooks (Single Event)

Example: `execve` - Captures program execution

```c
SEC("tp/syscalls/sys_enter_execve")
int sys_enter_execve(struct args_execve *ctx) {
    struct so_event *event = init_event();  // Stage 1 filter
    if (!event) return 0;

    __builtin_memcpy(event->syscall, "execve", 7);
    bpf_probe_read_user_str(&event->filename, sizeof(event->filename), ctx->filename);

    submit(ctx, event);  // Stage 2 filter + submit
    return 0;
}
```

### Correlated Hooks (Enter/Exit Pair)

Example: `openat` - Requires correlating enter and exit events

```c
// Capture arguments at entry
SEC("tp/syscalls/sys_enter_openat")
int sys_enter_openat(struct args_openat *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct enter_data_t data = {};
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), ctx->filename);
    data.flags = ctx->flags;
    bpf_map_update_elem(&open_data, &id, &data, BPF_ANY);
    return 0;
}

// Retrieve return value and submit
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
```

### Network Hooks

Example: `connect` - Parses IPv4 and IPv6 addresses

```c
SEC("tp/syscalls/sys_enter_connect")
int sys_enter_connect(struct args_connect *ctx) {
    struct so_event *event = init_event();
    if (!event) return 0;

    __builtin_memcpy(event->syscall, "connect", 8);
    event->fd = ctx->fd;

    u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), ctx->uservaddr);
    event->sa_family = family;

    if (family == 2) {  // AF_INET (IPv4)
        struct sockaddr_in addr = {};
        bpf_probe_read_user(&addr, sizeof(addr), ctx->uservaddr);
        event->dest_ip = bpf_ntohl(addr.sin_addr.s_addr);
        event->dest_port = bpf_ntohs(addr.sin_port);
    } else if (family == 10) {  // AF_INET6 (IPv6)
        struct sockaddr_in6 addr = {};
        bpf_probe_read_user(&addr, sizeof(addr), ctx->uservaddr);
        event->dest_port = bpf_ntohs(addr.sin6_port);
        bpf_probe_read_user(&event->dest_ipv6, sizeof(event->dest_ipv6), &addr.sin6_addr);
    }

    submit(ctx, event);
    return 0;
}
```