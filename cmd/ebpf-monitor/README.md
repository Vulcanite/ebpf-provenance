# eBPF Monitor - Go Application

User-space application that loads eBPF programs, processes kernel events, and manages event storage.

## Overview

The Go monitor application serves as the bridge between kernel-space eBPF programs and user-space storage systems. It handles event enrichment, formatting, and dual-output to both local JSON logs and Elasticsearch.

## Files

- **main.go** - Main application logic, event processing, and storage
- **gen.go** - Code generation directive for eBPF compilation
- **bpf_bpf.go** - Auto-generated Go bindings for eBPF programs (generated)
- **bpf_bpf.o** - Compiled eBPF object file (generated)

## Architecture

```
eBPF Kernel Programs
        |
        | (perf event buffer)
        v
+------------------+
| Event Reader     |
| - perf.Reader    |
+------------------+
        |
        v
+------------------+
| Event Parser     |
| - Binary decode  |
| - Enrich data    |
+------------------+
        |
        v
+------------------+
| Event Formatter  |
| - Add timestamps |
| - Parse IPs      |
| - Handle errors  |
+------------------+
        |
        v
+------------------+
| Dual Output      |
+------------------+
    |           |
    v           v
  JSON      Elasticsearch
  File      (bulk index)
```

## Dependencies

From `go.mod`:

```go
require (
    github.com/cilium/ebpf v0.20.0
    github.com/elastic/go-elasticsearch/v8 v8.19.0
)
```

- **cilium/ebpf** - Load and manage eBPF programs
- **go-elasticsearch** - Elasticsearch client for event indexing

## Usage

### Running Manually

```bash
# Ensure config exists
sudo mkdir -p /var/monitoring/events
sudo cp config/config.json /var/config.json

# Run as root (required for eBPF)
sudo ./ebpf-monitor
```

### Running as Service

```bash
# Start service
sudo systemctl start ebpf-monitor

# Enable on boot
sudo systemctl enable ebpf-monitor

# View status
sudo systemctl status ebpf-monitor

# View logs
sudo journalctl -u ebpf-monitor -f
```

### Log Rotation

```bash
# Trigger log rotation
sudo systemctl kill -s HUP ebpf-monitor

# Or use logrotate (automatic)
sudo logrotate -f /etc/logrotate.d/ebpf-provenance
```

## Configuration

Edit `/var/config.json`:

```json
{
  "events_dir": "/var/monitoring/events/",
  "output_dir": "/var/monitoring/outputs/",
  "storage_type": "elasticsearch",
  "es_config": {
    "es_host": "localhost",
    "es_port": 9200,
    "es_user": "elastic",
    "es_password": "changeme",
    "es_index": "ebpf-events",
    "batch_size": 500,
    "secure": true
  }
}
```

**Options:**
- `storage_type`: Set to `"elasticsearch"` or `"local"` (file-only)
- `secure`: `true` for HTTPS, `false` for HTTP
- `batch_size`: Number of events per bulk indexing batch
