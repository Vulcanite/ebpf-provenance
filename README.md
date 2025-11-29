# eBPF Provenance Monitor

A lightweight eBPF-based system for capturing and analyzing security-relevant system calls on Linux. Builds provenance graphs to trace process execution, file access, and network activity for forensic analysis.

## Overview

This tool uses eBPF to monitor system calls at the kernel level with minimal overhead. It correlates events into provenance graphs showing relationships between processes, files, and network connections.

**Key Features**:
- Real-time syscall monitoring (execve, openat, read, write, connect, clone, unlinkat)
- Context-aware filtering to reduce noise while preserving security events
- Interactive web interface for event querying and graph visualization
- Optional AI-powered threat analysis via Ollama

## Components

### 1. eBPF Collector (`bpf/` & `cmd/ebpf-monitor/`)

**What it does**: Attaches to kernel tracepoints to capture syscalls, filters events, and forwards them to storage.

**Tech Stack**: C (eBPF kernel programs) + Go (userspace collector)

**Output**: Events stored in Elasticsearch or local JSONL files

**Documentation**: [`bpf/README.md`](bpf/README.md), [`cmd/ebpf-monitor/README.md`](cmd/ebpf-monitor/README.md)

### 2. Web Interface (`web/`)

**What it does**: Provides a Streamlit dashboard for searching events, generating provenance graphs, and running analysis.

**Tech Stack**: Python (Streamlit, NetworkX, PyVis)

**Features**:
- Event search with time range and filter support
- Provenance graph generation with intelligent noise reduction
- Interactive graph visualization (zoomable, color-coded)
- AI chat interface for attack analysis (requires Ollama)

**Documentation**: [`web/README.md`](web/README.md)

### 3. Deployment Scripts (`scripts/`)

**What it does**: Systemd service files and installation scripts for production deployment.

**Includes**: Service units, log rotation, Streamlit setup automation

## Quick Start

### Install from Package
```bash
sudo dpkg -i ebpf-monitor_*.deb
sudo systemctl start ebpf-monitor
```

### Build from Source
```bash
make all
sudo make install
sudo systemctl start ebpf-monitor
```

### Launch Web Interface
```bash
cd web
pip install -r requirements.txt
streamlit run webapp.py
```

Access at: `http://localhost:8501`

## Configuration

Edit `/var/config.json`:
```json
{
  "events_dir": "/var/monitoring/events/",
  "storage_type": "elasticsearch",
  "es_config": {
    "es_host": "localhost",
    "es_port": 9200,
    "es_user": "elastic",
    "es_password": "changeme",
    "es_index": "ebpf-events"
  }
}
```

## Requirements

- Linux kernel 5.8+ (BTF support)
- Root privileges (for eBPF)
- Go 1.22+ (build only)
- Python 3.8+ (web interface)
- Elasticsearch 9.x (optional)

## Architecture
```
Kernel (eBPF) → Go Collector → Storage (ES/Files) → Python Web UI
```

1. **Kernel**: eBPF programs hook syscall tracepoints
2. **Collector**: Go app reads events, enriches data, writes to storage
3. **Storage**: Elasticsearch for queries or local JSONL files
4. **Web UI**: Python dashboard for analysis and visualization
