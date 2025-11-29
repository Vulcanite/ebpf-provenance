# Web Application - Streamlit Interface

Interactive web interface for querying events, generating provenance graphs, and performing AI-powered security analysis.

## Overview

The Streamlit web application provides a user-friendly interface for forensic analysis of eBPF-captured system events. It supports real-time querying, interactive graph visualization, and optional AI-powered threat assessment using Ollama.

## Files

- **webapp.py** - Main Streamlit application (UI and event querying)
- **analyzer.py** - Provenance graph generation with context-aware filtering
- **ollama_agent.py** - AI analysis integration for threat assessment
- **requirements.txt** - Python dependencies

## Features

### 1. Event Search and Querying
- Time range selection (relative or absolute)
- Filter by syscall type
- Filter by process name (comm)
- Filter by PID or PPID
- Paginated results with configurable page size
- Real-time event count display

### 2. Provenance Graph Generation
- Target selection (by PID, process name, or time window)
- Multiple output formats (DOT, GraphML, Interactive HTML)
- Context-aware noise filtering
- Automatic suspicious activity highlighting
- Color-coded nodes for different entity types

### 3. Interactive Visualization
- Zoomable, pannable graphs
- Physics-based layout
- Hover tooltips with detailed information
- Keyboard navigation
- Color-coded security relevance

### 4. AI-Powered Analysis (Optional)
- Upload graphs to Ollama for analysis
- Natural language threat assessment
- Behavioral pattern detection

## Dependencies

From `requirements.txt`:

```
streamlit==1.51.0       # Web framework
elasticsearch==9.2.0     # ES client
networkx==3.1           # Graph analysis
pydot==4.0.1            # DOT format support
pyvis==0.3.1            # Interactive graph visualization
```

## Architecture

```
User Browser
      |
      v
+-------------------+
| Streamlit UI      |
| - Event filters   |
| - Graph controls  |
+-------------------+
      |
      v
+-------------------+
| Query Engine      |
| - ES queries      |
| - Time windows    |
+-------------------+
      |
      v
+-------------------+
| Analyzer          |
| - Graph building  |
| - Noise filtering |
| - Coloring        |
+-------------------+
      |
      v
+-------------------+
| Visualization     |
| - PyVis (HTML)    |
| - DOT export      |
| - GraphML export  |
+-------------------+
      |
      v (optional)
+-------------------+
| Ollama Agent      |
| - AI analysis     |
+-------------------+
```

## Installation

### Automatic (Recommended)

```bash
cd ../scripts
sudo ./streamlit-setup.sh
```

This will:
- Install Python 3.12
- Create virtual environment
- Install dependencies
- Configure systemd service
- Set up environment variables

## Usage

### Starting the Application

**As a Service:**
```bash
sudo systemctl start streamlit-webapp
sudo systemctl status streamlit-webapp
```

**Manually:**
```bash
source venv/bin/activate
streamlit run webapp.py --server.port=8501 --server.address=0.0.0.0
```

Access at: `http://localhost:8501`

### Using the Interface

#### Event Search Tab

1. **Set Time Range**
   - Select relative time (last 1h, 6h, 24h) or custom range
   - Click "Search Events"

2. **Apply Filters**
   - Filter by syscall: `execve`, `openat`, `connect`, etc.
   - Filter by process: Enter exact process name
   - Filter by PID or PPID

3. **View Results**
   - Scroll through paginated events
   - View event details (timestamp, process, file, network, etc.)
   - Export results (copy JSON)

#### Provenance Graph Tab

1. **Select Target**
   - By PID: Analyze specific process
   - By Process Name: Find and analyze by comm
   - By Time Window: Analyze recent activity

2. **Choose Output Format**
   - **Interactive**: Zoomable HTML visualization
   - **DOT**: Graphviz format (for external tools)
   - **GraphML**: NetworkX XML format (for Gephi, etc.)

3. **Generate Graph**
   - Click "Generate Graph"
   - Wait for processing
   - View/download results

4. **Interpret Colors**
   - **Blue (#40A8D1)**: Suspicious processes
   - **Gray (#888888)**: Benign processes
   - **Red (#D14040)**: Sensitive files
   - **Orange (#D18C40)**: Downloads/temp files
   - **Pink (#FF69B4)**: Network connections
   - **Light Gray**: Normal files

#### AI Analysis Tab (if Ollama enabled)

1. **Generate Graph First**
   - Create provenance graph in DOT format

2. **Upload for Analysis**
   - Select graph file
   - Click "Analyze with Ollama"

3. **Review Results**
   - Read natural language threat assessment
   - Follow security recommendations

## Analyzer: Context-Aware Filtering

The analyzer implements intelligent noise reduction while preserving security-relevant events.

### Noise Categories

Events are categorized and filtered based on context:

**Authentication** (low sensitivity)
- Processes: `sshd`, `login`, `su`
- Files: `.ssh/*`, `shadow`, `passwd`
- Preserves anomalous auth activity

**System Logging** (low sensitivity)
- Processes: `systemd-journald`, `rsyslog`
- Files: `/var/log/*`
- Filters routine log operations

**Package Management** (low sensitivity)
- Processes: `dpkg`, `apt`, `yum`
- Files: `/var/lib/dpkg/*`, `/var/cache/apt/*`

**Shared Libraries** (medium sensitivity)
- Files: `/usr/lib/*.so`, `/lib/*.so`
- Filters routine library loads
- Preserves unusual library usage

**Kernel Pseudo-FS** (low sensitivity)
- Files: `/proc/*`, `/sys/*`, `/dev/null`
- Always filtered (high noise, low value)

**Terminal/Pager** (low sensitivity)
- Processes: `less`, `more`
- Files: `.less*`

### Filtering Logic

```python
def should_filter_event(event, category_filters):
    """
    Multi-factor filtering decision:
    1. Match against noise categories
    2. Check burst patterns (repeated ops)
    3. Consider syscall type
    4. Evaluate sensitivity level
    """
    # Check category match
    category = match_noise_category(event)
    if category:
        # Apply burst detection
        if is_burst_event(event):
            return True
        # Consider sensitivity
        if category['sensitivity'] == 'low':
            return True
    return False
```

### Graph Coloring

Nodes are colored based on security relevance:

```python
def assign_node_color(node, node_type):
    if node_type == 'process':
        if is_suspicious(node):
            return '#40A8D1'  # Blue
        else:
            return '#AAAAAA'  # Gray
    elif node_type == 'file':
        if is_sensitive_path(node):
            return '#D14040'  # Red
        elif is_download_temp(node):
            return '#D18C40'  # Orange
        else:
            return '#CCCCCC'  # Light Gray
    elif node_type == 'network':
        return '#FF69B4'  # Pink
```

## Configuration

### Elasticsearch Connection

Configured via `/var/config.json`:

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