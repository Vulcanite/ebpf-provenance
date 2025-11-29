# Provenance Analyzer & BEEP Algorithm

The `analyzer.py` module is the core forensic engine of the eBPF Provenance Monitor. It is responsible for querying raw system events, constructing a causal graph, and applying reduction algorithms to isolate relevant attack paths while suppressing system noise.

## 1. Core Logic Flow

The analysis pipeline follows a linear process:

- **Ingestion**: Fetch events from Elasticsearch based on time range or specific triggers.
- **Graph Construction**: Build a NetworkX graph where nodes are system entities and edges are operations.
- **Context Labeling**: Apply regex-based rules to tag nodes as benign, low, or high sensitivity.
- **BEEP Compression**: Apply the Bursty Event Elimination for Provenance algorithm to compress repetitive actions.
- **Structural Pruning**: Remove disconnected subgraphs that contain only benign noise.
- **Export**: Generate Graphviz (.dot) files or text summaries.

## 2. The BEEP Algorithm

BEEP (Bursty Event Elimination for Provenance) is implemented to solve the "supernode" problem in provenance graphs, where a single process (e.g., a compiler or log daemon) performs thousands of identical operations in a short timeframe, cluttering the graph.

### Implementation Details (`beep_edge_grouping`)

The algorithm operates on pairs of connected nodes $(u, v)$ and compresses edges based on temporal proximity.

### Parameters

- **Time Window ($\Delta t$)**: Default 2000ms. The maximum allowed time gap between two consecutive events to be considered part of the same "burst".
- **Threshold ($N$)**: Minimum number of events required to trigger compression.

### Algorithm Steps

1. **Edge Sorting**: For every pair of nodes $(u, v)$, retrieve all edges and sort them by timestamp.

2. **Burst Detection**: Iterate through the sorted edges. An edge $e_i$ is added to the current burst group if:
   
   $$timestamp(e_i) - timestamp(e_{i-1}) < \Delta t$$

3. **Compression**: If a group size exceeds threshold $N$:
   - **Remove**: All individual edges in the group are removed from the graph.
   - **Create**: A single Summary Edge is added.
   - **Metadata**: The summary edge stores:
     - `count`: Total events in the burst.
     - `start_time`: Timestamp of the first event.
     - `end_time`: Timestamp of the last event.
     - `label`: e.g., "write (x150)".

## 3. Context-Aware Filtering

To distinguish between background system noise and potential attacks, the analyzer uses a generalized tagging system defined in `NOISE_CATEGORIES`.

### Sensitivity Levels

- **Benign**: Known background noise (e.g., systemd-journald writing to /var/log).
- **Low**: Routine system operations (e.g., authentication checks).
- **High/Unknown**: Any activity not explicitly allow-listed (default).

### Pruning Logic (`remove_benign_only_subgraphs`)

After graph construction, the analyzer identifies Connected Components (isolated clusters of nodes).

1. It iterates through each component.
2. It checks the sensitivity tag of every node in that component.
3. **Rule**: If a component contains ZERO nodes of High or Unknown sensitivity, the entire component is discarded.
4. **Result**: We retain background noise only if it is causally connected to a potentially suspicious event.

## 4. Graph Entities (Nodes & Edges)

### Nodes

Nodes are uniquely identified to handle PID recycling:

- **Process**: ID = `{pid}:{start_time}` (e.g., `1234:1634500000`)
- **File**: ID = `{full_path}` (e.g., `/etc/passwd`)
- **Socket**: ID = `{ip}:{port}` (e.g., `192.168.1.5:80`)

### Edges

- **Ancestry**: Process A `--[execve]-->` Process B
- **Data Flow**: Process A `--[write]-->` File X
- **Networking**: Process A `--[connect]-->` Socket Y

## 5. Usage Example

To run the analyzer manually from the command line:
```bash
# Analyze events involving a specific process name
python3 analyzer.py --proc "suspicious_script.sh" --out graph.dot --text summary.txt

# Run with custom BEEP parameters (window=1s, threshold=10 events)
python3 analyzer.py --proc "nginx" --beep-window 1000 --beep-threshold 10
```

To visualize the output:
```bash
dot -Tpng graph.dot -o attack_graph.png
```