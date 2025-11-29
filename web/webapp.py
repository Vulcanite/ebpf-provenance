#!/usr/bin/env python3
# Streamlit web application code for eBPF forensic monitoring and analysis

import streamlit as st
from elasticsearch import Elasticsearch
from datetime import datetime, timedelta, timezone
import pandas as pd
import json
import os
import subprocess
import urllib3
import networkx as nx
from pyvis.network import Network
import streamlit.components.v1 as components
import tempfile
import pydot
import time
import re
import ollama_agent

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CONFIG_PATH = "/var/config.json"
ANALYZER_SCRIPT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "analyzer.py")

def load_config():
    if not os.path.exists(CONFIG_PATH):
        st.error(f"Config file not found at {CONFIG_PATH}")
        st.stop()
    with open(CONFIG_PATH, "r") as f:
        return json.load(f)

def to_epoch_ms(dt: datetime) -> int:
    return int(dt.astimezone().timestamp() * 1_000)

@st.cache_resource
def connect_elasticsearch(es_config):
    es_host = es_config.get("es_host", "localhost")
    es_port = es_config.get("es_port", "9200")
    es_user = es_config.get("es_user", None)
    es_pass = es_config.get("es_password", None)
    is_ssl_enabled = es_config.get("secure", False)

    host = f"http://{es_host}:{es_port}"
    if is_ssl_enabled:
        host = f"https://{es_host}:{es_port}"

    try:
        es = Elasticsearch(host, basic_auth=(es_user, es_pass), verify_certs=False, request_timeout=10)
        if not es.ping():
            st.error("Cannot connect to Elasticsearch")
            st.stop()
        return es
    except Exception as e:
        st.error(f"Elasticsearch connection error: {e}")
        st.stop()

def create_interactive_graph(dot_file_path):
    if not os.path.exists(dot_file_path):
        return None

    try:
        pydot_graphs = pydot.graph_from_dot_file(dot_file_path)
        if not pydot_graphs:
            return None
        
        graph = nx.DiGraph(nx.nx_pydot.from_pydot(pydot_graphs[0]))
        net = Network(height="750px", width="100%", bgcolor="#222222", font_color="white", directed=True)
        net.set_options("""
        {
          "nodes": {"font": {"size": 14}},
          "edges": {"color": {"inherit": true}, "smooth": {"type": "continuous"}, "arrows": {"to": {"enabled": true, "scaleFactor": 0.5}}},
          "physics": {"enabled": true, "stabilization": {"iterations": 200}, "barnesHut": {"gravitationalConstant": -8000, "centralGravity": 0.3, "springLength": 150, "springConstant": 0.04}},
          "interaction": {"hover": true, "tooltipDelay": 100, "navigationButtons": true, "keyboard": true}
        }
        """)

        for node_id in graph.nodes():
            node_attrs = graph.nodes[node_id]
            
            label = node_attrs.get('label', node_id).strip('"').replace('\\n', '\n')
            
            fillcolor = node_attrs.get('fillcolor', 'lightblue').strip('"')
            shape = node_attrs.get('shape', 'box').strip('"')
            
            shape_map = {'box': 'box', 'note': 'box', 'diamond': 'diamond', 'ellipse': 'ellipse'}
            pyvis_shape = shape_map.get(shape, 'box')

            # Enhanced color mapping for improved analyzer
            color_map = {
                'lightblue': '#40A8D1',    # Process (suspicious)
                '#40A8D1': '#40A8D1',      # Process (suspicious)
                '#AAAAAA': '#888888',      # Process (benign)
                'red': '#D14040',          # Sensitive file
                '#D14040': '#D14040',      # Sensitive file
                'orange': '#D18C40',       # Downloads/tmp
                '#D18C40': '#D18C40',      # Downloads/tmp
                'yellow': '#D1D140',
                '#D1D140': '#D1D140',
                'lightgray': '#CCCCCC',    # Normal file
                '#CCCCCC': '#CCCCCC',      # Normal file
                'pink': '#FF69B4',         # Network
                '#FF69B4': '#FF69B4',      # Network
                '#A8D1A0': '#A8D1A0'       # Network (green)
            }
            color = color_map.get(fillcolor, fillcolor)

            penwidth = node_attrs.get('penwidth', '1.0').strip('"')
            is_focus = float(penwidth) > 2.0
            
            tooltip = node_attrs.get('tooltip', label).strip('"').replace('\\n', '\n')

            net.add_node(
                node_id, label=label, title=tooltip, color=color, shape=pyvis_shape,
                size=30 if is_focus else 20, borderWidth=4 if is_focus else 2, borderWidthSelected=6
            )

        for u, v in graph.edges():
            edge_attrs = graph.edges[u, v]
            edge_label = edge_attrs.get('label', '').strip('"')
            edge_color = edge_attrs.get('color', 'gray').strip('"')
            tooltip = edge_attrs.get('tooltip', edge_label).strip('"')
            net.add_edge(u, v, label=edge_label, title=tooltip, color=edge_color)

        return net

    except Exception as e:
        st.error(f"Error creating interactive graph: {e}")
        return None

def get_total_event_count(es, es_index, start_ms, end_ms, syscall_filter=None, comm_filter=None, pid_filter=None, ppid_filter=None):
    """Get total count of events matching the filters"""
    must_conditions = [
        {"range": {"epoch_timestamp": {"gte": start_ms, "lte": end_ms}}}
    ]

    if syscall_filter: must_conditions.append({"term": {"syscall": syscall_filter}})
    if comm_filter: must_conditions.append({"term": {"comm": comm_filter}})
    if pid_filter: must_conditions.append({"term": {"pid": pid_filter}})
    if ppid_filter: must_conditions.append({"term": {"ppid": ppid_filter}})

    count_query = {"query": {"bool": {"must": must_conditions}}}
    try:
        if not es.indices.exists(index=es_index):
            return 0

        response = es.count(index=es_index, body=count_query)
        return response["count"]

    except Exception:
        pass

    return total_count

def fetch_events(es, es_index, start_ms, end_ms, syscall_filter=None, comm_filter=None, pid_filter=None, ppid_filter=None, page=1, page_size=1000):
    must_conditions = [
        {"range": {"epoch_timestamp": {"gte": start_ms, "lte": end_ms}}}
    ]

    if syscall_filter: must_conditions.append({"term": {"syscall": syscall_filter}})
    if comm_filter: must_conditions.append({"term": {"comm": comm_filter}})
    if pid_filter: must_conditions.append({"term": {"pid": pid_filter}})
    if ppid_filter: must_conditions.append({"term": {"ppid": ppid_filter}})

    query = {
        "query": {"bool": {"must": must_conditions}},
        "sort": [{"datetime": {"order": "desc"}}],
        "from": (page - 1) * page_size,
        "size": page_size
    }

    all_events = []
    try:
        if not es.indices.exists(index=es_index):
            return all_events

        response = es.search(index=es_index, body=query)
        for hit in response["hits"]["hits"]:
            all_events.append(hit["_source"])

    except Exception:
        pass

    return all_events

def parse_analyzer_stats(stdout_text):
    """Parse statistics from analyzer output"""
    stats = {
        'events_loaded': 0,
        'events_filtered': 0,
        'filter_percentage': 0,
        'nodes': 0,
        'edges': 0
    }

    for line in stdout_text.split('\n'):
        if 'Loaded' in line and 'events' in line:
            match = re.search(r'Loaded (\d+)', line)
            if match:
                stats['events_loaded'] = int(match.group(1))

        if 'Filtered' in line and '/' in line:
            match = re.search(r'Filtered (\d+)/(\d+) events \((\d+\.?\d*)%', line)
            if match:
                stats['events_filtered'] = int(match.group(1))
                stats['filter_percentage'] = float(match.group(3))

        # Match: [+] Graph built: 50 nodes, 80 edges
        if 'Graph built:' in line:
            match = re.search(r'(\d+) nodes, (\d+) edges', line)
            if match:
                stats['nodes'] = int(match.group(1))
                stats['edges'] = int(match.group(2))

        # Match: [+] Final graph: 23 nodes, 34 edges
        if 'Final graph:' in line:
            match = re.search(r'(\d+) nodes, (\d+) edges', line)
            if match:
                stats['nodes'] = int(match.group(1))
                stats['edges'] = int(match.group(2))

    return stats

st.set_page_config(page_title="eBPF based Provenance Analysis", layout="wide", page_icon="🔍")

st.markdown("""
<style>
    .stats-box {
        background-color: #0E1117;
        padding: 20px;
        border-radius: 10px;
        border: 1px solid #262730;
        margin: 10px 0;
    }
    .stat-value {
        font-size: 2em;
        font-weight: bold;
        color: #00D9FF;
    }
    .stat-label {
        font-size: 0.9em;
        color: #8B8B8B;
    }
    .reduction-badge {
        background-color: #00B894;
        color: white;
        padding: 4px 12px;
        border-radius: 12px;
        font-size: 0.9em;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

st.title("eBPF based Provenance Analysis 🔍")

config = load_config()
es_config = config.get("es_config", {})
es = connect_elasticsearch(es_config)
es_index = es_config.get("es_index", "ebpf-events")
output_dir = config.get("output_dir", ".")
events_dir = config.get("events_dir", ".")

# Ensure output directory exists
os.makedirs(output_dir, exist_ok=True)

st.sidebar.header("📅 Time Range")
preset = st.sidebar.selectbox("Quick Select", ["Last 1 Hour", "Last 24 Hours", "Today", "Custom"])

if preset == "Last 1 Hour":
    end_dt = datetime.now()
    start_dt = end_dt - timedelta(hours=1)
elif preset == "Last 24 Hours":
    end_dt = datetime.now()
    start_dt = end_dt - timedelta(hours=24)
elif preset == "Today":
    end_dt = datetime.now()
    start_dt = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
else:
    start_dt = datetime.now() - timedelta(hours=1)
    end_dt = datetime.now()

start_date = st.sidebar.date_input("Start Date", start_dt.date())
start_time = st.sidebar.time_input("Start Time", start_dt.time())
end_date = st.sidebar.date_input("End Date", end_dt.date())
end_time = st.sidebar.time_input("End Time", end_dt.time())

start_datetime = datetime.combine(start_date, start_time)
end_datetime = datetime.combine(end_date, end_time)
start_ms = to_epoch_ms(start_datetime)
end_ms   = to_epoch_ms(end_datetime)

if start_datetime >= end_datetime:
    st.sidebar.error("Start time must be before end time!")
    st.stop()

st.sidebar.markdown("---")
st.sidebar.header("Search Filters")
syscall_search = st.sidebar.text_input("Syscall", placeholder="e.g., openat")
comm_search = st.sidebar.text_input("Command", placeholder="e.g., bash")
pid_search = st.sidebar.text_input("PID", placeholder="e.g., 10466")
ppid_search = st.sidebar.text_input("PPID", placeholder="e.g., 28406")

tab1, tab2, tab3, tab4 = st.tabs(["Raw Log Viewer", "Attack Provenance Graph", "Statistics", "AI Analysis Chat"])

with tab1:
    st.subheader("Raw Event Logs")
    if 'total_events' not in st.session_state:
        st.session_state['total_events'] = 0
    if 'current_page' not in st.session_state:
        st.session_state['current_page'] = 1

    page_size = 1000
    if st.button("Fetch Logs", type="primary"):
        with st.spinner("Counting total events..."):
            pid_int = int(pid_search) if pid_search.isdigit() else None
            ppid_int = int(ppid_search) if ppid_search.isdigit() else None

            # Get total count
            total_count = get_total_event_count(es, es_index, start_ms, end_ms, syscall_search, comm_search, pid_int, ppid_int)
            if total_count == 0:
                st.info("No events found in the selected timeframe with the given filters.")

            st.session_state['total_events'] = total_count
            st.session_state['current_page'] = 1

    if st.session_state['total_events'] > 0:
        total_pages = (st.session_state['total_events'] + page_size - 1) // page_size

        # Display total stats
        st.info(f"Total events in timeframe: **{st.session_state['total_events']:,}** | Page {st.session_state['current_page']} of {total_pages}")

        # Pagination controls
        page_num = st.number_input("Go to page", min_value=1, max_value=total_pages,
                                    value=st.session_state['current_page'], key='page_input')
        if page_num != st.session_state['current_page']:
            st.session_state['current_page'] = page_num
            st.rerun()

        with st.spinner(f"Loading page {st.session_state['current_page']}..."):
            # Regenerate indices for the current timeframe
            pid_int = int(pid_search) if pid_search.isdigit() else None
            ppid_int = int(ppid_search) if ppid_search.isdigit() else None
            events = fetch_events(es, es_index, start_ms, end_ms, syscall_search, comm_search, pid_int, ppid_int, page=st.session_state['current_page'], page_size=page_size)
            if events:
                df = pd.DataFrame(events)
                cols = ['datetime', 'comm', 'pid', 'ppid', 'syscall', 'filename', 'fd', 'ret']
                cols = [c for c in cols if c in df.columns]

                start_idx = (st.session_state['current_page'] - 1) * page_size + 1
                end_idx = min(start_idx + len(events) - 1, st.session_state['total_events'])
                st.caption(f"Showing events {start_idx:,} to {end_idx:,}")

                # Reset index to start from the actual event number (not 0)
                df.index = range(start_idx, start_idx + len(df))
                st.dataframe(df[cols], width='stretch')

                # Download option
                csv = df.to_csv(index=False)
                st.download_button(
                    label="Download Current Page CSV",
                    data=csv,
                    file_name=f"events_page_{st.session_state['current_page']}.csv",
                    mime="text/csv"
                )
            else:
                st.warning("No events found on this page.")

with tab2:
    st.header("Attack Path Provenance Graph")
    st.caption("Build focused provenance graphs with intelligent noise reduction")
    
    # Main controls
    col1, col2 = st.columns([1, 1])
    with col1:
        target_comm = st.text_input("Target Process Name", value="run-attack.sh", help="Name of the suspicious process (e.g., bash)")
    with col2:
        target_pid = st.text_input("Target PID", help="PID of the suspicious process (e.g., 12345)")

    # Advanced filtering options
    with st.expander("⚙️ Advanced Filtering Options", expanded=True):
        col1, col5 = st.columns(2)
        with col1:
            disable_filtering = st.checkbox("Disable Event Filtering", value=False, help="Show all events (not recommended for large datasets)")

        with col5:
            prune_noise = st.checkbox("Prune High-Degree Files", value=False, help="Remove files accessed by many processes (system noise)")

        analysis_mode = st.selectbox(
            "Select Analysis Strategy",
            options=[
                "Standard",
                "BEEP Edge Grouping"
            ],
            index=0,
            help="Select a research-based algorithm to reduce graph noise."
        )

        use_beep = "BEEP" in analysis_mode

    if st.button("Analyze & Build Graph", type="primary", width='stretch'):
        if not target_comm and not target_pid:
            st.error("Please enter either a Target Process Name OR a Target PID.")
            st.stop()
        if target_comm and target_pid:
            st.info("ℹ️ PID and Process Name entered. Prioritizing PID.")
            target_comm = ""

        if not os.path.exists(ANALYZER_SCRIPT_PATH):
            st.error(f"Analyzer script not found: {ANALYZER_SCRIPT_PATH}")
        else:
            target_display = target_pid if target_pid else target_comm
            with st.spinner(f"Analyzing '{target_display}'"):
                try:
                    # Use configured output directory
                    timestamp = int(time.time())
                    TXT_OUTPUT = os.path.join(output_dir, f"attack_summary_{timestamp}.txt")
                    DOT_FILE = os.path.join(output_dir, f"provenance_attack_{timestamp}.dot")

                    cmd = [
                        "python3", ANALYZER_SCRIPT_PATH,
                        "--start", str(start_ms),
                        "--end", str(end_ms),
                        "--out", DOT_FILE,
                        "--text-out", TXT_OUTPUT,
                        "--depth", str(5)
                    ]

                    if prune_noise:
                        cmd.extend(["--prune", "--degree-threshold", str(5)])
                    if disable_filtering:
                        cmd.append("--no-filter")
                    if use_beep:
                        cmd.append("--beep")
                    if target_pid:
                        cmd.extend(["--pid", target_pid])
                    elif target_comm:
                        cmd.extend(["--comm", target_comm])

                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

                    st.session_state['analyzer_stdout'] = result.stdout
                    st.session_state['analyzer_stderr'] = result.stderr
                    st.session_state['analyzer_stats'] = parse_analyzer_stats(result.stdout)
                    
                    if os.path.exists(DOT_FILE) and os.path.getsize(DOT_FILE) > 0:
                        st.session_state['dot_file_path'] = DOT_FILE
                    else:
                        st.session_state['dot_file_path'] = None
                        st.warning(f"⚠️ No graph generated. Process '{target_comm}' might not be in the logs.")
                    
                    if os.path.exists(TXT_OUTPUT):
                        with open(TXT_OUTPUT, 'r') as f:
                            st.session_state['text_summary'] = f.read()
                    
                except subprocess.TimeoutExpired:
                    st.error("⏱️ Analysis timed out (>5 minutes). Try reducing the time range or graph depth.")
                    st.session_state['dot_file_path'] = None
                except Exception as e:
                    st.error(f"Error running analysis: {e}")
                    st.session_state['dot_file_path'] = None

    # Display statistics if available
    if 'analyzer_stats' in st.session_state:
        stats = st.session_state['analyzer_stats']
        
        st.markdown("### Analysis Statistics")
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Events Loaded", f"{stats['events_loaded']:,}")
        
        with col2:
            if stats['events_filtered'] > 0:
                st.metric("Events Filtered", f"{stats['events_filtered']:,}", 
                         delta=f"-{stats['filter_percentage']:.1f}%")
            else:
                st.metric("Events Filtered", "0")
        
        with col3:
            st.metric("Graph Nodes", f"{stats['nodes']}")
        
        with col4:
            st.metric("Graph Edges", f"{stats['edges']}")

    if st.session_state.get('dot_file_path'):
        # AI Analysis navigation button
        if st.button("🤖 Discuss with AI Assistant", type="secondary", help="Chat with AI about this attack analysis"):
            st.session_state['switch_to_ai_tab'] = True
            st.session_state['ai_context_loaded'] = False
            st.rerun()

        dot_file = st.session_state['dot_file_path']
        interactive_graph = create_interactive_graph(dot_file)
        if interactive_graph:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
                interactive_graph.save_graph(f.name)
                with open(f.name, 'r', encoding='utf-8') as html_file:
                    source_code = html_file.read()
                components.html(source_code, height=800, scrolling=True)
                os.unlink(f.name)

            png_file = dot_file.replace(".dot", ".png")
            try:
                if not os.path.exists(png_file):
                    subprocess.run(["dot", "-Tpng", dot_file, "-o", png_file],
                                    check=True, timeout=30, capture_output=True)

                if os.path.exists(png_file):
                    with open(png_file, 'rb') as f:
                        st.download_button(
                            label="📥 Download PNG Image",
                            data=f.read(),
                            file_name=os.path.basename(png_file),
                            mime="image/png"
                        )
            except Exception as e:
                st.warning(f"PNG generation unavailable: {e}")
        else:
            st.error("Failed to create interactive graph.")

        # Text summary
        if 'text_summary' in st.session_state:
            with st.expander("View Attack Relationships", expanded=False):
                st.text_area("Attack Chain Summary", value=st.session_state['text_summary'], height=300)
                
                # Download button
                st.download_button(
                    label="Download Summary",
                    data=st.session_state['text_summary'],
                    file_name="attack_summary.txt",
                    mime="text/plain"
                )

with tab3:
    st.header("Syscall Statistics")
    if st.button("Generate Statistics", type="primary"):
        with st.spinner("Analyzing events..."):
            agg_query = {
                "query": {
                    "range": {"epoch_timestamp": {"gte": start_ms, "lte": end_ms}}
                },
                "aggs": {
                    "syscalls": {"terms": {"field": "syscall", "size": 50}},
                    "processes": {"terms": {"field": "comm", "size": 20}},
                    "timeline": {
                        "date_histogram": {
                            "field": "datetime",
                            "fixed_interval": "1h"
                        }
                    }
                },
                "size": 0
            }

            syscall_counts = {}
            process_counts = {}
            timeline_data = []

            try:
                if not es.indices.exists(index=es_index):
                    st.warning("No data found in the selected timeframe")
                    st.stop()

                response = es.search(index=es_index, body=agg_query)

                # Syscall counts
                for bucket in response["aggregations"]["syscalls"]["buckets"]:
                    syscall_counts[bucket["key"]] = syscall_counts.get(bucket["key"], 0) + bucket["doc_count"]

                # Process counts
                for bucket in response["aggregations"]["processes"]["buckets"]:
                    process_counts[bucket["key"]] = process_counts.get(bucket["key"], 0) + bucket["doc_count"]

                # Timeline data
                for bucket in response["aggregations"]["timeline"]["buckets"]:
                    timeline_data.append({
                        "timestamp": bucket["key_as_string"],
                        "count": bucket["doc_count"]
                    })

                if syscall_counts:
                    st.markdown("---")
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("Unique Syscalls", len(syscall_counts))
                    with col2:
                        st.metric("Unique Processes", len(process_counts))
                    with col3:
                        st.metric("Total Events", sum(syscall_counts.values()))

                    st.markdown("---")
                    col1, col2 = st.columns(2)
                    with col1:
                        st.markdown("#### Top Syscalls")
                        df_syscalls = pd.DataFrame(list(syscall_counts.items()), columns=["Syscall", "Count"])
                        df_syscalls = df_syscalls.sort_values("Count", ascending=False).head(20)
                        st.bar_chart(df_syscalls.set_index("Syscall"))

                    with col2:
                        st.markdown("#### Top Processes")
                        df_processes = pd.DataFrame(list(process_counts.items()), columns=["Process", "Count"])
                        df_processes = df_processes.sort_values("Count", ascending=False).head(20)
                        st.bar_chart(df_processes.set_index("Process"))

                else:
                    st.warning("No syscall data found in the selected timeframe")

            except Exception as e:
                st.error(f"Error generating statistics: {e}")

    st.markdown("---")
    st.subheader("EBPF Index Overview")
    try:
        indices_info = es.cat.indices(index=f"{es_index}", format="json")
        if indices_info:
            df_indices = pd.DataFrame(indices_info)
            df_indices = df_indices[['index', 'docs.count', 'store.size']].sort_values('index', ascending=False)
            df_indices.columns = ['Index', 'Documents', 'Size']
            st.dataframe(df_indices, width='stretch')

            total_docs = df_indices['Documents'].astype(int).sum()
            st.metric("Total Events Stored", f"{total_docs:,}")
        else:
            st.info("No indices found")

    except Exception as e:
        st.error(f"Error fetching indices: {e}")

with tab4:
    st.header("AI-Powered Attack Analysis")
    if 'chat_history' not in st.session_state:
        st.session_state['chat_history'] = []     # Initialize chat history

    # Check Ollama connection
    col1, col2 = st.columns([3, 1])
    with col1:
        ollama_host = st.text_input("Ollama Host", value="http://localhost:11434", help="URL of your Ollama instance")

    is_connected, available_models_full, available_models_simple = ollama_agent.check_ollama_connection(ollama_host)

    with col2:
        if is_connected:
            st.success("✅ Connected")
        else:
            st.error("Not Connected")

    # Model selection - prefer full names with tags
    if available_models_full:
        # Show full model names in dropdown
        selected_model = st.selectbox("Select Model", options=available_models_full)
        st.caption(f"💡 Available models: {', '.join(available_models_simple)}")
    else:
        selected_model = st.text_input("Model Name", value="llama3:latest", help="Enter model name with tag (e.g., llama3:latest, llama3.2:latest)")
        if not is_connected:
            st.warning("⚠️ Ollama not connected. Start Ollama with: `ollama serve`")

    if 'analyzer_stats' in st.session_state or 'text_summary' in st.session_state:
        # Auto-load context when switching from Tab 2
        if st.session_state.get('switch_to_ai_tab') and not st.session_state.get('ai_context_loaded'):
            st.session_state['ai_context_loaded'] = True
            st.session_state['switch_to_ai_tab'] = False

            # Build context from analysis
            context_parts = ["# Attack Analysis Context\n"]

            if 'analyzer_stats' in st.session_state:
                stats = st.session_state['analyzer_stats']
                context_parts.append(f"""
                    ## Analysis Statistics
                    - Events Loaded: {stats['events_loaded']:,}
                    - Events Filtered: {stats['events_filtered']:,} ({stats['filter_percentage']:.1f}% reduction)
                    - Graph Nodes: {stats['nodes']}
                    - Graph Edges: {stats['edges']}
                """)

            if 'text_summary' in st.session_state:
                summary = st.session_state['text_summary']
                # Truncate if too long (keep first 8000 chars for better context)
                original_length = len(summary)
                if len(summary) > 8000:
                    summary = summary[:8000] + f"\n...(truncated from {original_length} chars)"
                context_parts.append(f"\n## Attack Chain Summary\n{summary}")

            context = "\n".join(context_parts)

            # Add context as first system message
            initial_prompt = f"""
            You are an expert Cyber Forensic Analyst using the MITRE ATT&CK framework.
            Analyze the provided execution graph summary from an eBPF monitor.

            Context:
            {context}

            Your Analysis Objectives:
            1. **Trace the Execution Chain:** Identify the root process (Patient Zero) and the sequence of spawned processes.
            2. **Identify Malicious Behaviors:** Look for ANY of the following:
            - **Collection:** Accessing sensitive files (secrets, keys, databases).
            - **C2/Exfiltration:** Network connections to non-standard ports or external IPs.
            - **Impact/Destruction:** File deletion, overwriting (ransomware behavior), or permission changes.
            - **Persistence:** Writing to startup locations (cron, init.d, .bashrc).
            3. **Analyze Noise Reduction:** If you see "BEEP" (grouped events) or "HOLMES" (causal filtering), explain what repetitive or noisy behavior was compressed.

            Final Output Format:
            - **Attack Type:** (e.g., Exfiltration, Ransomware, Dropper, etc.)
            - **Critical IOCs:** (List IPs, filenames, and PIDs)
            - **Narrative:** A brief chronological story of what happened.

            Based on the logs, provide your analysis."""

            # Get initial AI response
            with st.spinner("Loading attack context into AI..."):
                ai_response = ollama_agent.query_ollama(initial_prompt, model=selected_model, host=ollama_host)
                st.session_state['chat_history'] = [
                    {"role": "system", "content": context},
                    {"role": "assistant", "content": ai_response}
                ]

        # Show context loaded indicator
        with st.expander("📊 Attack Context Loaded", expanded=False):
            if 'analyzer_stats' in st.session_state:
                stats = st.session_state['analyzer_stats']
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric("Events", f"{stats['events_loaded']:,}")
                with col2:
                    st.metric("Filtered", f"{stats['filter_percentage']:.1f}%")
                with col3:
                    st.metric("Nodes", stats['nodes'])
                with col4:
                    st.metric("Edges", stats['edges'])

            # Show full context details
            if 'text_summary' in st.session_state:
                summary = st.session_state['text_summary']
                summary_length = len(summary)
                lines = summary.count('\n')
                st.caption(f"📄 Attack summary: {summary_length:,} chars, {lines} lines")

                # Show full summary
                with st.expander("View Full Attack Summary Context"):
                    st.text_area("Full Context Loaded into AI", value=summary, height=400)

            col_reload1, col_reload2 = st.columns(2)
            with col_reload1:
                if st.button("🔄 Reload Context"):
                    st.session_state['ai_context_loaded'] = False
                    st.session_state['switch_to_ai_tab'] = True
                    st.rerun()
            with col_reload2:
                if st.button("📋 Copy Context to Clipboard"):
                    if 'text_summary' in st.session_state:
                        st.code(st.session_state['text_summary'], language='text')

    else:
        st.info("💡 Run an attack analysis in the 'Attack Provenance Graph' tab first, then click '🤖 Discuss with AI Assistant' to load the context here.")

    # Chat interface
    st.markdown("### 💬 Chat")

    # Debug toggle
    show_debug = st.checkbox("🔍 Show debug info (conversation sent to AI)", value=False)

    # Display chat history
    for i, message in enumerate(st.session_state.get('chat_history', [])):
        if message['role'] == 'system':
            continue  # Don't display system context in chat

        if message['role'] == 'user':
            with st.chat_message("user"):
                st.markdown(message['content'])
        elif message['role'] == 'assistant':
            with st.chat_message("assistant"):
                st.markdown(message['content'])

    # Chat input
    user_input = st.chat_input("Ask about the attack analysis...")
    if user_input:
        if not is_connected:
            st.error("Cannot send message: Ollama is not connected")
        else:
            # Add user message to history
            st.session_state['chat_history'].append({"role": "user", "content": user_input})

            # Build conversation context for Ollama
            conversation = ""
            for msg in st.session_state['chat_history']:
                if msg['role'] == 'system':
                    conversation += f"System Context:\n{msg['content']}\n\n"
                elif msg['role'] == 'user':
                    conversation += f"User: {msg['content']}\n\n"
                elif msg['role'] == 'assistant':
                    conversation += f"Assistant: {msg['content']}\n\n"

            conversation += f"User: {user_input}\n\nAssistant:"

            # Show debug info if enabled
            if show_debug:
                with st.expander("🔍 Debug: Full Conversation Sent to AI", expanded=False):
                    st.text_area("Conversation", value=conversation, height=300)
                    st.caption(f"Total length: {len(conversation):,} chars")

            # Get AI response
            with st.spinner("Thinking..."):
                ai_response = ollama_agent.query_ollama(conversation, model=selected_model, host=ollama_host)

            # Add AI response to history
            st.session_state['chat_history'].append({"role": "assistant", "content": ai_response})

            # Rerun to display new messages
            st.rerun()

    # Clear chat button
    if st.session_state.get('chat_history'):
        col1, col2 = st.columns([6, 1])
        with col2:
            if st.button("🗑️ Clear Chat"):
                st.session_state['chat_history'] = []
                st.session_state['ai_context_loaded'] = False
                st.rerun()

st.markdown("---")