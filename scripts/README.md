# Installation and Setup Scripts

Collection of scripts for installing, configuring, and managing the eBPF Provenance Monitor system.

## Overview

These scripts automate the installation and configuration of all system components, including dependencies, services, and auxiliary tools.

## Files

### Setup Scripts

- **build-setup.sh** - Install build dependencies (Go, Clang, LLVM, headers)
- **streamlit-setup.sh** - Install and configure web application
- **es-setup.sh** - Install and configure Elasticsearch
- **ollama-setup.sh** - Install Ollama for AI analysis

### Service Files

- **ebpf-monitor.service** - Systemd service for eBPF monitor
- **streamlit-webapp.service** - Systemd service for web application
- **streamlit-webapp.env** - Environment template for web service

### Maintenance

- **ebpf-provenance-logrotate** - Logrotate configuration
- **postinstall.sh** - Post-installation tasks (for .deb package)
- **preremove.sh** - Pre-removal tasks (for .deb package)

### Setup Scripts

- **logrotate-setup.sh** - Install logrotate configuration

## Setup Scripts Usage

### build-setup.sh

Installs all build dependencies for compiling the eBPF monitor.

**Usage:**
```bash
sudo ./build-setup.sh
```

**What it installs:**
- Go 1.25+
- Clang 10+
- LLVM 10+
- libbpf-dev
- Linux headers for current kernel
- bpftool
- make and build essentials

**When to use:**
- Before first build from source
- Setting up development environment
- After kernel upgrade (to install matching headers)

**Example:**
```bash
cd scripts
sudo ./build-setup.sh

# Then build the project
cd ..
make generate
make build
```

### streamlit-setup.sh

Installs and configures the Streamlit web application.

**Usage:**
```bash
sudo ./streamlit-setup.sh
```

**What it does:**
1. Checks for Python 3.12 (installs if missing via deadsnakes PPA)
2. Creates Python virtual environment in `web/venv`
3. Installs Python dependencies from `web/requirements.txt`
4. Creates monitoring directories (`/var/monitoring/events`, `/var/monitoring/outputs`)
5. Copies default config to `/var/config.json` (if not exists)
6. Sets up systemd service for web app
7. Creates environment file at `/etc/default/streamlit-webapp`
8. Installs logrotate configuration

**Environment Configuration:**

The script automatically creates `/etc/default/streamlit-webapp`:
```bash
PROJECT_ROOT=/path/to/ebpf-provenance
```

**Manual run after setup:**
```bash
cd web
source venv/bin/activate
streamlit run webapp.py --server.port=8501 --server.address=0.0.0.0
```

**Service management:**
```bash
sudo systemctl start streamlit-webapp
sudo systemctl enable streamlit-webapp
sudo systemctl status streamlit-webapp
```

### es-setup.sh

Installs and configures Elasticsearch.

**Usage:**
```bash
sudo ./es-setup.sh
```

**What it does:**
1. Adds Elasticsearch GPG key and repository
2. Installs Elasticsearch 9.x
3. Configures for local access
4. Enables and starts service
5. Displays initial elastic password
6. Tests connection

**Post-installation:**
```bash
# Update credentials in config
sudo nano /var/config.json

# Update:
{
  "es_config": {
    "es_user": "elastic",
    "es_password": "YOUR_PASSWORD_HERE",
    ...
  }
}

# Restart monitor to use new credentials
sudo systemctl restart ebpf-monitor
```

**Testing:**
```bash
# Test connection
curl -k -u elastic:password https://localhost:9200

# Check index
curl -k -u elastic:password https://localhost:9200/ebpf-events/_count
```

### ollama-setup.sh

Installs Ollama for AI-powered analysis.

**Usage:**
```bash
sudo ./ollama-setup.sh
```

**What it does:**
1. Downloads and installs Ollama
2. Starts Ollama service
3. Instructions for pulling models

**Post-installation:**
```bash
# Pull a model (choose one)
ollama pull llama3        # General purpose (4.7GB)
ollama pull mistral       # Fast and efficient (4.1GB)
ollama pull llama3:70b    # Most capable (39GB)

# Test
ollama run llama3 "Explain what eBPF is in one sentence"
```

**Using with web app:**
- AI analysis tab will automatically detect Ollama
- Upload graph files for automated threat analysis
- Models run locally (no data sent externally)

## Service Files

### ebpf-monitor.service

Systemd service for the eBPF monitor.

**Location:** `/lib/systemd/system/ebpf-monitor.service`

**Content:**
```ini
[Unit]
Description=eBPF System Call Monitor
After=network.target auditd.service

[Service]
Type=simple
ExecStart=/usr/bin/ebpf-monitor
Restart=always
RestartSec=5s
User=root
Group=root

[Install]
WantedBy=multi-user.target
```

**Management:**
```bash
sudo systemctl start ebpf-monitor
sudo systemctl stop ebpf-monitor
sudo systemctl restart ebpf-monitor
sudo systemctl status ebpf-monitor
sudo systemctl enable ebpf-monitor   # Start on boot
sudo systemctl disable ebpf-monitor  # Don't start on boot
```

**Logs:**
```bash
# Follow live logs
sudo journalctl -u ebpf-monitor -f

# View last 100 lines
sudo journalctl -u ebpf-monitor -n 100

# View logs since boot
sudo journalctl -u ebpf-monitor -b
```

### streamlit-webapp.service

Systemd service for the web application.

**Location:** `/lib/systemd/system/streamlit-webapp.service`

**Content:**
```ini
[Unit]
Description=Streamlit eBPF Forensic Web Application
After=network.target elasticsearch.service

[Service]
Type=simple
WorkingDirectory=${PROJECT_ROOT}/web
ExecStart=${PROJECT_ROOT}/web/venv/bin/python -m streamlit run webapp.py --server.port=8501 --server.address=0.0.0.0
Restart=always
RestartSec=5s
User=root
Group=root
Environment="PATH=${PROJECT_ROOT}/web/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
EnvironmentFile=-/etc/default/streamlit-webapp

[Install]
WantedBy=multi-user.target
```

**Key features:**
- Uses `${PROJECT_ROOT}` from environment file
- Runs from virtual environment
- Auto-restarts on failure
- Waits for Elasticsearch (if installed)

**Environment file:** `/etc/default/streamlit-webapp`
```bash
PROJECT_ROOT=/path/to/your/ebpf-provenance
```

### streamlit-webapp.env

Template for the environment file.

**Usage:**
```bash
# Automatically created by streamlit-setup.sh
# Manual installation:
sudo cp streamlit-webapp.env /etc/default/streamlit-webapp
sudo nano /etc/default/streamlit-webapp
# Update PROJECT_ROOT to your installation path
```

## Log Rotation

### ebpf-provenance-logrotate

Logrotate configuration for automatic log management.

**Location:** `/etc/logrotate.d/ebpf-provenance`

**What it manages:**
1. eBPF monitor events (`/var/monitoring/events/events.jsonl`)
2. Output files (`/var/monitoring/outputs/*.log`)
3. Streamlit logs (`/var/log/streamlit-webapp/*.log`)

**Configuration:**
```
/var/monitoring/events/events.jsonl {
    daily                    # Rotate daily
    rotate 30                # Keep 30 days
    compress                 # Compress old logs
    delaycompress            # Don't compress most recent
    missingok                # Don't error if missing
    notifempty               # Don't rotate empty logs
    create 0644 root root    # Create new file with permissions
    dateext                  # Add date to filename
    dateformat -%Y%m%d       # Date format
    postrotate
        # Send SIGHUP to reopen log file
        if systemctl is-active --quiet ebpf-monitor.service; then
            systemctl kill -s HUP ebpf-monitor.service
        fi
    endscript
}
```

**Manual rotation:**
```bash
# Test configuration
sudo logrotate -d /etc/logrotate.d/ebpf-provenance

# Force rotation
sudo logrotate -f /etc/logrotate.d/ebpf-provenance

# View rotated logs
ls -lah /var/monitoring/events/
```

## Package Scripts

### postinstall.sh

Runs after .deb package installation.

**Actions:**
- Reload systemd daemon
- Enable ebpf-monitor service
- Display installation summary

**Location:** Called by nfpm during package installation

### preremove.sh

Runs before .deb package removal.

**Actions:**
- Stop ebpf-monitor service
- Disable service
- Clean up (but preserve config)

**Location:** Called by nfpm during package removal

## Common Workflows

### Fresh Installation

```bash
# 1. Install build dependencies
cd scripts
sudo ./build-setup.sh

# 2. Build and install monitor
cd ..
make build
sudo make install

# 3. Install Elasticsearch (optional)
cd scripts
sudo ./es-setup.sh

# 4. Update config with ES credentials
sudo nano /var/config.json

# 5. Install web application
sudo ./streamlit-setup.sh

# 6. Install Ollama (optional)
sudo ./ollama-setup.sh
ollama pull llama3

# 7. Start services
sudo systemctl start ebpf-monitor
sudo systemctl start streamlit-webapp

# 8. Access web interface
# http://localhost:8501
```

### Development Setup

```bash
# Install build tools
sudo ./build-setup.sh

# Don't install as service - run manually for development
cd ..
make build

# Run monitor manually
sudo ./ebpf-monitor

# In another terminal, run web app manually
cd web
source venv/bin/activate
streamlit run webapp.py
```

### Update Installation

```bash
# Stop services
sudo systemctl stop ebpf-monitor
sudo systemctl stop streamlit-webapp

# Update code
git pull

# Rebuild
make clean
make generate
make build

# Update installation
sudo cp ebpf-monitor /usr/bin/

# Update web dependencies (if changed)
cd web
source venv/bin/activate
pip install -r requirements.txt

# Restart services
sudo systemctl start ebpf-monitor
sudo systemctl start streamlit-webapp
```

## Troubleshooting

### Build Setup Issues

**Error: "Package not found"**
```bash
# Update package lists
sudo apt-get update
sudo apt-get upgrade

# Retry
sudo ./build-setup.sh
```

**Wrong kernel headers installed:**
```bash
# Check current kernel
uname -r

# Install matching headers
sudo apt-get install linux-headers-$(uname -r)
```

### Streamlit Setup Issues

**Python 3.12 installation fails:**
```bash
# Ensure PPA is added correctly
sudo add-apt-repository -y ppa:deadsnakes/ppa
sudo apt-get update
sudo apt-get install -y python3.12 python3.12-venv python3.12-dev
```

**Virtual environment creation fails:**
```bash
# Install venv module
sudo apt-get install python3.12-venv

# Retry
cd ../web
python3.12 -m venv venv
```

**Service won't start:**
```bash
# Check environment file
cat /etc/default/streamlit-webapp

# Ensure PROJECT_ROOT is correct
sudo nano /etc/default/streamlit-webapp

# Test manually
cd /path/to/project/web
source venv/bin/activate
streamlit run webapp.py
```

### Elasticsearch Setup Issues

**Installation fails:**
```bash
# Check if repository was added
ls /etc/apt/sources.list.d/ | grep elastic

# Manually add if missing
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
sudo apt-get update
sudo apt-get install elasticsearch
```

**Cannot connect to Elasticsearch:**
```bash
# Check service status
sudo systemctl status elasticsearch

# Check if listening
sudo netstat -tlnp | grep 9200

# View ES logs
sudo journalctl -u elasticsearch -n 100

# Reset elastic password
sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic
```

### Logrotate Issues

**Logs not rotating:**
```bash
# Check configuration
sudo logrotate -d /etc/logrotate.d/ebpf-provenance

# Check logrotate status
sudo cat /var/lib/logrotate/status | grep ebpf

# Force rotation
sudo logrotate -f /etc/logrotate.d/ebpf-provenance
```

**SIGHUP not working:**
```bash
# Test manually
sudo systemctl kill -s HUP ebpf-monitor.service

# Check monitor logs
sudo journalctl -u ebpf-monitor -n 20
```

## Security Considerations

### Service Accounts

For production, consider running services as non-root:

```bash
# Create service user
sudo useradd -r -s /bin/false ebpf-monitor

# Update service file
# User=ebpf-monitor
# Group=ebpf-monitor

# Grant CAP_BPF capability
sudo setcap cap_bpf+ep /usr/bin/ebpf-monitor
```

### File Permissions

```bash
# Secure config file
sudo chmod 600 /var/config.json

# Secure monitoring directories
sudo chmod 755 /var/monitoring
sudo chmod 700 /var/monitoring/events
sudo chmod 700 /var/monitoring/outputs
```
