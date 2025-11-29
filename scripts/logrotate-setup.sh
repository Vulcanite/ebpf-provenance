#!/bin/bash

echo "Setting up logrotate..."
sudo cp "$SCRIPT_DIR/ebpf-provenance-logrotate" /etc/logrotate.d/ebpf-provenance
sudo chmod 644 /etc/logrotate.d/ebpf-provenance
echo "Logrotate configuration installed"