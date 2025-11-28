BINARY_NAME := ebpf-monitor
SERVICE_NAME := ebpf-monitor
INSTALL_BIN := /usr/bin/$(SERVICE_NAME)
CONFIG_DIR := /etc/ebpf-monitor
CONFIG_SRC := config/config.json
SYSTEMD_DIR := /lib/systemd/system
SCRIPTS_DIR := scripts

# Detect architecture for BPF
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')

.PHONY: all generate build install uninstall clean logs package

# Default target
all: generate build

# 1. Generate Go bindings from C code
generate:
	@echo "[*] Generating eBPF bindings..."
	go generate ./...

# 2. Build the Go binary
build: generate
	@echo "[*] Building binary..."
	go build -o $(BINARY_NAME) ./cmd/ebpf-monitor

# 3. Install to system (Requires Root)
install: build
	@echo "[*] Installing to $(INSTALL_BIN)..."
	@mkdir -p $(CONFIG_DIR)
	@cp $(BINARY_NAME) $(INSTALL_BIN)
	@chmod 755 $(INSTALL_BIN)
	@# Only copy config if it doesn't exist to prevent overwriting custom settings
	@if [ ! -f $(CONFIG_DIR)/config.json ]; then \
		echo "[*] Installing default config to $(CONFIG_DIR)/config.json..."; \
		cp $(CONFIG_SRC) $(CONFIG_DIR)/config.json; \
		chmod 600 $(CONFIG_DIR)/config.json; \
	else \
		echo "[!] Config exists, skipping overwrite."; \
	fi
	@echo "[*] Installing Systemd Service..."
	@cp $(SCRIPTS_DIR)/$(SERVICE_NAME).service $(SYSTEMD_DIR)/$(SERVICE_NAME).service
	@systemctl daemon-reload
	@systemctl enable $(SERVICE_NAME)
	@echo "[+] Installation complete. Run 'make start' to start the service."

# Service Management
start:
	systemctl start $(SERVICE_NAME)
	systemctl status $(SERVICE_NAME)

stop:
	systemctl stop $(SERVICE_NAME)

restart:
	systemctl restart $(SERVICE_NAME)

logs:
	journalctl -u $(SERVICE_NAME) -f

# 4. Cleanup
clean:
	@echo "[*] Cleaning up..."
	rm -f $(BINARY_NAME)
	rm -f cmd/ebpf-monitor/bpf_bpf.go cmd/ebpf-monitor/bpf_bpf.o
	rm -rf build/

# 5. Full Uninstall
uninstall:
	@echo "[*] Uninstalling..."
	-systemctl stop $(SERVICE_NAME)
	-systemctl disable $(SERVICE_NAME)
	rm -f $(INSTALL_BIN)
	rm -f $(SYSTEMD_DIR)/$(SERVICE_NAME).service
	systemctl daemon-reload
	@echo "[+] Binary and Service removed. Config at $(CONFIG_DIR) was kept for safety."

# 6. Build Debian Package
package: build
	@echo "[*] Building Debian package with nfpm..."
	@mkdir -p build
	@which nfpm > /dev/null || (echo "[!] nfpm not found. Install it first." && exit 1)
	nfpm package --packager deb --target build/
	@echo "[+] Package created in build/ directory"