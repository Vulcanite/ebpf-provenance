#!/bin/bash

sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r) make

echo 'deb [trusted=yes] https://repo.goreleaser.com/apt/ /' | sudo tee /etc/apt/sources.list.d/goreleaser.list
sudo apt-get update
sudo apt-get install -y nfpm