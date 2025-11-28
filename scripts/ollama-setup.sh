#!/bin/sh
# Automated setup script for Ollama and pulling the Llama 3 model

curl -fsSL https://ollama.com/install.sh | sh

ollama pull llama3:latest