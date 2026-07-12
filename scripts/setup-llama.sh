#!/usr/bin/env bash
set -euo pipefail

# Installs llama.cpp server to /opt/llama.cpp and a tiny model to /opt/models
# Requires: git, cmake, build-essential, curl

sudo apt-get update
sudo apt-get install -y git cmake build-essential curl

sudo install -d -m0755 /opt/llama.cpp /opt/models

# Build in a temp dir, then install server binary
BUILD_DIR="/tmp/llama.cpp-$$"
git clone https://github.com/ggerganov/llama.cpp.git "${BUILD_DIR}"
cmake -S "${BUILD_DIR}" -B "${BUILD_DIR}/build" -DGGML_NATIVE=ON
cmake --build "${BUILD_DIR}/build" -j"$(nproc)" --target server
sudo install -m0755 "${BUILD_DIR}/build/bin/server" /opt/llama.cpp/server
rm -rf "${BUILD_DIR}"

# Download TinyLlama (Q4_K_M) as a fast baseline
if [[ ! -f /opt/models/tinyllama.gguf ]]; then
  curl -L -o /opt/models/tinyllama.gguf \
    https://huggingface.co/TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF/resolve/main/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf
fi

echo "llama.cpp installed at /opt/llama.cpp/server"
echo "Model at /opt/models/tinyllama.gguf"
echo "Run: nohup /opt/llama.cpp/server -m /opt/models/tinyllama.gguf -t $(nproc) -c 4096 --batch 512 --ubatch 256 --parallel 4 --host 127.0.0.1 --port 11434 >/tmp/llama.log 2>&1 &"
