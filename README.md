# ScanTrace – Dead Reckoning Edition

[![Release](https://img.shields.io/badge/release-v0.5.0-blue)](https://github.com/Risen24x7/ScanTrace/releases/tag/v0.5.0)

...

## Quickstart (llama.cpp-only)

1) Start llama.cpp server (adjust paths):
   ./server -m /models/phi-3-mini.q4_K_M.gguf -t $(nproc) -c 1024 -b 256 --port 11434
   Optional systemd unit: contrib/llamacpp-server.service

2) Install ScanTrace agent non-interactively:
   make install-service-noninteractive \
     LLM_BASE_URL=http://127.0.0.1:11434 \
     LLM_MODEL=phi-3-mini.q4_K_M.gguf

3) Verify:
   systemctl --no-pager status scantrace-agent

Notes: use q4_K_M (or q5_K_M) for speed vs. quality; warm up with a short request.
