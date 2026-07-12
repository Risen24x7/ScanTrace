# ScanTrace – Dead Reckoning Edition

[![Latest tag](https://img.shields.io/github/v/tag/Risen24x7/ScanTrace?include_prereleases&sort=semver)](https://github.com/Risen24x7/ScanTrace/tags)

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
