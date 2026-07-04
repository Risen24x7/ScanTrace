# ScanTrace — 90-second Quickstart (local)

This is a hackathon-scoped quickstart for running ScanTrace locally without Docker.

Prereqs
- Go 1.21+
- Linux host (Ubuntu/Debian recommended)
- make, gcc (for CGO/sqlite3)

Steps
1) Clone and build

    git clone https://github.com/Risen24x7/ScanTrace.git
    cd ScanTrace
    make build

2) Create .env

    cp scantrace-agent/.env.example scantrace-agent/.env
    # Edit tokens and channel IDs in scantrace-agent/.env

3) Grant port capability and run

    sudo setcap cap_net_bind_service=+ep ./bin/scantrace
    ./bin/scantrace

4) Next docs
- Docs/INDEX.md — master index
- INSTALL.md — full install and env details
- Docs/GETTING_STARTED.md — demos and run modes
- docs/router-logging-setup.md — router logging and syslog
- Docs/TROUBLESHOOTING.md — common fixes

Notes
- Default syslog ingest port: UDP 5140 (override via SCANTRACE_SYSLOG_PORT)
- No Dockerfile in this repo; use local Go + Makefile path
