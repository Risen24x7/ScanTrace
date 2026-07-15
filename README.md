# ScanTrace – Dead Reckoning Edition

[![Latest tag](https://img.shields.io/github/v/tag/Risen24x7/ScanTrace?include_prereleases&sort=semver)](https://github.com/Risen24x7/ScanTrace/tags)

...

This is ScanTrace, a project a created for the Slack Hackathon challenge 2026, Agent for Good entry. 

Please forgive the messiness as I decided to try and learn Go on the fly and then try and use GitHub for more than just a place to store random things. This is a solo sprint where I had to come up with the idea after I decided to enter. So the documentation was quite shotty and the code was functional but rough. Since I don't know any Go coders I had to resort to Google and AI to try and get my documentation and pretty up the code. The installation sequence is a work in progress while I implement new ideas and stumble upon my own goofs.

I hop you like the idea and are interested in taking an upfront approach when it come to the security of your network.

...

# What it does

Every internet-facing system is continuously scanned by automated tooling—botnets, vulnerability scanners, nation-state reconnaissance platforms, and internet mapping services such as Shodan and Censys.

Security teams typically face two poor choices:


• Ignore the noise and risk missing meaningful reconnaissance activity.

• Drown in raw telemetry by exporting logs into SIEMs, writing detection rules, and maintaining dashboards outside their normal workflow.


Neither approach creates evidence-quality investigations that can be escalated, shared, or reported.

ScanTrace bridges the gap between raw scan telemetry and actionable threat intelligence by transforming scanning activity into evidence-backed investigations directly inside Slack. Instead of reviewing thousands of disconnected log entries, analysts receive aggregated events, enriched context, and case-ready evidence within the platform where they already collaborate.

If attackers can aggregate millions of internet-connected devices to gather intelligence, why can't we aggregate their activity to detect, track, and close the gaps they rely on?

...

## Quickstart (llama.cpp-only) (WIP)

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
