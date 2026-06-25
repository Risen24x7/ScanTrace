# Getting Started with ScanTrace – Dead Reckoning Edition

This guide walks through the quickest way to run the demo paths for the hackathon baseline.

## Prerequisites

- Go toolchain installed (Go 1.21+ recommended).
- Git.
- SQLite (for inspecting the DB directly, optional).
- For the live network demo:
  - A router or firewall capable of sending syslog to your ScanTrace host (e.g., Asus router with remote log server enabled).[web:179]
  - A Linux host (or VM) to run ScanTrace and rsyslog.

## 1. Clone the repository

```bash
git clone https://github.com/Risen24x7/ScanTrace.git
cd ScanTrace
```

## 2. Testdata demo (Suricata EVE JSON)

This path shows the full pipeline using bundled EVE JSON testdata.

1. Ingest events from testdata:

   ```bash
   CGO_ENABLED=1 go run ./cmd/bot/ ingest \
     --file ./testdata/suricata-eve.json \
     --adapter suricata
   ```

2. Correlate events into patterns/campaigns:

   ```bash
   CGO_ENABLED=1 go run ./cmd/bot/ correlate
   ```

3. List cases:

   ```bash
   CGO_ENABLED=1 go run ./cmd/bot/ cases
   ```

4. Render a case report (replace `<CASE_ID>` with an ID from the previous command):

   ```bash
   CGO_ENABLED=1 go run ./cmd/bot/ report --case <CASE_ID>
   ```

You should see a Markdown-like incident summary similar to the sample "Scan activity from 198.51.100.10" case.

## 3. Live home-router syslog demo (Asus example)

### 3.1 Configure the router

On an Asus router running stock AsusWRT:[web:179]

- Log into the web GUI.
- Navigate to **System Log → General Log**.
- Enable **Remote log server**.
- Set **Remote log server** to the IP address of your ScanTrace host.
- Set **Port** to `514`.
- Apply the changes.

The router will start sending syslog messages (e.g., `dnsmasq-dhcp`, `hostapd`) to your host on UDP 514.[web:179]

### 3.2 Configure rsyslog on the ScanTrace host

1. Enable UDP syslog reception:

   Edit `/etc/rsyslog.conf` and ensure these lines are present (uncommented):[web:190]

   ```conf
   $ModLoad imudp
   $UDPServerRun 514
   ```

2. Add a rule to store Asus logs in a dedicated file, adjusting the IP to match your router (example `192.168.50.1`):[web:190]

   ```bash
   sudo sh -c 'cat > /etc/rsyslog.d/asus-router.conf <<EOF
   if $fromhost-ip == "192.168.50.1" then /var/log/asus-router.log
   & stop
   EOF'
   ```

3. Restart rsyslog:

   ```bash
   sudo systemctl restart rsyslog
   ```

4. Verify logs are arriving:

   ```bash
   sudo tail -n 20 /var/log/asus-router.log
   ```

   You should see lines containing `dnsmasq-dhcp` and `hostapd` from the router.

### 3.3 Ingest live Asus syslog into ScanTrace

With logs flowing into `/var/log/asus-router.log`, run:

```bash
CGO_ENABLED=1 sudo tail -F /var/log/asus-router.log \
  | go run ./cmd/bot/ ingest --file - --adapter asus-syslog
```

In another terminal, run:

```bash
CGO_ENABLED=1 go run ./cmd/bot/ correlate
CGO_ENABLED=1 go run ./cmd/bot/ cases
```

You should see new events and cases reflecting activity from your home network. The exact adapter name and options may evolve; see `Docs/HACKATHON_GOALS.md` and `Docs/scantrace_build_order.md` for the latest build/adapter details.[cite:254][cite:255]

## 4. Where things live

- `cmd/bot/` – CLI entrypoint; implements commands like `ingest`, `correlate`, `cases`, and `report`.
- `internal/collector/` – Collector and adapters for different log formats (Suricata, syslog, etc.).[cite:209]
- `internal/enricher/` – Infrastructure enrichment logic (ASN, reverse DNS, basic metadata).[file:196]
- `internal/correlator/` – Grouping of repeated scan-related events into higher-level patterns/campaigns.[file:196]
- `Docs/` – Project brief, architecture overview, build order, hackathon goals, and other documentation.[file:196][cite:254][cite:255]

## 5. Next steps

- Review `Docs/HACKATHON_GOALS.md` for the hackathon baseline and stretch goals.
- Check `CHANGELOG.md` for recent changes.
- See `Docs/scantrace_build_order.md` for a more detailed build/implementation roadmap.
