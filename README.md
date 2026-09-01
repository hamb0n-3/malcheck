# malcheck (defensive, Linux)

A minimal, **defensive** script to help you sanity-check a Linux binary before you publish it. It:
- Computes hashes & basic metadata
- Optionally runs ClamAV and YARA (if installed)
- Executes the binary inside a **sandbox** (Firejail if present) while tracing only **network** syscalls
- Extracts target domains/IPs/ports and compares against an optional local indicators list
- Produces a Markdown report, JSON, and a simple PNG chart of destinations

> No tool can **prove** the absence of malware. Treat this as one layer in your release process. Prefer running in a disposable VM in addition to this sandbox. Publish the SHA‑256 of your releases and consider code signing.

## Requirements

- Linux
- Python 3.9+
- `strace` (required)
- `firejail` (recommended; script falls back to no sandbox if missing)
- Optional: `clamscan` (ClamAV) and `yara`
- Optional Python dependency for chart: `matplotlib`

Install Python dependency for the chart:

```bash
python3 -m pip install -r requirements.txt
```

Install system tools (Debian/Ubuntu example):

```bash
sudo apt-get update
sudo apt-get install -y strace firejail clamav yara file
```

## Usage

Basic run (15s timeout, network tracing only):

```bash
python3 malcheck.py ./your_binary
```

Pass arguments to the target (use `--` then args):

```bash
python3 malcheck.py ./your_binary -- --help
```

Produce output to a custom folder and use indicators + YARA rules:

```bash
python3 malcheck.py ./your_binary --out out_dir \
 --indicators indicators.json \
 --yara-rules ./yara_rules
```

Skip the sandbox (not recommended):

```bash
python3 malcheck.py ./your_binary --no-sandbox
```

Exit codes:
- `0` — no detections found by ClamAV/indicators (still not a proof of safety)
- `1` — ClamAV hit or indicator match
- `2/3` — argument / dependency error

## Outputs

- `report.md` — human-readable report
- `report.json` — structured data
- `network_destinations.png` — bar chart (if matplotlib installed)
- `network_strace.log` — raw strace output (appendix)

## CI tip

If you want this to run in CI for each release artifact, consider a job that:
1. Runs `malcheck.py` on the built binary (inside a disposable runner/VM)
2. Uploads `report.md`, `report.json`, and `network_destinations.png` as build artifacts
3. Publishes the SHA‑256 in your release notes

## Indicators file format

`indicators.json`:

```json
{
 "domains": ["example.bad", "malicious.example"],
 "ips": ["203.0.113.10", "2001:db8::1234"]
}
```

## Limitations

- Linux-only (uses `strace` and optionally Firejail).
- Traces **only** network syscalls by design. It does not perform deep behavioral analysis.
- Not a substitute for professional malware analysis or code review.