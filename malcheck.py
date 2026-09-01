#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# -----------------------------
# Optional plotting dependency
# -----------------------------
def _try_import_matplotlib() -> bool:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt  # noqa: F401
        return True
    except Exception:
        return False

HAS_MPL = _try_import_matplotlib()

# -----------------------------
# Utilities
# -----------------------------
def which(cmd: str) -> bool:
    return shutil.which(cmd) is not None

def _run_command(args: List[str], timeout: Optional[int] = None, env: Optional[dict] = None) -> Tuple[int, str, str]:
    try:
        p = subprocess.run(args, capture_output=True, text=True, check=False, timeout=timeout, env=env)
        return p.returncode, p.stdout or "", p.stderr or ""
    except FileNotFoundError as e:
        return 127, "", str(e)
    except Exception as e:
        return 1, "", str(e)

def _safe_env(tmp_home: Path) -> dict:
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(tmp_home),
        "LC_ALL": "C",
        "LANG": "C",
    }

def _bytes(n_mb: Optional[int]) -> Optional[int]:
    return None if n_mb is None else int(n_mb) * 1024 * 1024

# -----------------------------
# File info & hashes
# -----------------------------
def compute_hashes(fp: Path) -> dict:
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(fp, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            md5.update(chunk); sha1.update(chunk); sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}

def identify_file(fp: Path) -> dict:
    info = {"mime": None, "description": None, "size_bytes": fp.stat().st_size}
    try:
        if which("file"):
            rc1, mime_out, _ = _run_command(["file", "-b", "--mime-type", str(fp)])
            rc2, desc_out, _ = _run_command(["file", "-b", str(fp)])
            info["mime"] = (mime_out or "").strip() or None
            info["description"] = (desc_out or "").strip() or None
        else:
            import mimetypes
            info["mime"] = mimetypes.guess_type(str(fp))[0]
            info["description"] = "Unknown (install `file` for better detection)"
    except Exception as e:
        info["description"] = f"Error detecting type: {e}"
    return info

def file_permissions(fp: Path) -> dict:
    st = fp.stat()
    return {
        "mode_octal": oct(st.st_mode & 0o7777),
        "is_setuid": bool(st.st_mode & stat.S_ISUID),
        "is_setgid": bool(st.st_mode & stat.S_ISGID),
        "world_writable": bool(st.st_mode & stat.S_IWOTH),
        "owner_uid": st.st_uid,
        "owner_gid": st.st_gid,
    }

# -----------------------------
# Optional AV/YARA
# -----------------------------
def clamscan(fp: Path) -> Optional[dict]:
    if not which("clamscan"):
        return None
    try:
        rc, out, err = _run_command(["clamscan", "--no-summary", str(fp)])
        text = (out + ("\n" + err if err else "")).strip()
        return {"tool": "ClamAV", "returncode": rc, "infected": "FOUND" in text, "raw_output": text}
    except Exception as e:
        return {"tool": "ClamAV", "error": str(e)}

def yara_scan(fp: Path, rules_dir: Optional[Path]) -> Optional[dict]:
    if rules_dir is None or not rules_dir.exists() or not which("yara"):
        return None
    try:
        rc, out, err = _run_command(["yara", "-r", str(rules_dir), str(fp)])
        hits = []
        for line in (out or "").splitlines():
            parts = line.strip().split(None, 1)
            if parts:
                hits.append(parts[0])
        return {"tool": "YARA", "returncode": rc, "matches": hits, "raw_output": (out or "").strip(), "stderr": (err or "").strip()}
    except Exception as e:
        return {"tool": "YARA", "error": str(e)}

# -----------------------------
# Strings & URLs
# -----------------------------
SUSPICIOUS_TOKENS = [
    "http://", "https://",
    "/bin/sh", "/bin/bash", "cmd.exe", "powershell",
    "wget ", "curl ", "nc ", "netcat", "ftp ", "tftp ",
    "ssh ", "scp ",
    "Base64", "base64",
    "LD_PRELOAD", "ptrace", "strace",
    "X-Api-Key", "Authorization:", "Bearer "
]

URL_REGEX = re.compile(r'(?i)\b(?:https?|ftp)://[^\s"\'<>]+')

def extract_strings(fp: Path, min_len: int = 6, max_bytes: int = 10_000_000) -> List[str]:
    strings: List[str] = []
    try:
        with open(fp, "rb") as f:
            data = f.read(max_bytes)
        buf = bytearray()
        for b in data:
            if 32 <= b <= 126:
                buf.append(b)
            else:
                if len(buf) >= min_len:
                    strings.append(buf.decode(errors="ignore"))
                buf.clear()
        if len(buf) >= min_len:
            strings.append(buf.decode(errors="ignore"))
    except Exception:
        pass
    return strings

def scan_strings(strings: List[str]) -> List[str]:
    hits: List[str] = []
    lower = "\n".join(strings).lower()
    for token in SUSPICIOUS_TOKENS:
        if token.lower() in lower:
            hits.append(token)
    return sorted(set(hits))

def extract_urls(strings: List[str]) -> List[str]:
    text = "\n".join(strings)
    urls = set(URL_REGEX.findall(text))
    return sorted(urls)

# -----------------------------
# ELF inspection (no deps)
# -----------------------------
def elf_inspect(fp: Path, desc: str) -> Optional[dict]:
    if "ELF" not in (desc or ""):
        return None
    if not which("readelf"):
        return {"error": "readelf not installed"}
    info = {
        "type": None, "interpreter": None, "pie": None,
        "nx_enabled": None, "relro": None,
        "rpath": None, "runpath": None,
        "needed": [], "static": None,
        "packer_hint": None,
        "raw": {}
    }
    # headers/sections/program/dynamic/notes (wide)
    for key, args in {
        "h": ["-hW"], "S": ["-SW"], "l": ["-lW"], "d": ["-dW"], "n": ["-nW"]
    }.items():
        rc, out, err = _run_command(["readelf"] + args + [str(fp)])
        info["raw"][key] = out

    hdr = info["raw"]["h"]; ph = info["raw"]["l"]; dyn = info["raw"]["d"]; sec = info["raw"]["S"]

    # Type / PIE heuristic: DYN+interpreter => PIE executable
    m = re.search(r"Type:\s+(\w+)", hdr)
    if m:
        info["type"] = m.group(1)
    m = re.search(r"Requesting program interpreter:\s+([^\s]+)", ph)
    if m:
        info["interpreter"] = m.group(1)
    info["pie"] = True if (info["type"] == "DYN" and info["interpreter"]) else False

    # NX: GNU_STACK not executable => NX enabled
    info["nx_enabled"] = None
    if "GNU_STACK" in ph:
        info["nx_enabled"] = (" RWE " not in ph and " R E " not in ph)  # crude but effective

    # RELRO presence
    info["relro"] = "GNU_RELRO" in ph

    # RPATH / RUNPATH / NEEDED
    info["rpath"] = _find_dyn_val(dyn, r"Library rpath:\s*\[(.*?)\]")
    info["runpath"] = _find_dyn_val(dyn, r"Library runpath:\s*\[(.*?)\]")
    info["needed"] = re.findall(r"Shared library:\s*\[(.+?)\]", dyn)

    # Static: no NEEDED and/or desc mentions statically linked
    info["static"] = (("statically linked" in (desc or "").lower()) or (len(info["needed"]) == 0))

    # Packer hints (UPX)
    upx_in_sections = bool(re.search(r"\.upx\d?", sec, flags=re.I))
    upx_magic_in_strings = False
    try:
        with open(fp, "rb") as f:
            head = f.read(4096)
        upx_magic_in_strings = b"UPX!" in head
    except Exception:
        pass
    if upx_in_sections or upx_magic_in_strings:
        info["packer_hint"] = "UPX"
    return info

def _find_dyn_val(dyn_text: str, pattern: str) -> Optional[str]:
    m = re.search(pattern, dyn_text)
    return m.group(1) if m else None

# -----------------------------
# Sandbox & strace
# -----------------------------
TRACE_MAP = {
    "network": "network",
    "fs": "file",
    "process": "process",
    "all": "all",
}

def build_sandbox_prefix(tmp_home: Path, mode: str, allow_network: bool) -> Tuple[List[str], str]:
    if mode in ("auto", "firejail") and which("firejail"):
        args = [
            "firejail", "--quiet", "--allow-debuggers",
            f"--private={tmp_home}",
            "--caps.drop=all",
            "--nonewprivs",
            "--rlimit-nofile=256",
            "--shell=none",
        ]
        if allow_network:
            args += ["--protocol=inet,inet6"]
        else:
            args += ["--net=none"]
        return args, "Firejail"
    if mode in ("auto", "bwrap") and which("bwrap"):
        # Minimal bwrap FS sandbox; cannot drop network unprivileged.
        args = [
            "bwrap", "--die-with-parent", "--unshare-all", "--new-session",
            "--ro-bind", "/", "/",
            "--dev", "/dev",
            "--proc", "/proc",
            "--dir", "/home/sandbox",
            "--chdir", "/home/sandbox",
            "--setenv", "HOME", "/home/sandbox",
        ]
        return args, "Bubblewrap"
    return [], "None"

def _make_preexec(rlim_cfg: dict):
    def _preexec():
        try:
            os.setsid()  # new process group
            import resource
            if rlim_cfg.get("cpu") is not None:
                resource.setrlimit(resource.RLIMIT_CPU, (rlim_cfg["cpu"], rlim_cfg["cpu"]))
            if rlim_cfg.get("mem") is not None:
                resource.setrlimit(resource.RLIMIT_AS, (rlim_cfg["mem"], rlim_cfg["mem"]))
            if rlim_cfg.get("nproc") is not None:
                resource.setrlimit(resource.RLIMIT_NPROC, (rlim_cfg["nproc"], rlim_cfg["nproc"]))
            if rlim_cfg.get("nofile") is not None:
                resource.setrlimit(resource.RLIMIT_NOFILE, (rlim_cfg["nofile"], rlim_cfg["nofile"]))
            # No core dumps
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        except Exception:
            pass
    return _preexec

def _kill_process_group(p: subprocess.Popen, grace: float = 1.5) -> None:
    try:
        pgid = os.getpgid(p.pid)
    except Exception:
        pgid = None
    try:
        if pgid is not None:
            os.killpg(pgid, signal.SIGTERM)
        else:
            p.terminate()
    except Exception:
        pass
    deadline = time.time() + grace
    while time.time() < deadline:
        if p.poll() is not None:
            return
        time.sleep(0.05)
    try:
        if pgid is not None:
            os.killpg(pgid, signal.SIGKILL)
        else:
            p.kill()
    except Exception:
        pass

def run_with_strace(
    binary: Path,
    argv: List[str],
    timeout_s: int,
    workdir: Path,
    sandbox_mode: str,
    allow_network: bool,
    trace_scope: str,
    rlim_cfg: dict,
) -> dict:
    tmp_home = workdir / "sandbox_home"
    tmp_home.mkdir(parents=True, exist_ok=True)
    log_path = workdir / "strace.log"

    trace_expr = TRACE_MAP.get(trace_scope, "network")
    strace_cmd = ["strace", "-f", "-tt", "-yy", "-s", "256", "-e", f"trace={trace_expr}", "-o", str(log_path)]

    sandbox_prefix, sandbox_name = build_sandbox_prefix(tmp_home, sandbox_mode, allow_network)
    cmd = sandbox_prefix + strace_cmd + [str(binary)] + argv
    env = _safe_env(tmp_home)

    start = time.time()
    try:
        p = subprocess.Popen(
            cmd, cwd=str(workdir), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            preexec_fn=_make_preexec(rlim_cfg)
        )
        try:
            stdout, stderr = p.communicate(timeout=timeout_s)
            duration = time.time() - start
            return {
                "used_sandbox": sandbox_name,
                "cmd": cmd,
                "returncode": p.returncode,
                "stdout": stdout,
                "stderr": stderr,
                "duration_s": duration,
                "strace_log": str(log_path),
                "trace_scope": trace_scope,
                "network_policy": ("deny" if (sandbox_name == "Firejail" and not allow_network) else "allow"),
            }
        except subprocess.TimeoutExpired:
            _kill_process_group(p)
            duration = time.time() - start
            return {
                "used_sandbox": sandbox_name,
                "cmd": cmd,
                "error": f"timeout after {timeout_s}s",
                "duration_s": duration,
                "strace_log": str(log_path),
                "trace_scope": trace_scope,
                "network_policy": ("deny" if (sandbox_name == "Firejail" and not allow_network) else "allow"),
            }
    except FileNotFoundError as e:
        return {"error": f"missing dependency: {e}"}

# -----------------------------
# strace parsing
# -----------------------------
GAI_REGEX = re.compile(r'getaddrinfo\("([^"]+)"')
V4_CONNECT_REGEX = re.compile(
    r'connect\([^,]+,\s*\{sa_family=AF_INET[^}]*sin_port=htons\((\d+)\)[^}]*sin_addr=inet_addr\("([0-9]{1,3}(?:\.[0-9]{1,3}){3})"\)'
)
V6_CONNECT_REGEX = re.compile(
    r'connect\([^,]+,\s*\{sa_family=AF_INET6[^}]*sin6_port=htons\((\d+)\)[^}]*inet_pton\(AF_INET6,\s*"([0-9a-fA-F:]+)"\)'
)
V4_SENDTO_REGEX = re.compile(
    r'sendto\([^,]+,.*\{sa_family=AF_INET[^}]*sin_port=htons\((\d+)\)[^}]*sin_addr=inet_addr\("([0-9]{1,3}(?:\.[0-9]{1,3}){3})"\)'
)
V6_SENDTO_REGEX = re.compile(
    r'sendto\([^,]+,.*\{sa_family=AF_INET6[^}]*sin6_port=htons\((\d+)\)[^}]*inet_pton\(AF_INET6,\s*"([0-9a-fA-F:]+)"\)'
)
EXECVE_REGEX = re.compile(r'execve\("([^"]+)"')
OPEN_WRITE_REGEX = re.compile(r'(openat|open)\([^,]+,\s*"([^"]+)"[^)]*O_.*(WRONLY|RDWR)')
UNLINK_REGEX = re.compile(r'(unlinkat|unlink)\([^,]+,\s*"([^"]+)"')
RENAME_REGEX = re.compile(r'rename(at)?\([^"]*"([^"]+)"[^"]*"([^"]+)"')

def parse_strace(log_path: Path, trace_scope: str) -> dict:
    net_domains: Dict[str, int] = {}
    net_ip_ports: Dict[str, int] = {}
    files_written: Dict[str, int] = {}
    files_deleted: Dict[str, int] = {}
    renames: List[Tuple[str, str]] = []
    execs: Dict[str, int] = {}
    total_lines = 0

    try:
        with open(log_path, "r", errors="ignore") as f:
            for line in f:
                total_lines += 1

                # Network: domains
                for m in GAI_REGEX.finditer(line):
                    d = m.group(1).strip().rstrip(".")
                    if d:
                        net_domains[d] = net_domains.get(d, 0) + 1

                # Network: connect() + sendto()
                for regex in (V4_CONNECT_REGEX, V6_CONNECT_REGEX, V4_SENDTO_REGEX, V6_SENDTO_REGEX):
                    for m in regex.finditer(line):
                        port, ip = m.group(1), m.group(2)
                        key = f"{ip}:{port}"
                        net_ip_ports[key] = net_ip_ports.get(key, 0) + 1

                # Filesystem writes
                if trace_scope in ("fs", "all"):
                    m = OPEN_WRITE_REGEX.search(line)
                    if m:
                        path = m.group(2)
                        files_written[path] = files_written.get(path, 0) + 1
                    m = UNLINK_REGEX.search(line)
                    if m:
                        path = m.group(2)
                        files_deleted[path] = files_deleted.get(path, 0) + 1
                    m = RENAME_REGEX.search(line)
                    if m:
                        old, new = m.group(2), m.group(3)
                        renames.append((old, new))

                # Process exec
                if trace_scope in ("process", "all"):
                    m = EXECVE_REGEX.search(line)
                    if m:
                        pth = m.group(1)
                        execs[pth] = execs.get(pth, 0) + 1
    except FileNotFoundError:
        pass

    # IP classification buckets
    ip_classes = {"public": 0, "private": 0, "loopback": 0, "link_local": 0, "multicast": 0, "reserved": 0}
    for key in net_ip_ports:
        ip = key.split(":", 1)[0]
        try:
            ipobj = ipaddress.ip_address(ip)
            if ipobj.is_private: ip_classes["private"] += 1
            elif ipobj.is_loopback: ip_classes["loopback"] += 1
            elif ipobj.is_link_local: ip_classes["link_local"] += 1
            elif ipobj.is_multicast: ip_classes["multicast"] += 1
            elif ipobj.is_reserved: ip_classes["reserved"] += 1
            else: ip_classes["public"] += 1
        except Exception:
            pass

    return {
        "domains": net_domains,
        "ip_ports": net_ip_ports,
        "ip_class_counts": ip_classes,
        "files_written": files_written,
        "files_deleted": files_deleted,
        "renames": renames,
        "execve": execs,
        "log_lines": total_lines
    }

# -----------------------------
# Indicators & plotting
# -----------------------------
def load_indicators(path: Optional[Path]) -> dict:
    if not path or not path.exists():
        return {"domains": [], "ips": []}
    try:
        with open(path, "r") as f:
            data = json.load(f)
        return {"domains": data.get("domains", []), "ips": data.get("ips", [])}
    except Exception:
        return {"domains": [], "ips": []}

def match_indicators(network_summary: dict, indicators: dict, urls: List[str]) -> dict:
    flagged = {"domains": [], "ips": [], "url_domains": []}
    net_domains = set(network_summary.get("domains", {}).keys())
    ioc_domains = set(indicators.get("domains", []))
    url_domains = set()
    for u in urls:
        try:
            host = re.split(r"/", re.sub(r"^[a-z]+://", "", u), 1)[0]
            url_domains.add(host.lower().rstrip("."))
        except Exception:
            pass
    flagged["domains"] = sorted(net_domains.intersection(ioc_domains))
    # URLs present in strings
    flagged["url_domains"] = sorted(url_domains.intersection(ioc_domains))
    for ip_port in network_summary.get("ip_ports", {}):
        ip = ip_port.split(":", 1)[0]
        if ip in indicators.get("ips", []):
            flagged["ips"].append(ip)
    flagged["ips"] = sorted(set(flagged["ips"]))
    return flagged

def make_plot(network_summary: dict, out_png: Path) -> bool:
    if not HAS_MPL:
        return False
    import matplotlib.pyplot as plt
    counts: Dict[str, int] = {}
    for d, c in network_summary.get("domains", {}).items():
        counts[d] = counts.get(d, 0) + c
    for ip_port, c in network_summary.get("ip_ports", {}).items():
        counts[ip_port] = counts.get(ip_port, 0) + c
    items = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:10]
    if not items:
        return False
    labels = [k for k, _ in items]
    values = [v for _, v in items]
    plt.figure(figsize=(10, 4))
    plt.bar(range(len(values)), values)
    plt.xticks(range(len(values)), labels, rotation=45, ha="right")
    plt.ylabel("Connections (calls)")
    plt.title("Outbound connection attempts (top 10)")
    plt.tight_layout()
    plt.savefig(out_png, dpi=150)
    return True

# -----------------------------
# Allowlist & weights
# -----------------------------
def load_allowlist(path: Optional[Path]) -> set:
    if not path or not Path(path).exists():
        return set()
    vals = set()
    for line in Path(path).read_text().splitlines():
        line = line.strip().lower()
        if line and re.fullmatch(r"[0-9a-f]{64}", line):
            vals.add(line)
    return vals

DEFAULT_WEIGHTS = {
    "clamav_infected": 80,
    "yara_base": 10,
    "yara_per_match": 5,
    "indicator_hit": 40,
    "many_dests": 10,
    "strings_token": 5,
    "nx_disabled": 25,
    "rpath_or_runpath": 10,
    "setuid": 40,
    "world_writable": 15,
    "packed_upx": 15,
    "public_ip_nonstd_port": 10,
}

def load_weights(path: Optional[Path]) -> dict:
    w = dict(DEFAULT_WEIGHTS)
    if not path:
        return w
    try:
        data = json.loads(Path(path).read_text())
        for k, v in data.items():
            if k in w and isinstance(v, int):
                w[k] = v
    except Exception:
        pass
    return w

# -----------------------------
# Risk scoring (explainable)
# -----------------------------
def compute_risk_score(
    weights: dict,
    scans: dict,
    net: dict,
    indicators: dict,
    string_hits: List[str],
    elf: Optional[dict],
    perms: dict,
) -> Tuple[int, List[dict]]:
    reasons: List[dict] = []
    score = 0

    def add(points: int, reason: str):
        nonlocal score
        if points <= 0:
            return
        score += points
        reasons.append({"points": points, "reason": reason})

    # AV / YARA
    clam = scans.get("clamav")
    if isinstance(clam, dict) and clam.get("infected"):
        add(weights["clamav_infected"], "ClamAV signature matched (INFECTED)")
    yara = scans.get("yara")
    if isinstance(yara, dict) and yara.get("matches"):
        add(weights["yara_base"] + weights["yara_per_match"] * len(yara["matches"]), f"YARA matched {len(yara['matches'])} rule(s)")

    # Indicators
    if indicators.get("domains") or indicators.get("ips") or indicators.get("url_domains"):
        add(weights["indicator_hit"], "Indicator (domain/IP/URL) matched")

    # Network volume heuristic
    num_dests = len(net.get("domains", {})) + len(net.get("ip_ports", {}))
    if num_dests >= 5:
        add(weights["many_dests"], f"Multiple destinations observed ({num_dests})")

    # Strings tokens
    add(min(30, weights["strings_token"] * len(string_hits)), f"Suspicious tokens in strings ({len(string_hits)})")

    # ELF hardening & packers
    if elf and not elf.get("error"):
        if elf.get("nx_enabled") is False:
            add(weights["nx_disabled"], "NX disabled (executable stack detected)")
        if elf.get("rpath") or elf.get("runpath"):
            add(weights["rpath_or_runpath"], "RPATH/RUNPATH present (potential library hijack vector)")
        if elf.get("packer_hint") == "UPX":
            add(weights["packed_upx"], "Packer hint: UPX")

    # File perms
    if perms.get("is_setuid"):
        add(weights["setuid"], "Setuid bit set")
    if perms.get("world_writable"):
        add(weights["world_writable"], "World-writable binary")

    # Ports heuristic: public IP on non-standard port
    std_ports = {"80", "443", "53", "123"}
    for key in net.get("ip_ports", {}):
        port = key.split(":", 1)[1]
        ip = key.split(":", 1)[0]
        try:
            if ipaddress.ip_address(ip).is_global and port not in std_ports:
                add(weights["public_ip_nonstd_port"], f"Public IP on non-standard port {port}")
                break
        except Exception:
            pass

    return min(score, 100), reasons

# -----------------------------
# Reporting
# -----------------------------
def write_report(
    out_dir: Path,
    meta: dict,
    file_info: dict,
    hashes: dict,
    perms: dict,
    scans: dict,
    strings_hits: List[str],
    urls: List[str],
    sandbox_run: dict,
    net: dict,
    elf: Optional[dict],
    indicators: dict,
    risk_score: int,
    breakdown: List[dict],
    chart_path: Optional[Path],
):
    out_dir.mkdir(parents=True, exist_ok=True)
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    md: List[str] = []
    md.append("# Binary Safety Check Report")
    md.append("")
    md.append(f"- **Generated:** {now}")
    md.append(f"- **Target:** `{meta['target']}`")
    md.append(f"- **Arguments:** `{meta['args']}`")
    md.append(f"- **Version:** malcheck.py v2")
    md.append("")
    md.append("## Summary")
    md.append(f"- **Risk score (0–100):** **{risk_score}** *(heuristic; lower is better)*")
    if breakdown:
        md.append("- **Score breakdown:**")
        for item in breakdown:
            md.append(f"  - +{item['points']}: {item['reason']}")
    if scans.get("clamav") is not None:
        md.append(f"- **ClamAV:** {'INFECTED' if scans['clamav'].get('infected') else 'No signature match'}")
    if scans.get("yara") is not None:
        yhits = len(scans["yara"].get("matches", []))
        md.append(f"- **YARA:** {yhits} rule(s) matched")
    md.append(f"- **Network endpoints observed:** {len(net.get('domains', {})) + len(net.get('ip_ports', {}))}")
    if indicators.get("domains") or indicators.get("ips") or indicators.get("url_domains"):
        md.append(f"- **Indicator matches:** domains={indicators.get('domains')}, url_domains={indicators.get('url_domains')}, ips={indicators.get('ips')}")
    else:
        md.append(f"- **Indicator matches:** none")

    md.append("")
    md.append("## File details")
    md.append(f"- Size: {file_info.get('size_bytes')} bytes")
    md.append(f"- Type: {file_info.get('description')} (MIME: {file_info.get('mime')})")
    md.append(f"- Mode: {perms.get('mode_octal')} | setuid={perms.get('is_setuid')} | world_writable={perms.get('world_writable')}")
    md.append("")
    md.append("### Hashes")
    for k, v in hashes.items():
        md.append(f"- {k.upper()}: `{v}`")

    if elf:
        md.append("")
        md.append("## ELF hardening")
        if elf.get("error"):
            md.append(f"- Error: {elf['error']}")
        else:
            md.append(f"- Type: {elf.get('type')} | PIE: {elf.get('pie')} | Interpreter: {elf.get('interpreter')}")
            md.append(f"- NX enabled: {elf.get('nx_enabled')} | RELRO present: {elf.get('relro')}")
            md.append(f"- RPATH: {elf.get('rpath') or '-'} | RUNPATH: {elf.get('runpath') or '-'}")
            md.append(f"- NEEDED libraries: {', '.join(elf.get('needed', [])) or '-'}")
            md.append(f"- Statically linked: {elf.get('static')} | Packer hint: {elf.get('packer_hint') or '-'}")

    md.append("")
    md.append("## Static heuristics (strings)")
    if strings_hits:
        md.append(f"- Suspicious tokens: {', '.join(strings_hits)}")
    else:
        md.append("- No suspicious tokens observed in simple string scan.")
    if urls:
        md.append(f"- URLs found ({len(urls)}):")
        for u in urls[:25]:
            md.append(f"  - {u}")
        if len(urls) > 25:
            md.append(f"  - ... and {len(urls)-25} more")

    md.append("")
    md.append("## Execution (strace)")
    if sandbox_run:
        if sandbox_run.get("error"):
            md.append(f"- Error: {sandbox_run['error']}")
        else:
            md.append(f"- Return code: {sandbox_run.get('returncode')}")
            md.append(f"- Duration: {sandbox_run.get('duration_s'):.2f} s")
        md.append(f"- Sandbox: {sandbox_run.get('used_sandbox')}")
        md.append(f"- Network policy: {sandbox_run.get('network_policy', 'allow')}")
        md.append(f"- Trace scope: {sandbox_run.get('trace_scope', 'network')}")
        if sandbox_run.get("strace_log"):
            md.append(f"- strace log: `{sandbox_run.get('strace_log')}`")
    else:
        md.append("- Not executed (`--static-only` was used).")

    md.append("")
    md.append("## Network findings")
    if chart_path and chart_path.exists():
        md.append(f"![Network destinations chart]({chart_path.name})")
    if net.get("domains"):
        md.append("### Domains")
        for d, c in sorted(net["domains"].items(), key=lambda kv: kv[1], reverse=True):
            md.append(f"- {d} — {c}")
    if net.get("ip_ports"):
        md.append("### IP:Port")
        for k, c in sorted(net["ip_ports"].items(), key=lambda kv: kv[1], reverse=True):
            md.append(f"- {k} — {c}")
    if net.get("ip_class_counts"):
        md.append(f"- IP classes: {net['ip_class_counts']}")

    if (net.get("files_written") or net.get("files_deleted") or net.get("renames") or net.get("execve")):
        md.append("")
        md.append("## Filesystem & process activity")
        if net.get("files_written"):
            md.append("### Writes")
            for pth, cnt in sorted(net["files_written"].items(), key=lambda kv: kv[1], reverse=True)[:20]:
                md.append(f"- {pth} — {cnt}")
        if net.get("files_deleted"):
            md.append("### Deletes")
            for pth, cnt in sorted(net["files_deleted"].items(), key=lambda kv: kv[1], reverse=True)[:20]:
                md.append(f"- {pth} — {cnt}")
        if net.get("renames"):
            md.append("### Renames")
            for old, new in net["renames"][:20]:
                md.append(f"- {old} -> {new}")
        if net.get("execve"):
            md.append("### Execve")
            for pth, cnt in sorted(net["execve"].items(), key=lambda kv: kv[1], reverse=True)[:20]:
                md.append(f"- {pth} — {cnt}")

    md.append("")
    md.append("## Notes & limitations")
    md.append("- This tool reduces risk but cannot guarantee the absence of malware.")
    md.append("- Default tracing is **network**; use `--trace fs|process|all` for deeper visibility.")
    md.append("- Prefer running unknown binaries inside a dedicated VM in addition to this sandbox.")

    (out_dir / "report.md").write_text("\n".join(md))

    # JSON payload
    payload = {
        "schema_version": "2.0",
        "generated_utc": now,
        "target": meta["target"],
        "args": meta["args"],
        "hashes": hashes,
        "permissions": perms,
        "file_info": file_info,
        "clamav": scans.get("clamav"),
        "yara": scans.get("yara"),
        "strings_hits": strings_hits,
        "urls": urls,
        "sandbox_run": sandbox_run,
        "trace": net,
        "elf": elf,
        "indicator_matches": indicators,
        "risk_score": risk_score,
        "risk_breakdown": breakdown,
    }
    with open(out_dir / "report.json", "w") as f:
        json.dump(payload, f, indent=2)

# -----------------------------
# CLI / Orchestration
# -----------------------------
def profile_defaults(profile: str, timeout_s: int) -> dict:
    # Conservative, and bounded by timeout
    if profile == "minimal":
        return {"cpu": min(timeout_s, 10), "mem": _bytes(256), "nproc": 64, "nofile": 256}
    if profile == "paranoid":
        return {"cpu": min(timeout_s, 15), "mem": _bytes(256), "nproc": 64, "nofile": 256}
    # standard
    return {"cpu": min(timeout_s + 2, max(timeout_s, 20)), "mem": _bytes(512), "nproc": 128, "nofile": 256}

def main():
    parser = argparse.ArgumentParser(description="Run defensive checks on a binary (Linux).")
    parser.add_argument("binary", help="Path to the binary to check")
    parser.add_argument("--args", nargs=argparse.REMAINDER, default=[], help="Arguments to pass to the binary (after --)")
    parser.add_argument("--timeout", type=int, default=15, help="Seconds to allow the binary to run")
    parser.add_argument("--out", default="malcheck_out", help="Output directory for the report")
    parser.add_argument("--indicators", help="Path to indicators JSON with 'domains' and 'ips' arrays")
    parser.add_argument("--yara-rules", help="Directory containing YARA rules (optional)")
    parser.add_argument("--sandbox", choices=["auto", "firejail", "bwrap", "none"], default="auto", help="Sandbox engine")
    parser.add_argument("--deny-network", action="store_true", help="Deny outbound network (effective with Firejail)")
    parser.add_argument("--static-only", action="store_true", help="Skip execution (no strace)")
    parser.add_argument("--trace", choices=["network", "fs", "process", "all"], default="network", help="Syscall trace scope")
    parser.add_argument("--profile", choices=["minimal", "standard", "paranoid"], default="standard", help="Resource limits profile")
    parser.add_argument("--rlimit-cpu", type=int, default=None, help="Override CPU seconds limit")
    parser.add_argument("--rlimit-mem-mb", type=int, default=None, help="Override memory (MB) limit")
    parser.add_argument("--rlimit-nproc", type=int, default=None, help="Override process count limit")
    parser.add_argument("--no-plot", action="store_true", help="Disable chart generation even if matplotlib is available")
    parser.add_argument("--strings-min-len", type=int, default=6, help="Min ASCII string length")
    parser.add_argument("--strings-max-bytes", type=int, default=10_000_000, help="Max bytes to scan for strings")
    parser.add_argument("--allowlist-hashes", help="Path to newline-delimited SHA-256 allowlist")
    parser.add_argument("--weights", help="Path to JSON overriding risk weights")
    parser.add_argument("--fail-risk", type=int, default=None, help="Exit 1 if risk score >= N (e.g., 50)")
    args = parser.parse_args()

    target = Path(args.binary).resolve()
    if not target.exists() or not target.is_file():
        print(f"ERROR: file not found: {target}", file=sys.stderr)
        sys.exit(2)

    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    # File info & hashes & perms
    file_info = identify_file(target)
    hashes = compute_hashes(target)
    perms = file_permissions(target)

    # Allowlist short-circuit
    allow = load_allowlist(Path(args.allowlist_hashes) if args.allowlist_hashes else None)
    if hashes["sha256"].lower() in allow:
        # Write a minimal report and exit cleanly with risk 0
        meta = {"target": str(target), "args": " ".join(args.args)}
        write_report(out_dir, meta, file_info, hashes, perms, {"clamav": None, "yara": None},
                     strings_hits=[], urls=[], sandbox_run={}, net={}, elf=None,
                     indicators={"domains": [], "ips": [], "url_domains": []},
                     risk_score=0, breakdown=[{"points": 0, "reason": "Allowlisted SHA-256"}], chart_path=None)
        print(f"Allowlisted. Report written to: {out_dir / 'report.md'}")
        print(f"JSON: {out_dir / 'report.json'}")
        sys.exit(0)

    # Static scans
    scans = {"clamav": clamscan(target), "yara": yara_scan(target, Path(args.yara_rules) if args.yara_rules else None)}

    # Strings + URLs
    strings = extract_strings(target, min_len=args.strings_min_len, max_bytes=args.strings_max_bytes)
    string_hits = scan_strings(strings)
    urls = extract_urls(strings)

    # ELF inspection
    elf = elf_inspect(target, file_info.get("description") or "")

    # Execution + strace
    sandbox_run: dict = {}
    net_summary = {"domains": {}, "ip_ports": {}, "ip_class_counts": {}, "files_written": {}, "files_deleted": {}, "renames": [], "execve": {}, "log_lines": 0}
    allow_network = not args.deny_network
    if not args.static_only:
        if not which("strace"):
            print("ERROR: strace is required. Install it or use --static-only.", file=sys.stderr)
            sys.exit(3)

        # Resource limits
        rlim = profile_defaults(args.profile, args.timeout)
        if args.rlimit_cpu is not None: rlim["cpu"] = args.rlimit_cpu
        if args.rlimit_mem_mb is not None: rlim["mem"] = _bytes(args.rlimit_mem_mb)
        if args.rlimit_nproc is not None: rlim["nproc"] = args.rlimit_nproc

        sandbox_run = run_with_strace(
            target, args.args, args.timeout, out_dir,
            sandbox_mode=args.sandbox, allow_network=allow_network, trace_scope=args.trace,
            rlim_cfg=rlim
        )
        net_summary = parse_strace(Path(sandbox_run.get("strace_log", "")), args.trace)

        # Warn if bwrap used but --deny-network requested
        if args.deny_network and sandbox_run.get("used_sandbox") == "Bubblewrap":
            print("NOTE: --deny-network cannot be enforced by unprivileged Bubblewrap; network is observed, not blocked.", file=sys.stderr)

    # Indicators
    indicators_set = load_indicators(Path(args.indicators) if args.indicators else None)
    matches = match_indicators(net_summary, indicators_set, urls)

    # Chart
    chart_path: Optional[Path] = None
    if HAS_MPL and (not args.no_plot):
        chart_path = out_dir / "network_destinations.png"
        if not make_plot(net_summary, chart_path):
            chart_path = None

    # Risk score (+ breakdown)
    weights = load_weights(Path(args.weights) if args.weights else None)
    risk, breakdown = compute_risk_score(weights, scans, net_summary, matches, string_hits, elf, perms)

    meta = {"target": str(target), "args": " ".join(args.args)}
    write_report(out_dir, meta, file_info, hashes, perms, scans, string_hits, urls, sandbox_run, net_summary, elf, matches, risk, breakdown, chart_path)

    print(f"Report written to: {out_dir / 'report.md'}")
    if chart_path:
        print(f"Chart: {chart_path}")
    print(f"JSON: {out_dir / 'report.json'}")

    exit_due_to_scans = (isinstance(scans.get('clamav'), dict) and scans['clamav'].get('infected')) \
                        or bool(matches["domains"] or matches["ips"] or matches["url_domains"])
    exit_due_to_risk = args.fail_risk is not None and risk >= args.fail_risk
    if exit_due_to_scans or exit_due_to_risk:
        sys.exit(1)

if __name__ == "__main__":
    try:
        os.umask(0o077)  # private outputs by default
    except Exception:
        pass
    main()
