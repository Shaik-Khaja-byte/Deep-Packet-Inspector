import os
import re
import subprocess
import time
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
ENGINE_EXE = ROOT_DIR / "dpi_engine.exe"


def run_engine(input_pcap, output_pcap, block_apps=None):
    block_apps = block_apps or []
    cmd = [str(ENGINE_EXE), str(input_pcap), str(output_pcap)]
    for app in block_apps:
        if app:
            cmd.extend(["--block-app", app])

    start = time.perf_counter()
    proc = subprocess.run(
        cmd,
        cwd=ROOT_DIR,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
    stdout = proc.stdout or ""
    stderr = proc.stderr or ""
    parsed = parse_engine_stdout(stdout, elapsed_ms)
    parsed["return_code"] = proc.returncode
    parsed["stderr"] = stderr
    parsed["command"] = " ".join(cmd)
    parsed["output_pcap"] = os.path.basename(output_pcap)
    return parsed


def parse_engine_stdout(stdout, elapsed_ms):
    stats = {
        "total_packets": 0,
        "forwarded": 0,
        "dropped": 0,
        "tcp_packets": 0,
        "udp_packets": 0,
        "processing_time_ms": elapsed_ms,
    }
    applications = []
    domains = []
    logs = []
    in_domains = False
    in_apps = False

    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        clean = _clean_box_line(line)
        if clean:
            logs.append(clean)

        if "[Detected Domains/SNIs]" in line:
            in_domains = True
            in_apps = False
            continue

        if "APPLICATION BREAKDOWN" in line:
            in_apps = True
            in_domains = False
            continue

        if in_domains:
            match = re.search(r"-\s+(.+?)\s+->\s+(.+)$", clean)
            if match:
                domains.append({"hostname": match.group(1).strip(), "app": match.group(2).strip()})
            continue

        for label, key in [
            ("Total Packets", "total_packets"),
            ("Forwarded", "forwarded"),
            ("Dropped", "dropped"),
            ("TCP Packets", "tcp_packets"),
            ("UDP Packets", "udp_packets"),
        ]:
            if label in clean:
                num = re.search(r"(\d+)", clean.split(label, 1)[1])
                if num:
                    stats[key] = int(num.group(1))

        if in_apps:
            app_match = re.match(r"([A-Za-z0-9/ .-]+?)\s+(\d+)\s+([\d.]+)%", clean)
            if app_match and not clean.startswith(("LB", "FP")):
                applications.append(
                    {
                        "app": app_match.group(1).strip(),
                        "count": int(app_match.group(2)),
                        "percentage": float(app_match.group(3)),
                    }
                )

    stats["remaining_packets"] = stats["forwarded"]
    return {"statistics": stats, "applications": applications, "domains": domains, "logs": logs}


def _clean_box_line(line):
    line = re.sub(r"[╔╗╚╝║╠╣═]+", " ", line)
    line = re.sub(r"\s+", " ", line)
    return line.strip()
