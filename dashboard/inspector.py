import socket
import struct
from collections import Counter, defaultdict


APP_PATTERNS = [
    ("YouTube", ["youtube", "youtu.be", "ytimg", "youtubei", "googlevideo", "youtube-nocookie", "music.youtube", "yt3.ggpht"]),
    ("Google", ["google", "gstatic", "googleapis", "ggpht", "gvt1"]),
    ("Facebook", ["facebook", "fbcdn", "fb.com", "fbsbx", "meta.com"]),
    ("Instagram", ["instagram", "cdninstagram"]),
    ("Discord", ["discord", "discordapp"]),
    ("GitHub", ["github", "githubusercontent"]),
    ("Spotify", ["spotify", "scdn.co"]),
    ("TikTok", ["tiktok", "tiktokcdn", "musical.ly", "bytedance"]),
    ("Netflix", ["netflix", "nflxvideo", "nflximg"]),
    ("Amazon", ["amazon", "amazonaws", "cloudfront", "aws"]),
    ("Microsoft", ["microsoft", "msn.com", "office", "azure", "live.com", "outlook", "bing"]),
    ("Apple", ["apple", "icloud", "mzstatic", "itunes"]),
    ("Telegram", ["telegram", "t.me"]),
    ("Zoom", ["zoom"]),
    ("Cloudflare", ["cloudflare", "cf-"]),
    ("Twitter/X", ["twitter", "twimg", "x.com", "t.co"]),
    ("WhatsApp", ["whatsapp", "wa.me"]),
]


def inspect_pcap(path, blocked_apps=None, max_packets=5000):
    blocked_apps = set(blocked_apps or [])
    packets = []
    flows = {}
    dns_rows = []
    quic_rows = []
    domains = {}
    counters = Counter()

    for packet in _read_pcap(path):
        parsed = _parse_packet(packet["data"])
        if not parsed:
            continue
        counters["total"] += 1
        if parsed["protocol"] == "TCP":
            counters["tcp"] += 1
        elif parsed["protocol"] == "UDP":
            counters["udp"] += 1

        hostname = ""
        sni_status = "Not present"
        app = "Unknown"
        reason = "Forwarded because no selected block rule matched this packet."

        if parsed["protocol"] == "TCP" and parsed["dst_port"] == 443:
            hostname = _extract_tls_sni(parsed["payload"]) or ""
            sni_status = "SNI extracted" if hostname else "TLS packet without readable SNI"
            app = classify_host(hostname) if hostname else "HTTPS"
        elif parsed["protocol"] == "TCP" and parsed["dst_port"] == 80:
            hostname = _extract_http_host(parsed["payload"]) or ""
            sni_status = "HTTP Host extracted" if hostname else "No Host header"
            app = classify_host(hostname) if hostname else "HTTP"
        elif parsed["protocol"] == "UDP" and (parsed["dst_port"] == 443 or parsed["src_port"] == 443):
            hostname = _extract_quic_sni(parsed["payload"]) or ""
            app = classify_host(hostname) if hostname else "QUIC"
            sni_status = "QUIC Initial SNI extracted" if hostname else "QUIC Initial or UDP/443 without readable SNI"
            quic_rows.append(
                {
                    "packet_number": packet["number"],
                    "hostname": hostname or "(not extracted)",
                    "blocked": app in blocked_apps,
                    "flow_id": _flow_key(parsed),
                    "reason": _block_reason(app, blocked_apps, hostname),
                }
            )
        elif parsed["src_port"] == 53 or parsed["dst_port"] == 53:
            app = "DNS"
            dns_name, dns_kind = _extract_dns_name(parsed["payload"])
            hostname = dns_name or ""
            sni_status = dns_kind
            if dns_name:
                dns_app = classify_host(dns_name)
                dns_rows.append(
                    {
                        "hostname": dns_name,
                        "type": dns_kind,
                        "app": dns_app,
                        "blocked": dns_app in blocked_apps,
                        "forwarded": dns_app not in blocked_apps,
                        "reason": _block_reason(dns_app, blocked_apps, dns_name),
                    }
                )

        if hostname:
            app = classify_host(hostname)
            domains[hostname] = app

        key = _flow_key(parsed)
        flow = flows.setdefault(
            key,
            {
                "flow_id": key,
                "client": f"{parsed['src_ip']}:{parsed['src_port']}",
                "server": f"{parsed['dst_ip']}:{parsed['dst_port']}",
                "application": app,
                "hostname": hostname,
                "blocked": False,
                "packet_count": 0,
                "reason": "",
            },
        )
        flow["packet_count"] += 1
        if hostname:
            flow["hostname"] = hostname
            flow["application"] = app
        elif flow["application"] == "Unknown":
            flow["application"] = app
        if flow["application"] in blocked_apps:
            flow["blocked"] = True
        flow["reason"] = _block_reason(flow["application"], blocked_apps, flow.get("hostname", ""))

        blocked = flow["blocked"] or app in blocked_apps
        if blocked:
            reason = _block_reason(app if app in blocked_apps else flow["application"], blocked_apps, hostname or flow.get("hostname", ""))

        if len(packets) < max_packets:
            packets.append(
                {
                    "packet_number": packet["number"],
                    "protocol": app if app in ("DNS", "QUIC", "HTTP", "HTTPS") else parsed["protocol"],
                    "hostname": hostname,
                    "sni": sni_status,
                    "detected_application": app,
                    "blocked": blocked,
                    "reason": reason,
                    "src": f"{parsed['src_ip']}:{parsed['src_port']}",
                    "dst": f"{parsed['dst_ip']}:{parsed['dst_port']}",
                    "flow_id": key,
                }
            )

    domain_rows = [{"hostname": h, "app": a} for h, a in sorted(domains.items())]
    return {
        "packets": packets,
        "domains": domain_rows,
        "dns": dns_rows,
        "flows": sorted(flows.values(), key=lambda row: row["flow_id"]),
        "quic": quic_rows,
        "packet_counters": dict(counters),
    }


def classify_host(host):
    if not host:
        return "Unknown"
    lower = host.lower()
    for app, patterns in APP_PATTERNS:
        if any(pattern in lower for pattern in patterns):
            return app
    return "Unknown"


def _read_pcap(path):
    with open(path, "rb") as handle:
        header = handle.read(24)
        if len(header) != 24:
            return
        magic = header[:4]
        if magic == b"\xd4\xc3\xb2\xa1":
            endian = "<"
        elif magic == b"\xa1\xb2\xc3\xd4":
            endian = ">"
        else:
            endian = "<"
        packet_no = 0
        while True:
            ph = handle.read(16)
            if len(ph) != 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + "IIII", ph)
            data = handle.read(incl_len)
            if len(data) != incl_len:
                break
            packet_no += 1
            yield {"number": packet_no, "ts_sec": ts_sec, "ts_usec": ts_usec, "data": data}


def _parse_packet(data):
    if len(data) < 34:
        return None
    eth_type = struct.unpack("!H", data[12:14])[0]
    if eth_type != 0x0800:
        return None
    ip_start = 14
    ihl = (data[ip_start] & 0x0F) * 4
    if len(data) < ip_start + ihl + 4:
        return None
    proto = data[ip_start + 9]
    src_ip = socket.inet_ntoa(data[ip_start + 12 : ip_start + 16])
    dst_ip = socket.inet_ntoa(data[ip_start + 16 : ip_start + 20])
    transport = ip_start + ihl
    if proto == 6 and len(data) >= transport + 20:
        src_port, dst_port = struct.unpack("!HH", data[transport : transport + 4])
        tcp_hl = ((data[transport + 12] >> 4) & 0x0F) * 4
        payload_offset = transport + tcp_hl
        protocol = "TCP"
    elif proto == 17 and len(data) >= transport + 8:
        src_port, dst_port = struct.unpack("!HH", data[transport : transport + 4])
        payload_offset = transport + 8
        protocol = "UDP"
    else:
        return None
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "payload": data[payload_offset:],
    }


def _flow_key(parsed):
    left = (parsed["src_ip"], parsed["src_port"])
    right = (parsed["dst_ip"], parsed["dst_port"])
    a, b = sorted([left, right])
    return f"{parsed['protocol']} {a[0]}:{a[1]} <-> {b[0]}:{b[1]}"


def _extract_tls_sni(payload):
    if len(payload) < 9 or payload[0] != 0x16 or payload[5] != 0x01:
        return None
    offset = 5 + 4 + 2 + 32
    if offset >= len(payload):
        return None
    offset += 1 + payload[offset]
    if offset + 2 > len(payload):
        return None
    cipher_len = struct.unpack("!H", payload[offset : offset + 2])[0]
    offset += 2 + cipher_len
    if offset >= len(payload):
        return None
    offset += 1 + payload[offset]
    if offset + 2 > len(payload):
        return None
    ext_len = struct.unpack("!H", payload[offset : offset + 2])[0]
    offset += 2
    ext_end = min(len(payload), offset + ext_len)
    while offset + 4 <= ext_end:
        ext_type, size = struct.unpack("!HH", payload[offset : offset + 4])
        offset += 4
        if offset + size > ext_end:
            break
        if ext_type == 0 and size >= 5:
            name_len = struct.unpack("!H", payload[offset + 3 : offset + 5])[0]
            start = offset + 5
            end = start + name_len
            if end <= offset + size:
                return payload[start:end].decode("utf-8", "ignore")
        offset += size
    return None


def _extract_http_host(payload):
    text = payload.decode("iso-8859-1", "ignore")
    if not text.startswith(("GET ", "POST", "PUT ", "HEAD", "DELETE", "PATCH", "OPTIONS")):
        return None
    for line in text.splitlines():
        if line.lower().startswith("host:"):
            return line.split(":", 1)[1].strip().split(":", 1)[0]
    return None


def _extract_dns_name(payload):
    if len(payload) < 12:
        return None, "DNS packet"
    is_response = bool(payload[2] & 0x80)
    offset = 12
    labels = []
    while offset < len(payload):
        size = payload[offset]
        if size == 0:
            break
        if size > 63 or offset + 1 + size > len(payload):
            return None, "DNS response" if is_response else "DNS query"
        offset += 1
        labels.append(payload[offset : offset + size].decode("utf-8", "ignore"))
        offset += size
    return ".".join(labels) if labels else None, "DNS response" if is_response else "DNS query"


def _extract_quic_sni(payload):
    if len(payload) < 5 or not (payload[0] & 0x80):
        return None
    for idx in range(5, max(5, len(payload) - 9)):
        if payload[idx] == 0x16 and idx + 9 < len(payload):
            sni = _extract_tls_sni(payload[idx:])
            if sni:
                return sni
    return None


def _block_reason(app, blocked_apps, hostname=""):
    if app in blocked_apps:
        target = f" for {hostname}" if hostname else ""
        return f"Dropped because {app}{target} matched the selected block application."
    if hostname:
        return f"Forwarded because {hostname} was classified as {app}, which is not selected for blocking."
    return f"Forwarded because the flow is classified as {app} and no matching block rule was selected."
