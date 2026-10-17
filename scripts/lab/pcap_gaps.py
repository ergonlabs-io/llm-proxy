#!/usr/bin/env python3
"""Find Nagle / delayed-ACK stalls in a loopback capture of the proxy's hops.

Usage: pcap_gaps.py CAPTURE.pcap --proxy-port P --upstream-port U [--json OUT]

Reads `tcpdump -tt -nn -r` output, so it needs only tcpdump (no scapy or
tshark). For each hop and direction it reports data segments, and STALLS: a
data segment sent at least --stall-ms after the previous data segment in the
same direction of the same connection, where the peer sent a pure ACK within
--ack-window-ms before it, sent NO data in between (otherwise the gap is a
request/response turn or an idle keep-alive connection, not a held write),
and the wait is under --max-stall-ms (Linux caps the delayed ACK at 200 ms).
That is the signature of Nagle holding a small write until the peer's delayed
ACK (about 40 ms on Linux) releases it. A CPU
profile cannot show this, because nothing is running while it waits.

Validate before trusting it: a capture of a hop that sets TCP_NODELAY should
report close to zero stalls, and one that does not, under request/response
traffic with small writes, should report many.
"""
import argparse
import collections
import json
import re
import statistics
import subprocess
import sys

LINE = re.compile(
    r"^(?P<ts>\d+\.\d+) IP6? (?P<src>[\d.:a-f]+)\.(?P<sport>\d+) > (?P<dst>[\d.:a-f]+)\.(?P<dport>\d+): "
    r"Flags \[(?P<flags>[^\]]*)\].*?length (?P<len>\d+)"
)


def packets(path):
    out = subprocess.run(
        ["tcpdump", "-tt", "-nn", "-r", path],
        check=True, capture_output=True, text=True,
    ).stdout
    for line in out.splitlines():
        m = LINE.match(line)
        if m:
            yield (float(m["ts"]), int(m["sport"]), int(m["dport"]), m["flags"], int(m["len"]))


def hop_name(sport, dport, proxy_port, upstream_port):
    if dport == proxy_port:
        return "client->proxy"
    if sport == proxy_port:
        return "proxy->client"
    if dport == upstream_port:
        return "proxy->upstream"
    if sport == upstream_port:
        return "upstream->proxy"
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--proxy-port", type=int, required=True)
    ap.add_argument("--upstream-port", type=int, required=True)
    ap.add_argument("--stall-ms", type=float, default=30.0)
    ap.add_argument("--ack-window-ms", type=float, default=2.0)
    ap.add_argument("--max-stall-ms", type=float, default=250.0)
    ap.add_argument("--json")
    args = ap.parse_args()

    last_data = {}                        # (sport, dport) -> ts of last data segment
    last_pure_ack = {}                    # (sport, dport) -> ts of last pure ACK
    segs = collections.Counter()
    stalls = collections.defaultdict(list)
    first = last = None
    for ts, sport, dport, flags, length in packets(args.pcap):
        hop = hop_name(sport, dport, args.proxy_port, args.upstream_port)
        if hop is None:
            continue
        first = ts if first is None else first
        last = ts
        key = (sport, dport)
        if length == 0:
            if flags == ".":
                last_pure_ack[key] = ts
            continue
        segs[hop] += 1
        prev = last_data.get(key)
        peer = (dport, sport)
        peer_ack = last_pure_ack.get(peer)
        peer_data = last_data.get(peer)
        gap_ms = (ts - prev) * 1000 if prev is not None else 0
        if (prev is not None and args.stall_ms <= gap_ms <= args.max_stall_ms
                and peer_ack is not None and 0 <= (ts - peer_ack) * 1000 <= args.ack_window_ms
                and peer_ack > prev
                and (peer_data is None or peer_data < prev)):
            stalls[hop].append((ts - prev) * 1000)
        last_data[key] = ts

    report = {"capture_seconds": round((last or 0) - (first or 0), 3), "hops": {}}
    for hop in ("client->proxy", "proxy->upstream", "upstream->proxy", "proxy->client"):
        s = stalls.get(hop, [])
        report["hops"][hop] = {
            "data_segments": segs.get(hop, 0),
            "stalls": len(s),
            "stalls_per_1000_segments": round(1000 * len(s) / segs[hop], 2) if segs.get(hop) else 0,
            "stall_ms_p50": round(statistics.median(s), 1) if s else None,
            "stall_ms_max": round(max(s), 1) if s else None,
        }
    text = json.dumps(report, indent=2)
    print(text)
    if args.json:
        with open(args.json, "w") as f:
            f.write(text + "\n")


if __name__ == "__main__":
    sys.exit(main())
