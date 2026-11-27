"""dns-nxdomain: answer every DNS query with "no such domain" (NXDOMAIN) at once, on 127.0.0.1:10053 (UDP).

dns-blocklist's /etc/resolver files point the web guard's canary and callback domains here. Without an answer,
macOS keeps retrying a dead port for about 30 seconds before a lookup fails, so every program that touched a
blocked domain froze for that long. This forwards nothing and resolves nothing: the only answer it gives is
NXDOMAIN. If it isn't running, lookups for those domains still fail, just slowly (fail closed).

Each query is logged to ~/.local/state/claude-guard/web.log as {"mode":"dns","name":...} (the queried name only),
so a blocked lookup from Playwright, Chrome, an MCP server or any script shows up there too.

Runs as `/usr/bin/python3 -I <this file> [--port N] [--log FILE]`, standard library only, under a launchd agent.
"""
import json
import os
import socket
import sys
import time

HOST = "127.0.0.1"
PORT = 10053
LOG = os.path.expanduser("~/.local/state/claude-guard/web.log")


def question_name(packet):
    """(name, end offset of the question) or (None, None) for a packet we can't read."""
    labels, i = [], 12
    try:
        while True:
            n = packet[i]
            if n == 0:
                i += 1
                break
            if n & 0xC0:  # compression pointers don't belong in a query's question
                return None, None
            labels.append(packet[i + 1:i + 1 + n].decode("ascii", "replace"))
            i += 1 + n
        if i + 4 > len(packet):
            return None, None
        return ".".join(labels).lower(), i + 4
    except IndexError:
        return None, None


def nxdomain(packet, end):
    flags_in = int.from_bytes(packet[2:4], "big")
    if flags_in & 0x8000:  # a response, not a query
        return None
    opcode, rd = flags_in & 0x7800, flags_in & 0x0100
    flags = 0x8000 | opcode | 0x0400 | rd | 0x0080 | 3  # QR, AA, RD copied, RA, RCODE=NXDOMAIN
    return packet[0:2] + flags.to_bytes(2, "big") + (1).to_bytes(2, "big") + bytes(6) + packet[12:end]


def log(path, name):
    try:
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(json.dumps({"time": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "mode": "dns", "name": name[:253],
                                "decision": "nxdomain", "rule": "dns-blocklist"}) + "\n")
    except Exception:
        pass


def main():
    args, port, path = sys.argv[1:], PORT, LOG
    while args:
        a = args.pop(0)
        if a == "--port" and args:
            port = int(args.pop(0))
        elif a == "--log" and args:
            path = args.pop(0)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, port))
    last = {}  # name -> time logged, so a retry storm doesn't flood the log
    while True:
        packet, addr = sock.recvfrom(4096)
        if len(packet) < 17:
            continue
        name, end = question_name(packet)
        if name is None:
            continue
        reply = nxdomain(packet, end)
        if reply is None:
            continue
        sock.sendto(reply, addr)
        now = time.time()
        if now - last.get(name, 0) > 60:
            last[name] = now
            if len(last) > 5000:
                last.clear()
            log(path, name)


if __name__ == "__main__":
    main()
