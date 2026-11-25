#!/usr/bin/env python3
import argparse
import random
import select
import socket
import struct
import sys
import time


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def get_local_ip(target_ip):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect((target_ip, 80))
        return s.getsockname()[0]


def ipv4_header(src_ip, dst_ip, proto, payload_len):
    src, dst = socket.inet_aton(src_ip), socket.inet_aton(dst_ip)
    fields = (0x45, 0, 20 + payload_len, random.randint(1, 65535), 0, 64, proto, 0, src, dst)
    hdr = struct.pack("!BBHHHBBH4s4s", *fields)
    return struct.pack("!BBHHHBBH4s4s", *(fields[:7] + (checksum(hdr), src, dst)))


def tcp_segment(src_ip, dst_ip, sport, dport, seq, ack, flags):
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, socket.htons(65535), 0, 0)
    pseudo = struct.pack("!4s4sBBH", socket.inet_aton(src_ip), socket.inet_aton(dst_ip), 0, socket.IPPROTO_TCP, len(hdr))
    return struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, socket.htons(65535), checksum(pseudo + hdr), 0)


def send_tcp(sock, src, dst, sport, dport, seq, ack, flags):
    seg = tcp_segment(src, dst, sport, dport, seq, ack, flags)
    sock.sendto(ipv4_header(src, dst, socket.IPPROTO_TCP, len(seg)) + seg, (dst, 0))


def parse_ports(port_str):
    ports = []
    for part in port_str.split(","):
        part = part.strip()
        if not part:
            raise ValueError(f"Пустой диапазон портов в '{port_str}'")
        if "-" in part:
            start, end = map(int, part.split("-", 1))
            if not (0 <= start <= end <= 65535):
                raise ValueError(f"Некорректный диапазон портов '{part}'")
            ports.extend(range(start, end + 1))
        else:
            p = int(part)
            if not (0 <= p <= 65535):
                raise ValueError(f"Некорректный порт '{p}'")
            ports.append(p)
    return ports


def parse_targets(specs):
    result = {"TCP": [], "UDP": []}
    for spec in specs:
        proto, _, ports_raw = spec.partition("/")
        proto = proto.upper()
        if proto not in result:
            raise ValueError(f"Некорректное указание объекта сканирования '{spec}'")
        result[proto].extend(parse_ports(ports_raw) if ports_raw else range(1, 65536))
    return {k: sorted(set(v)) for k, v in result.items()}


def probe_once(ip, port, proto, payload, timeout, dns_tcp=False):
    t = min(timeout, 1.0)
    try:
        if proto == "UDP":
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(t)
                s.sendto(payload, (ip, port))
                return s.recvfrom(512)[0]
        with socket.create_connection((ip, port), timeout=t) as s:
            s.settimeout(t)
            s.sendall(struct.pack("!H", len(payload)) + payload if dns_tcp else payload)
            return s.recv(512)
    except OSError:
        return b""


def probe_protocol(ip, port, proto, timeout):
    data = probe_once(ip, port, "TCP", b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n", timeout)
    if data.startswith(b"HTTP/"):
        return "HTTP"

    parts = [
        0x12, 0x34,
        0x01, 0x00,
        0x00, 0x01,
        *([0] * 6),
        7, *"example".encode("ascii"),
        3, *"com".encode("ascii"),
        0,
        0, 1,
        0, 1,
    ]
    query = bytes(parts)
    data = probe_once(ip, port, proto, query, timeout, dns_tcp=(proto != "UDP"))
    if proto == "UDP" and struct.unpack("!H", data[:2])[0] == 0x1234:
        return "DNS"
    if proto == "TCP" and struct.unpack("!H", data[:2])[0] == 0x1234:
        return "DNS"

    return "-"


def wait_readable(socks, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return None
    ready, _, _ = select.select(socks, [], [], min(remaining, 0.05))
    return ready


def scan_tcp_syn(ip, local_ip, ports, timeout):
    if not ports:
        return {}

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    sock.setblocking(False)

    open_ports = {}
    pending = {}
    base_sport = random.randint(20000, 50000)

    for i, dport in enumerate(ports):
        sport = base_sport + (i % 15000)
        send_tcp(sock, local_ip, ip, sport, dport, random.randint(1, 0xFFFFFFFF), 0, 0x02)
        pending[sport] = (dport, time.monotonic())

    deadline = time.monotonic() + timeout
    while pending:
        ready = wait_readable([sock], deadline)
        if ready is None:
            break
        if not ready:
            continue
        try:
            pkt, addr = sock.recvfrom(65535)
        except BlockingIOError:
            continue
        if addr[0] != ip or len(pkt) < 40:
            continue
        ihl = (pkt[0] & 0x0F) * 4
        if len(pkt) < ihl + 20:
            continue
        src_p, dst_p, _, ack_num, _, flags, _, _, _ = struct.unpack("!HHIIBBHHH", pkt[ihl:ihl + 20])
        if dst_p not in pending:
            continue
        dport, start_t = pending[dst_p]
        if src_p != dport:
            continue
        if (flags & 0x12) == 0x12:
            open_ports[dport] = (time.monotonic() - start_t) * 1000.0
            send_tcp(sock, local_ip, ip, dst_p, dport, ack_num, 0, 0x04)
            del pending[dst_p]
        elif flags & 0x04:
            del pending[dst_p]

    sock.close()
    return open_ports


def scan_udp(ip, ports, timeout):
    if not ports:
        return {}

    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.setblocking(False)
    try:
        icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        icmp_sock.setblocking(False)
    except OSError:
        icmp_sock = None

    open_ports = {}
    pending = {dport: time.monotonic() for dport in ports}
    for dport in ports:
        try:
            udp_sock.sendto(b"\x00", (ip, dport))
        except OSError:
            pass

    socks = [udp_sock] + ([icmp_sock] if icmp_sock else [])
    deadline = time.monotonic() + timeout
    while pending:
        ready = wait_readable(socks, deadline)
        if ready is None:
            break
        for sock in ready:
            try:
                pkt, addr = sock.recvfrom(65535)
            except BlockingIOError:
                continue
            if sock is udp_sock:
                if addr[0] == ip and addr[1] in pending:
                    open_ports[addr[1]] = (time.monotonic() - pending.pop(addr[1])) * 1000.0
                continue
            if addr[0] != ip or len(pkt) < 28:
                continue
            ihl = (pkt[0] & 0x0F) * 4
            icmp_hdr = pkt[ihl:ihl + 8]
            if len(icmp_hdr) < 8:
                continue
            icmp_type, icmp_code, _, _ = struct.unpack("!BBH4s", icmp_hdr)
            if icmp_type != 3 or icmp_code != 3:
                continue
            orig_ip = ihl + 8
            if len(pkt) < orig_ip + 24:
                continue
            orig_udp = orig_ip + (pkt[orig_ip] & 0x0F) * 4
            if len(pkt) >= orig_udp + 4:
                pending.pop(struct.unpack("!HH", pkt[orig_udp:orig_udp + 4])[1], None)

    open_ports.update({p: None for p in pending})
    udp_sock.close()
    if icmp_sock:
        icmp_sock.close()
    return open_ports


def print_rows(kind, found, args, ip):
    for port in sorted(found):
        parts = [kind, str(port)]
        if args.verbose:
            ms = found[port]
            parts.append(f"{ms:.2f}" if ms is not None else "-")
        if args.guess:
            parts.append(probe_protocol(ip, port, kind, args.timeout))
        print(" ".join(parts))


def main():
    parser = argparse.ArgumentParser(prog="portscan")
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("-j", "--num-threads", type=int, default=1)
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-g", "--guess", action="store_true")
    parser.add_argument("ip_address")
    parser.add_argument("specs", nargs="+")

    try:
        args = parser.parse_args()
        socket.inet_aton(args.ip_address)
        if args.timeout <= 0 or args.num_threads <= 0:
            raise ValueError("Некорректное числовое значение опции")
        targets = parse_targets(args.specs)
    except Exception as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 1

    try:
        local_ip = get_local_ip(args.ip_address)
        tcp_open = scan_tcp_syn(args.ip_address, local_ip, targets["TCP"], args.timeout)
        udp_open = scan_udp(args.ip_address, targets["UDP"], args.timeout)
    except PermissionError:
        print("Ошибка: raw-сокеты требуют права root")
        return 1
    except OSError as exc:
        print(f"Ошибка: {exc}")
        return 1

    print_rows("TCP", tcp_open, args, args.ip_address)
    print_rows("UDP", udp_open, args, args.ip_address)
    return 0


if __name__ == "__main__":
    sys.exit(main())
