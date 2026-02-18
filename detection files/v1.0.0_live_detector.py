import socket
import struct
import time
import joblib
import pandas as pd
import numpy as np
import os
import subprocess
import json
from collections import defaultdict

# --- Configuration ---
INTERFACE = "eth0"
WINDOW_SECONDS = 2.0
MODEL_FILENAME = 'multi_class_model.joblib'
BLOCK_SUBNET_PREFIX = "192.168.10."
FLOODLIGHT_CONTROLLER_IP = "192.168.50.165"
CURL_INTERFACE = "eth1"

FEATURE_NAMES = [
    'total_packet_rate', 'total_byte_rate', 'avg_packet_size',
    'tcp_rate', 'udp_rate', 'icmp_rate',
    'syn_rate', 'ack_rate', 'syn_to_ack_ratio',
    'tcp_to_total_ratio', 'udp_to_total_ratio', 'icmp_to_total_ratio',
    'unique_source_ips'
]

LABEL_MAP = {
    0: 'Normal',
    1: 'TCP SYN Flood',
    2: 'UDP Flood',
    3: 'ICMP Flood'
}
LABEL_TO_PROTO = {
    'ICMP Flood': 1,
    'TCP SYN Flood': 6,
    'UDP Flood': 17
}

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def clear_acl_rules(controller_ip=FLOODLIGHT_CONTROLLER_IP, iface=CURL_INTERFACE):
    subprocess.run([
        "curl", "--interface", iface,
        "-X", "GET", "-H", "Content-Type: application/json",
        f"http://{controller_ip}:8080/wm/acl/clear/json"
    ], capture_output=True)

def remove_acl_rules_by_protocol(proto, controller_ip=FLOODLIGHT_CONTROLLER_IP, iface=CURL_INTERFACE):
    res = subprocess.run([
        "curl", "--interface", iface,
        "-s", "-H", "Content-Type: application/json",
        "-X", "GET", f"http://{controller_ip}:8080/wm/acl/rules/json"
    ], capture_output=True, text=True, check=True)
    rules = json.loads(res.stdout)
    all_ids = [r['id'] for r in rules]
    print(f"{bcolors.OKBLUE}🔍 Retrieved rule IDs: {all_ids}{bcolors.ENDC}")

    removed = []
    for r in rules:
        raw_str = str(r.get('nw_proto'))
        try:
            proto_val = int(raw_str, 16)
        except:
            continue
        print(f"    rule {r['id']}: raw nw_proto={raw_str} → {proto_val}")
        if proto_val == proto:
            rid = r['id']
            removed.append(rid)
            subprocess.run([
                "curl", "--interface", iface,
                "-s", "-X", "DELETE",
                "-H", "Content-Type: application/json",
                "-d", json.dumps({"ruleid": rid}),
                f"http://{controller_ip}:8080/wm/acl/rules/json"
            ], capture_output=True, text=True, check=True)
    print(f"{bcolors.OKBLUE}🔍 Protocol {proto} rules removed: {removed}{bcolors.ENDC}")

def parse_ip_header(data):
    try:
        iph = struct.unpack('!BBHHHBBH4s4s', data[:20])
        return iph[6], socket.inet_ntoa(iph[8]), socket.inet_ntoa(iph[9]), data[20:]
    except:
        return None, None, None, None

def parse_udp_header(data):
    if len(data) < 8:
        return None
    src_port, dst_port = struct.unpack('!HH', data[:4])
    return dst_port

def parse_tcp_header_flags(data):
    try:
        flags = struct.unpack('!HHLLHHHH', data[:20])[4]
        return bool(flags & 0x002), bool(flags & 0x010)
    except:
        return False, False

def parse_icmp_header(data):
    if len(data) < 4:
        return None
    return struct.unpack('!BBH', data[:4])[0]

def push_acl_rule(src_ip, dst_ip, protocol, tp_dst=None, controller_ip=FLOODLIGHT_CONTROLLER_IP, iface=CURL_INTERFACE):
    if not src_ip.startswith(BLOCK_SUBNET_PREFIX):
        return None
    rule = {
        "src-ip": f"{src_ip}/32",
        "dst-ip": f"{dst_ip}/32",
        "eth-type": "IPv4",
        "nw-proto": protocol.upper(),
        "action": "deny"
    }
    if protocol == "UDP" and tp_dst:
        rule["tp-dst"] = tp_dst

    res = subprocess.run([
        "curl", "-X", "POST",
        "-H", "Content-Type: application/json",
        "-d", json.dumps(rule),
        f"http://{controller_ip}:8080/wm/acl/rules/json",
        "--interface", iface
    ], capture_output=True, text=True)
    if res.returncode == 0:
        print(f"{bcolors.OKCYAN}🚫 ACL Rule pushed: DENY {protocol} {src_ip}→{dst_ip}{bcolors.ENDC}")
        return time.time()
    else:
        print(f"{bcolors.FAIL}❌ Push failed: {res.stdout.strip()}{bcolors.ENDC}")
        return None

def compute_features(stats, window_seconds):
    tp, tb = stats['total_packets'], stats['total_bytes']
    if tp == 0:
        print(f"[{time.ctime()}] {bcolors.OKBLUE}No traffic in this window.{bcolors.ENDC}")
        return [0.0]*len(FEATURE_NAMES)
    return [
        tp/window_seconds,
        tb/window_seconds,
        tb/tp,
        stats['tcp_packets']/window_seconds,
        stats['udp_packets']/window_seconds,
        stats['icmp_packets']/window_seconds,
        stats['syn_packets']/window_seconds,
        stats['ack_packets']/window_seconds,
        stats['syn_packets']/(stats['ack_packets']+1e-6),
        stats['tcp_packets']/tp,
        stats['udp_packets']/tp,
        stats['icmp_packets']/tp,
        len(stats['source_ips'])
    ]

def predict_and_log(stats, label, model):
    df = pd.DataFrame([compute_features(stats, WINDOW_SECONDS)], columns=FEATURE_NAMES)
    idx = model.predict(df)[0]
    name = LABEL_MAP.get(idx, "Unknown")
    prob = model.predict_proba(df)[0][idx]*100
    col = bcolors.OKGREEN if name=="Normal" else bcolors.FAIL if "Flood" in name else bcolors.WARNING
    ts = time.ctime()
    if label == "Raw":
        print(f"{bcolors.BOLD}{'-'*80}{bcolors.ENDC}")
        print(f"[{ts}] {bcolors.OKCYAN}Raw ICMP Rate:  {stats['icmp_packets']/WINDOW_SECONDS:.2f}{bcolors.ENDC}")
        print(f"[{ts}] {bcolors.OKCYAN}Raw TCP  Rate:  {stats['tcp_packets']/WINDOW_SECONDS:.2f}{bcolors.ENDC}")
        print(f"[{ts}] {bcolors.OKCYAN}Raw UDP  Rate:  {stats['udp_packets']/WINDOW_SECONDS:.2f}{bcolors.ENDC}")
        print(f"[{ts}] {bcolors.OKCYAN}Raw Total Rate:{stats['total_packets']/WINDOW_SECONDS:.2f}{bcolors.ENDC}")
        print(f"[{ts}] Raw Pred:      {col}{name}{bcolors.ENDC} ({prob:.2f}%)")
    else:
        print(f"[{ts}] Filtered Pred: {col}{name}{bcolors.ENDC} ({prob:.2f}%)")
    return name, prob

def main():
    try:
        subprocess.run(["ip", "link", "set", INTERFACE, "promisc", "on"],
                       check=True, capture_output=True, text=True)
        print(f"{bcolors.OKGREEN}✅ Enabled promiscuous mode on {INTERFACE}{bcolors.ENDC}")
    except subprocess.CalledProcessError as e:
        print(f"{bcolors.FAIL}❌ Failed to enable promiscuous mode: {e.stderr}{bcolors.ENDC}")
        return

    print(f"{bcolors.WARNING}⏹ Clearing existing ACL rules...{bcolors.ENDC}")
    clear_acl_rules()

    if os.geteuid() != 0:
        return
    try:
        model = joblib.load(MODEL_FILENAME)
    except FileNotFoundError:
        return

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    s.bind((INTERFACE, 0))

    flooded = {1: {}, 6: {}, 17: {}}
    last_flood_time = {'ICMP Flood': None, 'TCP SYN Flood': None, 'UDP Flood': None}
    is_udp_flood_active = False

    try:
        while True:
            window_end = time.time() + WINDOW_SECONDS
            win_stats = defaultdict(float); win_stats['source_ips'] = set()
            raw_stats = defaultdict(float); raw_stats['source_ips'] = set()

            while time.time() < window_end:
                pkt, _ = s.recvfrom(65535)
                proto, sip, dip, tdat = parse_ip_header(pkt[14:])
                if not proto or not sip:
                    continue
                key = f"{sip}-{dip}"
                blocked = any(key in flooded[p] for p in flooded)
                L = len(pkt)

                icmp_type = parse_icmp_header(tdat) if proto == 1 else None
                if proto == 1 and is_udp_flood_active and icmp_type == 3:
                    continue

                raw_stats['total_packets'] += 1
                raw_stats['total_bytes'] += L
                raw_stats['source_ips'].add(sip)
                if proto == 6:
                    raw_stats['tcp_packets'] += 1
                if proto == 17:
                    raw_stats['udp_packets'] += 1
                if proto == 1 and icmp_type == 8:
                    raw_stats['icmp_packets'] += 1

                if not blocked:
                    win_stats['total_packets'] += 1
                    win_stats['total_bytes'] += L
                    win_stats['source_ips'].add(sip)
                    if proto == 6:
                        syn, ack = parse_tcp_header_flags(tdat)
                        if syn:
                            win_stats['syn_packets'] += 1
                            win_stats['tcp_syn_pair'] = (sip, dip)
                        if ack:
                            win_stats['ack_packets'] += 1
                    if proto == 17:
                        win_stats['udp_packets'] += 1
                        win_stats['udp_pair'] = (sip, dip)
                    if proto == 1 and icmp_type == 8:
                        win_stats['icmp_packets'] += 1
                        win_stats['icmp_pair'] = (sip, dip)

            raw_label, raw_conf = predict_and_log(raw_stats, "Raw", model)
            filt_label, filt_conf = predict_and_log(win_stats, "Filtered", model)
            now = time.time()

            udp_rate = win_stats['udp_packets'] / WINDOW_SECONDS
            total_rate = win_stats['total_packets'] / WINDOW_SECONDS
            udp_percentage = (udp_rate / total_rate) * 100 if total_rate > 0 else 0

            if raw_conf < 70 and udp_percentage > 20:
                raw_label = "UDP Flood"
                is_udp_flood_active = True
            else:
                is_udp_flood_active = False

            if raw_label in last_flood_time:
                last_flood_time[raw_label] = now
            for lbl, t0 in last_flood_time.items():
                if t0 and (now - t0) > 10 and raw_label != lbl and not is_udp_flood_active:
                    proto = LABEL_TO_PROTO[lbl]
                    remove_acl_rules_by_protocol(proto)
                    flooded[proto].clear()
                    if proto == 17:
                        remove_acl_rules_by_protocol(1)
                        flooded[1].clear()
                    last_flood_time[lbl] = None

            if 'icmp_pair' in win_stats and filt_label == "ICMP Flood":
                sip, dip = win_stats['icmp_pair']
                k = f"{sip}-{dip}"
                if k not in flooded[1]:
                    flooded[1][k] = push_acl_rule(sip, dip, "ICMP")
            if 'tcp_syn_pair' in win_stats and filt_label == "TCP SYN Flood":
                sip, dip = win_stats['tcp_syn_pair']
                k = f"{sip}-{dip}"
                if k not in flooded[6]:
                    flooded[6][k] = push_acl_rule(sip, dip, "TCP")
            if 'udp_pair' in win_stats and filt_label == "UDP Flood":
                sip, dip = win_stats['udp_pair']
                k = f"{sip}-{dip}"
                if k not in flooded[17]:
                    flooded[17][k] = push_acl_rule(sip, dip, "UDP")
                    flooded[1][k] = push_acl_rule(dip, sip, "ICMP")

    except KeyboardInterrupt:
        print("Detector stopped.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    main()



