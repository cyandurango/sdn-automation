import socket
import struct
import time
from collections import defaultdict

ETH_P_ALL = 3
ETH_P_IP = 0x0800

def mac_addr(bytes_addr):
    return ':'.join('%02x' % b for b in bytes_addr)

def ip_addr(addr):
    return '.'.join(map(str, addr))

def parse_ethernet_header(data):
    eth_header = struct.unpack('!6s6sH', data[:14])
    dest_mac = mac_addr(eth_header[0])
    src_mac = mac_addr(eth_header[1])
    proto = eth_header[2]
    return dest_mac, src_mac, proto, data[14:]

def parse_ip_header(data):
    iph = struct.unpack('!BBHHHBBH4s4s', data[:20])
    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0xF) * 4
    ttl = iph[5]
    protocol = iph[6]
    src_ip = ip_addr(iph[8])
    dest_ip = ip_addr(iph[9])
    return version, ihl, ttl, protocol, src_ip, dest_ip, data[ihl:]

def parse_icmp_header(data):
    if len(data) < 8:
        return None, None, None, None, None, None
    icmp_type, code, checksum = struct.unpack('!BBH', data[:4])
    identifier, sequence = struct.unpack('!HH', data[4:8])
    payload = data[8:] if len(data) > 8 else b''
    return icmp_type, code, checksum, identifier, sequence, payload

def parse_tcp_header(data):
    if len(data) < 20:
        return None
    src_port, dst_port, seq, ack, offset_reserved_flags, window, checksum, urg_ptr = struct.unpack('!HHLLHHHH', data[:20])
    offset = (offset_reserved_flags >> 12) * 4
    flags = offset_reserved_flags & 0x01FF
    flag_names = []
    if flags & 0x002: flag_names.append('SYN')
    if flags & 0x010: flag_names.append('ACK')
    if flags & 0x001: flag_names.append('FIN')
    if flags & 0x004: flag_names.append('RST')
    if flags & 0x008: flag_names.append('PSH')
    if flags & 0x020: flag_names.append('URG')
    return {
        'src_port': src_port,
        'dst_port': dst_port,
        'seq': seq,
        'ack': ack,
        'flags': flag_names,
        'window': window,
        'header_len': offset,
        'payload': data[offset:]
    }

def get_icmp_type_description(icmp_type, code):
    icmp_types = {
        0: "Echo Reply", 3: "Destination Unreachable", 4: "Source Quench",
        5: "Redirect", 8: "Echo Request", 9: "Router Advertisement",
        10: "Router Solicitation", 11: "Time Exceeded", 12: "Parameter Problem",
        13: "Timestamp Request", 14: "Timestamp Reply"
    }
    dest_unreach_codes = {
        0: "Net Unreachable", 1: "Host Unreachable", 2: "Protocol Unreachable",
        3: "Port Unreachable", 4: "Fragmentation Needed", 5: "Source Route Failed"
    }
    time_exceeded_codes = {
        0: "TTL Exceeded in Transit", 1: "Fragment Reassembly Time Exceeded"
    }
    type_desc = icmp_types.get(icmp_type, f"Unknown Type {icmp_type}")
    if icmp_type == 3:
        code_desc = dest_unreach_codes.get(code, f"Unknown Code {code}")
        return f"{type_desc} ({code_desc})"
    elif icmp_type == 11:
        code_desc = time_exceeded_codes.get(code, f"Unknown Code {code}")
        return f"{type_desc} ({code_desc})"
    else:
        return type_desc

def format_payload_preview(payload, max_len=32):
    if not payload:
        return "No payload"
    try:
        text = payload[:max_len].decode('ascii', errors='replace')
        text = ''.join(c if c.isprintable() else '.' for c in text)
        hex_data = ' '.join(f'{b:02x}' for b in payload[:16])
        return f"Text: '{text}' | Hex: {hex_data}"
    except:
        hex_data = ' '.join(f'{b:02x}' for b in payload[:16])
        return f"Hex: {hex_data}"

def main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s.bind(("eth0", 0))

    print("🔍 Packet Sniffer Started")
    print("📡 Monitoring eth0 for ICMP, TCP, and UDP traffic...")
    print("⌨️  Press Ctrl+C to stop\n")

    icmp_count = 0
    tcp_count = 0
    udp_count = 0

    try:
        while True:
            raw_data, addr = s.recvfrom(65535)
            dest_mac, src_mac, eth_proto, data = parse_ethernet_header(raw_data)

            if eth_proto == ETH_P_IP:
                version, ihl, ttl, proto, src_ip, dest_ip, ip_data = parse_ip_header(data)

                if proto == 1:  # ICMP
                    icmp_type, code, checksum, identifier, sequence, payload = parse_icmp_header(ip_data)
                    if icmp_type is not None:
                        icmp_count += 1
                        type_desc = get_icmp_type_description(icmp_type, code)
                        payload_preview = format_payload_preview(payload)
                        print(f"{'='*80}")
                        print(f"ICMP Packet #{icmp_count}")
                        print(f"{'='*80}")
                        print(f"📍 Source:      {src_ip}")
                        print(f"🎯 Destination: {dest_ip}")
                        print(f"🔧 Type:        {icmp_type} ({type_desc})")
                        print(f"📝 Code:        {code}")
                        print(f"✅ Checksum:    0x{checksum:04x}")
                        if icmp_type in [0, 8]:
                            direction = "🏓 PING REQUEST" if icmp_type == 8 else "✅ PING REPLY"
                            print(f"📌 Direction:   {direction}")
                            print(f"🆔 Identifier:  {identifier}")
                            print(f"🔢 Sequence:    {sequence}")
                        print(f"📊 TTL:         {ttl}")
                        print(f"📦 Payload:     {payload_preview}")
                        print(f"📏 Size:        {len(payload)} bytes payload\n")

                elif proto == 6:  # TCP
                    tcp_info = parse_tcp_header(ip_data)
                    if tcp_info:
                        tcp_count += 1
                        payload_preview = format_payload_preview(tcp_info['payload'])
                        print(f"{'='*80}")
                        print(f"TCP Packet #{tcp_count}")
                        print(f"{'='*80}")
                        print(f"📍 Source:      {src_ip}:{tcp_info['src_port']}")
                        print(f"🎯 Destination: {dest_ip}:{tcp_info['dst_port']}")
                        print(f"📊 TTL:         {ttl}")
                        print(f"🔢 Seq:         {tcp_info['seq']}")
                        print(f"✅ Ack:         {tcp_info['ack']}")
                        print(f"🚩 Flags:       {', '.join(tcp_info['flags']) if tcp_info['flags'] else 'None'}")
                        print(f"📐 Header Len:  {tcp_info['header_len']} bytes")
                        print(f"🪟 Window Size: {tcp_info['window']}")
                        print(f"📦 Payload:     {payload_preview}")
                        print(f"📏 Size:        {len(tcp_info['payload'])} bytes payload\n")

                elif proto == 17:  # UDP
                    if len(ip_data) >= 8:
                        udp_count += 1
                        src_port, dst_port = struct.unpack('!HH', ip_data[:4])
                        print(f"{'='*80}")
                        print(f"UDP Packet #{udp_count}")
                        print(f"{'='*80}")
                        print(f"📍 Source:      {src_ip}:{src_port}")
                        print(f"🎯 Destination: {dest_ip}:{dst_port}")
                        print(f"📊 TTL:         {ttl}")
                        print(f"📏 Size:        {len(ip_data)} bytes\n")

    except KeyboardInterrupt:
        print(f"\n🛑 Stopping sniffer...")
        print(f"📊 Total ICMP packets captured: {icmp_count}")
        print(f"📊 Total TCP packets captured:  {tcp_count}")
        print(f"📊 Total UDP packets captured:  {udp_count}")
        print("👋 Goodbye!")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()
