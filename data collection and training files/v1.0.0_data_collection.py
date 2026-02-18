import socket
import struct
import time
import csv
import argparse
import os
from collections import defaultdict

# --- Configuration ---
ETH_P_IP = 0x0800
# Define the features that will be our CSV columns
FEATURE_COLUMNS = [
    # Volume Features
    'total_packet_rate', 'total_byte_rate', 'avg_packet_size',
    # Protocol-Specific Rates
    'tcp_rate', 'udp_rate', 'icmp_rate',
    # TCP-Specific Features
    'syn_rate', 'ack_rate', 'syn_to_ack_ratio',
    # Protocol Ratios
    'tcp_to_total_ratio', 'udp_to_total_ratio', 'icmp_to_total_ratio',
    # Source/Destination Features
    'unique_source_ips',
    # Label
    'label'
]

# --- Helper Parsing Functions (Mostly unchanged) ---
def parse_ip_header(data):
    try:
        iph = struct.unpack('!BBHHHBBH4s4s', data[:20])
        protocol = iph[6]
        src_ip = '.'.join(map(str, iph[8]))
        return protocol, src_ip, data[20:]
    except struct.error:
        return None, None, None

def parse_tcp_header_flags(data):
    try:
        # We only need the flags for this script
        (_ , _, _, _, offset_reserved_flags, _, _, _) = struct.unpack('!HHLLHHHH', data[:20])
        flags = offset_reserved_flags & 0x01FF
        is_syn = (flags & 0x002) != 0 and (flags & ~0x002) == 0 # Check if ONLY SYN is set
        is_ack = (flags & 0x010) != 0
        return is_syn, is_ack
    except struct.error:
        return False, False

# --- Main Data Collection Logic ---
def main(args):
    """Main function to capture traffic and extract features."""
    
    # Check for root privileges, required for raw sockets
    if os.geteuid() != 0:
        print("❌ Error: This script requires root privileges to create a raw socket.")
        print("Please run it with 'sudo'.")
        return

    # Create a raw socket to capture everything
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) # ETH_P_ALL
        s.bind((args.interface, 0))
    except Exception as e:
        print(f"❌ Error binding to interface {args.interface}: {e}")
        print("Please make sure the interface name is correct. Use 'ip addr' or 'ifconfig' to check.")
        return

    # Open the CSV file for writing
    with open(args.output, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(FEATURE_COLUMNS) # Write the header

        print(f"🚀 Starting data collection on interface '{args.interface}'...")
        print(f"💾 Saving features to '{args.output}' with label '{args.label}'")
        print(f"⏱️  Using a {args.window} second time window.")
        print("⌨️  Press Ctrl+C to stop.")

        start_time = time.time()
        
        try:
            while True:
                # --- A: Initialize Stats for the Window ---
                window_end_time = time.time() + args.window
                window_stats = defaultdict(float)
                window_stats['source_ips'] = set()
                
                # --- B: Collect Packets for the Duration of the Window ---
                while time.time() < window_end_time:
                    try:
                        raw_data, _ = s.recvfrom(65535)
                        
                        # Basic packet info
                        packet_len = len(raw_data)
                        window_stats['total_packets'] += 1
                        window_stats['total_bytes'] += packet_len
                        
                        # --- Parse IP Layer ---
                        # We skip the Ethernet header (first 14 bytes)
                        ip_header_data = raw_data[14:]
                        protocol, src_ip, transport_data = parse_ip_header(ip_header_data)
                        
                        if protocol is None or src_ip is None:
                            continue # Skip non-IP packets or parsing errors

                        window_stats['source_ips'].add(src_ip)

                        if protocol == 6:  # TCP
                            window_stats['tcp_packets'] += 1
                            is_syn, is_ack = parse_tcp_header_flags(transport_data)
                            if is_syn:
                                window_stats['syn_packets'] += 1
                            if is_ack:
                                window_stats['ack_packets'] += 1
                        
                        elif protocol == 17:  # UDP
                            window_stats['udp_packets'] += 1
                        
                        elif protocol == 1:  # ICMP
                            window_stats['icmp_packets'] += 1

                    except BlockingIOError:
                        # No packet received, just continue waiting
                        continue
                    except Exception as e:
                        # print(f"Warning: Could not process a packet. Error: {e}")
                        pass
                
                # --- C: Calculate Features After Window Ends ---
                total_packets = window_stats['total_packets']
                if total_packets == 0:
                    continue # Skip empty windows

                # Volume Features
                total_packet_rate = total_packets / args.window
                total_byte_rate = window_stats['total_bytes'] / args.window
                avg_packet_size = window_stats['total_bytes'] / total_packets

                # Protocol-Specific Rates
                tcp_rate = window_stats['tcp_packets'] / args.window
                udp_rate = window_stats['udp_packets'] / args.window
                icmp_rate = window_stats['icmp_packets'] / args.window

                # TCP-Specific Features
                syn_rate = window_stats['syn_packets'] / args.window
                ack_rate = window_stats['ack_packets'] / args.window
                # Add a small epsilon to avoid division by zero
                syn_to_ack_ratio = window_stats['syn_packets'] / (window_stats['ack_packets'] + 1e-6)

                # Protocol Ratios
                tcp_to_total_ratio = window_stats['tcp_packets'] / total_packets
                udp_to_total_ratio = window_stats['udp_packets'] / total_packets
                icmp_to_total_ratio = window_stats['icmp_packets'] / total_packets
                
                # Source/Destination Features
                unique_source_ips = len(window_stats['source_ips'])

                # --- D: Write Feature Row to CSV ---
                feature_row = [
                    total_packet_rate, total_byte_rate, avg_packet_size,
                    tcp_rate, udp_rate, icmp_rate,
                    syn_rate, ack_rate, syn_to_ack_ratio,
                    tcp_to_total_ratio, udp_to_total_ratio, icmp_to_total_ratio,
                    unique_source_ips,
                    args.label # Add the user-defined label
                ]
                writer.writerow(feature_row)
                f.flush() # Ensure data is written to disk immediately
                
                print(f"[{time.ctime()}] Wrote window data. Total packets in window: {int(total_packets)}")

        except KeyboardInterrupt:
            print(f"\n🛑 Stopping data collection...")
            duration = time.time() - start_time
            print(f"Total collection time: {duration:.2f} seconds.")
            print(f"Data saved to '{args.output}'")
            print("👋 Goodbye!")
        except Exception as e:
            print(f"❌ An unexpected error occurred: {e}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Network Traffic Feature Collector for AI Model Training.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        '-i', '--interface',
        type=str,
        default='eth0',
        help="Network interface to capture traffic from (e.g., 'eth0', 'wlan0')."
    )
    parser.add_argument(
        '-o', '--output',
        type=str,
        required=True,
        help="Name of the output CSV file to save features."
    )
    parser.add_argument(
        '-l', '--label',
        type=str,
        required=True,
        help="Label for the captured traffic (e.g., 'normal', 'syn_flood', 'udp_flood')."
    )
    parser.add_argument(
        '-w', '--window',
        type=float,
        default=2.0,
        help="Time window in seconds to aggregate features."
    )
    
    args = parser.parse_args()
    main(args)
