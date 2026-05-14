from scapy.all import *
from collections import defaultdict
import numpy as np
import pandas as pd
import ipaddress
import time

PCAP_FILE = "network_traffic_capture_5min.pcap"
OUTPUT_FILE = "results_packetAnalysis.txt"

start_script = time.time()

print("Reading packets...")
# Store analysis results in dictionary
flows = defaultdict(lambda: {
    "start_time": None,
    "end_time": None,
    "packet_lengths": [],
    "timestamps": [],
    "syn_count": 0
})
total_packets = 0
outgoing_packets = 0
application_protocols = set()
possible_apps = set()
all_packet_timestamps = []
all_packet_lengths = []

# helper function to check if an IP address is private
def is_private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except:
        return False

# Process packets
try:
    with PcapReader(PCAP_FILE) as pcap:
        for packet in pcap:
            total_packets += 1
            if total_packets %100000 == 0:
                print(f"Processed {total_packets} packets")
            
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                protocol = packet[IP].proto
                timestamp = float(packet.time)
                all_packet_timestamps.append(timestamp)
                packet_length = len(packet)
                all_packet_lengths.append(packet_length)
                src_port = 0
                dst_port = 0
                if TCP in packet:
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    #SYN packet count for TCP
                    if packet[TCP].flags & 0x02:
                        flow_syn = True
                    else:
                        flow_syn = False
                elif UDP in packet:
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    flow_syn = False
                else:
                    flow_syn = False
                
                #Define Flow key
                flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)
                flow = flows[flow_key]
                #Start/End time
                if flow["start_time"] is None:
                    flow["start_time"] = timestamp
                flow["end_time"] = timestamp

                flow["packet_lengths"].append(packet_length)
                flow["timestamps"].append(timestamp)
                if flow_syn:
                    flow["syn_count"] += 1

                #Outgoing traffic: from private to public IP
                if is_private(src_ip) and not is_private(dst_ip):
                    outgoing_packets += 1
                
                #Application protocol detection (Port-based guesses)
                ports = [src_port, dst_port]
                if 53 in ports:
                    application_protocols.add("DNS")
                if 443 in ports:
                    application_protocols.add("HTTPS/TLS")
                if 80 in ports:
                    application_protocols.add("HTTP")
                

                # DNS-based detection
                if packet.haslayer(DNSQR):
                    queried_domain = (packet[DNSQR].qname.decode(errors="ignore").lower())

                    # Google Search
                    if "google" in queried_domain:
                        possible_apps.add("Google Search")
                    # Gmail
                    if "gmail" in queried_domain:
                        possible_apps.add("Gmail")
                    # ChatGPT / OpenAI
                    if ("openai" in queried_domain or "chatgpt" in queried_domain):
                        possible_apps.add("ChatGPT")
                    # NIT Calicut SIP Portal
                    if ("nitc" in queried_domain or "nitcalicut" in queried_domain or "sip" in queried_domain):
                        possible_apps.add("SIP Portal NIT Calicut")
                    # YouTube
                    if ("youtube" in queried_domain or "googlevideo" in queried_domain or "ytimg" in queried_domain):
                        possible_apps.add("YouTube")
                    # LinkedIn
                    if "linkedin" in queried_domain:
                        possible_apps.add("LinkedIn")
                    # PDF download (heuristic)
                    if ".pdf" in queried_domain:
                        possible_apps.add("PDF Download from Gmail")
except Exception as e:
    print(f"Error processing pcap file: {e}")                

# Global interval arrival time analysis
global_iat = []
all_packet_timestamps.sort()
for i in range(1, len(all_packet_timestamps)):
    global_iat.append(all_packet_timestamps[i] - all_packet_timestamps[i - 1])
global_iat_mean = (np.mean(global_iat) if global_iat else 0)
global_iat_min = (np.min(global_iat) if global_iat else 0)
global_iat_max = (np.max(global_iat) if global_iat else 0)
global_iat_std = (np.std(global_iat) if global_iat else 0)

#global packet length analysis
global_pkt_mean = (np.mean(all_packet_lengths) if all_packet_lengths else 0)
global_pkt_min = (np.min(all_packet_lengths) if all_packet_lengths else 0)
global_pkt_max = (np.max(all_packet_lengths) if all_packet_lengths else 0)
global_pkt_std = (np.std(all_packet_lengths) if all_packet_lengths else 0)

# Flow analysis
results = []
for flow_key, flow_data in flows.items():
    duration = ( flow_data["end_time"] - flow_data["start_time"])
    packet_lengths = flow_data["packet_lengths"]
    result = {
        "Flow": flow_key,
        "Duration(sec)": round(duration, 4),
        "SYN Count": flow_data["syn_count"]
    }
    results.append(result)

# Save (Write) results to file
try:
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("------------NETWORK TRAFFIC ANALYSIS------------\n\n")

        #--------------Qn a ------------------
        f.write("Q(a): How many flows existed in the captured traffic?\n")
        f.write(f"Total Flows: {len(flows)}\n\n")

        #--------------Qn b ------------------
        f.write("Q(b): How many packets were generated? Out of these packets, how many packets left the local network?\n")
        f.write(f"Total Packets: {total_packets}\n")
        f.write(f"Packets Leaving Local Network: {outgoing_packets}\n\n")

        #--------------Qn c and d ------------------
        f.write("Q(c): What was the duration of each flow?\n")
        f.write("Q(d): How many SYN packets were generated in a flow?\n")
        f.write("\n")
        for row in results:
            f.write(f"Flow: {row['Flow']} ")
            f.write(f"Duration: {row['Duration(sec)']} sec ")
            f.write(f"SYN Count: {row['SYN Count']}\n")
        f.write("\n")

        #--------------Qn e ------------------
        f.write("Q(e): What is the time difference between consecutive packets, including mean, min, max, and standard deviation of Inter Arrival Time?\n")
        f.write("Time Difference Between Consecutive Packets (Inter Arrival Time)\n\n")
        # Show sample values
        f.write("Sample Inter Arrival Times (first 20 packet pairs):\n")
        sample_count = min(20,len(global_iat))
        for i in range(sample_count):
            f.write(f"Packet {i+1} → Packet {i+2}: {global_iat[i]:.6f} sec\n")
        f.write("\n")
        # Statistics
        f.write("Inter Arrival Time Statistics\n\n")
        f.write(f"Mean IAT: {global_iat_mean:.6f} sec\n")
        f.write(f"Minimum IAT: {global_iat_min:.6f} sec\n")
        f.write(f"Maximum IAT: {global_iat_max:.6f} sec\n")
        f.write(f"Standard Deviation: {global_iat_std:.6f}\n")
        f.write("\n")

        #--------------Qn f ------------------
        f.write("Q(f): What is the minimum, maximum, mean, and standard deviation of packet lengths within a flow?\n")
        f.write(f"Packet Length Mean: {global_pkt_mean}\n")
        f.write(f"Packet Length Min: {global_pkt_min}\n")
        f.write(f"Packet Length Max: {global_pkt_max}\n")
        f.write(f"Packet Length Std: {global_pkt_std:.2f}\n")
        f.write("\n")

        #--------------Qn g ------------------
        f.write("Q(g): Identify the name of application layer protocols \n")
        f.write("Application Layer Protocols:\n")
        for proto in application_protocols:
            f.write(f"- {proto}\n")
        f.write("\n")

        #--------------Qn h ------------------
        f.write("Q(h):  Identify the name of the applications used in the captured traffic.\n")
        f.write("\nPossible Applications Used:\n")
        for app in possible_apps:
            f.write(f"- {app}\n")
        f.write("\n")

    end_script = time.time()

    print("\nFinished!")
    print(f"Total packets: {total_packets}")
    print(f"Total flows: {len(flows)}")
    print(
        f"Execution time: "
        f"{round(end_script - start_script, 2)} sec"
    )

    print("\nResults saved to:")
    print(OUTPUT_FILE)
except Exception as e:
    print(f"Error writing results to file: {e}")