# Network Traffic Packet and Flow Analysis

A Python-based network traffic analysis project using **Wireshark packet capture (.pcap/.pcapng)** and **Python scripting** to analyze captured network traffic and extract flow-level and packet-level statistics.

This project captures **5 minutes of real-world network traffic** and analyzes various networking metrics such as:

- Number of flows
- Packet statistics
- Outgoing traffic
- Flow duration
- TCP SYN packet count
- Inter-arrival time statistics
- Packet length statistics
- Application layer protocols
- Applications used during capture

---

## Project Objective

The objective of this project is to:

1. Capture different types of network traffic using **Wireshark**
2. Save the captured traffic in `.pcap/.pcapng` format
3. Analyze the traffic using a Python script
4. Export results into a readable report file

---

## Traffic Captured

Traffic was captured for **5 minutes** using Wireshark.

### Activities Performed During Capture

1. Google Search  
2. Gmail  
3. ChatGPT  
4. SIP Portal – NIT Calicut  
5. PDF Download from Gmail  
6. YouTube Video Streaming  
7. LinkedIn

---

## Features Implemented

The analysis script answers the following questions:

### (a) Number of Flows

Calculates the total number of network flows based on:

```text
(Source IP,
 Destination IP,
 Source Port,
 Destination Port,
 Protocol)
```

---

### (b) Packet Statistics

Determines:

- Total number of packets generated
- Number of packets leaving the local network

---

### (c) Flow Duration

Calculates:

```text
Flow Duration =
End Time - Start Time
```

for every network flow.

---

### (d) SYN Packet Count

Counts the number of:

```text
TCP SYN packets
```

generated within each flow.

---

### (e) Inter Arrival Time (IAT)

Computes the **time difference between consecutive packets** across the entire capture.

Statistics calculated:

- Mean
- Minimum
- Maximum
- Standard Deviation

---

### (f) Packet Length Statistics

Computes packet size statistics for the captured traffic:

- Mean packet length
- Minimum packet length
- Maximum packet length
- Standard deviation

---

### (g) Application Layer Protocol Detection

Detects protocols such as:

- DNS
- HTTP
- HTTPS/TLS

---

### (h) Application Identification

Identifies applications used during traffic capture using:

- DNS queries
- Domain analysis
- Port information

Applications detected include:

- Google Search
- Gmail
- ChatGPT
- SIP Portal NIT Calicut
- YouTube
- LinkedIn
- PDF Download

---

## Project Structure

```text
NetworkTraffic_PacketAndFlowAnalysis/
│
├── traffic_capture.pcapng
│
├── analyze_traffic.py
│
├── results_packetAnalysis.txt
│
├── requirements.txt
│
└── README.md
```

---

## Technologies Used

### Network Traffic Capture

- Wireshark

### Programming Language

- Python 3

### Python Libraries

- Scapy
- NumPy
- Pandas
- ipaddress

---

## Installation

### 1. Clone Repository

```bash
git clone <your-repository-link>
cd NetworkTraffic_PacketAndFlowAnalysis
```

---

### 2. Create Virtual Environment

#### Windows PowerShell

```powershell
python -m venv venv
venv\Scripts\activate
```

#### Git Bash

```bash
python -m venv venv
source venv/Scripts/activate
```

---

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

Or manually:

```bash
pip install scapy numpy pandas
```

---

## How to Run

Ensure the packet capture file exists inside:

```text
captures/
```

Then run:

```bash
python script/analyze_traffic.py
```

---

## Output

The script generates:

```text
results_packetAnalysis.txt
```

inside the `output/` folder.

The output report contains:

- Flow statistics
- Packet statistics
- Inter-arrival time analysis
- Protocol detection
- Application detection
- Flow duration
- SYN packet count

---

## Sample Output

```text
NETWORK TRAFFIC ANALYSIS REPORT

QUESTION (A)
------------------------------------------------
Total Number of Flows: 1824

QUESTION (B)
------------------------------------------------
Total Packets Generated: 1300000
Packets Leaving Local Network: 450321

QUESTION (E)
------------------------------------------------
Mean IAT: 0.000227 sec
Minimum IAT: 0.000001 sec
Maximum IAT: 2.049760 sec
Standard Deviation: 0.006849
```

---

## Key Networking Concepts Used

- TCP/IP Protocol Stack
- Network Flows
- Packet Analysis
- Inter Arrival Time (IAT)
- TCP SYN Flag Analysis
- Packet Statistics
- Application Layer Protocol Detection
- Wireshark Traffic Capture

---

## Author
**Pooja Senthilkumar**
This project is created for **educational and academic purposes**.
