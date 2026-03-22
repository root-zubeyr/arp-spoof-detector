# arp-spoof-detector
Lightweight ARP security engine that detects, blocks, and corrects MITM attacks on local networks

## 🚀 Features
- Real-time ARP spoof detection
- Gateway protection
- Automatic attacker blocking (iptables/nftables)
- ARP table correction
- MAC-IP anomaly detection
- Logging system (JSONL)

- ## ⚙️ Requirements
- Linux (root required)
- Python 3
- Scapy (`pip install scapy`)
- iptables or nftables for blocking

- ## 📦 Installation
```bash
git clone https://github.com/root-zubeyr/arp-spoof-detector.git
cd arp-guard
pip install scapy

## 5️⃣ Usage / Çalıştırma
```md
## ▶️ Usage
```bash
sudo python3 arp_spoof_detector.py

## 6️⃣ Testing / Test Etme
```md
## 🧪 Testing
Use tools like Bettercap or arpspoof to simulate ARP spoofing atta
