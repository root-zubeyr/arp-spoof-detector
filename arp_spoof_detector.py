#!/usr/bin/env python3
import os
import sys
import time
import json
import logging 
from datetime import datetime
from threading import Lock, Thread
from subprocess import run, DEVNULL, check_output

from scapy.all import ARP, Ether, conf, sniff, srp, sendp, get_if_list, get_if_hwaddr

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-7s | %(message)s")
logger = logging.getLogger("ARP-Guard")

lock = Lock()

arp_table = {}
real_mac_cache = {}
cache_timestamp = {}
last_alert_time = {}
mac_to_ips = {}

COOLDOWN = 12
CACHE_TTL = 180
LOG_FILE = "arp_spoof_alerts.jsonl"
MAX_RETRY = 6
ARP_COUNT = 5
ARP_INTER = 0.35

def get_iface():
    try:
        route = check_output(["ip", "route", "show", "default"]).decode()
        for line in route.splitlines():
            if "default via" in line and "dev" in line:
                return line.split("dev")[1].split()[0]
    except:
        pass
    for i in get_if_list():
        if i.startswith(("en", "eth", "wl")) and i != "lo":
            return i
    return conf.iface

def get_gateway():
    try:
        route = check_output(["ip", "route", "show", "default"]).decode()
        for line in route.splitlines():
            if "default via" in line:
                return line.split("via")[1].split()[0]
    except:
        pass
    return None

def run_cmd(cmd):
    try:
        run(cmd, check=True, stdout=DEVNULL, stderr=DEVNULL)
        return True
    except:
        return False

def block(mac):
    mac = mac.lower()
    for ch in ["input", "forward"]:
        run_cmd(["nft", "add", "rule", "inet", "filter", ch, "ether", "saddr", mac, "drop"])
    for ch in ["INPUT", "FORWARD"]:
        run_cmd(["iptables", "-A", ch, "-m", "mac", "--mac-source", mac, "-j", "DROP"])

def corrective_arp(ip, mac):
    try:
        p = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=ip, hwsrc=mac, pdst="255.255.255.255")
        sendp(p, iface=iface, count=ARP_COUNT, inter=ARP_INTER, verbose=False)
    except:
        pass

def real_mac(ip):
    now = time.time()
    with lock:
        if ip in real_mac_cache and now - cache_timestamp.get(ip, 0) < CACHE_TTL:
            return real_mac_cache[ip]
    try:
        p = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        ans, _ = srp(p, timeout=1.8, retry=2, iface=iface, verbose=False)
        if ans:
            m = ans[0][1].hwsrc.lower()
            with lock:
                real_mac_cache[ip] = m
                cache_timestamp[ip] = now
            return m
    except:
        pass
    return None

def clean():
    now = time.time()
    with lock:
        for k in list(cache_timestamp):
            if now - cache_timestamp[k] > CACHE_TTL:
                real_mac_cache.pop(k, None)
                cache_timestamp.pop(k, None)

def alert(ip, fake, real, tag=""):
    now = time.time()
    with lock:
        if ip in last_alert_time and now - last_alert_time[ip] < COOLDOWN:
            return
        last_alert_time[ip] = now
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(LOG_FILE, "a") as f:
            json.dump({"ts": ts, "ip": ip, "seen": fake, "real": real, "tag": tag}, f)
            f.write("\n")
    except:
        pass
    logger.warning(f"SPOOF {tag} → {ip} sahte:{fake} gerçek:{real}")

def learn_gw_mac(gw):
    for _ in range(MAX_RETRY):
        m = real_mac(gw)
        if m:
            return m
        time.sleep(1.8)
    sys.exit(1)

def handler(pkt):
    if ARP not in pkt or pkt[ARP].op != 2:
        return
    arp = pkt[ARP]
    ip = arp.psrc
    mac = arp.hwsrc.lower()
    clean()
    with lock:
        known = arp_table.get(ip)
        mac_to_ips.setdefault(mac, set()).add(ip)
    if ip == gw_ip:
        if known and known != mac:
            real = real_mac(ip)
            if real and real != mac:
                alert(ip, mac, real, "[GW]")
                block(mac)
                corrective_arp(ip, real)
                with lock:
                    arp_table[ip] = real
                return
    elif known and known != mac:
        real = real_mac(ip)
        if real and real != mac:
            alert(ip, mac, real)
            block(mac)
            corrective_arp(ip, real)
            with lock:
                arp_table[ip] = real
            return
    with lock:
        if len(mac_to_ips.get(mac, set())) > 5:
            logger.warning(f"Çoklu IP MAC → {mac}")
        arp_table[ip] = mac

def periodic():
    while True:
        time.sleep(60)
        clean()

if __name__ == "__main__":
    if os.geteuid() != 0:
        sys.exit("sudo gerekli")
    global iface, gw_ip
    iface = get_iface()
    gw_ip = get_gateway()
    if not iface or not gw_ip:
        sys.exit("Arayüz veya gateway bulunamadı")
    logger.info(f"→ {iface}   gw: {gw_ip}")
    gw_mac = learn_gw_mac(gw_ip)
    with lock:
        arp_table[gw_ip] = gw_mac
    Thread(target=periodic, daemon=True).start()
    try:
        sniff(iface=iface, filter="arp", prn=handler, store=False)
    except KeyboardInterrupt:
        pass
