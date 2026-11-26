# HTTP Session Hijacking via ARP Spoofing and Sidejacking

An educational offensive-security project for **CSE406: Cyber Security Sessional** (BUET, CSE).
It demonstrates how an attacker on the same LAN can hijack a victim's web session over
plaintext HTTP, then shows the countermeasure that defeats the attack.

> ⚠️ **Ethical and legal scope.** Every part of this was built and run on a private,
> isolated LAN using only machines owned by the authors, with no route to any external
> network. ARP poisoning, traffic interception and credential replay are illegal without
> explicit authorisation. Use this only on networks and devices you own or are authorised
> to test. All account data in the demo is fabricated.

## How the attack works

Three machines share one isolated, switched LAN:

| Role | OS | Software |
|---|---|---|
| Attacker | Linux | `arp_poison.py`, `sniff_cookie.py`, `curl` replay |
| Server | Linux | Flask login app (`server.py`) |
| Victim | macOS | Web browser |

The attacker abuses the unauthenticated **ARP** protocol to become a transparent
man-in-the-middle. Because the site runs over plaintext **HTTP** and the server authenticates
each request by its session cookie alone, the attacker reads the `Cookie:` header off the wire
and replays it, impersonating the victim **without ever learning the password**.

The attack succeeds only when three conditions hold at once:
1. **ARP is unauthenticated** — the victim accepts a forged reply and the attacker becomes MITM.
2. **The transport is plaintext HTTP** — the cookie appears verbatim on the wire.
3. **The server authenticates by cookie alone** — a replayed token is indistinguishable from the real user.

## The countermeasure

Serving the site over **HTTPS (TLS)** encrypts the whole exchange, so the MITM — still in the
path — sees only ciphertext and the cookie can no longer be stolen. This is combined with
cookie hardening (`Secure`, `HttpOnly`, `SameSite=Strict`) and an HSTS header. The result is
the intended asymmetry: ARP poisoning still succeeds, but **sidejacking fails** — proving the
root cause was the plaintext transport, not the network layer.

## Repository contents

| File | Purpose |
|---|---|
| `server.py` | Intentionally vulnerable Flask login app (plaintext HTTP, weak cookie) |
| `arp_poison.py` | ARP cache poisoner that makes the attacker a MITM (Scapy) |
| `sniff_cookie.py` | Sniffer that captures the cleartext session cookie |
| `server_https.py` | Hardened app: TLS, hardened cookie, HSTS |
| `sniff_cookie_https.py` | Sniffer re-run against TLS, showing only ciphertext |
| `Report.pdf` | Full implementation report with observations and evidence |

## Setup and usage

**Prerequisites:** Python 3, Scapy, Flask, and a Linux attacker host (for raw ARP injection
and kernel IP forwarding).

```bash
pip install scapy flask
```

Before running, set the `VICTIM` and `SERVER` IPs in `arp_poison.py` to match your own lab.

### Running the attack (HTTP)
```bash
# Server
sudo python3 server.py

# Attacker — enable forwarding so the victim stays online
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -P FORWARD ACCEPT        # permit forwarded traffic
sudo python3 arp_poison.py             # verify two distinct MACs are printed

# Attacker — in a second terminal
sudo python3 sniff_cookie.py

# Victim: log in and browse the site; the sniffer prints the cookie.
# Attacker: replay it
curl http://SERVER_IP/account -H "Cookie: sessionid=STOLEN_VALUE"
```

### Running the defense (HTTPS)
```bash
# Generate a self-signed certificate
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 30 \
  -subj "/CN=SERVER_IP"

sudo python3 server_https.py
sudo python3 sniff_cookie_https.py     # now shows ciphertext only — no cookie
```

## Authors

- MD. Shadman Shafie
- Arpita Dhar
- Prachurja Dhar