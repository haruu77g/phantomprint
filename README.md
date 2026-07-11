# PHANTOMPRINT

**Passive Hybrid ANalysis Tool for Os-agnostic Multiprotocol PRofiling & INTelligence**

![Python](https://img.shields.io/badge/Python-3.11+-blue)
![License](https://img.shields.io/badge/License-GPL--3.0-green)
![Status](https://img.shields.io/badge/Status-Active%20Development-yellow)
![MITRE](https://img.shields.io/badge/MITRE-T1040%20%7C%20T1046-red)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey)

> Fingerprint hosts on your network **without sending a single packet**.

PHANTOMPRINT correlates multiple passive signals (TCP/IP stack, TLS/JA4, DHCP Option 55, HTTP/2 HPACK, DNS behavior) to identify operating systems, browsers, and devices from observed traffic alone.

---

## Why PHANTOMPRINT?

| Tool | TCP/IP FP | TLS JA4 | DHCP FP | Multi-signal | Confidence Score |
|------|-----------|---------|---------|--------------|------------------|
| p0f | ✅ | ❌ | ❌ | ❌ | ❌ |
| Zeek | ✅ | plugin | ❌ | ❌ | ❌ |
| JA3er | ❌ | ✅ | ❌ | ❌ | ❌ |
| **PHANTOMPRINT** | ✅ | ✅ | ✅ | ✅ | ✅ |

**p0f** hasn't been maintained since 2014. **Zeek** requires heavy infrastructure. **Nothing** correlates all these signals into a unified, scored host profile.

---

## How It Works

```
Network Traffic
      │
      ├─── TCP SYN/SYN-ACK ──→ TCPIPParser  ──→ TTL + Window + Options hash
      ├─── TLS ClientHello  ──→ TLSParser    ──→ JA4 fingerprint
      ├─── DHCP DISCOVER    ──→ DHCPParser   ──→ Option 55 fingerprint
      └─── (HTTP/2, DNS)    ──→ [coming v1.5]
                                      │
                                 SignalMerger
                                      │
                            Bayesian Score Engine
                                      │
                               HostProfile
                          ┌──────────┴──────────┐
                       Terminal              JSON / STIX
```

No packets are sent. No connections are opened. Fully passive.

---

## Installation

```bash
git clone https://github.com/youruser/phantomprint
cd phantomprint
pip install -e ".[dev]"
```

Requires Python 3.11+ and root/CAP_NET_RAW for live capture.

---

## Usage

### Live capture
```bash
sudo phantomprint live -i eth0
sudo phantomprint live -i eth0 -t 60 -o results.json
sudo phantomprint live -i eth0 --verbose
```

### Analyze a PCAP file (no root needed)
```bash
phantomprint pcap capture.pcap
phantomprint pcap capture.pcap -o results.json
```

### List loaded signatures
```bash
phantomprint signatures
phantomprint signatures --category os
phantomprint signatures --category browser
```

---

## Example Output

```
◈ PHANTOMPRINT v0.1.0 — Results (4 hosts)

┌─────────────────┬──────────────────┬───────────────┬──────────────────────┬───────┐
│ Host / MAC      │ OS               │ Browser / App │ Signals              │ Score │
├─────────────────┼──────────────────┼───────────────┼──────────────────────┼───────┤
│ 192.168.1.45    │ Windows 11       │ Chrome 120    │ TCP TLS DHCP         │  78%  │
│ 192.168.1.12    │ Linux 6.x        │ curl          │ TCP TLS              │  52%  │
│ 192.168.1.1     │ Cisco IOS Router │ —             │ TCP                  │  18%  │
│ aa:bb:cc:dd:... │ Android 12-14    │ —             │ DHCP                 │  31%  │
└─────────────────┴──────────────────┴───────────────┴──────────────────────┴───────┘
```

---

## Signature Format

Signatures live in `signatures/raw/` as YAML files:

```yaml
# signatures/raw/os/windows11.yaml
id: os_win11
name: Windows 11
type: os
description: Windows 11 / Windows Server 2022
signals:
  tcp_ip:
    - "128:65535:1:mss,nop,wscale,sackok,timestamp"
    - "128:64240:1:mss,nop,wscale,sackok,timestamp"
  dhcp:
    - "1,3,6,15,31,33,43,44,46,47,119,121,249,252"
```

Add your own signatures and they're loaded automatically.

---

## Use Cases

- **Red Team**: Silent OS/browser reconnaissance before exploitation — zero IDS alerts
- **Pentesting**: Map network assets passively during initial access phase
- **SOC / Threat Hunting**: Detect rogue devices or fingerprint changes (VM migration, evasion)
- **Bug Bounty**: Passive infrastructure recon without generating target-side logs
- **Forensics**: Reconstruct which OS/browsers were active from historical PCAPs
- **Threat Intelligence**: Track actors rotating infrastructure via composite hash

---

## Roadmap

```
v1.0  ─ TCP/IP + TLS/JA4 + DHCP parsers (current)
v1.5  ─ HTTP/2 HPACK fingerprinting, DNS behavior analysis, Rust capture engine
v2.0  ─ Cross-sensor correlation (Redis), behavioral drift detection, STIX 2.1 output
v2.5  ─ Zeek plugin, Elastic/Splunk output, web UI
```

---

## Legal & Ethics

PHANTOMPRINT is designed for use on networks you own or have explicit authorization to monitor. Passive fingerprinting falls under MITRE ATT&CK T1040 (Network Sniffing) — ensure you have appropriate authorization before deployment.

Licensed under GPL-3.0.
