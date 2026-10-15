# SOC Analyst Home Lab Portfolio

A hands-on project built around one goal: learn Wazuh properly. Not by running the
one-line installer and clicking through the dashboard, but by building the whole
SIEM by hand, step by step, and then actually working through it — its pipeline,
its modules, and real detection scenarios on live hosts. To understand what I'm
detecting, I also attack: I run real exploits against a vulnerable target and build
the detection for each one myself.

## The approach

The thread running through everything here is learning Wazuh deeply, from the
ground up.

**Build it by hand.** I installed the full Wazuh stack (indexer, manager,
dashboard) package by package instead of using the automated script. Doing it the
hard way is the point — it surfaces every dependency the installer hides (TLS
certificates, Filebeat as its own log shipper, the exact config names each
component wants) and forces real troubleshooting when things break (DNS hijacking,
disk filling up, systemd timeouts). All of that is written up as it happened, not
cleaned up after the fact.

**Work through it on a live endpoint.** With the SIEM running, I went module by
module on a monitored host: the event pipeline (decoder → rule → correlation), the
Vulnerability Detection module, alert triage. Each one became a scenario where I
generate the activity, watch how Wazuh handles it, and triage the result the way
an L1 analyst would — including the cases where Wazuh's default behaviour has
limits worth knowing about.

**Attack, so I understand the detection.** In a separate attack range I exploit a
deliberately vulnerable target (Metasploitable2), then build network detection for
each exploit: custom Suricata rules, wired into Wazuh through a custom
decoder/rules approach with MITRE ATT&CK mapping, and finally Active Response that
blocks the attacker automatically. Running the attack myself is what makes the
detection meaningful — I know exactly what it's supposed to catch and why.

> **Two environments.** The Wazuh learning and endpoint scenarios run against a
> live monitored host on one network. The exploit work and its network detection
> run in a separate attack range (Kali + Metasploitable2) with its own hand-built
> Wazuh stack. Both exist for the same reason: to learn Wazuh from more than one
> angle.

## Topology

The attack range (Kali → Metasploitable2) with the Suricata sensor watching
passively:

![Network topology](assets/network_topology.svg)

## Infrastructure & SIEM Setup

Building and understanding the stack itself.

Manual install of the Wazuh SIEM stack (indexer, manager, dashboard) on Ubuntu
Server — TLS certificates, Filebeat integration, and the real troubleshooting that
came with doing it by hand:
[infrastructure/wazuh-siem-setup/README.md](infrastructure/wazuh-siem-setup/README.md)

Suricata IDS integrated with Wazuh via a custom decoder/rules approach, with MITRE
ATT&CK mapping showing up in the Threat Hunting dashboard:
[infrastructure/wazuh-siem-setup/suricata-decoder-integration.md](infrastructure/wazuh-siem-setup/suricata-decoder-integration.md)

Wazuh Active Response — automatic iptables block of the attacker's IP when a
custom Suricata rule fires, with auto-unblock after a timeout:
[infrastructure/wazuh-siem-setup/active-response.md](infrastructure/wazuh-siem-setup/active-response.md)

## Wazuh Detection Scenarios

Working through Wazuh on a live monitored endpoint — the blue-team side, one module
at a time.

| # | Scenario | What it covers | MITRE |
|---|----------|----------------|-------|
| 01 | [SSH Brute Force](01-ssh-brute-force) | Event pipeline, correlation rules, and a finding on how attack parallelism evades threshold detection | T1110 |
| 02 | [Vulnerability Management](02-vulnerability-mgmt) | Vulnerability Detection module, CVSS triage, risk-based remediation, and state-based verification | — |

## Exploitation Writeups

The attack range. Each writeup runs the full flow end to end — enumeration,
exploitation (by hand and/or with Metasploit), detection from the blue-team side,
and remediation — with MITRE ATT&CK mapping throughout.

| # | Name | CVE | Method | MITRE ATT&CK |
|---|-------|-----|-------|---------------|
| 00 | [Recon](writeups/00-recon) | — | Nmap full scan | T1046, T1590 |
| 01 | [vsftpd 2.3.4 Backdoor](writeups/01-vsftpd-backdoor) | CVE-2011-2523 | Manual + Metasploit | T1190, T1059 |
| 02 | [Samba usermap_script RCE](writeups/02-samba-usermap) | CVE-2007-2447 | Manual + Metasploit | T1190, T1059, T1021.002 |
| 03 | [UnrealIRCd Backdoor](writeups/03-unrealircd-backdoor) | CVE-2010-2075 | Manual + Metasploit | T1190, T1059 |
| 04 | [distcc RCE](writeups/04-distccd-rce) | CVE-2004-2687 | Metasploit | T1190, T1059 |

## Detection Engineering

The Suricata rules behind the exploits above — one per attack, each tested against
the real thing, including tracking down and fixing a false positive:
[detection-engineering/](detection-engineering)

## Tools used in the lab
- Wazuh SIEM (indexer, manager, dashboard, Filebeat) — built and run by hand
- Suricata IDS (custom rules, MITRE ATT&CK mapping)
- Kali Linux (attacker), Metasploitable2 (target)
- Nmap, Metasploit Framework, Hydra, smbclient, netcat
- VirtualBox (host-only networking)

## About me

I'm moving from data engineering into cybersecurity, aiming at SOC Analyst (L1/L2)
roles. My background is in physical chemistry and spectroscopy (University of
Belgrade), and I currently work as a Data Integration Engineer at ZF Group. This
lab is where I learn the defensive tooling properly and work through attacks from
both sides to prepare for a SOC role. I hold CompTIA Security+.
