# SSH Brute-Force Detection with Wazuh

**Scenario 01 — Credential Access / Brute Force**

Detection and triage of an SSH brute-force attack against a monitored Linux
host, including a notable detection-evasion finding: how attack parallelism
can bypass a threshold-based correlation rule.

---

## 1. Objective

Demonstrate the full detection lifecycle for an SSH brute-force attack:
generate the attack, observe how Wazuh decodes and correlates the events,
triage the resulting alert as an L1 analyst would, and identify the limits
of threshold-based detection.

**Why it matters:** SSH brute force is one of the most common attacks against
internet-facing Linux hosts (MITRE ATT&CK T1110). Understanding how it is
detected — and how it can be evaded — is core SOC knowledge.

---

## 2. Environment

| Role | Host | IP | Notes |
|------|------|----|----|
| Wazuh server (manager, indexer, dashboard) | `Ubuntu-implementacija` | `192.168.100.145` | Target, monitored as agent `000` |
| Attacker | Kali Linux VM | `192.168.56.101` (NAT'd) | Source of the attack |

**Wazuh version:** 4.14.x
**Log source on target:** `journald` (modern OpenSSH logs via `sshd-session`)

> **Topology note:** The Kali VM reaches the target through a VirtualBox NAT
> gateway. As a result, the source IP recorded by Wazuh is **not** the Kali
> address but the NAT-translated host address `192.168.100.182`. This is a
> realistic reflection of production environments, where NAT, proxies and load
> balancers mask the true origin of traffic. **Lesson: never assume the source
> IP — always verify what the system actually logged.**

---

## 3. Understanding the Detection Pipeline

Before attacking, the event pipeline was validated with `wazuh-logtest`, which
runs a single log line through the three processing phases.

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Input (a single failed SSH login):

```
Oct  6 10:15:01 Ubuntu-implementacija sshd[1234]: Failed password for invalid user test from 192.168.100.50 port 51234 ssh2
```

| Phase | What happens | Key output |
|-------|--------------|-----------|
| 1 — Pre-decoding | Extracts the "envelope" | `timestamp`, `hostname`, `program_name: sshd` |
| 2 — Decoding | Decoder `sshd` extracts fields | `srcip`, `srcuser` |
| 3 — Filtering | Rule engine evaluates | `rule.id: 5710`, `level: 5` |

**Takeaway:** the decoder extracting `srcip` is what later makes IP-based
correlation possible. Without decoded fields there is nothing to correlate on.

<!-- SCREENSHOT: wazuh-logtest output showing all three phases -->
*(screenshot: `screenshots/01-logtest-phases.png`)*

---

## 4. The Correlation Rule

The brute-force detection is built on a parent/child rule chain. The relevant
built-in rule:

```xml
<rule id="5712" level="10" frequency="8" timeframe="120" ignore="60">
  <if_matched_sid>5710</if_matched_sid>
  <same_source_ip />
  <description>sshd: brute force trying to get access to the system. Non existent user.</description>
  <mitre>
    <id>T1110</id>
  </mitre>
</rule>
```

Read as a sentence: *if rule 5710 fires 8 times from the same source IP within
120 seconds, raise the event to level 10, then stay silent for 60 seconds.*

| Element | Meaning |
|---------|---------|
| `if_matched_sid` 5710 | Listens to a **rule**, not a raw log — counts occurrences of 5710 |
| `frequency` 8 | Must occur 8 times to fire |
| `timeframe` 120 | …within a 120-second window (separates a human from a tool) |
| `same_source_ip` | All 8 must come from the **same** IP |
| `ignore` 60 | After firing, suppress for 60s (prevents alert flooding) |

The full SSH rule group hangs off a single root rule:

```xml
<rule id="5700" level="0" noalert="1">
  <decoded_as>sshd</decoded_as>
</rule>
```

Rule 5700 matches every log decoded as `sshd` and never alerts itself; all
other SSH rules chain from it via `if_sid`.

---

## 5. Executing the Attack

A short password list was used against a non-existent user (so the attack is
guaranteed to fail — no real account can be compromised).

```bash
printf 'password\n123456\nadmin\nroot\ntoor\nletmein\nqwerty\nwelcome\nmonkey\ndragon\n' > pass.txt
hydra -l nepostojeci -P pass.txt ssh://192.168.100.145 -t 4 -V
```

<!-- SCREENSHOT: Hydra running in the Kali terminal -->
*(screenshot: `screenshots/02-hydra-run.png`)*

---

## 6. Key Finding — Parallelism Evades Threshold Correlation

> This is the most valuable result of the scenario.

**First run (`-t 4`, parallel):** The dashboard showed a stream of level-5
alerts (rule 5710 and the PAM equivalent 5503), but the level-10 brute-force
alert (5712) **never fired** — even though well over 8 failures occurred within
seconds, comfortably inside the 120s window.

Inspecting the timestamps revealed the cause: with 4 parallel threads, Hydra
delivered attempts in bursts that **shared near-identical sub-second
timestamps**, and the correlation counter did not register 8 clean, sequential
`5710` events from the single source.

**Second run (`-t 1 -W 1`, serial):** Running one attempt at a time with a
1-second gap produced an orderly sequence — and rule **5712 fired as expected**
at level 10.

```bash
hydra -l nepostojeci -P pass.txt ssh://192.168.100.145 -t 1 -W 1 -V
```

### Alerts observed in the successful (serial) run

| Rule ID | Level | Description |
|---------|-------|-------------|
| 5710 | 5 | sshd: attempt to login using a non-existent user |
| 5503 | 5 | PAM: user login failed |
| **5712** | **10** | **sshd: brute force trying to get access to the system** |
| 5758 | 8 | Maximum authentication attempts exceeded (OpenSSH closed the session) |
| 2502 | 10 | syslog: user missed the password more than one time |

<!-- SCREENSHOT: dashboard alert list showing 5712 (level 10) and surrounding alerts -->
*(screenshot: `screenshots/03-dashboard-alerts.png`)*

### Security implication

A real attacker can **deliberately slow or parallelise** a brute-force attack
to slip under `frequency=8 / timeframe=120`. A "low and slow" attack (one
attempt every few minutes) or rotation across source IPs would never trigger
this rule. **Threshold-based correlation alone is not complete protection** —
it must be complemented by other controls (rate limiting, key-based auth,
fail2ban, anomaly detection).

---

## 7. Triage — Alert 5712

The `previous_output` field of the 5712 alert carries the raw logs that led to
correlation, which makes triage straightforward.

| Question | Answer (from alert JSON) |
|----------|--------------------------|
| **What happened?** | SSH brute force, rule 5712, level 10 |
| **Source?** | `192.168.100.182` (internal host via NAT — authorised lab activity) |
| **Target?** | `Ubuntu-implementacija` (agent 000), user `nepostojeci` (does not exist) |
| **When / how much?** | 8 failures in ~18 s, same IP / same port — automated pattern |
| **Technique?** | MITRE T1110 — Brute Force (Credential Access) |

<!-- SCREENSHOT: expanded 5712 alert, JSON tab -->
*(screenshot: `screenshots/04-alert-5712-json.png`)*

### Triage conclusion (ticket-ready)

> **Alert:** SSH brute force (rule 5712, level 10) — MITRE T1110.
> **Source:** 192.168.100.182 (internal host via NAT, authorised lab test).
> **Target:** Ubuntu-implementacija (agent 000), account "nepostojeci" (non-existent).
> **Detail:** 8 failed attempts in ~18 s from a single IP/port — clear automated pattern.
> **Assessment:** True positive by detection, but **benign** — authorised test in a
> controlled environment, the targeted account does not exist, no access was gained.
> **Recommendation:** Close as benign/authorised testing. In production the next
> steps would be: block the source IP (Active Response) and **verify no successful
> login occurred from the same address**.

**Analyst reflex:** after any brute force, always confirm the attack did **not**
succeed. Filter for a successful SSH login from the same source:

```
data.srcip: 192.168.100.182 AND rule.id: 5715
```

---

## 8. MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|----|
| Credential Access | Brute Force | T1110 |
| (sub-technique, single attempts) | Password Guessing | T1110.001 |

---

## 9. Remediation / Production Recommendations

- **Block the source** automatically via Wazuh Active Response (`firewall-drop`).
- **Enforce key-based authentication** and disable password login where possible.
- **Rate-limit** SSH (e.g. `fail2ban`, `sshd` `MaxAuthTries`).
- **Add low-and-slow detection** — a longer-window correlation rule (e.g. N
  failures over hours) to catch attacks that evade the 120s threshold, directly
  addressing the finding in Section 6.
- **Monitor for success-after-failure** — the highest-value correlation: a burst
  of failures followed by a successful login from the same IP.

---

## 10. Skills Demonstrated

- Wazuh event pipeline (decoder → rule → correlation)
- Reading and interpreting correlation rule logic
- Live attack generation (Hydra) and detection validation
- Alert triage and ticket-ready documentation
- Identifying and articulating a detection gap (evasion via parallelism)
- MITRE ATT&CK mapping
- Network-topology awareness (NAT and source-IP attribution)
