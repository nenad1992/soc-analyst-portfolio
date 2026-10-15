# Manual installation of the Wazuh SIEM stack (Ubuntu Server 22.04 LTS / VirtualBox)

## Goal

I installed the full Wazuh SIEM stack (indexer, manager, dashboard) on Ubuntu
Server 22.04 LTS inside VirtualBox, doing it manually package by package instead
of running the official `wazuh-install.sh` all-in-one script.

The point wasn't just to end up with a working SIEM. I wanted to actually
understand the architecture: how the components talk to each other, where the TLS
certificates come from, and which dependencies the automated script quietly
handles for you. Doing it by hand also meant dealing with real failures when
something broke, which is where most of the learning happened.

## Architecture

```
Suricata (eve.json) ──► [planned: next step]

Wazuh Manager (analysis, ruleset)
        │
        │  Filebeat (sends alerts.json over HTTPS/TLS)
        ▼
Wazuh Indexer (OpenSearch database, TLS)
        ▲
        │  HTTPS/TLS
        │
Wazuh Dashboard (UI)
```

- **Wazuh Indexer** — the OpenSearch database that stores and indexes all
  alerts/events.
- **Wazuh Manager** — analyzes incoming logs, generates alerts from the ruleset,
  and writes them locally to `/var/ossec/logs/alerts/alerts.json`.
- **Filebeat** — reads `alerts.json` and ships it to the indexer over HTTPS. The
  manager does not write to the database directly; Filebeat is what gets the data
  there.
- **Wazuh Dashboard** — the web UI (a fork of OpenSearch Dashboards). It pulls
  data from the indexer and talks to the manager over the REST API (port 55000)
  for agent management.

All three talk to each other over TLS only, using a self-signed CA
(`root-ca.pem`) that I generated with `wazuh-certs-tool.sh`.

**Lab environment:**
- Ubuntu Server 22.04 LTS, VirtualBox
- Host-only network `192.168.56.0/24`, VM IP `192.168.56.105`
- Wazuh version: `4.14.7-rc1`

## Key problems and solutions

Because the manual install skips everything `wazuh-install.sh` does for you, I had
to spot and fix each of those steps myself. These are the ones that actually cost
me time.

### 1. Wrong URL for the Wazuh GPG key
My first attempt at adding the repo used `package.wazuh.com` (no "s") instead of
`packages.wazuh.com`. That gave me an empty (0 byte) GPG keyring file and a
`NO_PUBKEY` error on `apt update`. Took me a minute to realize it was a one-letter
typo and not a real repo problem.

Fix was just to re-import the key from the right URL:
```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
```

### 2. TLS certificates are not generated automatically
The all-in-one script generates certs for you. `apt install
wazuh-indexer/manager/dashboard` does not. It only drops the binaries, so every
service died on startup looking for `root-ca.pem` and its node certificates, none
of which existed yet.

So I pulled down `wazuh-certs-tool.sh` and `config.yml`, generated the certs with
`wazuh-certs-tool.sh -A`, and copied them into the right place for each component:
- Indexer: `/etc/wazuh-indexer/certs/`
- Filebeat (manager → indexer link): `/etc/filebeat/certs/` (names `filebeat.pem`,
  `filebeat-key.pem`, `root-ca.pem`)
- Dashboard: `/etc/wazuh-dashboard/certs/` (names `dashboard.pem`,
  `dashboard-key.pem`, `root-ca.pem`)

One thing that bit me: the file names each component expects are not the same
across components. I stopped guessing and just checked each component's YAML
directly with `grep -i ssl <config>.yml`.

### 3. Filebeat is not pulled in by the manual install
The manager doesn't send anything to the indexer on its own. Filebeat does that,
and when you install manually it is not an automatic dependency of the
`wazuh-manager` package. So the manager was happily generating alerts locally
while the dashboard sat completely empty, which was confusing until I traced it
back to the missing shipper.

Fix: install it explicitly (`apt install filebeat`), grab the official
`filebeat.yml` template, `wazuh-template.json`, and the Wazuh filebeat module, and
add the credentials to a keystore (`filebeat keystore add username/password`).

### 4. DNS hijacking on `raw.githubusercontent.com`
Downloading `wazuh-template.json` from GitHub kept returning 404, even though the
exact same URL worked fine from another machine. My first assumption was a wrong
version or path. It wasn't. `curl -v` showed the VM was connecting to
`103.224.182.253`, which is nowhere near the Fastly/GitHub CDN range
(`185.199.108-111.x`). Some DNS resolver along the way (ISP level, most likely)
was pointing me at the wrong server, and that server just returns a generic 404
page.

Workaround was to skip DNS and force the right IP through curl:
```bash
curl -o /etc/filebeat/wazuh-template.json --resolve raw.githubusercontent.com:443:185.199.108.133 https://raw.githubusercontent.com/wazuh/wazuh/v4.14.7/extensions/elasticsearch/7.x/wazuh-template.json
```

### 5. Certificates "disappearing" after certain steps
Twice (once with filebeat, once with dashboard) certs I had already copied were
gone from their folders by the time I went to test the config, so I got `ENOENT:
no such file or directory`. I never fully pinned down why. My best guess is that
some early `chmod`/`mkdir` sequence left the folders in a weird state. What saved
me was still having the original certs, so I just re-copied them from
`~/wazuh-certificates/`.

Lesson I took from it: keep that `wazuh-certificates/` folder around (outside
`/etc/`) until the whole stack is stable, because you end up re-provisioning
individual components more than once.

### 6. Disk full from a vulnerability-detection temp file
After a few hours the indexer and manager started dying with `No space left on
device`, even though `df -h` had looked fine when I started. Running
`du -h -x / --max-depth=2` pointed straight at it:
`/var/ossec/tmp/vd_1.0.0_vd_4.13.0.tar` was sitting at **8.5 GB**. It was a
half-unpacked CVE feed for the vulnerability-detection module, and it got
regenerated every time the manager tried to start.

For now I deleted it and turned the module off until I can give the disk more
room:
```bash
sudo rm -f /var/ossec/tmp/vd_1.0.0_vd_4.13.0.tar
```
plus `<vulnerability-detection><enabled>no</enabled></vulnerability-detection>` in
`/var/ossec/etc/ossec.conf`. The real fix is on the TODO list: grow the VirtualBox
disk from 18 GB to something like 40-50 GB and turn the module back on.

### 7. `wazuh-apid` timeout and a leftover "failed" marker
After a VM restart the manager started timing out on boot (`start operation timed
out`). I bumped `TimeoutStartSec` with a systemd override, but the API process
(`wazuh-apid`) still refused to come up. Two things were going on: a leftover
`wazuh-apid.failed` marker file, and underneath that the same full-disk problem
from point 6, which was the actual root cause.

The override:
```bash
sudo mkdir -p /etc/systemd/system/wazuh-manager.service.d
sudo tee /etc/systemd/system/wazuh-manager.service.d/override.conf << 'EOF'
[Service]
TimeoutStartSec=300
EOF
sudo systemctl daemon-reload
```
But the restart only actually succeeded once I'd freed up the disk.

## What I took away from this

- Installing by hand drags all the hidden dependencies into the open: the TLS
  certs, Filebeat as its own package, the per-component cert file names. The
  all-in-one script does all of that silently, and you learn none of it.
- "Disk full" is not always disk full, and sometimes it really is. Early on,
  apport told me the disk was full and it wasn't (an inode/GB check had plenty of
  room). Later the identical message was dead on, caused by that one temp file. I
  stopped trusting the message and started checking `df -h` and `df -i` myself.
- A network problem can wear an application's clothes. That GitHub 404 looked like
  a bad URL for ages, when it was really DNS hijacking one layer down. `curl -v`
  and checking the IP range is what gave it away.
- `systemctl edit` can silently fail to save if you close the editor the wrong
  way. Now I either `cat` the file afterwards to confirm, or skip the editor
  entirely and write it with `tee`.

## Next steps

- Grow the VirtualBox disk and re-enable vulnerability-detection.
- Snapshot the stack while it's stable, before the next round of work.

## Continuation

I wrote up the Suricata `eve.json` integration (via a custom decoder/rules
approach rather than the stock Filebeat module) separately:
[suricata-decoder-integration.md](suricata-decoder-integration.md).
