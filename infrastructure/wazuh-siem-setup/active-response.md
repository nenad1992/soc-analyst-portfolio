# Wazuh Active Response: blocking the attacker automatically

Follows on from [the Suricata → Wazuh integration](suricata-decoder-integration.md).
Here I set up the **Active Response** module so Wazuh automatically blocks the
attacker's IP whenever one of my custom Suricata rules fires.

## Goal

Close the loop. Instead of just *seeing* the attack in the dashboard, I wanted the
system to *act* on it — drop the attacker's IP at the firewall (iptables) the
moment Wazuh raises the alert, then lift the block automatically after a timeout.

```
Suricata alert (eve.json)
        ↓
Wazuh logcollector → custom rule 100100-100103 (level 10, MITRE tag)
        ↓
Wazuh execd calls suricata-firewall-drop.sh
        ↓
iptables -I INPUT -s <src_ip> -j DROP
        ↓
Auto-unblock after 300 seconds
```

## Why a custom script and not the built-in `firewall-drop`

Wazuh ships a built-in `firewall-drop` script (a compiled Go binary) that does
the iptables block. The snag: it expects a field called `srcip` in the alert's
decoded data, but Wazuh's generic JSON decoder decodes Suricata events with
`src_ip` (underscore).

So the script gets called, can't find the IP, and prints:
```
Cannot read 'srcip' from data or invalid IP format
```

The way around it is a custom shell script that parses the full JSON alert Wazuh
hands it on stdin, instead of relying on the built-in `srcip` convention.

## Configuration

### 1. `ossec.conf` — add the command and active-response blocks

In `/var/ossec/etc/ossec.conf`, inside `<ossec_config>`:

```xml
<command>
  <name>suricata-firewall-drop</name>
  <executable>suricata-firewall-drop.sh</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>

<active-response>
  <disabled>no</disabled>
  <command>suricata-firewall-drop</command>
  <location>local</location>
  <rules_id>100100,100101,100102,100103</rules_id>
  <timeout>300</timeout>
</active-response>
```

The parameters:
- `<location>local</location>` — run it on the same machine that raised the alert (wazuh-server, agent 000)
- `<rules_id>` — all four custom Suricata rules
- `<timeout>300</timeout>` — auto-unblock after 5 minutes

### 2. The custom Active Response script

`/var/ossec/active-response/bin/suricata-firewall-drop.sh`:

```bash
#!/bin/bash

INPUT=$(cat)
ACTION=$(echo "$INPUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('command',''))" 2>/dev/null)
IP=$(echo "$INPUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['parameters']['alert']['data']['src_ip'])" 2>/dev/null)

LOG="/var/ossec/logs/active-responses.log"

echo "$(date) suricata-firewall-drop: ACTION=$ACTION IP=$IP" >> $LOG

if [ -z "$IP" ]; then
    echo "$(date) suricata-firewall-drop: Cannot extract src_ip" >> $LOG
    exit 1
fi

if [ "$ACTION" = "add" ]; then
    iptables -I INPUT -s "$IP" -j DROP
    echo "$(date) suricata-firewall-drop: Blocked $IP" >> $LOG
elif [ "$ACTION" = "delete" ]; then
    iptables -D INPUT -s "$IP" -j DROP
    echo "$(date) suricata-firewall-drop: Unblocked $IP" >> $LOG
fi

exit 0
```

Permissions:
```bash
sudo chmod 750 /var/ossec/active-response/bin/suricata-firewall-drop.sh
sudo chown root:wazuh /var/ossec/active-response/bin/suricata-firewall-drop.sh
```

### 3. Why Python3 and not shell regex

In Wazuh 4.x the Active Response script gets the whole JSON alert on `stdin`, not
as command-line arguments. And the structure is deeply nested:

```json
{
  "command": "add",
  "parameters": {
    "alert": {
      "data": {
        "src_ip": "192.168.56.101",
        ...
      }
    }
  }
}
```

I tried shell regex first (`grep -oP` Perl regex, `grep -o` POSIX) and couldn't
get it reliable, partly because of the escaped characters in the JSON and partly
because the Perl regex module isn't there on Ubuntu Server. Python3 `json.load()`
was the one approach that just worked. It doesn't care about regex dialects, it
handles the escaped characters properly, and it's already on Ubuntu 22.04 by
default.

## Verification

### Manual test (calling the script directly)

Checking that the script parses Wazuh's JSON format and blocks the IP:

```bash
cat << 'EOF' | sudo /var/ossec/active-response/bin/suricata-firewall-drop.sh
{"version":1,"origin":{"name":"node01","module":"wazuh-execd"},"command":"add","parameters":{"extra_args":[],"alert":{"data":{"src_ip":"192.168.56.101","event_type":"alert","dest_ip":"192.168.56.102","dest_port":"6200"}}}}
EOF
```

Confirmed in iptables and the log:
```bash
sudo iptables -L INPUT -n | grep 192.168.56.101
# DROP all -- 192.168.56.101 0.0.0.0/0

sudo tail -5 /var/ossec/logs/active-responses.log
# Tue Aug 18 07:27:40 AM UTC 2026 suricata-firewall-drop: ACTION=add IP=192.168.56.101
# Tue Aug 18 07:27:40 AM UTC 2026 suricata-firewall-drop: Blocked 192.168.56.101
```

### Checking the auto-unblock

After 300 seconds Wazuh sends a `delete` to the same script, which pulls the
iptables rule:
```bash
sudo iptables -L INPUT -n | grep 192.168.56.101
# (empty output — rule gone)
```

## Problems I hit along the way

### Problem 1: `Cannot read 'srcip' from data`
The built-in `firewall-drop` binary wants `srcip`, but Wazuh decodes the Suricata
field as `src_ip`. Solved by writing my own script that parses the JSON itself.

### Problem 2: a custom decoder broke JSON auto-decoding
My first instinct was to add a custom decoder that mapped `src_ip` → `srcip`. That
backfired: Wazuh then lost all the other decoded fields (Phase 2 showed only
`name: 'json'` with nothing extracted). So I dropped the decoder idea entirely and
handled it in the AR script with the Python3 parser instead.

### Problem 3: shell regex isn't reliable for JSON
`grep -oP` (Perl regex) isn't on Ubuntu Server 22.04 by default. `grep -o` (POSIX)
was fine for simple cases but not for the messier escaped JSON strings. Python3
`json.load()` was the fix.

## Architecture notes for the portfolio

**Where the block lands in this lab:** Active Response runs on the `wazuh-server`
machine (agent 000, `location: local`). So the block sits at the wazuh-server
firewall — while it's active, the Kali VM can't reach wazuh-server at all (SSH,
dashboard, etc.). In production you'd run AR on the agents protecting the actual
targets, not on the SIEM server itself.

**Metasploitable2 can't take a Wazuh agent:** it's Ubuntu 8.04 (kernel 2.6.x,
32-bit), and the modern Wazuh agent needs at least Ubuntu 14. So AR can't block
traffic directly on Metasploitable2. That would take either a newer target with an
agent, or blocking at the network level (the router, say).

**On the automatic trigger:** the manual test proves the script parses Wazuh's
JSON and blocks the IP correctly. Getting it to fire automatically off live
traffic needs a steady stream for Suricata to catch on `enp0s8`, and that's a
limit of this particular lab setup (ports close between tests, Metasploit has
payload trouble with these old services) rather than anything wrong with the AR
config.

## Next steps

- Put a Wazuh agent on a more modern Linux target (an Ubuntu 22.04 VM, say) for
  host-based detection and direct AR blocking right on the target.
- A custom dashboard view for the `exploit_attempt` group that also shows which
  IPs are currently blocked.
- Extend AR to more rules, like the SSH brute-force rules from the built-in Wazuh
  ruleset.
