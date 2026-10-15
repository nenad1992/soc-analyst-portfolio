# Suricata → Wazuh integration: custom decoder and rules

Follows on from [the manual Wazuh install](README.md). Here I wire the Suricata
NIDS into the Wazuh manager using a **custom decoder/rules approach**, rather than
the stock Filebeat Suricata module or Wazuh's generic JSON auto-decode with no
classification.

## Why custom rules instead of a ready-made module

Wazuh has a generic JSON integration
(`<localfile><log_format>json</log_format>`) that auto-decodes `eve.json` and tags
it as the `suricata` group via the built-in rule `86601`. It works out of the box,
but for a portfolio it falls short in one big way: every alert, no matter the
signature, gets the same generic description (*"Suricata: Alert - [signature
text]"*), a fixed level 3, and **no MITRE ATT&CK mapping at all**.

What I wanted was for each of my four Suricata signatures (already tested in the
[exploit writeups](../../writeups)) to come through with:
- a specific, readable description
- a sensible severity level
- MITRE ATT&CK techniques and tactics, showing up in the Threat Hunting dashboard

## Architecture

```
Suricata (eve.json, custom.rules)
        │  localfile (log_format: json)
        ▼
Wazuh Manager
        │  generic JSON decoder → default rule 86601 (level 3, "suricata")
        │  local_rules.xml → specific rules per signature_id (level 10, MITRE)
        ▼
Filebeat → Wazuh Indexer → Wazuh Dashboard (Threat Hunting)
```

## Configuration

### 1. Point the manager at `eve.json`

Suricata runs on the same box as the manager (all-in-one lab), so I read the log
directly with a `localfile` stanza in `/var/ossec/etc/ossec.conf`:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>
```

### 2. Decoder fields (for reference)

Wazuh's generic JSON decoder already flattens the nested Suricata objects into
usable fields, so I didn't have to write any decoder XML. `wazuh-logtest`
confirmed the fields were there:

```
alert.signature_id: '1000001'
alert.signature: 'VSFTPD 2.3.4 Backdoor Shell Connection'
alert.severity: '3'
dest_port: '6200'
src_ip: '192.168.56.101'
```

I wrote the custom rules (step 3) against these fields. No separate `decoder.xml`
was needed, just referencing the existing dynamic fields in the rules' `<field>`
tags.

### 3. Custom rules (`/var/ossec/etc/rules/local_rules.xml`)

One rule per `signature_id`, each hanging off the default Suricata rule `86601`
via `if_sid`, with MITRE mapping spelled out:

```xml
<group name="suricata,">

  <rule id="100100" level="10">
    <if_sid>86601</if_sid>
    <field name="alert.signature_id">1000001</field>
    <description>VSFTPD 2.3.4 Backdoor Shell Connection detected by Suricata</description>
    <mitre>
      <id>T1190</id>
      <id>T1059</id>
    </mitre>
    <group>suricata_vsftpd,exploit_attempt,</group>
  </rule>

  <rule id="100101" level="10">
    <if_sid>86601</if_sid>
    <field name="alert.signature_id">1000002</field>
    <description>Samba usermap_script Command Injection Attempt detected by Suricata</description>
    <mitre>
      <id>T1190</id>
      <id>T1059</id>
      <id>T1021.002</id>
    </mitre>
    <group>suricata_samba,exploit_attempt,</group>
  </rule>

  <rule id="100102" level="10">
    <if_sid>86601</if_sid>
    <field name="alert.signature_id">1000003</field>
    <description>UnrealIRCd Backdoor Command Attempt detected by Suricata</description>
    <mitre>
      <id>T1190</id>
      <id>T1059</id>
    </mitre>
    <group>suricata_unrealircd,exploit_attempt,</group>
  </rule>

  <rule id="100103" level="10">
    <if_sid>86601</if_sid>
    <field name="alert.signature_id">1000004</field>
    <description>Distcc RCE Attempt detected by Suricata</description>
    <mitre>
      <id>T1190</id>
      <id>T1059</id>
    </mitre>
    <group>suricata_distcc,exploit_attempt,</group>
  </rule>

</group>
```

The MITRE techniques line up with the mappings from the exploit writeups
(vsftpd/UnrealIRCd/distcc → T1190, T1059; Samba also gets T1021.002 for the
lateral movement over SMB).

## The problem that cost me time: "Too many fields for JSON decoder"

Right after I added the `localfile` stanza, `ossec.log` started spewing the same
error over and over:

```
wazuh-analysisd: ERROR: Too many fields for JSON decoder.
```

Turned out Wazuh's generic JSON decoder caps the number of fields per event
(`analysisd.decoder_order_size`, default 256). Suricata's other event types
(`flow`, `http`, `tls`, `stats`) carry way more nested fields than an `alert`
event, and once flattened they blow right past that cap.

I raised the limit to the max through `local_internal_options.conf` (not the main
`internal_options.conf`, which gets wiped on update):

```bash
echo "analysisd.decoder_order_size=1024" | sudo tee -a /var/ossec/etc/local_internal_options.conf
sudo systemctl restart wazuh-manager
```

Worth flagging for later: a few people in the community say even 1024 isn't enough
for really verbose `http`/`tls` events. I didn't need it here, but the other fix
is to filter Suricata's `eve.json` down to just `event_type: alert` instead of
emitting every type.

## Testing with `wazuh-logtest`

Before putting anything live, I tested each rule in isolation by pasting a real
`eve.json` alert line into `wazuh-logtest`:

```bash
sudo /var/ossec/bin/wazuh-logtest
```

What a confirmed VSFTPD result looked like:

```
**Phase 3: Completed filtering (rules).
        id: '100100'
        level: '10'
        description: 'VSFTPD 2.3.4 Backdoor Shell Connection detected by Suricata'
        groups: '['suricata', 'suricata_vsftpd', 'exploit_attempt']'
        mitre.id: '['T1190', 'T1059']'
        mitre.tactic: '['Initial Access', 'Execution']'
        mitre.technique: '['Exploit Public-Facing Application', 'Command and Scripting Interpreter']'
```

I confirmed all four the same way before restarting the manager for real.

## End-to-end verification

After re-running all four exploits from Kali (vsftpd, Samba, UnrealIRCd, distcc),
I checked the custom-classified alerts at three levels:

1. **`alerts.log` on the manager** — each event mapped to its own rule
   (`100100`–`100103`), not the generic `86601`.
2. **Wazuh Indexer directly** (a `curl` to port 9200) — confirmed the alerts (e.g.
   10 records for `rule.id:100103`) made it across via Filebeat, with
   `data.alert.signature_id` populated correctly.
3. **Wazuh Dashboard, Threat Hunting** — the filter `rule.groups:suricata` shows
   all of them, and the **Top 10 MITRE ATT&CKS** panel finally shows a real
   technique breakdown instead of "No results found".

   ![Top 10 MITRE ATT&CK techniques — donut chart](assets/mitre-attck-donut-chart.png)

   The split in the chart matches what I mapped in `local_rules.xml`: **Exploit
   Public-Facing Application** (T1190) and **Command and Scripting Interpreter**
   (T1059) dominate because all four rules carry them, while **SMB/Windows Admin
   Shares** (T1021.002) shows up only on the Samba rule (100101).

One troubleshooting note that's easy to waste time on: at one point the alerts
were confirmed in `alerts.log` and in the indexer by direct query, but weren't
showing in the dashboard. It wasn't a data problem at all — it was the dashboard's
time filter. The default "This week" isn't always wide enough for alerts you
generate in quick bursts during testing. Check that filter first before you go
spelunking through the data pipeline.

## Next steps

- Add a real custom decoder (not just rules) if I ever add a Suricata signature
  whose structure needs parsing beyond the generic JSON flattening.
- Filter `eve.json` to `alert` events only, to cut the load and sidestep the "too
  many fields" edge cases.
- Build a custom dashboard view aimed specifically at the `exploit_attempt` alert
  group.
