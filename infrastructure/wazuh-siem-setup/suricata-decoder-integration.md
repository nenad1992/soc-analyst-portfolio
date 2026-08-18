# Suricata → Wazuh integracija: custom decoder i rules

Nastavak na [Wazuh SIEM stack — manuelna instalacija](README.md). Ovaj deo pokriva
povezivanje Suricata NIDS-a sa Wazuh manager-om preko **custom decoder/rules
pristupa**, umesto gotovog Filebeat Suricata modula ili generičkog Wazuh
JSON auto-decode-a bez klasifikacije.

## Zašto custom rules, a ne gotov modul

Wazuh nudi generičku JSON integraciju (`<localfile><log_format>json</log_format>`)
koja automatski dekodira `eve.json` i prepoznaje ga kao `suricata` grupu preko
ugrađenog pravila `86601`. Ovo radi "od kutije", ali ima ozbiljno ograničenje
za portfolio svrhe: svaki alert — bez obzira na signature — dobija identičan,
generički opis (*"Suricata: Alert - [signature text]"*), fiksni level 3, i
**nema MITRE ATT&CK mapiranje**.

Cilj ovog dela je da svaki od četiri custom Suricata potpisa (već testirana
u ranijim [exploit writeup-ovima](../../writeups)) dobije:
- Specifičan, čitljiv opis
- Odgovarajući severity level
- MITRE ATT&CK tehnike i taktike, vidljive u Threat Hunting dashboard-u

## Arhitektura

```
Suricata (eve.json, custom.rules)
        │  localfile (log_format: json)
        ▼
Wazuh Manager
        │  generički JSON decoder → default rule 86601 (level 3, "suricata")
        │  local_rules.xml → specifična pravila po signature_id (level 10, MITRE)
        ▼
Filebeat → Wazuh Indexer → Wazuh Dashboard (Threat Hunting)
```

## Konfiguracija

### 1. Povezivanje manager-a sa `eve.json`

Suricata radi na istoj mašini kao manager (all-in-one lab), pa se log čita
direktno preko `localfile` stanze u `/var/ossec/etc/ossec.conf`:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>
```

### 2. Custom decoder polja (referenca)

Wazuh-ov generički JSON decoder već spljošti ugnježdene Suricata objekte u
dostupna polja bez potrebe za ručnim decoder XML-om — potvrđeno preko
`wazuh-logtest`:

```
alert.signature_id: '1000001'
alert.signature: 'VSFTPD 2.3.4 Backdoor Shell Connection'
alert.severity: '3'
dest_port: '6200'
src_ip: '192.168.56.101'
```

Na osnovu ovih polja pišu se custom rules (korak 3) — nije bio potreban
poseban `decoder.xml`, samo referenciranje postojećih dinamičkih polja u
`<field>` tagovima pravila.

### 3. Custom rules (`/var/ossec/etc/rules/local_rules.xml`)

Jedno pravilo po `signature_id`, svako sa `if_sid` na default Suricata
pravilo `86601` i eksplicitnim MITRE mapiranjem:

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

MITRE tehnike su usklađene sa mapiranjima iz postojećih exploit writeup-ova
(vsftpd/UnrealIRCd/distcc → T1190, T1059; Samba → dodatno T1021.002 zbog
lateral movement preko SMB-a).

## Ključni problem i rešenje: "Too many fields for JSON decoder"

Nakon dodavanja `localfile` stanze, `ossec.log` je počeo beležiti kontinuirane
greške:

```
wazuh-analysisd: ERROR: Too many fields for JSON decoder.
```

**Uzrok:** Wazuh-ov generički JSON decoder ima podrazumevani limit broja
polja po eventu (`analysisd.decoder_order_size`, default 256). Suricata
`eve.json` eventi drugih tipova (`flow`, `http`, `tls`, `stats`) imaju znatno
više ugnježdenih polja od `alert` eventa i lako premašuju taj limit kad se
spljošte.

**Rešenje:** povećanje limita na maksimum preko `local_internal_options.conf`
(ne menjati glavni `internal_options.conf` — briše se pri update-u):

```bash
echo "analysisd.decoder_order_size=1024" | sudo tee -a /var/ossec/etc/local_internal_options.conf
sudo systemctl restart wazuh-manager
```

Napomena: nekoliko izvora u zajednici navodi da ni maksimalna vrednost
(1024) ne rešava problem u svim slučajevima kod vrlo opširnih `http`/`tls`
eventa. Alternativa koja nije bila potrebna u ovom slučaju, ali vrijedi
zabeležiti za buduće skaliranje: filtrirati Suricata `eve.json` izlaz da
piše samo `event_type: alert` evente, umesto svih tipova.

## Testiranje preko `wazuh-logtest`

Pre primene u produkciji, svako pravilo testirano je izolovano lepljenjem
stvarnog `eve.json` alert reda u `wazuh-logtest`:

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Primer potvrđenog rezultata za VSFTPD:

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

Sva četiri pravila potvrđena su na isti način pre restarta manager-a u
produkciji.

## Verifikacija end-to-end

Nakon ponovnog izvođenja sva četiri exploita sa Kali VM-a (vsftpd, Samba,
UnrealIRCd, distcc), alarmi klasifikovani custom pravilima potvrđeni su na
tri nivoa:

1. **`alerts.log` na manageru** — svaki event ispravno mapiran na svoje
   pravilo (`100100`–`100103`), ne generičko `86601`.
2. **Wazuh Indexer direktno** (`curl` upit na port 9200) — potvrđeno da su
   svi alarmi (npr. 10 zapisa za `rule.id:100103`) stigli preko Filebeat-a,
   sa ispravno popunjenim `data.alert.signature_id` poljem.
3. **Wazuh Dashboard, Threat Hunting modul** — filter `rule.groups:suricata`
   prikazuje sve alarme; panel **Top 10 MITRE ATT&CKS** prikazuje raspodelu
   tehnika (Exploit Public-Facing Application, Command and Scripting
   Interpreter, SMB/Windows Admin Shares) umesto praznog "No results found".

   ![Top 10 MITRE ATT&CK tehnika — donut chart](assets/mitre-attck-donut-chart.png)

   Raspodela prikazana na grafiku odgovara tehnikama mapiranim u
   `local_rules.xml`: **Exploit Public-Facing Application** (T1190) i
   **Command and Scripting Interpreter** (T1059) dominiraju jer se javljaju
   kod sva četiri custom pravila, dok se **SMB/Windows Admin Shares**
   (T1021.002) pojavljuje isključivo kod Samba pravila (100101).

**Lekcija iz troubleshooting-a:** kad su alarmi bili potvrđeni u
`alerts.log` i u indexer-u preko direktnog upita, ali se nisu prikazivali u
dashboard-u, uzrok nije bio u obradi podataka nego u **vremenskom filteru**
dashboard-a (podrazumevano "This week" nije uvek dovoljno široko za
alarme generisane tokom testiranja u kratkim intervalima) — vredno je prvo
proveriti taj filter pre dubljeg troubleshooting-a lanca podataka.

## Sledeći koraci

- Dodavanje custom decoder-a (ne samo rules) ako se u budućnosti doda
  Suricata potpis sa strukturom koja zahteva parsiranje van generičkog
  JSON spljoštavanja.
- Filtriranje `eve.json` na samo `alert` event tipove radi smanjenja
  opterećenja i izbegavanja graničnih slučajeva "too many fields" greške.
- Kreiranje custom dashboard vizualizacije specifično za `exploit_attempt`
  grupu alarma.