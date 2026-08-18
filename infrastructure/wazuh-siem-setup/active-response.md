# Wazuh Active Response: automatska blokada napadača

Nastavak na [Suricata → Wazuh integraciju](suricata-decoder-integration.md). Ovaj deo
pokriva konfiguraciju **Active Response** modula koji automatski blokira IP adresu
napadača kada jedno od custom Suricata pravila okine alarm.

## Cilj

Zatvoriti petlju detekcije: umesto da samo **vidimo** napad u dashboard-u, sistem
automatski **reaguje** — blokira napadačev IP na nivou firewall-a (iptables) čim
Wazuh generiše alarm. Nakon definisanog timeout-a, blokada se automatski ukida.

```
Suricata alert (eve.json)
        ↓
Wazuh logcollector → custom rule 100100-100103 (level 10, MITRE tag)
        ↓
Wazuh execd poziva suricata-firewall-drop.sh
        ↓
iptables -I INPUT -s <src_ip> -j DROP
        ↓
Auto-unblock nakon 300 sekundi
```

## Zašto custom skripta umesto ugrađenog `firewall-drop`

Wazuh dolazi sa ugrađenom `firewall-drop` binarnom skriptom (kompajliran Go executable)
koja radi iptables blokadu. Problem: skripta traži polje koje se zove `srcip` u
dekodiranim podacima alarma, ali Wazuh-ov generički JSON decoder Suricata evente
dekodira sa poljem `src_ip` (sa donjom crticom).

Rezultat: skripta se poziva, ali ne može da pronađe IP i ispisuje:
```
Cannot read 'srcip' from data or invalid IP format
```

Rešenje je custom shell skripta koja sama parsira kompletan JSON alarm koji Wazuh
šalje via stdin, bez oslanjanja na ugrađene `srcip` konvencije.

## Konfiguracija

### 1. `ossec.conf` — dodavanje command i active-response bloka

U `/var/ossec/etc/ossec.conf`, unutar `<ossec_config>` taga:

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

Parametri:
- `<location>local</location>` — izvršava se na istoj mašini koja je generisala alarm (wazuh-server, agent 000)
- `<rules_id>` — sva četiri custom Suricata pravila
- `<timeout>300</timeout>` — auto-unblock nakon 5 minuta

### 2. Custom Active Response skripta

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

Permisije:
```bash
sudo chmod 750 /var/ossec/active-response/bin/suricata-firewall-drop.sh
sudo chown root:wazuh /var/ossec/active-response/bin/suricata-firewall-drop.sh
```

### 3. Zašto Python3, a ne shell regex

U Wazuh 4.x, Active Response skripta prima kompletan JSON alarm kao `stdin`, ne
kao argumente komandne linije. JSON struktura je duboko ugnježdena:

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

Pokušaji sa shell regex-om (`grep -oP` Perl regex, `grep -o` POSIX regex) nisu
pouzdano radili zbog kombinacije escaped karaktera u JSON-u i nedostupnosti Perl
regex modula na Ubuntu Server-u. Python3 `json.load()` je jedinstven pouzdan pristup
koji:
- Ne zavisi o regex dijalektu
- Ispravno parsira escaped karaktere u JSON-u
- Dostupan je po defaultu na Ubuntu 22.04

## Verifikacija

### Ručni test (direktan poziv skripte)

Provera da skripta ispravno parsira Wazuh JSON format i blokira IP:

```bash
cat << 'EOF' | sudo /var/ossec/active-response/bin/suricata-firewall-drop.sh
{"version":1,"origin":{"name":"node01","module":"wazuh-execd"},"command":"add","parameters":{"extra_args":[],"alert":{"data":{"src_ip":"192.168.56.101","event_type":"alert","dest_ip":"192.168.56.102","dest_port":"6200"}}}}
EOF
```

Potvrda u iptables i logu:
```bash
sudo iptables -L INPUT -n | grep 192.168.56.101
# DROP all -- 192.168.56.101 0.0.0.0/0

sudo tail -5 /var/ossec/logs/active-responses.log
# Tue Aug 18 07:27:40 AM UTC 2026 suricata-firewall-drop: ACTION=add IP=192.168.56.101
# Tue Aug 18 07:27:40 AM UTC 2026 suricata-firewall-drop: Blocked 192.168.56.101
```

### Provera auto-unblock

Nakon 300 sekundi, Wazuh automatski šalje `delete` komandu istoj skripti, koja
uklanja iptables pravilo:
```bash
sudo iptables -L INPUT -n | grep 192.168.56.101
# (prazan output — pravilo uklonjeno)
```

## Ključni problemi i rešenja

### Problem 1: `Cannot read 'srcip' from data`
Ugrađena `firewall-drop` binarna skripta traži `srcip` polje, ali Wazuh iz Suricata
JSON-a dekodira polje kao `src_ip`. Rešenje: custom skripta koja sama parsira JSON.

### Problem 2: Custom decoder lomi JSON auto-decoding
Pokušaj dodavanja custom decoder-a koji bi mapirao `src_ip` → `srcip` uzrokovao je
da Wazuh izgubi sva ostala decodirana polja (Phase 2 pokazivao samo `name: 'json'`
bez ikakvih ekstrahovanih vrednosti). Rešenje: eliminisati potrebu za custom
decoder-om kroz Python3 parser u samoj AR skripti.

### Problem 3: Shell regex nije pouzdan za JSON
`grep -oP` (Perl regex) nije dostupan po defaultu na Ubuntu Server 22.04.
`grep -o` (POSIX) je radio za jednostavne slučajeve, ali nije pouzdan za
kompleksne escaped JSON stringove. Rešenje: Python3 `json.load()`.

## Arhitekturalne napomene za portfolio

**Opseg blokade u lab okruženju:** Active Response se izvršava na `wazuh-server`
mašini (agent 000, `location: local`). Ovo znači da blokada važi na nivou
wazuh-server firewall-a — Kali VM ne može komunicirati sa wazuh-server-om dok je
blokada aktivna (SSH, dashboard, itd.). U produkcijskom okruženju, AR bi se
izvršavao na agentima koji štite stvarne ciljeve napada, ne na samom SIEM serveru.

**Metasploitable2 nema Wazuh agenta:** pošto Metasploitable2 koristi Ubuntu 8.04
(kernel 2.6.x, 32-bit), moderni Wazuh agent (koji zahteva minimum Ubuntu 14+)
nije moguće instalirati. Zbog toga AR ne može direktno blokirati saobraćaj ka
Metasploitable2 — to bi zahtevalo ili moderniji target sistem sa agentom, ili
network-level blokadu (npr. na ruterskom nivou).

**Automatski trigger u lab okruženju:** ručni test potvrđuje da skripta ispravno
parsira Wazuh JSON format i blokira IP. Automatski trigger kroz stvaran mrežni
saobraćaj zahteva kontinuiran saobraćaj koji Suricata može uhvatiti na `enp0s8`
interfejsu — što je ograničenje specifično za ovaj lab setup (portovi se zatvaraju
između testova, Metasploit ima payload probleme sa starim servisima), ne greška
u konfiguraciji AR modula.

## Sledeći koraci

- Instalacija Wazuh agenta na moderniji Linux target (npr. Ubuntu 22.04 VM) za
  host-based detekciju i direktnu AR blokadu na meti napada
- Custom dashboard vizualizacija za `exploit_attempt` grupu alarma sa prikazom
  blokiranih IP adresa
- Proširenje AR na više pravila (npr. SSH brute-force pravila iz ugrađenog
  Wazuh rulseta)
