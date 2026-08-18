# Manuelna instalacija Wazuh SIEM stack-a (Ubuntu Server 22.04 LTS / VirtualBox)

## Cilj

Instalacija kompletnog Wazuh SIEM stack-a (indexer, manager, dashboard) na Ubuntu Server 22.04 LTS unutar VirtualBox okruženja, korišćenjem **manuelne, paket-po-paket instalacije** umesto zvanične `wazuh-install.sh` all-in-one skripte.

Cilj ovakvog pristupa nije samo funkcionalan SIEM, nego razumevanje same arhitekture: kako komponente međusobno komuniciraju, gde se generišu TLS sertifikati, koje zavisnosti automated skripta sakriva i kako izgleda realan troubleshooting proces kada nešto pukne.

## Arhitektura

```
Suricata (eve.json) ──► [planirano: sledeći korak]

Wazuh Manager (analiza, ruleset)
        │
        │  Filebeat (šalje alerts.json preko HTTPS/TLS)
        ▼
Wazuh Indexer (OpenSearch baza, TLS)
        ▲
        │  HTTPS/TLS
        │
Wazuh Dashboard (UI)
```

- **Wazuh Indexer** — OpenSearch baza gde se skladište i indeksiraju svi alarmi/eventi.
- **Wazuh Manager** — analizira dolazne logove, generiše alarme na osnovu ruleset-a, piše ih lokalno u `/var/ossec/logs/alerts/alerts.json`.
- **Filebeat** — čita `alerts.json` i šalje sadržaj indexer-u preko HTTPS-a. Manager sam po sebi ne šalje podatke direktno u bazu.
- **Wazuh Dashboard** — web UI (OpenSearch Dashboards fork), povlači podatke iz indexer-a, komunicira sa manager-om preko REST API-ja (port 55000) za agent management.

Sve tri komponente međusobno komuniciraju isključivo preko TLS-a, korišćenjem sopstvenog self-signed CA (`root-ca.pem`) generisanog preko `wazuh-certs-tool.sh`.

**Lab okruženje:**
- Ubuntu Server 22.04 LTS, VirtualBox
- Host-only mreža `192.168.56.0/24`, VM IP `192.168.56.105`
- Wazuh verzija: `4.14.7-rc1`

## Ključni problemi i rešenja

Manuelna instalacija namerno preskače korake koje `wazuh-install.sh` radi automatski, pa je svaki od njih trebalo prepoznati i rešiti ručno.

### 1. Pogrešan URL za Wazuh GPG ključ
Prvi pokušaj dodavanja repozitorijuma koristio je `package.wazuh.com` (bez "s") umjesto `packages.wazuh.com`, što je rezultovalo praznim (0 bajtova) GPG keyring fajlom i `NO_PUBKEY` greškom pri `apt update`.

**Rešenje:** ponovni import ključa sa ispravnim URL-om:
```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
```

### 2. TLS sertifikati se ne generišu automatski
Za razliku od all-in-one skripte, `apt install wazuh-indexer/manager/dashboard` samo instalira binarne fajlove — ne generiše TLS sertifikate. Svi servisi pucaju na startu jer traže `root-ca.pem` i node-specifične sertifikate koji ne postoje.

**Rešenje:** ručno preuzimanje `wazuh-certs-tool.sh` + `config.yml`, generisanje sertifikata (`wazuh-certs-tool.sh -A`), i ručno kopiranje u tačne foldere za svaku komponentu:
- Indexer: `/etc/wazuh-indexer/certs/`
- Filebeat (manager → indexer veza): `/etc/filebeat/certs/` (imena `filebeat.pem`, `filebeat-key.pem`, `root-ca.pem`)
- Dashboard: `/etc/wazuh-dashboard/certs/` (imena `dashboard.pem`, `dashboard-key.pem`, `root-ca.pem`)

Bitna lekcija: imena fajlova koje pojedina komponenta očekuje **nisu univerzalna** — proveravaju se direktno u YAML konfiguraciji svake komponente (`grep -i ssl <config>.yml`) umesto pretpostavljanja.

### 3. Filebeat nije uključen u manuelnu instalaciju
Wazuh manager sam po sebi ne šalje podatke indexer-u — to radi Filebeat, koji kod manuelne instalacije **nije automatska zavisnost** paketa `wazuh-manager`. Bez njega, manager generiše alarme lokalno, ali dashboard ostaje prazan.

**Rešenje:** eksplicitna instalacija (`apt install filebeat`), preuzimanje zvaničnog `filebeat.yml` template-a, `wazuh-template.json`, i Wazuh filebeat modula, plus keystore za kredencijale (`filebeat keystore add username/password`).

### 4. DNS hijacking na `raw.githubusercontent.com`
Preuzimanje `wazuh-template.json` sa GitHub-a dosledno vraćalo 404, iako je isti URL radio ispravno sa druge lokacije. Dijagnostika (`curl -v`) pokazala je da se VM povezuje na IP izvan Fastly/GitHub CDN opsega (`103.224.182.253` umesto `185.199.108-111.x`) — DNS resolver (vjerovatno na ISP nivou) preusmeravao je zahteve na pogrešan server koji vraća generičku 404 stranicu.

**Rešenje (workaround):** forsiranje ispravnog IP-a direktno kroz curl, zaobilazeći DNS:
```bash
curl -o /etc/filebeat/wazuh-template.json --resolve raw.githubusercontent.com:443:185.199.108.133 https://raw.githubusercontent.com/wazuh/wazuh/v4.14.7/extensions/elasticsearch/7.x/wazuh-template.json
```

### 5. Sertifikati "nestaju" nakon određenih koraka
U dva navrata (filebeat i dashboard), sertifikati koji su ranije uspešno kopirani nestali su iz svojih foldera pre nego što je konfiguracija testirana, izazivajući `ENOENT: no such file or directory`. Uzrok nije definitivno utvrđen (moguće da su rani pokušaji `chmod`/`mkdir` sekvenci ostavili foldere u nekonzistentnom stanju), ali se rešenje sastojalo od ponovnog kopiranja iz sačuvanog `~/wazuh-certificates/` foldera.

**Lekcija:** čuvati originalni `wazuh-certificates/` folder van `/etc/` sve dok se ne potvrdi da je celi stack stabilan, jer se pojedine komponente povremeno moraju re-provizionirati.

### 6. Disk pun zbog vulnerability-detection privremenog fajla
Nakon nekoliko sati rada, `wazuh-indexer` i `wazuh-manager` počeli su da pucaju sa `No space left on device`, iako je `df -h` na početku pokazivao dovoljno prostora. Analiza (`du -h -x / --max-depth=2`) otkrila je da `/var/ossec/tmp/vd_1.0.0_vd_4.13.0.tar` zauzima **8.5 GB** — nepotpuno raspakovan CVE feed za vulnerability-detection modul, koji se ponovo generisao pri svakom pokušaju starta manager-a.

**Rešenje (privremeno):**
```bash
sudo rm -f /var/ossec/tmp/vd_1.0.0_vd_4.13.0.tar
```
i onemogućavanje vulnerability-detection modula u `/var/ossec/etc/ossec.conf` (`<vulnerability-detection><enabled>no</enabled></vulnerability-detection>`) dok se VirtualBox disk ne proširi na trajno rešenje (planiran budući korak: povećanje diska sa 18 GB na 40-50 GB).

### 7. `wazuh-apid` timeout i "failed" marker fajl
Nakon restarta VM-a, `wazuh-manager` je prvo počeo da timeout-uje pri startu (`start operation timed out`), a nakon produžavanja `TimeoutStartSec` preko systemd override-a, API proces (`wazuh-apid`) je i dalje odbijao da se pokrene zbog prethodno ostavljenog `wazuh-apid.failed` marker fajla i (pravi uzrok) istog problema sa punim diskom iz tačke 6.

**Rešenje:**
```bash
sudo mkdir -p /etc/systemd/system/wazuh-manager.service.d
sudo tee /etc/systemd/system/wazuh-manager.service.d/override.conf << 'EOF'
[Service]
TimeoutStartSec=300
EOF
sudo systemctl daemon-reload
```
plus rešavanje pravog uzroka (disk prostor) pre nego što je restart uspeo.

## Naučene lekcije

- **Manuelna instalacija otkriva skrivene zavisnosti** koje automated skripta rešava tiho: TLS sertifikati, Filebeat kao poseban paket, tačna imena cert fajlova po komponenti.
- **"Disk full" greške ne treba uzimati zdravo za gotovo** — u ranoj fazi instalacije, apport-ova dijagnoza "disk full" bila je pogrešna (inode/GB provera je pokazala dovoljno prostora); kasnije, identična poruka bila je tačna i uzrokovana specifičnim privremenim fajlom. Uvek proveriti `df -h` i `df -i` direktno, ne verovati generičkim porukama.
- **Mrežni/DNS problemi mogu ličiti na aplikacione greške** — 404 sa GitHub-a izgledao je kao pogrešan URL/verzija, dok je stvarni uzrok bio DNS hijacking na nivou mreže, otkriven tek kroz `curl -v` i proveru IP opsega.
- **Systemd override fajlovi** (`systemctl edit`) mogu tiho ne uspeti da se sačuvaju ako se editor pogrešno zatvori — proveriti rezultat direktnim `cat`-om, ili kreirati fajl direktno preko `tee` da se izbjegne interaktivni editor.

## Sledeći koraci

- Proširenje VirtualBox diska i ponovno uključivanje vulnerability-detection modula.
- Snapshot stabilnog stanja VM-a prije sledeće faze rada.

## Nastavak

Integracija Suricata `eve.json` logova preko custom decoder/rules pristupa
(umjesto gotovog Filebeat modula) dokumentovana je odvojeno:
[suricata-decoder-integration.md](suricata-decoder-integration.md).
