# SOC Analyst Home Lab Portfolio

Praktičan rad na eksploataciji, detekciji i analizi bezbednosnih ranjivosti
u kontrolisanom lab okruženju (Kali Linux + Metasploitable2, VirtualBox).
Svaki writeup pokriva ceo tok — od enumeracije, preko eksploatacije (ručne
i/ili preko Metasploit-a), do detekcije sa blue team ugla i predloga za
remedijaciju, sa MITRE ATT&CK mapiranjem.

## Writeup-ovi


|
#
|
 Naziv 
|
 CVE 
|
 Metod 
|
 MITRE ATT&CK 
|
|
---
|
-------
|
-----
|
-------
|
---------------
|
|
 00 
|
[
Recon
](
writeups/00-recon
)
|
 — 
|
 Nmap full scan 
|
 T1046, T1590 
|
|
 01 
|
[
vsftpd 2.3.4 Backdoor
](
writeups/01-vsftpd-backdoor
)
|
 CVE-2011-2523 
|
 Ručno + Metasploit 
|
 T1190, T1059 
|
|
 02 
|
[
Samba usermap_script RCE
](
writeups/02-samba-usermap
)
|
 CVE-2007-2447 
|
 Ručno + Metasploit 
|
 T1190, T1059, T1021.002 
|

## Alati korišćeni u lab-u
- Kali Linux (attacker)
- Metasploitable2 (target)
- Nmap, Metasploit Framework, smbclient, netcat
- VirtualBox (host-only mreža)

## O meni

Prelazim iz data engineering-a u cybersecurity, sa fokusom na SOC Analyst
(L1/L2) pozicije. Background u fizičkoj hemiji i spektroskopiji (Univerzitet
u Beogradu), trenutno radim kao Data Integration Engineer u ZF Group. Ovaj
lab dokumentuje moj praktičan rad na razumevanju napada iz oba ugla —
ofanzivnog i defanzivnog — kao pripremu za SOC ulogu.