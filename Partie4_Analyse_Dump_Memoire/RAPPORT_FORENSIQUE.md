# Rapport d'Analyse Forensique - Dump Memoire

**Date de l'analyse :** 05 Mars 2026
**Analyste :** Etudiant Forensic
**Outil principal :** Volatility 3 Framework 2.27.0
**Fichier analyse :** `memdump.mem` (2 139 095 040 octets / ~2 Go)

---

## Table des matieres

1. [Resume executif](#1-resume-executif)
2. [Informations systeme](#2-informations-systeme)
3. [Chronologie de l'attaque](#3-chronologie-de-lattaque)
4. [Analyse du vecteur d'attaque - Email de phishing](#4-analyse-du-vecteur-dattaque---email-de-phishing)
5. [Analyse des processus](#5-analyse-des-processus)
6. [Analyse reseau - Connexions C2](#6-analyse-reseau---connexions-c2)
7. [Malware identifie](#7-malware-identifie)
8. [Activite post-exploitation](#8-activite-post-exploitation)
9. [Injection memoire (Malfind)](#9-injection-memoire-malfind)
10. [Fichiers suspects](#10-fichiers-suspects)
11. [Indicateurs de compromission (IOCs)](#11-indicateurs-de-compromission-iocs)
12. [Conclusion](#12-conclusion)
13. [Annexe - Fichiers de preuves](#13-annexe---fichiers-de-preuves)

---

## 1. Resume executif

L'analyse du dump memoire revele une **compromission complete** de la machine de l'utilisateur **johnoc** (John Opoc) via une attaque de **spear-phishing par email**. L'attaquant a envoye un email malveillant depuis une adresse jetable **GuerrillaMail** contenant un document Word avec macro malveillante (`invoice.docm`). L'ouverture du document a declenche l'execution d'un payload **Metasploit/Meterpreter** qui a etabli un reverse shell vers le serveur C2 de l'attaquant (`172.16.169.164:4444`). L'attaquant a ensuite realise de la reconnaissance systeme et deploye des outils de credential dumping (**Mimikatz/Kiwi**).

---

## 2. Informations systeme

### Commande executee :
```bash
vol -f memdump.mem windows.info
```

### Resultats :

| Parametre | Valeur |
|-----------|--------|
| **Systeme d'exploitation** | Windows 7 SP1 (Build 7601.17514) |
| **Architecture** | x86 (32-bit), PAE active |
| **Nom machine** | johnocPC |
| **Racine systeme** | C:\Windows |
| **Type produit** | NtProductWinNt (Workstation) |
| **Nombre de processeurs** | 1 |
| **Date/heure du dump** | 2019-07-31 13:45:40 UTC |
| **Virtualisation** | VMware (VMware Tools installe) |
| **Version majeure/mineure** | 6.1 |
| **Kernel Base** | 0x82a0f000 |
| **DTB** | 0x185000 |

### Hash du dump memoire :
```
MD5:    382e0a06865ddcf5aee46aa414fa011b
SHA256: e35a660421752b58989ee575566ff42a7c16ed3c9869a69dbce0bc23405d3a7c
```

> **Fichier de preuve :** `evidence/01_system_info.txt`

---

## 3. Chronologie de l'attaque

| Heure (UTC) | Evenement |
|-------------|-----------|
| 11:49:59 | Demarrage du systeme |
| 11:50:01 | Chargement des services systeme |
| 11:56:18 | Ouverture de session utilisateur (explorer.exe) |
| 11:56:34 | **Lancement de OUTLOOK.EXE** (PID 3476) - client email |
| 12:03:30 | Lancement de Chrome (PID 724) - consultation Gmail |
| 12:06:58 | Lancement de Icecream Screen Recorder |
| 12:44:26 | Fermeture de Chrome |
| **12:45:34** | **Ouverture de `invoice.docm` dans WINWORD.EXE (PID 3544)** |
| **12:45:47** | **Execution de `rad5163B.tmp.exe` (PID 1416) - PAYLOAD MALVEILLANT** |
| 12:46:05 | Lancement de FTK Imager (investigation en cours?) |
| **12:51:27** | **Reconnaissance : NETSTAT, cmd.exe, net.exe** |
| **12:51:36** | **Reconnaissance : systeminfo.exe** |
| **12:51:38** | **Reconnaissance : reg.exe (multiple instances)** |
| **12:53:57** | **Execution de script VBS malveillant via cscript.exe** |
| **12:53:57** | **Lancement de `rfhyMVOQxfc.exe` (second payload)** |
| 12:55:36 - 13:22:18 | Multiples commandes cmd.exe (activite attaquant) |
| **13:38:21 - 13:40:10** | **8 instances de `whoami.exe` (enumeration de privileges)** |
| **13:39:28** | **Ouverture de notepad.exe (exfiltration de donnees?)** |
| **13:45:12** | **Relancement de `rfhyMVOQxfc.exe` (nouvelle session)** |
| 13:45:40 | **Moment du dump memoire** |

> **Fichier de preuve :** `evidence/02_pslist.txt`, `evidence/03_pstree.txt`

---

## 4. Analyse du vecteur d'attaque - Email de phishing

### Commande executee :
```bash
strings -a memdump.mem | grep -iE "guerrillamail|john\.opoc|Your.*invoice|34625"
strings -a -e l memdump.mem | grep -iE "guerrillamail|john\.opoc|Your.*invoice|34625"
```

### Details de l'email malveillant :

| Champ | Valeur |
|-------|--------|
| **De (From)** | `hu6nsk+fgbeuap1buy4o@guerrillamail.com` |
| **A (To)** | `john.opoc2@gmail.com` (John Opoc) |
| **Sujet** | `Your invoice 34625` |
| **Corps** | `Please find attached your latest invoice.` |
| **Piece jointe** | `invoice.zip` contenant `invoice.docm` |
| **Message-ID** | `<543bbcc75ae0202f89fe5fcb408d235ae031@guerrillamail.com>` |
| **Service d'envoi** | GuerrillaMail (service d'email jetable/anonyme) |
| **IP serveur mail** | `2607:5300:60:689e::` (IPv6, OVH) |
| **Signature DKIM** | Valide (`dkim=pass`) |
| **SPF** | Pass |
| **DMARC** | Pass (`p=REJECT`) |

### Profil de la victime (extrait de Chrome) :
```json
{
  "email": "john.opoc2@gmail.com",
  "full_name": "john oc",
  "gaia": "118203655579579320720",
  "locale": "fr"
}
```

### IP publique de la victime :
```
77.136.43.214 (214.43.136.77.rev.sfr.net) - FAI: SFR (France)
```

### Chaine d'infection :
1. L'attaquant envoie un email depuis **GuerrillaMail** (email jetable)
2. La victime recoit l'email sur **Gmail** (via Outlook IMAP)
3. La victime **telecharge** `invoice.zip` depuis Gmail
4. La victime **extrait** `invoice.docm` du ZIP
5. La victime **ouvre** `invoice.docm` dans **Microsoft Word 2013** (Office 15)
6. La **macro malveillante** s'execute et drop `rad5163B.tmp.exe` dans `%TEMP%`

> **Fichiers de preuve :** `evidence/31_strings_email_details.txt`, `evidence/34_strings_guerrillamail.txt`, `evidence/33_strings_email_unicode.txt`

---

## 5. Analyse des processus

### Commande executee :
```bash
vol -f memdump.mem windows.pstree
vol -f memdump.mem windows.cmdline
```

### Arbre des processus suspects (extrait) :

```
explorer.exe (PID 588)
├── OUTLOOK.EXE (PID 3476)          <-- Client email
├── chrome.exe (PID 724)            <-- Navigateur (ferme a 12:44)
├── WINWORD.EXE (PID 3544)          <-- Ouvre invoice.docm
│   └── rad5163B.tmp.exe (PID 1416) <-- *** MALWARE INITIAL ***
│       ├── NETSTAT.EXE (x2)        <-- Reconnaissance reseau
│       ├── cmd.exe (x5)            <-- Shells de commande
│       ├── net.exe                  <-- Enumeration reseau
│       ├── systeminfo.exe           <-- Info systeme
│       ├── reg.exe (x5)            <-- Acces registre
│       ├── notepad.exe              <-- Possible exfiltration
│       ├── cscript.exe (PID 2728)   <-- Executeur VBS
│       │   ├── rfhyMVOQxfc.exe (PID 1292) <-- Payload #2 (termine)
│       │   └── rfhyMVOQxfc.exe (PID 1808) <-- Payload #2 (actif)
│       └── whoami.exe (x8)          <-- Enumeration de privileges
├── FTK Imager.exe (PID 2108)       <-- Outil forensique (response)
```

### Lignes de commande critiques :

```
PID 3544 (WINWORD.EXE):
  "C:\Program Files\Microsoft Office\Office15\WINWORD.EXE" /n "C:\Users\johnoc\Downloads\invoice\invoice.docm"

PID 1416 (rad5163B.tmp.exe):
  "C:\Users\johnoc\AppData\Local\Temp\rad5163B.tmp.exe"

PID 2728 (cscript.exe):
  cscript "C:\Users\johnoc\AppData\Local\Temp\krtYMkVgyjNdd.vbs"

PID 1808 (rfhyMVOQxfc.exe):
  "C:\Users\johnoc\AppData\Local\Temp\rad41020.tmp\rfhyMVOQxfc.exe"
```

### SIDs du processus malveillant (PID 1416) :

```bash
vol -f memdump.mem windows.getsids --pid 1416
```

```
S-1-5-21-4052921086-732667259-1946374124-1000  johnoc
S-1-5-21-4052921086-732667259-1946374124-513   Domain Users
S-1-5-32-544                                    Administrators
S-1-5-32-545                                    Users
S-1-5-4                                         Interactive
S-1-5-11                                        Authenticated Users
S-1-16-8192                                     Medium Mandatory Level
```

> Le malware s'execute sous le contexte de l'utilisateur **johnoc** qui est membre du groupe **Administrators**.

> **Fichiers de preuve :** `evidence/02_pslist.txt`, `evidence/03_pstree.txt`, `evidence/05_cmdline.txt`, `evidence/13_sids_malware.txt`

---

## 6. Analyse reseau - Connexions C2

### Commande executee :
```bash
vol -f memdump.mem windows.netscan
```

### Connexions malveillantes identifiees :

| Source | Destination | Port | Etat | PID | Processus |
|--------|-------------|------|------|-----|-----------|
| 172.16.169.167:49848 | **172.16.169.164:4444** | TCP | **ESTABLISHED** | 1416 | rad5163B.tmp.exe |
| 172.16.169.167:49850 | **172.16.169.164:4444** | TCP | CLOSED | 1292 | rfhyMVOQxfc.exe |
| 172.16.169.167:49855 | **172.16.169.164:4444** | TCP | CLOSED | 2708 | bVwHCYX.exe |
| 172.16.169.167:49857 | **172.16.169.164:4444** | TCP | CLOSED | - | - |
| 172.16.169.167:49858 | **172.16.169.164:4444** | TCP | **ESTABLISHED** | 1808 | rfhyMVOQxfc.exe |

### Connexions legitimes notables :

| Source | Destination | Port | PID | Processus | Description |
|--------|-------------|------|-----|-----------|-------------|
| 172.16.169.167 | 66.102.1.108:993 | TCP | 3476 | OUTLOOK.EXE | Gmail IMAP (ESTABLISHED) |
| - | 54.154.128.160:443 | TCP | 2472 | systeminfo.exe | AWS (suspect - C2 secondaire?) |

### Analyse :
- Le **port 4444** est le port par defaut de **Metasploit/Meterpreter** pour les reverse shells
- **5 connexions** vers le meme serveur C2 (`172.16.169.164`)
- **2 connexions actives** au moment du dump (PID 1416 et 1808)
- **3 payloads differents** se sont connectes au C2 : `rad5163B.tmp.exe`, `rfhyMVOQxfc.exe`, `bVwHCYX.exe`
- `systeminfo.exe` se connecte a une IP AWS (`54.154.128.160:443`) - possible canal C2 secondaire ou exfiltration

> **Fichier de preuve :** `evidence/04_netscan.txt`

---

## 7. Malware identifie

### Executable principal : rad5163B.tmp.exe

```bash
# Dump du malware depuis la memoire
vol --output-dir ./dumped_files -f memdump.mem windows.dumpfiles --pid 1416
```

| Attribut | Valeur |
|----------|--------|
| **Nom** | rad5163B.tmp.exe |
| **Chemin** | C:\Users\johnoc\AppData\Local\Temp\rad5163B.tmp.exe |
| **Type** | PE32 executable for MS Windows 4.00 (GUI), Intel i386 |
| **Taille (dump)** | 73 728 octets |
| **MD5** | `599bda78a88be6bc15f9141bd8423057` |
| **SHA1** | `44ebac29bc7f1924f762980b24c521d1bf7bda1f` |
| **SHA256** | `3e5c3481529d9dd11646a99074ba3af9597cdef88708e7f8faf85ad37b0cf4dd` |
| **Parent** | WINWORD.EXE (PID 3544) |
| **Detection** | `Exploit:Win32/Weedymut.Albqrq.B0005-a2` (Windows Defender) |

### DLLs chargees par le malware :

```bash
vol -f memdump.mem windows.dlllist --pid 1416
```

DLLs notables chargees : `System.Management.Automation.ni.dll` (PowerShell), `mscorwks.dll` (.NET CLR), `ws2_32.dll` (Winsock), `wininet.dll` (Internet), `crypt32.dll` (Crypto), `winhttp.dll` (HTTP)

> Le malware est un executable .NET qui charge PowerShell et utilise des communications reseau.

### Payloads secondaires :

| Fichier | Chemin | PID | Connexion C2 |
|---------|--------|-----|--------------|
| `krtYMkVgyjNdd.vbs` | %TEMP%\ | 2728 (cscript) | N/A (droppeur) |
| `rfhyMVOQxfc.exe` | %TEMP%\rad0C636.tmp\ | 1292 | 172.16.169.164:4444 |
| `rfhyMVOQxfc.exe` | %TEMP%\rad41020.tmp\ | 1808 | 172.16.169.164:4444 |
| `bVwHCYX.exe` | (non resolu) | 2708 | 172.16.169.164:4444 |

### Preuves Meterpreter/Mimikatz dans la memoire :

```bash
strings -a memdump.mem | grep -iE "MSF\.|Meterpreter|Kiwi|mimikatz"
```

Extraits des strings trouvees :
```
$s = New-Object MSF.Powershell.Meterpreter.Kiwi+DcSyncAllSettings
$t = New-Object MSF.Powershell.Meterpreter.Transport+TransportInstance
$t.Url = $Url + [MSF.Powershell.Meterpreter.Transport]::GenerateTransportUri()
$output=send-forcedloggingsettingsmail-pebytes$($bytes)-exeargs$($exeargs)-funcreturntype"wstring"-funcname"powershell_reflective_mimikatz"
'$registrypayloadvaluename'
0HSTR:Win32/Meterpreter!CMD
$base64payload=[convert]::tobase64string([text.encoding]::unicode.getbytes
Exploit:Win32/Weedymut.Albqrq.B0005-a2
```

> Ces strings confirment l'utilisation de :
> - **Meterpreter** (agent Metasploit)
> - **Kiwi** (module Meterpreter pour Mimikatz)
> - **DcSync** (technique d'extraction de credentials Active Directory)
> - **PowerShell Reflective Mimikatz** (injection en memoire de Mimikatz)
> - **Persistence par registre** (`$registrypayloadvaluename`)

> **Fichiers de preuve :** `evidence/08_dlllist_rad5163B.txt`, `evidence/32_strings_meterpreter.txt`, `evidence/MALWARE_rad5163B.tmp.exe.dumped`

---

## 8. Activite post-exploitation

### Commandes de reconnaissance executees par l'attaquant

Le processus `rad5163B.tmp.exe` (PID 1416) a lance les commandes suivantes :

| Heure | Commande | PID | Objectif |
|-------|----------|-----|----------|
| 12:51:27 | `NETSTAT.EXE` (x2) | 3928, 1716 | Enumeration des connexions reseau |
| 12:51:27 | `cmd.exe` | 2284 | Shell de commande |
| 12:51:27 | `net.exe` / `net1.exe` (x5) | Multiple | Enumeration des comptes/groupes |
| 12:51:36 | `systeminfo.exe` | 2472 | Informations systeme completes |
| 12:51:38 | `reg.exe` (x5) | Multiple | Lecture/modification du registre |
| 12:53:57 | `cscript.exe` | 2728 | Execution de script VBS (droppeur) |
| 12:55:36 - 13:22:18 | `cmd.exe` (x4) | Multiple | Shells additionnels |
| 13:38:21 - 13:40:10 | `whoami.exe` (x8) | Multiple | Verification des privileges |
| 13:39:28 | `notepad.exe` | 2592 | Lecture/ecriture de fichiers |

### Script VBS de staging :

```
cscript "C:\Users\johnoc\AppData\Local\Temp\krtYMkVgyjNdd.vbs"
```

Ce script VBS a declenche le telechargement et l'execution du deuxieme payload (`rfhyMVOQxfc.exe`).

### Outils de credential dumping :

Les strings en memoire revelent l'utilisation de :
- **Mimikatz** via PowerShell reflective injection
- **Kiwi** (module Meterpreter integre)
- **DcSync** (attaque sur Active Directory)

> **Fichiers de preuve :** `evidence/02_pslist.txt`, `evidence/26_strings_c2.txt`, `evidence/35_strings_c2_extra.txt`

---

## 9. Injection memoire (Malfind)

### Commande executee :
```bash
vol -f memdump.mem windows.malfind
```

### Resultats :

Le plugin `malfind` a detecte **des zones memoire suspectes** avec la protection `PAGE_EXECUTE_READWRITE` dans le processus `svchost.exe` (PID 2896) :

```
PID 2896  svchost.exe  VPN: 0x4fe0000-0x505ffff  PAGE_EXECUTE_READWRITE
PID 2896  svchost.exe  VPN: 0x5060000-0x515ffff  PAGE_EXECUTE_READWRITE
```

> La presence de zones memoire avec des permissions `RWX` dans `svchost.exe` indique une **injection de code** (technique classique de Meterpreter).

> **Fichiers de preuve :** `evidence/09_malfind.txt`, `evidence/18_malfind_rad5163B.txt`

---

## 10. Fichiers suspects

### Commande executee :
```bash
vol -f memdump.mem windows.filescan | grep -iE "invoice|rad5163B|rfhyMVO|krtYMk"
```

### Fichiers lies a l'attaque trouves en memoire :

| Fichier | Chemin |
|---------|--------|
| `invoice.docm` | C:\Users\johnoc\Downloads\invoice\invoice.docm |
| `invoice.lnk` | C:\Users\johnoc\AppData\Roaming\Microsoft\Windows\Recent\invoice.lnk |
| `invoice.asd` | AutoRecovery save of invoice.asd |
| `rad5163B.tmp.exe` | C:\Users\johnoc\AppData\Local\Temp\rad5163B.tmp.exe |
| `rfhyMVOQxfc.exe` | C:\Users\johnoc\AppData\Local\Temp\rad41020.tmp\rfhyMVOQxfc.exe |

### UserAssist (historique d'execution) :

```bash
vol -f memdump.mem windows.registry.userassist
```

| Programme | Derniere execution | Nb executions |
|-----------|--------------------|---------------|
| OUTLOOK.EXE | 2019-07-31 11:56:34 | 5 |
| Chrome | 2019-07-31 12:03:30 | 2 |
| WINWORD.EXE | 2019-07-31 12:45:34 | 2 |
| FTK Imager.exe | 2019-07-31 12:46:05 | 1 |
| cmd.exe | 2019-07-31 11:57:05 | 4 |

> **Fichiers de preuve :** `evidence/16_suspicious_files.txt`, `evidence/24_userassist_filtered.txt`

---

## 11. Indicateurs de compromission (IOCs)

### Adresses IP :

| IP | Port | Role |
|----|------|------|
| `172.16.169.164` | 4444 | Serveur C2 Metasploit (reseau interne) |
| `172.16.169.167` | - | Machine victime |
| `54.154.128.160` | 443 | Serveur secondaire (AWS eu-west-1) |
| `2607:5300:60:689e::` | - | Serveur mail GuerrillaMail (OVH) |

### Adresses email :

| Email | Role |
|-------|------|
| `hu6nsk+fgbeuap1buy4o@guerrillamail.com` | Expediteur (attaquant) |
| `john.opoc2@gmail.com` | Victime |

### Hashs du malware (rad5163B.tmp.exe) :

| Algorithme | Hash |
|------------|------|
| **MD5** | `599bda78a88be6bc15f9141bd8423057` |
| **SHA1** | `44ebac29bc7f1924f762980b24c521d1bf7bda1f` |
| **SHA256** | `3e5c3481529d9dd11646a99074ba3af9597cdef88708e7f8faf85ad37b0cf4dd` |

### Noms de fichiers malveillants :

- `invoice.docm` (macro Word malveillante)
- `rad5163B.tmp.exe` (payload initial)
- `krtYMkVgyjNdd.vbs` (script VBS de staging)
- `rfhyMVOQxfc.exe` (payload secondaire Meterpreter)
- `bVwHCYX.exe` (payload secondaire Meterpreter)

### Chemins suspects :

- `C:\Users\johnoc\AppData\Local\Temp\rad5163B.tmp.exe`
- `C:\Users\johnoc\AppData\Local\Temp\krtYMkVgyjNdd.vbs`
- `C:\Users\johnoc\AppData\Local\Temp\rad41020.tmp\rfhyMVOQxfc.exe`
- `C:\Users\johnoc\AppData\Local\Temp\rad0C636.tmp\rfhyMVOQxfc.exe`
- `C:\Users\johnoc\Downloads\invoice\invoice.docm`

### Signatures de detection :

- `Exploit:Win32/Weedymut.Albqrq.B0005-a2` (Windows Defender)
- `HSTR:Win32/Meterpreter!CMD`

---

## 12. Conclusion

### Resume de l'attaque

Cette analyse forensique revele une attaque de type **spear-phishing** suivie d'une **compromission complete** du poste de travail :

1. **Vecteur initial :** Email de phishing envoye depuis GuerrillaMail (email jetable) avec le sujet "Your invoice 34625" contenant `invoice.zip`
2. **Exploitation :** La victime ouvre `invoice.docm`, une macro malveillante s'execute et drop un executable dans `%TEMP%`
3. **Command & Control :** Le payload `rad5163B.tmp.exe` etablit un reverse shell Meterpreter vers `172.16.169.164:4444`
4. **Reconnaissance :** L'attaquant execute `netstat`, `systeminfo`, `net`, `reg`, `whoami` pour cartographier le systeme
5. **Persistence :** Deploiement de payloads secondaires via VBS (`rfhyMVOQxfc.exe`, `bVwHCYX.exe`)
6. **Credential dumping :** Utilisation de Mimikatz/Kiwi via Meterpreter pour extraire les credentials (DcSync)

### Evaluation de la severite : **CRITIQUE**

- L'attaquant a un acces shell complet au systeme
- Des outils de credential dumping ont ete deployes
- Plusieurs sessions Meterpreter ont ete etablies
- L'utilisateur compromis est membre du groupe Administrators
- Le dump memoire a ete effectue pendant que l'attaque etait **encore active**

### Recommandations :

1. **Isoler immediatement** la machine du reseau
2. **Bloquer** l'IP C2 `172.16.169.164` sur le firewall
3. **Changer tous les mots de passe** du domaine (DcSync detecte)
4. **Scanner** les autres machines du reseau `172.16.169.0/24`
5. **Analyser** les logs du serveur mail pour d'autres destinataires
6. **Bloquer** les emails provenant de `guerrillamail.com`
7. **Desactiver** les macros dans Microsoft Office ou les restreindre

---

## 13. Annexe - Fichiers de preuves

Tous les fichiers de preuves sont stockes dans le dossier `evidence/` :

| Fichier | Description |
|---------|-------------|
| `01_system_info.txt` | Informations systeme (windows.info) |
| `02_pslist.txt` | Liste des processus (windows.pslist) |
| `03_pstree.txt` | Arbre des processus (windows.pstree) |
| `04_netscan.txt` | Connexions reseau (windows.netscan) |
| `05_cmdline.txt` | Lignes de commande (windows.cmdline) |
| `07_filescan.txt` | Scan des fichiers en memoire (windows.filescan) |
| `08_dlllist_rad5163B.txt` | DLLs du malware PID 1416 |
| `09_malfind.txt` | Code injecte en memoire (windows.malfind) |
| `10_hivelist.txt` | Ruches de registre (windows.registry.hivelist) |
| `11_envars_malware.txt` | Variables d'environnement du malware |
| `12_handles_rad5163B.txt` | Handles du processus malware |
| `13_sids_malware.txt` | SIDs du processus malware |
| `14_userassist.txt` | Historique d'execution (UserAssist) |
| `15_svcscan.txt` | Services Windows |
| `16_suspicious_files.txt` | Fichiers suspects filtres |
| `18_malfind_rad5163B.txt` | Malfind specifique au malware |
| `19_dlllist_rfhyMVOQxfc.txt` | DLLs du second payload |
| `20_privileges_malware.txt` | Privileges du processus malware |
| `21_strings_email.txt` | Strings email (Unicode) |
| `22_strings_urls.txt` | URLs extraites (ASCII) |
| `23_strings_urls_unicode.txt` | URLs extraites (Unicode) |
| `24_userassist_filtered.txt` | UserAssist filtre |
| `25_psscan.txt` | Scan de processus caches |
| `26_strings_c2.txt` | Strings liees au C2/Metasploit |
| `27_strings_malware_keywords.txt` | Mots-cles malware |
| `28_callbacks.txt` | Callbacks kernel |
| `29_dlllist_cscript.txt` | DLLs de cscript.exe |
| `30_sids_winword.txt` | SIDs de WINWORD.EXE |
| `31_strings_email_details.txt` | Details email (ASCII) |
| `32_strings_meterpreter.txt` | Strings Meterpreter/Mimikatz |
| `33_strings_email_unicode.txt` | Details email (Unicode) |
| `34_strings_guerrillamail.txt` | Strings GuerrillaMail |
| `35_strings_c2_extra.txt` | Strings C2 additionnelles |
| `37_strings_phishing_body.txt` | Corps du mail de phishing |
| `MALWARE_rad5163B.tmp.exe.dumped` | Executable malveillant extrait de la memoire |
| `dumped_files/` | Tous les fichiers dumpes du processus malware |

---

*Rapport genere le 05 Mars 2026*
*Outil : Volatility 3 Framework 2.27.0 sur Kali Linux*
