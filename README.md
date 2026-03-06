# TP1 - Analyse Forensique

Ce dépôt contient le rendu du TP d'analyse forensique, organisé en six parties distinctes.

---

## 📁 Structure du dépôt

### [Partie 1 - Analyse Malware](./Partie1_Analyse_Malware/)

Analyse complète de malware (Res.exe et Env.exe) utilisant des techniques de reverse engineering et d'analyse statique.

**Contenu :**
- 📄 [README.md](./Partie1_Analyse_Malware/README.md) - Rapport d'analyse malware complet
- 📄 [ANALYSE_MALWARE.md](./Partie1_Analyse_Malware/ANALYSE_MALWARE.md) - Analyse détaillée du malware
- 📄 [DECOMPILATION_DETAILLEE.md](./Partie1_Analyse_Malware/DECOMPILATION_DETAILLEE.md) - Décompilation et analyse du code
- 📄 [GUIDE_OUTILS_REVERSE_ENGINEERING.md](./Partie1_Analyse_Malware/GUIDE_OUTILS_REVERSE_ENGINEERING.md) - Guide des outils utilisés
- 📄 [TUTORIEL_COMPLET_COMMANDES.md](./Partie1_Analyse_Malware/TUTORIEL_COMPLET_COMMANDES.md) - Tutoriel des commandes d'analyse

**Résumé :** Identification et analyse d'un dropper/spyware avec capacités d'exfiltration SMTP, persistance via registre Windows, et comportements malveillants confirmés.

---

### [Partie 2 - Analyse Dump RAM](./Partie2_Dump_RAM/)

Analyse forensique d'un dump mémoire RAM utilisant Volatility Framework.

**Contenu :**
- 📄 [RAPPORT_DUMP_RAM.md](./Partie2_Dump_RAM/RAPPORT_DUMP_RAM.md) - Rapport d'analyse du dump mémoire
- 📄 [COMMANDES_DUMP_RAM.md](./Partie2_Dump_RAM/COMMANDES_DUMP_RAM.md) - Commandes Volatility utilisées
- 📁 [results/](./Partie2_Dump_RAM/results/) - Résultats des analyses Volatility

**Résumé :** Investigation mémoire pour identifier les processus, connexions réseau, artefacts malveillants et autres IOCs présents dans le dump RAM.

---

### [Partie 3 - Copie Bit-à-Bit de Disque](./Partie3_copie_disque/)

Acquisition forensique d'une partition disque avec copie bit-à-bit et vérification d'intégrité.

**Contenu :**
- 📄 [RAPPORT_COPIE_DISQUE.md](./Partie3_copie_disque/RAPPORT_COPIE_DISQUE.md) - Rapport forensique complet de l'acquisition
- 📄 [GUIDE_COPIE_DISQUE.md](./Partie3_copie_disque/GUIDE_COPIE_DISQUE.md) - Guide pratique avec tutoriel et commandes
- 📁 [images/](./Partie3_copie_disque/images/) - Image bit-à-bit de la partition (sda1.img - 976 Mo)
- 📁 [hashes/](./Partie3_copie_disque/hashes/) - Hashes MD5/SHA1/SHA256 pour vérification d'intégrité
- 📁 [logs/](./Partie3_copie_disque/logs/) - Métadonnées d'acquisition et logs

**Résumé :** Création d'une image forensique bit-à-bit de la partition EFI (/dev/sda1) avec dd, calcul de hashes cryptographiques (MD5, SHA1, SHA256) et vérification d'intégrité complète. L'image est une copie exacte vérifiée pour analyse forensique.

---

### [Partie 4 - Analyse Forensique d'un Dump Mémoire (Spear-Phishing & Meterpreter)](./Partie4_Analyse_Dump_Memoire/)

Analyse forensique approfondie d'un dump mémoire Windows 7 SP1 (2 Go) avec **Volatility 3**, comprenant l'identification complète d'une attaque de **spear-phishing** avec déploiement de **Meterpreter/Metasploit**.

**Contenu :**
- 📄 [RAPPORT_FORENSIQUE.md](./Partie4_Analyse_Dump_Memoire/RAPPORT_FORENSIQUE.md) - Rapport forensique complet avec commandes et sorties réelles
- 📁 [evidence/](./Partie4_Analyse_Dump_Memoire/evidence/) - 39 fichiers de preuves (sorties Volatility, strings, fichiers dumpés)
- 🔬 [evidence/MALWARE_rad5163B.tmp.exe.dumped](./Partie4_Analyse_Dump_Memoire/evidence/MALWARE_rad5163B.tmp.exe.dumped) - Exécutable malveillant extrait de la mémoire
- 📁 [evidence/dumped_files/](./Partie4_Analyse_Dump_Memoire/evidence/dumped_files/) - DLLs et binaires dumpés du processus malveillant

**Résumé de l'attaque identifiée :**

| Étape | Détails |
|-------|---------|
| **Vecteur** | Email de phishing via GuerrillaMail (`hu6nsk+fgbeuap1buy4o@guerrillamail.com`) |
| **Victime** | `john.opoc2@gmail.com` (utilisateur `johnoc`) |
| **Sujet** | "Your invoice 34625" avec pièce jointe `invoice.zip` |
| **Payload** | `invoice.docm` → macro Word → `rad5163B.tmp.exe` |
| **C2** | `172.16.169.164:4444` (Meterpreter reverse shell) |
| **Post-exploitation** | Reconnaissance (netstat, systeminfo, whoami), Mimikatz/Kiwi, DcSync |
| **IOC principal** | MD5: `599bda78a88be6bc15f9141bd8423057` / SHA256: `3e5c3481529d9dd11646a99074ba3af9597cdef88708e7f8faf85ad37b0cf4dd` |

**Preuves collectées (39 fichiers) :**
- Sorties Volatility : `pslist`, `pstree`, `netscan`, `cmdline`, `malfind`, `filescan`, `dlllist`, `getsids`, `userassist`, etc.
- Strings extraits : emails, URLs, mots-clés Meterpreter/Mimikatz, données GuerrillaMail
- Exécutable malveillant dumpé depuis la mémoire avec hashes cryptographiques

---

### [Partie 5 - Analyse Forensique d'une Image Disque HDD](./Partie5_Dump_HDD/)

Analyse forensique complète d'une image disque Windows 7 (25,6 Go, 18 segments FTK Imager) avec **The Sleuth Kit**, **RegRipper** et **python-evtx**, faisant suite à la Partie 4 (même machine compromise).

**Contenu :**
- 📄 [RAPPORT_ANALYSE_HDD.md](./Partie5_Dump_HDD/RAPPORT_ANALYSE_HDD.md) - Rapport forensique complet (chaîne de custody, timeline, IOCs)
- 📁 [evidence/](./Partie5_Dump_HDD/evidence/) - 28 fichiers de preuves (partitions, registre, journaux, malwares extraits)
- 🔬 [evidence/malware_samples/](./Partie5_Dump_HDD/evidence/malware_samples/) - 5 échantillons malveillants extraits (exe, docm, vbs)

**Résumé des découvertes :**

| Artefact | Détails |
|----------|---------|
| **Vecteur** | `invoice.zip` téléchargé le 31/07/2019 à 12:44 UTC (ZoneId=3 = Internet) |
| **Payload initial** | `rad5163B.tmp.exe` créé à 12:45:47 UTC par la macro `invoice.docm` |
| **Persistance** | `krtYMkVgyjNdd.vbs` déposé à 12:53:57 UTC, clé Run registre |
| **Anti-forensics** | Script VBS redéploie un exe base64 toutes les 5s puis le supprime |
| **Malwares** | `rad5163B.tmp.exe`, `bVwHCYX.exe`, `RGoEsDNcZhEnl.exe`, `tior.exe` |
| **Fichier supprimé** | `memdump.mem` mis à la corbeille par l'attaquant |

---

### [Partie 6 (Bonus) - Gestion des Incidents : SIEM Wazuh](./Partie6_Bonus_Gestion_incidents/)

Déploiement, configuration et test d'un SIEM open source **Wazuh 4.9.2** via Docker Compose (architecture 3 tiers), avec installation d'un agent sur la machine Kali et génération d'alertes réelles.

**Contenu :**
- 📄 [RAPPORT_SIEM_WAZUH.md](./Partie6_Bonus_Gestion_incidents/RAPPORT_SIEM_WAZUH.md) - Rapport complet (théorie SIEM + comparatif + déploiement pratique)
- 📁 [evidence/](./Partie6_Bonus_Gestion_incidents/evidence/) - 20 fichiers de preuves (API, logs, alertes, stats)
- 📁 [wazuh-deploy/](./Partie6_Bonus_Gestion_incidents/wazuh-deploy/) - Stack Docker Compose + configs TLS complètes

**Architecture déployée :**

| Composant | Image | Port | Status |
|-----------|-------|------|--------|
| wazuh.manager | `wazuh/wazuh-manager:4.9.2` | 1514, 1515, 514/udp, 55000 | active |
| wazuh.indexer | `wazuh/wazuh-indexer:4.9.2` (OpenSearch 2.13.0) | 9200 | active, cluster GREEN |
| wazuh.dashboard | `wazuh/wazuh-dashboard:4.9.2` | 443 (HTTPS) | active |
| wazuh-agent | installé sur Kali (ID:002, kali-forensic) | - | active, connecté |

**Résultats :** 3019 événements décodés, **50 alertes générées** (SCA, rootcheck, FIM, sudo, PAM), 0 perte.

---

## 🛠️ Technologies utilisées

**Partie 1 :**
- Kali Linux (environnement isolé)
- `strings`, `file`, `objdump`
- Analyse statique de binaires PE32
- Reverse engineering

**Partie 2 :**
- LiME (Linux Memory Extractor)
- Volatility Framework
- Analyse forensique mémoire
- Investigation d'incidents

**Partie 3 :**
- dd (disk dump)
- Copie bit-à-bit (disk imaging)
- Hashing cryptographique (MD5, SHA1, SHA256)
- Vérification d'intégrité forensique
- Chaîne de traçabilité

**Partie 4 :**
- Volatility 3 Framework (2.27.0)
- `strings` (extraction ASCII/Unicode)
- Analyse de dump mémoire Windows (.mem)
- Identification de malware (IOCs, hashes)
- Analyse réseau (connexions C2)
- Extraction de preuves numériques

**Partie 5 :**
- FTK Imager 3.1.1.8 (acquisition, 18 segments)
- The Sleuth Kit : `mmls`, `fsstat`, `fls`, `icat`
- RegRipper (userassist, run, shellbags, MRU, typedurls)
- python-evtx (Security, System, PowerShell-Operational)
- Analyse de métadonnées NTFS, ADS (Zone.Identifier)

**Partie 6 :**
- Docker 27.5.1 + Docker Compose v5.0.2
- Wazuh 4.9.2 (Manager, Indexer, Dashboard)
- OpenSearch 2.13.0 + OpenSearch Dashboards
- Wazuh Agent (multi-plateforme)
- TLS mutuel (PKI interne, certificats par composant)
- API REST Wazuh (JWT)

---

## ⚠️ Avertissement

Ce dépôt contient des analyses de malware à des fins éducatives uniquement. Les binaires analysés sont dangereux et ne doivent **JAMAIS** être exécutés en dehors d'un environnement isolé.

---

## 📝 Licence

Voir le fichier [LICENSE](./LICENSE) pour plus d'informations.

---

**Date de dernière mise à jour:** 2026-03-06
**Environnement:** Kali GNU/Linux 2025.4 (kernel 6.18.5+kali-amd64)
**Auteur:** nyx

## 📊 Statistiques du TP

| Partie | Fichiers | Taille totale |
|--------|----------|---------------|
| **Partie 1** | 5 documents | ~120 Ko |
| **Partie 2** | 2 documents + dump 12 Go | ~12 Go |
| **Partie 3** | 2 documents + image 976 Mo | ~976 Mo |
| **Partie 4** | 1 rapport + 39 fichiers de preuves + malware dumpé | ~1.2 Mo |
| **Partie 5** | 1 rapport + 28 fichiers de preuves + 5 malwares extraits | ~25.6 Go |
| **Partie 6** | 1 rapport + 20 fichiers de preuves + configs Docker | ~500 Ko |
| **TOTAL** | **~80 fichiers** | **~38 Go** |
