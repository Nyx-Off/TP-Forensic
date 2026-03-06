# GUIDE COMPLET : OUTILS DE REVERSE ENGINEERING

**Date:** 2025-12-01
**Objectif:** Apprendre à analyser un malware avec des outils gratuits
**Niveau:** Débutant à Intermédiaire
**OS:** Kali Linux (ou toute distribution Linux)

---

## TABLE DES MATIÈRES

1. [Introduction aux outils](#introduction-aux-outils)
2. [Outil 1 : file - Identification de fichiers](#outil-1--file)
3. [Outil 2 : strings - Extraction de chaînes](#outil-2--strings)
4. [Outil 3 : md5sum & sha256sum - Calcul de hash](#outil-3--md5sum--sha256sum)
5. [Outil 4 : objdump - Désassembleur basique](#outil-4--objdump)
6. [Outil 5 : radare2 - Suite complète](#outil-5--radare2)
7. [Workflow complet d'analyse](#workflow-complet-danalyse)
8. [Commandes avancées](#commandes-avancées)
9. [Outils complémentaires](#outils-complémentaires)

---

## INTRODUCTION AUX OUTILS

### Vue d'ensemble

| Outil | Rôle | Complexité | Quand l'utiliser |
|-------|------|------------|------------------|
| **file** | Identification type de fichier | ★☆☆☆☆ | Toujours en premier |
| **strings** | Extraction de texte lisible | ★☆☆☆☆ | Recherche rapide d'infos |
| **md5sum/sha256sum** | Calcul d'empreinte | ★☆☆☆☆ | Vérification réputation |
| **objdump** | Désassemblage et analyse PE | ★★☆☆☆ | Analyse structure binaire |
| **radare2** | Suite complète de RE | ★★★★☆ | Analyse approfondie |

### Installation (si nécessaire)

```bash
# Sur Kali Linux (déjà installés normalement)
sudo apt update
sudo apt install -y binutils radare2 file

# Vérification des installations
which file strings md5sum sha256sum objdump radare2
```

---

## OUTIL 1 : file

### Description
`file` détermine le type d'un fichier en analysant son contenu (magic bytes), pas son extension.

### Syntaxe de base
```bash
file [OPTIONS] FICHIER
```

### Commandes utilisées dans l'analyse

#### Commande 1 : Identifier tous les fichiers
```bash
file *.exe *.dll
```

**Ce que j'ai exécuté:**
```bash
file Res.exe Env.exe *.dll
```

**Résultat obtenu:**
```
Res.exe:             PE32 executable for MS Windows 4.00 (console), Intel i386 (stripped to external PDB), 8 sections
Env.exe:             PE32 executable for MS Windows 4.00 (GUI), Intel i386 (stripped to external PDB), 8 sections
libgcc_s_dw2-1.dll:  PE32 executable for MS Windows 4.00 (DLL), Intel i386 (stripped to external PDB), 10 sections
Qt5Core.dll:         PE32 executable for MS Windows 4.00 (DLL), Intel i386 (stripped to external PDB), 11 sections
```

**Interprétation:**
- `PE32` = Portable Executable 32 bits (Windows)
- `console` = Application console (fenêtre CMD)
- `GUI` = Application graphique (fenêtres)
- `Intel i386` = Architecture 32 bits
- `stripped to external PDB` = Symboles de debug retirés
- `8 sections` = Nombre de sections dans le PE

### Options utiles

```bash
# Format détaillé (MIME type)
file -i Res.exe
# Résultat: application/x-dosexec; charset=binary

# Afficher uniquement le type (sans le nom du fichier)
file -b Res.exe
# Résultat: PE32 executable for MS Windows 4.00 (console)...

# Vérifier plusieurs fichiers récursivement
find . -type f -exec file {} \;
```

### Cas d'usage
✅ **Utiliser file pour:**
- Vérifier si un .txt est vraiment un texte ou un binaire renommé
- Identifier l'architecture (32/64 bits)
- Détecter des fichiers cachés/renommés
- Première étape d'analyse

❌ **Ne pas utiliser file pour:**
- Analyser le contenu détaillé
- Désassembler du code
- Extraire des chaînes

---

## OUTIL 2 : strings

### Description
`strings` extrait toutes les chaînes de caractères imprimables (ASCII/Unicode) d'un fichier binaire.

### Syntaxe de base
```bash
strings [OPTIONS] FICHIER
```

### Commandes utilisées dans l'analyse

#### Commande 1 : Extraire toutes les chaînes
```bash
strings Res.exe
```

**Exemple de sortie:**
```
!This program cannot be run in DOS mode.
.text
.data
.rdata
libgcc_s_dw2-1.dll
mkdir c:\WindSyst
XCOPY Res.exe c:\WindSyst /S
codé par le magniquime Hafnium !
```

#### Commande 2 : Filtrer les résultats avec grep
```bash
strings Res.exe | grep -i "http"
strings Res.exe | grep -i "\.exe"
strings Res.exe | grep -i "HKEY"
```

**Ce que j'ai exécuté:**
```bash
strings Env.exe | grep -E "(http|ftp|www|\.exe|\.dll|HKEY|SOFTWARE|CurrentVersion|Run)"
```

**Résultat:**
```
libgcc_s_dw2-1.dll
Qt5Core.dll
Qt5Network.dll
C:\WindSyst\Res.exe
C:\WindSyst\Env.exe
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
```

**Interprétation:**
- Le malware référence des chemins vers `c:\WindSyst`
- Modification du registre Windows détectée
- DLLs Qt utilisées (interface graphique)

#### Commande 3 : Recherche de patterns spécifiques
```bash
# Chercher des emails
strings Env.exe | grep -E "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
```

**Résultat:**
```
aaaaaaaaaaaa@laposte.net
aaaaaaaaaaaa@gmail.com
```

```bash
# Chercher des serveurs SMTP
strings Env.exe | grep -i smtp
```

**Résultat:**
```
smtp.gmail.com
smtp.laposte.net
SMTP Example
```

```bash
# Chercher des mots de passe (patterns communs)
strings Env.exe | grep -i "pass"
```

**Résultat:**
```
Password:
z98tmFrance
```

### Options avancées

```bash
# Minimum 10 caractères (-n 10)
strings -n 10 Res.exe

# Extraire Unicode aussi (-e l = little-endian UTF-16)
strings -e l Res.exe

# Afficher les offsets (positions) dans le fichier
strings -t x Res.exe
# Format: offset_hexa  chaine

# Limiter aux 100 premières lignes
strings Res.exe | head -100

# Compter le nombre de chaînes
strings Res.exe | wc -l
```

### Cas d'usage pratiques

```bash
# Rechercher tous les fichiers référencés
strings malware.exe | grep -E "\.(exe|dll|sys|bat|ps1|vbs)"

# Rechercher des URLs
strings malware.exe | grep -E "https?://"

# Rechercher des adresses IP
strings malware.exe | grep -E "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b"

# Rechercher des clés de registre
strings malware.exe | grep -i "HKEY_"

# Rechercher des commandes PowerShell/CMD
strings malware.exe | grep -iE "(powershell|cmd\.exe|wscript)"

# Rechercher des fonctions API Windows dangereuses
strings malware.exe | grep -E "(CreateProcess|VirtualAlloc|WriteProcessMemory|LoadLibrary)"
```

### Astuce : Combiner avec d'autres outils

```bash
# Extraire et trier par fréquence
strings Res.exe | sort | uniq -c | sort -rn | head -20

# Extraire uniquement les longues chaînes (possibles URLs/chemins)
strings Res.exe | awk 'length > 30'

# Exporter dans un fichier pour analyse
strings Res.exe > res_strings.txt
strings Env.exe > env_strings.txt
```

---

## OUTIL 3 : md5sum & sha256sum

### Description
Calculent l'empreinte cryptographique (hash) d'un fichier. Permet de vérifier l'identité d'un fichier et sa réputation sur des bases de données comme VirusTotal.

### Syntaxe de base
```bash
md5sum FICHIER
sha256sum FICHIER
```

### Commandes utilisées dans l'analyse

#### Commande 1 : Calculer SHA256 (recommandé)
```bash
sha256sum *.exe
```

**Ce que j'ai exécuté:**
```bash
sha256sum Res.exe Env.exe
```

**Résultat:**
```
e09ec2098363a129de143fdaf73ad6e2e61266fba3f638a25214af3a8bc8f2f2  Res.exe
49f091ade48890bfa22d2b455494be95e52392c478b67e10626222b6aee37e1e  Env.exe
```

#### Commande 2 : Calculer MD5 (pour compatibilité)
```bash
md5sum *.exe
```

**Résultat:**
```
abbc02a7e5ff7b884700eac7087cf743  Res.exe
d872a3086fbb82ed08a8322c028692dc  Env.exe
```

### Vérifier sur VirusTotal

**Méthode 1 : Web**
1. Aller sur https://www.virustotal.com/
2. Coller le hash SHA256 dans la barre de recherche
3. Voir les résultats de 70+ antivirus

**Méthode 2 : CLI (avec API)**
```bash
# Installer vt-cli
pip3 install vt-py

# Rechercher un hash
vt file e09ec2098363a129de143fdaf73ad6e2e61266fba3f638a25214af3a8bc8f2f2
```

### Créer une base de données de hashes

```bash
# Calculer tous les hashes d'un répertoire
find . -type f -exec sha256sum {} \; > hashes.txt

# Format pour import dans des outils
sha256sum *.exe *.dll | awk '{print $1}' > iocs.txt
```

### Vérifier l'intégrité

```bash
# Créer un fichier de checksums
sha256sum *.exe > checksums.sha256

# Vérifier plus tard
sha256sum -c checksums.sha256

# Résultat:
# Res.exe: OK
# Env.exe: OK
# ou
# Res.exe: FAILED (si modifié)
```

---

## OUTIL 4 : objdump

### Description
`objdump` est un désassembleur et analyseur de fichiers objets. Parfait pour analyser la structure des PE (Portable Executable) Windows.

### Syntaxe de base
```bash
objdump [OPTIONS] FICHIER
```

### Commandes utilisées dans l'analyse

#### Commande 1 : Afficher les sections du PE
```bash
objdump -h Res.exe
```

**Résultat:**
```
Res.exe:     format de fichier pei-i386

Sections :
Idx Name          Taille    VMA       LMA       Off fich  Algn
  0 .text         00002768  00401000  00401000  00000400  2**4
                  CONTENTS, ALLOC, LOAD, READONLY, CODE, DATA
  1 .data         000000b0  00404000  00404000  00002c00  2**5
                  CONTENTS, ALLOC, LOAD, DATA
  2 .rdata        0000102c  00405000  00405000  00002e00  2**5
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  3 .eh_fram      00000dac  00407000  00407000  00004000  2**2
```

**Interprétation:**
- `.text` = Code exécutable (10 KB)
- `.data` = Données initialisées en lecture/écriture
- `.rdata` = Données en lecture seule (strings, constantes)
- `VMA` = Virtual Memory Address (où la section sera chargée)
- `Off fich` = Offset dans le fichier sur disque

#### Commande 2 : Afficher le header du fichier
```bash
objdump -f Res.exe
```

**Résultat:**
```
Res.exe:     format de fichier pei-i386
architecture: i386, fanions 0x00000102:
EXEC_P, D_PAGED
adresse de départ 0x004014e0
```

**Interprétation:**
- Architecture : i386 (32 bits)
- Point d'entrée : `0x004014e0` (première instruction exécutée)

#### Commande 3 : Désassembler une section
```bash
objdump -d Res.exe > res_disasm.txt
```

**Options:**
- `-d` : Désassemble les sections de code
- Crée un fichier texte avec tout le code assembleur

**Exemple de sortie:**
```asm
004014e0 <.text>:
  4014e0:       55                      push   %ebp
  4014e1:       89 e5                   mov    %esp,%ebp
  4014e3:       83 ec 18                sub    $0x18,%esp
```

#### Commande 4 : Afficher les symboles
```bash
objdump -t Res.exe
```

**Note:** Sur des binaires "stripped", peu de symboles visibles.

#### Commande 5 : Afficher toutes les informations
```bash
objdump -x Res.exe | less
```

**Contenu:**
- Sections
- Symboles
- Tables d'import/export
- Relocations

### Extraire les imports (DLLs et fonctions)

```bash
# Rechercher les imports dans la sortie
objdump -x Res.exe | grep "DLL Name"
```

**Résultat:**
```
DLL Name: KERNEL32.dll
DLL Name: msvcrt.dll
DLL Name: USER32.dll
DLL Name: Qt5Core.dll
```

```bash
# Voir les fonctions importées
objdump -x Res.exe | grep -A 5 "DLL Name: KERNEL32.dll"
```

### Cas d'usage

```bash
# Chercher des appels à des fonctions dangereuses
objdump -d malware.exe | grep -i "call.*CreateProcess"
objdump -d malware.exe | grep -i "call.*VirtualAlloc"
objdump -d malware.exe | grep -i "call.*system"

# Trouver des références à des strings
objdump -s -j .rdata Res.exe | grep -i "windsyst"

# Exporter le désassemblage complet
objdump -D -M intel Res.exe > full_disasm.asm
```

### Options utiles

| Option | Description |
|--------|-------------|
| `-h` | Affiche les sections |
| `-f` | Affiche le header |
| `-d` | Désassemble le code |
| `-D` | Désassemble tout (code + data) |
| `-x` | Affiche toutes les infos |
| `-s` | Dump hexadécimal des sections |
| `-t` | Affiche la table des symboles |
| `-M intel` | Syntaxe Intel (au lieu d'AT&T) |
| `--prefix-addresses` | Affiche les adresses complètes |

---

## OUTIL 5 : radare2

### Description
`radare2` (r2) est une suite complète de reverse engineering ultra-puissante. C'est l'outil le plus avancé de cette liste.

### Syntaxe de base
```bash
r2 [OPTIONS] FICHIER
```

### Mode 1 : Commandes non-interactives

#### Commande 1 : Analyser et lister les fonctions
```bash
r2 -q -c "aaa; afl" Res.exe 2>/dev/null
```

**Décomposition:**
- `-q` : Mode quiet (pas de banner)
- `-c "commandes"` : Exécute des commandes puis quitte
- `aaa` : Analyze All Automatically (analyse profonde)
- `afl` : Analysis Function List (liste des fonctions)
- `2>/dev/null` : Redirige les erreurs (masque les warnings)

**Résultat:**
```
0x004014e0   42    867 entry0
0x004035a0    1    157 main
0x00401aa0   21    722 fcn.00401aa0
0x00402280   11     93 fcn.00402280
0x004031dc    1      6 sub.msvcrt.dll_system
```

**Interprétation:**
- `0x004014e0` = Adresse de la fonction
- `42` = Nombre de basic blocks
- `867` = Taille en octets
- `entry0` = Point d'entrée
- `main` = Fonction principale
- `sub.msvcrt.dll_system` = Import de system()

#### Commande 2 : Désassembler une fonction
```bash
r2 -q -c "aaa; s main; pdf" Res.exe 2>/dev/null
```

**Décomposition:**
- `s main` : Seek (aller à) l'adresse de main
- `pdf` : Print Disassembly Function

**Résultat:**
```asm
┌ 157: int main (char **argv);
│           0x004035a0      lea ecx, [argv]
│           0x004035a4      and esp, 0xfffffff0
│           0x004035a7      push dword [ecx - 4]
│           0x004035aa      push ebp
│           0x004035ab      mov ebp, esp
│           ...
│           0x004035e0      mov dword [var_4h], str.cod_par_le_magniquime_Hafnium
│           0x004035ef      call fcn.00402090
│           0x00403612      call fcn.00401aa0  ; ← FONCTION MALVEILLANTE
│           0x0040363c      ret
```

#### Commande 3 : Chercher des cross-références
```bash
r2 -q -c "aaa; axt sym.imp.msvcrt.dll_system" Res.exe 2>/dev/null
```

**Décomposition:**
- `axt` : Analysis Xrefs To (trouver qui appelle cette fonction)
- `sym.imp.msvcrt.dll_system` = La fonction system()

**Résultat:**
```
sub.msvcrt.dll_system 0x4031dc [CODE:--x] jmp dword [sym.imp.msvcrt.dll_system]
```

#### Commande 4 : Extraire les strings avec positions
```bash
r2 -q -c "aaa; izz~WindSyst" Res.exe 2>/dev/null
```

**Décomposition:**
- `izz` : List all strings in binary
- `~WindSyst` : Grep pour "WindSyst" (~ = grep interne de r2)

**Résultat:**
```
88  0x00002e64 0x00405064 19  20   .rdata   ascii   c:\WindSyst\log.txt
89  0x00002e78 0x00405078 17  18   .rdata   ascii   mkdir c:\WindSyst
90  0x00002e8c 0x0040508c 39  40   .rdata   ascii   XCOPY libgcc_s_dw2-1.dll c:\WindSyst /S
```

**Interprétation:**
- `0x00002e64` = Offset dans le fichier
- `0x00405064` = Adresse virtuelle en mémoire
- `.rdata` = Section contenant la string

#### Commande 5 : Rechercher des patterns
```bash
# Chercher toutes les strings SMTP
r2 -q -c "aaa; izz~smtp" Env.exe 2>/dev/null

# Chercher les emails
r2 -q -c "aaa; izz~@" Env.exe 2>/dev/null

# Chercher les mots de passe (case insensitive)
r2 -q -c "aaa; izz~+pass" Env.exe 2>/dev/null
```

### Mode 2 : Mode interactif

#### Lancer radare2 en mode interactif
```bash
r2 Res.exe
```

**Prompt:**
```
[0x004014e0]>
```

#### Commandes de base en mode interactif

```r2
# Analyser le binaire
[0x004014e0]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Finding and parsing C++ vtables (avrr)
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information (aanr)
[x] Use -AA or aaaa to perform additional experimental analysis.

# Lister les fonctions
[0x004014e0]> afl
0x004014e0    867  entry0
0x004035a0    157  main
0x00401aa0    722  fcn.00401aa0

# Aller à main
[0x004014e0]> s main
[0x004035a0]>

# Désassembler
[0x004035a0]> pdf
┌ 157: int main (char **argv);
│           0x004035a0      lea ecx, [argv]
...

# Afficher les strings
[0x004035a0]> iz
[Strings]
nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00002e64 0x00405064 19  20   .rdata  ascii c:\WindSyst\log.txt
...

# Chercher un pattern
[0x004035a0]> / WindSyst
0x00405064 hit0_0 c:\WindSyst\log.txt

# Afficher la table d'imports
[0x004035a0]> ii
[Imports]
nth vaddr      bind   type   lib name
――――――――――――――――――――――――――――――――――――――――
1   0x004031dc GLOBAL FUNC   msvcrt.dll system

# Afficher le graphe d'une fonction (mode visuel)
[0x004035a0]> VV

# Quitter
[0x004035a0]> q
```

### Mode 3 : Analyse automatisée avec scripts

#### Créer un script r2
```bash
cat > analyze.r2 << 'EOF'
# Script d'analyse automatique
e scr.color=false
aaa
echo "=== FUNCTIONS ==="
afl
echo ""
echo "=== IMPORTS ==="
ii
echo ""
echo "=== STRINGS ==="
izz~http,exe,dll,HKEY
q
EOF
```

#### Exécuter le script
```bash
r2 -i analyze.r2 Res.exe > rapport.txt
```

### Commandes avancées radare2

```bash
# Afficher le CFG (Control Flow Graph) en ASCII
r2 -q -c "aaa; s main; agf" Res.exe

# Trouver les appels à une adresse spécifique
r2 -q -c "aaa; axt @ 0x00401aa0" Res.exe

# Dump une section en hexadécimal
r2 -q -c "s section..rdata; px 100" Res.exe

# Chercher des bytes spécifiques (shellcode, signatures)
r2 -q -c "/x 558bec" Res.exe  # Cherche le prologue 55 8b ec

# Émuler l'exécution d'une fonction (ESIL)
r2 -q -c "aaa; s main; aei; aeim; aeip; 10aes" Res.exe

# Extraire les valeurs des registres après exécution
r2 -q -c "aaa; s main; aei; aeim; aeip; 10aes; dr" Res.exe
```

### Raccourcis utiles en mode interactif

| Commande | Description |
|----------|-------------|
| `?` | Aide générale |
| `aaa` | Analyse complète |
| `afl` | Liste fonctions |
| `s addr` | Aller à adresse |
| `pdf` | Désassembler fonction |
| `iz` | Strings en .data |
| `izz` | Toutes les strings |
| `ii` | Imports |
| `iE` | Exports |
| `is` | Symboles |
| `ic` | Classes (C++) |
| `V` | Mode visuel |
| `VV` | Graphe visuel |
| `px 100` | Hexdump 100 bytes |
| `q` | Quitter |

---

## WORKFLOW COMPLET D'ANALYSE

Voici le workflow exact que j'ai suivi pour analyser Res.exe et Env.exe :

### ÉTAPE 1 : Reconnaissance initiale (5 min)

```bash
# 1.1 Identifier le type de fichier
file *.exe *.dll

# 1.2 Calculer les hashes
sha256sum *.exe > hashes.txt
md5sum *.exe >> hashes.txt

# 1.3 Voir la taille des fichiers
ls -lh *.exe
```

### ÉTAPE 2 : Extraction de strings (10 min)

```bash
# 2.1 Extraire toutes les strings
strings Res.exe > res_strings.txt
strings Env.exe > env_strings.txt

# 2.2 Recherche de patterns suspects
echo "=== Recherche URLs ===" >> analysis.txt
strings Res.exe | grep -iE "(http|ftp)://" >> analysis.txt

echo "=== Recherche emails ===" >> analysis.txt
strings Env.exe | grep -E "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" >> analysis.txt

echo "=== Recherche registre Windows ===" >> analysis.txt
strings Res.exe | grep -i "HKEY" >> analysis.txt

echo "=== Recherche fichiers ===" >> analysis.txt
strings Res.exe | grep -iE "\.(exe|dll|bat|ps1)" >> analysis.txt

echo "=== Recherche commandes ===" >> analysis.txt
strings Res.exe | grep -iE "(mkdir|xcopy|copy|move|del)" >> analysis.txt

# 2.3 Recherche de credentials
strings Env.exe | grep -iE "(password|user|login|pass|pwd)" >> analysis.txt
```

### ÉTAPE 3 : Analyse de structure (15 min)

```bash
# 3.1 Analyser les sections PE
objdump -h Res.exe > res_sections.txt
objdump -h Env.exe > env_sections.txt

# 3.2 Obtenir les infos du header
objdump -f Res.exe >> res_sections.txt
objdump -f Env.exe >> env_sections.txt

# 3.3 Extraire les imports
objdump -x Res.exe | grep "DLL Name" > res_imports.txt
objdump -x Env.exe | grep "DLL Name" > env_imports.txt

# 3.4 Rechercher des imports dangereux
objdump -x Res.exe | grep -iE "(CreateProcess|VirtualAlloc|WriteProcessMemory|system|exec)" >> analysis.txt
```

### ÉTAPE 4 : Analyse radare2 (30 min)

```bash
# 4.1 Lister toutes les fonctions
r2 -q -c "aaa; afl" Res.exe 2>/dev/null > res_functions.txt
r2 -q -c "aaa; afl" Env.exe 2>/dev/null > env_functions.txt

# 4.2 Désassembler main()
r2 -q -c "aaa; s main; pdf" Res.exe 2>/dev/null > res_main.asm
r2 -q -c "aaa; s main; pdf" Env.exe 2>/dev/null > env_main.asm

# 4.3 Trouver les appels à system()
r2 -q -c "aaa; axt sym.imp.msvcrt.dll_system" Res.exe 2>/dev/null >> analysis.txt

# 4.4 Extraire les strings avec adresses
r2 -q -c "aaa; izz~WindSyst" Res.exe 2>/dev/null >> res_strings_addr.txt
r2 -q -c "aaa; izz~smtp" Env.exe 2>/dev/null >> env_strings_addr.txt
r2 -q -c "aaa; izz~laposte" Env.exe 2>/dev/null >> env_strings_addr.txt

# 4.5 Analyser une fonction suspecte
r2 -q -c "aaa; s 0x00401aa0; pdf" Res.exe 2>/dev/null > function_malicious.asm
```

### ÉTAPE 5 : Désassemblage complet (20 min)

```bash
# 5.1 Désassembler complètement avec objdump
objdump -D -M intel Res.exe > res_full_disasm.asm
objdump -D -M intel Env.exe > env_full_disasm.asm

# 5.2 Désassembler avec radare2 (plus détaillé)
r2 -q -c "aaa; af @@ *; pdf @@ fcn.*" Res.exe 2>/dev/null > res_r2_disasm.asm
```

### ÉTAPE 6 : Recherche de patterns (15 min)

```bash
# 6.1 Chercher des APIs Windows dangereuses
for api in CreateProcess VirtualAlloc WriteProcessMemory LoadLibrary GetProcAddress URLDownloadToFile WinExec ShellExecute RegSetValue RegCreateKey; do
    echo "=== $api ===" >> dangerous_apis.txt
    strings Res.exe | grep -i "$api" >> dangerous_apis.txt
    strings Env.exe | grep -i "$api" >> dangerous_apis.txt
done

# 6.2 Chercher des protocoles réseau
strings Env.exe | grep -iE "(EHLO|HELO|AUTH|MAIL FROM|RCPT TO|DATA|QUIT)" >> smtp_commands.txt

# 6.3 Chercher des chemins suspects
strings Res.exe | grep -iE "c:\\\\.*\\\\|%temp%|%appdata%|\\\\system32" >> suspicious_paths.txt
```

### ÉTAPE 7 : Compilation du rapport (30 min)

```bash
# 7.1 Créer un rapport structuré
cat > RAPPORT_FINAL.txt << 'EOF'
ANALYSE DE MALWARE - RAPPORT FINAL
===================================

1. INFORMATIONS DE BASE
EOF

file Res.exe Env.exe >> RAPPORT_FINAL.txt
echo "" >> RAPPORT_FINAL.txt

echo "2. HASHES" >> RAPPORT_FINAL.txt
cat hashes.txt >> RAPPORT_FINAL.txt
echo "" >> RAPPORT_FINAL.txt

echo "3. STRINGS SUSPECTS" >> RAPPORT_FINAL.txt
cat analysis.txt >> RAPPORT_FINAL.txt
echo "" >> RAPPORT_FINAL.txt

echo "4. FONCTIONS IDENTIFIÉES" >> RAPPORT_FINAL.txt
cat res_functions.txt >> RAPPORT_FINAL.txt
echo "" >> RAPPORT_FINAL.txt

echo "5. IMPORTS" >> RAPPORT_FINAL.txt
cat res_imports.txt >> RAPPORT_FINAL.txt
```

---

## COMMANDES AVANCÉES

### Analyse automatisée avec script bash

```bash
#!/bin/bash
# analyze_malware.sh - Script d'analyse automatique

MALWARE=$1

if [ -z "$MALWARE" ]; then
    echo "Usage: $0 <fichier_malware>"
    exit 1
fi

echo "[+] Analyse de $MALWARE"
echo ""

# 1. Identification
echo "=== TYPE DE FICHIER ==="
file "$MALWARE"
echo ""

# 2. Hashes
echo "=== HASHES ==="
echo "MD5:    $(md5sum "$MALWARE" | cut -d' ' -f1)"
echo "SHA256: $(sha256sum "$MALWARE" | cut -d' ' -f1)"
echo ""

# 3. Taille
echo "=== TAILLE ==="
ls -lh "$MALWARE"
echo ""

# 4. Sections
echo "=== SECTIONS PE ==="
objdump -h "$MALWARE" | grep -A 1 "Sections"
echo ""

# 5. Point d'entrée
echo "=== POINT D'ENTRÉE ==="
objdump -f "$MALWARE" | grep "start address"
echo ""

# 6. Imports
echo "=== DLLs IMPORTÉES ==="
objdump -x "$MALWARE" | grep "DLL Name"
echo ""

# 7. Strings suspects
echo "=== STRINGS SUSPECTS ==="
echo "[URLs]"
strings "$MALWARE" | grep -iE "https?://"
echo ""
echo "[Emails]"
strings "$MALWARE" | grep -E "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
echo ""
echo "[Chemins Windows]"
strings "$MALWARE" | grep -iE "c:\\\\|\\\\windows\\\\|%temp%|%appdata%"
echo ""
echo "[Registre]"
strings "$MALWARE" | grep -i "HKEY"
echo ""

# 8. Fonctions (radare2)
echo "=== FONCTIONS (top 10) ==="
r2 -q -c "aaa; afl" "$MALWARE" 2>/dev/null | head -10
echo ""

echo "[+] Analyse terminée!"
```

**Utilisation:**
```bash
chmod +x analyze_malware.sh
./analyze_malware.sh Res.exe > rapport_res.txt
./analyze_malware.sh Env.exe > rapport_env.txt
```

### Recherche batch sur plusieurs fichiers

```bash
# Analyser tous les .exe d'un répertoire
for file in *.exe; do
    echo "=== Analyse de $file ===" >> batch_analysis.txt
    sha256sum "$file" >> batch_analysis.txt
    strings "$file" | grep -i "http" >> batch_analysis.txt
    echo "" >> batch_analysis.txt
done

# Créer une base IOCs (Indicators of Compromise)
cat > extract_iocs.sh << 'EOF'
#!/bin/bash
echo "=== IPs ==="
strings "$1" | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b"
echo ""
echo "=== URLs ==="
strings "$1" | grep -oE "https?://[a-zA-Z0-9./?=_-]*"
echo ""
echo "=== Emails ==="
strings "$1" | grep -oE "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
echo ""
echo "=== Domains ==="
strings "$1" | grep -oE "[a-zA-Z0-9.-]+\.(com|net|org|info|biz|ru|cn)"
EOF

chmod +x extract_iocs.sh
./extract_iocs.sh Env.exe > iocs.txt
```

---

## OUTILS COMPLÉMENTAIRES

### 1. hexdump - Visualisation hexadécimale

```bash
# Voir les premiers bytes (magic bytes)
hexdump -C -n 64 Res.exe

# Résultat:
# 00000000  4d 5a 90 00 03 00 00 00  04 00 00 00 ff ff 00 00  |MZ..............|
# ↑ 4D 5A = "MZ" = signature PE

# Chercher un pattern en hex
hexdump -C Res.exe | grep "WindSyst"
```

### 2. xxd - Autre viewer hex

```bash
# Affichage hex + ASCII
xxd Res.exe | less

# Extraire une section spécifique (offset 0x2e64, 20 bytes)
xxd -s 0x2e64 -l 20 Res.exe
```

### 3. readelf (pour ELF Linux, info sur PE avec pev)

```bash
# Installer pev (PE tools)
sudo apt install pev

# Analyser un PE
readpe Res.exe
peres Res.exe
pescan Res.exe
```

### 4. peframe - Analyse PE automatisée

```bash
# Installer
pip3 install peframe

# Analyser
peframe Res.exe --json > res_peframe.json
```

### 5. Yara - Détection de signatures

```bash
# Installer Yara
sudo apt install yara

# Créer une règle
cat > malware_rules.yar << 'EOF'
rule Hafnium_Dropper {
    meta:
        description = "Détecte le dropper Hafnium"
        author = "Analyste"
    strings:
        $s1 = "WindSyst" ascii
        $s2 = "magniquime Hafnium" ascii
        $s3 = "XCOPY Res.exe" ascii
    condition:
        2 of them
}
EOF

# Scanner
yara malware_rules.yar Res.exe
```

### 6. capa - Détection de capabilities

```bash
# Installer capa
pip3 install flare-capa

# Analyser
capa Res.exe > res_capabilities.txt
```

**Résultat exemple:**
```
+------------------------+----------------+
| Capability             | Namespace      |
+------------------------+----------------+
| create registry key    | host-interaction/registry |
| execute command        | host-interaction/process  |
| copy file              | host-interaction/file     |
+------------------------+----------------+
```

---

## CHEAT SHEET - COMMANDES ESSENTIELLES

### Analyse rapide (5 minutes)

```bash
# Type + Hash + Strings suspects
file malware.exe && \
sha256sum malware.exe && \
strings malware.exe | grep -iE "(http|exe|dll|HKEY|password|admin)"
```

### Analyse moyenne (15 minutes)

```bash
# Structure + Imports + Fonctions
objdump -f malware.exe && \
objdump -h malware.exe && \
objdump -x malware.exe | grep "DLL Name" && \
r2 -q -c "aaa; afl" malware.exe 2>/dev/null
```

### Analyse complète (1 heure)

```bash
# Tout en un coup
{
  echo "=== FILE INFO ==="
  file malware.exe

  echo -e "\n=== HASHES ==="
  md5sum malware.exe
  sha256sum malware.exe

  echo -e "\n=== SECTIONS ==="
  objdump -h malware.exe

  echo -e "\n=== ENTRY POINT ==="
  objdump -f malware.exe

  echo -e "\n=== IMPORTS ==="
  objdump -x malware.exe | grep "DLL Name"

  echo -e "\n=== SUSPICIOUS STRINGS ==="
  strings malware.exe | grep -iE "(http|\.exe|HKEY|password|cmd|powershell)"

  echo -e "\n=== FUNCTIONS ==="
  r2 -q -c "aaa; afl" malware.exe 2>/dev/null

} > full_report.txt
```

---

## EXERCICES PRATIQUES

### Exercice 1 : Analyse de base

**Objectif:** Analyser un binaire inconnu

```bash
# 1. Quel est le type du fichier ?
file unknown.exe

# 2. Quel est son hash SHA256 ?
sha256sum unknown.exe

# 3. Contient-il des URLs ?
strings unknown.exe | grep -i "http"

# 4. Quelles DLLs importe-t-il ?
objdump -x unknown.exe | grep "DLL Name"

# 5. Combien de fonctions contient-il ?
r2 -q -c "aaa; afl" unknown.exe 2>/dev/null | wc -l
```

### Exercice 2 : Recherche de malware

**Objectif:** Identifier des comportements suspects

```bash
# 1. Rechercher des appels système
strings malware.exe | grep -iE "(system|exec|cmd|powershell)"

# 2. Rechercher des modifications de registre
strings malware.exe | grep -i "HKEY"

# 3. Rechercher des opérations fichiers
strings malware.exe | grep -iE "(copy|move|delete|xcopy)"

# 4. Rechercher des connexions réseau
strings malware.exe | grep -iE "(connect|socket|send|recv)"
```

### Exercice 3 : Reverse engineering

**Objectif:** Désassembler et comprendre une fonction

```bash
# 1. Trouver la fonction main
r2 -q -c "aaa; afl~main" malware.exe 2>/dev/null

# 2. Désassembler main
r2 -q -c "aaa; s main; pdf" malware.exe 2>/dev/null

# 3. Trouver les appels de fonction dans main
r2 -q -c "aaa; s main; pdf" malware.exe 2>/dev/null | grep "call"

# 4. Analyser une fonction appelée (exemple: 0x00401aa0)
r2 -q -c "aaa; s 0x00401aa0; pdf" malware.exe 2>/dev/null
```

---

## RESSOURCES SUPPLÉMENTAIRES

### Documentation officielle

- **radare2**: https://book.rada.re/
- **objdump**: `man objdump`
- **strings**: `man strings`

### Tutoriels en ligne

- Malware Unicorn Reverse Engineering 101: https://malwareunicorn.org/workshops/re101.html
- Radare2 Book: https://book.rada.re/
- Reverse Engineering for Beginners: https://beginners.re/

### Bases de données malware

- **VirusTotal**: https://www.virustotal.com/
- **MalwareBazaar**: https://bazaar.abuse.ch/
- **Hybrid Analysis**: https://www.hybrid-analysis.com/

### Outils GUI (alternatives graphiques)

- **Ghidra** (NSA): https://ghidra-sre.org/
- **IDA Free**: https://hex-rays.com/ida-free/
- **Cutter** (GUI pour radare2): https://cutter.re/
- **Binary Ninja Cloud**: https://cloud.binary.ninja/

---

## CONCLUSION

### Résumé des outils

| Outil | Quand l'utiliser | Niveau |
|-------|------------------|--------|
| `file` | Premier contact avec un fichier | Débutant |
| `strings` | Recherche rapide d'infos | Débutant |
| `md5sum/sha256sum` | Vérification réputation | Débutant |
| `objdump` | Structure et désassemblage simple | Intermédiaire |
| `radare2` | Analyse approfondie complète | Avancé |

### Ordre d'utilisation recommandé

1. **file** → Identifier le type
2. **sha256sum** → Calculer le hash
3. **strings** → Recherche rapide
4. **objdump -h/-f** → Structure
5. **objdump -x** → Imports
6. **radare2 afl** → Fonctions
7. **radare2 pdf** → Désassemblage

### Commandes à retenir

```bash
# Les 5 commandes essentielles
file malware.exe
sha256sum malware.exe
strings malware.exe | grep -i "suspect"
objdump -h malware.exe
r2 -q -c "aaa; afl" malware.exe 2>/dev/null
```

---

**Auteur:** Claude Code
**Version:** 1.0
**Dernière mise à jour:** 2025-12-01

**⚠️ AVERTISSEMENT:** Ces outils sont destinés à l'analyse de malware en environnement isolé uniquement. Ne jamais exécuter de malware sur un système de production.
