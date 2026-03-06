# Mini Projet - Gestion des Incidents et Forensics : SIEM avec Wazuh

**Date :** 06 Mars 2026  
**Environnement :** Kali GNU/Linux 2025.4 (kernel 6.18.5+kali-amd64)  
**SIEM déployé :** Wazuh v4.9.2 (Docker Compose, architecture 3 tiers)  
**Outils :** Docker 27.5.1, Docker Compose v5.0.2, curl, wazuh-agent 4.9.2

---

## Table des matières

1. [Fonctionnement d'un SIEM](#1-fonctionnement-dun-siem)
2. [Solutions SIEM du marché](#2-solutions-siem-du-marché)
3. [Étude comparative](#3-étude-comparative)
4. [Partie pratique : Déploiement de Wazuh](#4-partie-pratique--déploiement-de-wazuh)

---

## 1. Fonctionnement d'un SIEM

Un **SIEM (Security Information and Event Management)** est une plateforme centralisant la collecte, l'analyse et la corrélation des événements de sécurité provenant de l'ensemble du système d'information. Il opère en 7 étapes :

### 1.1 La collecte

La collecte est la première étape : le SIEM ingère les logs depuis toutes les sources disponibles.

**Sources typiques :**
- Équipements réseau (routeurs, switches, firewalls)
- Systèmes d'exploitation (syslog Linux, Event Log Windows)
- Applications (serveurs web, bases de données, antivirus)
- Équipements de sécurité (IDS/IPS, proxies, VPN)

**Protocoles de collecte :**
- Syslog (UDP/514, TCP/514, TLS/6514)
- SNMP Traps
- Agents dédiés (Filebeat, Wazuh Agent, NXLog)
- API REST (collecte active)

Dans Wazuh, la collecte est assurée par le `wazuh-logcollector` sur l'agent et le port UDP 514 sur le manager.

### 1.2 L'agrégation

L'agrégation consiste à **regrouper les événements similaires** pour réduire le volume de données traitées. Elle permet d'éviter les doublons et de diminuer la charge des étapes suivantes.

**Mécanismes :**
- Regroupement par source et type d'événement
- Comptage des occurrences dans une fenêtre temporelle
- Déduplication (suppression des événements strictement identiques)

### 1.3 La normalisation

Les logs bruts arrivent dans des formats hétérogènes (syslog, JSON, XML, CEF, LEEF...). La normalisation les **convertit dans un format unifié** (champs standardisés : timestamp, source IP, utilisateur, action, etc.).

**Standard commun :** ECS (Elastic Common Schema), CEF (Common Event Format)

Wazuh utilise des **décodeurs** (fichiers XML) pour analyser les logs et extraire les champs sémantiques.

### 1.4 La corrélation

Le cœur du SIEM : le moteur de corrélation **analyse les événements normalisés** et détecte des patterns d'attaque en appliquant des règles.

**Types de corrélation :**
- **Corrélation simple** : une règle déclenche une alerte sur un seul événement
- **Corrélation temporelle** : N événements du même type en T secondes (ex. : brute force)
- **Corrélation multi-sources** : événements liés de plusieurs équipements (ex. : IDS + firewall)
- **Corrélation comportementale** : détection d'anomalies par rapport à la baseline

Wazuh utilise un moteur de règles en XML avec niveaux de criticité (0-15).

### 1.5 Le reportage

Le SIEM génère des **rapports automatiques** sur l'état de sécurité :
- Tableaux de bord temps réel (alertes actives, top sources)
- Rapports périodiques (quotidiens, hebdomadaires)
- Rapports de conformité (PCI-DSS, HIPAA, GDPR, CIS)
- Indicateurs KPI de sécurité (MTTD, MTTR)

### 1.6 L'archivage

Les logs sont **conservés** conformément aux exigences légales et métiers :
- Durée de rétention : 1 an minimum (RGPD), 6 ans (données médicales)
- Stockage chiffré et intègre (hashing pour preuve légale)
- Index hot/warm/cold selon l'âge des données (ILM - Index Lifecycle Management)

### 1.7 Le rejeu des événements

Le **rejeu (replay)** permet de réanalyser des logs historiques avec de nouvelles règles :
- Détection rétrospective d'incidents passés
- Test de nouvelles règles sur données historiques
- Investigation forensique (recherche d'indicateurs d'une APT non détectée)

---

## 2. Solutions SIEM du marché

### 2.1 Solutions payantes

| Éditeur | Produit | Points forts |
|---------|---------|-------------|
| **IBM** | QRadar | Threat intelligence intégrée, corrélation avancée, certifié ANSSI |
| **Splunk** | Splunk Enterprise Security | Puissance de recherche SPL, marketplace d'apps, très grande scalabilité |
| **Microsoft** | Sentinel (Azure) | Cloud-native, intégration native M365/Azure AD, IA intégrée |
| **ArcSight (Micro Focus)** | ESM | Corrélation temps réel, compliance PCI/HIPAA, marché gouvernemental |
| **LogRhythm** | SIEM | UEBA intégré, réponse automatisée (SOAR), interface intuitive |

### 2.2 Solutions open source

| Projet | Éditeur | Caractéristiques |
|--------|---------|-----------------|
| **Wazuh** | Wazuh Inc. | Fork OSSEC, agents multi-OS, XDR, FIM, SCA, MITRE ATT&CK |
| **ELK Stack** | Elastic | Elasticsearch + Logstash + Kibana, très flexible, grande communauté |
| **OSSEC** | OSSEC Project | Ancêtre de Wazuh, IDS hôte, analyse de logs, alertes email |
| **Graylog** | Graylog Inc. | Moteur de recherche puissant, alertes, dashboards, version Enterprise |
| **OpenSearch** | Amazon/Linux Foundation | Fork Elasticsearch, composant de Wazuh Indexer |

### 2.3 Points forts / faibles des SIEM

**Points forts :**
- Vision centralisée et unifiée de la sécurité
- Détection de menaces sophistiquées (corrélation multi-sources)
- Conformité réglementaire (PCI-DSS, HIPAA, RGPD, ISO 27001)
- Forensique et investigation d'incidents
- Automatisation de la réponse aux incidents

**Points faibles :**
- Coût élevé des solutions commerciales (licence + infrastructure + personnel)
- Taux de faux positifs important si les règles sont mal configurées
- Nécessite une expertise dédiée (analyste SOC)
- Complexité de déploiement et de maintenance
- Volume de logs à traiter peut devenir ingérable (scalabilité)

---

## 3. Étude comparative des solutions SIEM

| Critère | Wazuh | Splunk ES | IBM QRadar | Microsoft Sentinel | Graylog |
|---------|-------|-----------|------------|-------------------|---------|
| **Licence** | GPL v2 (gratuit) | Payant (volume) | Payant (EPS) | Payant (Go/jour) | Open core |
| **Déploiement** | On-prem / Docker | On-prem / Cloud | On-prem / Cloud | Cloud Azure | On-prem / Cloud |
| **Agent** | Wazuh Agent (multi-OS) | Universal Forwarder | WinCollect / Syslog | Azure Monitor Agent | Sidecar |
| **Corrélation** | Règles XML + ML | SPL + ES apps | MITRE + règles avancées | KQL + ML | Streams + alertes |
| **MITRE ATT&CK** | Oui (intégré) | Via apps | Oui | Oui | Non natif |
| **FIM** | Oui (natif) | Via apps | Via apps | Partiel | Non |
| **SCA** | Oui (CIS) | Via apps | Via apps | Via Defender | Non |
| **Scalabilité** | Multi-nœuds | Très haute | Haute | Très haute (cloud) | Haute |
| **Communauté** | Très active | Grande | Modérée | Grande | Active |
| **Courbe apprentissage** | Modérée | Élevée | Très élevée | Modérée | Modérée |
| **Adapté pour** | PME, forensic, enseignement | Grandes entreprises | Banques, télécom | Entreprises Azure | Développeurs, DevOps |

**Verdict :** Wazuh est la solution open source la plus complète pour un environnement académique ou PME. Il combine SIEM, XDR, HIDS, FIM et conformité dans un seul produit, avec une communauté active et une documentation exhaustive.

---

## 4. Partie pratique : Déploiement de Wazuh

### 4.1 Architecture déployée

```
┌─────────────────────────────────────────────────────────────┐
│                    Machine Kali (Hôte)                      │
│                                                              │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              Docker Network (bridge)                  │   │
│  │                                                       │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌───────────┐  │   │
│  │  │wazuh.manager │  │wazuh.indexer │  │wazuh.dash │  │   │
│  │  │:1514 :1515   │  │:9200         │  │:443(5601) │  │   │
│  │  │:514/udp      │  │(OpenSearch)  │  │(Wazuh UI) │  │   │
│  │  │:55000 (API)  │  │              │  │           │  │   │
│  │  └──────┬───────┘  └──────────────┘  └───────────┘  │   │
│  │         │ Filebeat (TLS)                              │   │
│  └─────────┼───────────────────────────────────────────┘   │
│            │                                                  │
│  ┌─────────▼────────┐                                        │
│  │  wazuh-agent     │ (installé directement sur Kali)        │
│  │  kali-forensic   │                                        │
│  │  ID: 002         │                                        │
│  └──────────────────┘                                        │
└─────────────────────────────────────────────────────────────┘
```

**Composants :**
- **Wazuh Manager** : Serveur central, analyse et corrélation des logs
- **Wazuh Indexer** : Moteur de stockage basé sur OpenSearch 2.13.0
- **Wazuh Dashboard** : Interface web (fork de OpenSearch Dashboards)
- **Wazuh Agent** : Agent installé sur la machine Kali (kali-forensic, ID:002)

### 4.2 Prérequis et vérification

```bash
$ docker --version && docker compose version
```

**Sortie (fichier `evidence/01_docker_version.txt`) :**
```
Docker version 27.5.1+dfsg4, build cab968b3
Docker Compose version v5.0.2
```

### 4.3 Génération des certificats TLS

L'ensemble des communications entre composants Wazuh est sécurisé par TLS mutuel. Le générateur de certificats Wazuh crée une PKI interne (CA root + certificats par composant).

**Correction préalable du fichier `config/certs.yml`** (IP `0.0.0.0` rejetée par le générateur) :

```yaml
# config/certs.yml
nodes:
  indexer:
    - name: wazuh.indexer
      ip: 127.0.0.1
  server:
    - name: wazuh.manager
      ip: 127.0.0.1
  dashboard:
    - name: wazuh.dashboard
      ip: 127.0.0.1
```

**Commande de génération :**

```bash
$ docker compose -f generate-indexer-certs.yml run --rm generator
```

**Sortie :**
```
06/03/2026 12:03:38 INFO: Generating the root certificate.
06/03/2026 12:03:39 INFO: Generating Admin certificates.
06/03/2026 12:03:39 INFO: Admin certificates created.
06/03/2026 12:03:39 INFO: Generating Wazuh indexer certificates.
06/03/2026 12:03:39 INFO: Wazuh indexer certificates created.
06/03/2026 12:03:39 INFO: Generating Filebeat certificates.
06/03/2026 12:03:39 INFO: Wazuh Filebeat certificates created.
06/03/2026 12:03:39 INFO: Generating Wazuh dashboard certificates.
06/03/2026 12:03:39 INFO: Wazuh dashboard certificates created.
Moving created certificates to the destination directory
```

**Certificats générés (`evidence/02_certs_generated.txt`) :**
```
admin-key.pem          root-ca-manager.pem    wazuh.dashboard-key.pem
admin.pem              root-ca-manager.key    wazuh.dashboard.pem
root-ca.key            wazuh.indexer-key.pem  wazuh.manager-key.pem
root-ca.pem            wazuh.indexer.pem      wazuh.manager.pem
```

### 4.4 Configuration des services

**4.4.1 Wazuh Indexer (`config/wazuh_indexer/wazuh.indexer.yml`)**

```yaml
network.host: "0.0.0.0"
node.name: "wazuh.indexer"
cluster.initial_master_nodes:
- "wazuh.indexer"
cluster.name: "wazuh-cluster"
path.data: /var/lib/wazuh-indexer
path.logs: /var/log/wazuh-indexer

plugins.security.ssl.http.pemcert_filepath: /usr/share/wazuh-indexer/certs/wazuh.indexer.pem
plugins.security.ssl.http.pemkey_filepath: /usr/share/wazuh-indexer/certs/wazuh.indexer.key
plugins.security.ssl.http.pemtrustedcas_filepath: /usr/share/wazuh-indexer/certs/root-ca.pem
plugins.security.ssl.transport.pemcert_filepath: /usr/share/wazuh-indexer/certs/wazuh.indexer.pem
plugins.security.ssl.transport.pemkey_filepath: /usr/share/wazuh-indexer/certs/wazuh.indexer.key
plugins.security.ssl.transport.pemtrustedcas_filepath: /usr/share/wazuh-indexer/certs/root-ca.pem
plugins.security.ssl.http.enabled: true
plugins.security.ssl.transport.enforce_hostname_verification: false
plugins.security.ssl.transport.resolve_hostname: false

plugins.security.authcz.admin_dn:
- "CN=admin,OU=Wazuh,O=Wazuh,L=California,C=US"
plugins.security.nodes_dn:
- "CN=wazuh.indexer,OU=Wazuh,O=Wazuh,L=California,C=US"
plugins.security.restapi.roles_enabled:
- "all_access"
- "security_rest_api_access"
```

**4.4.2 Wazuh Dashboard (`config/wazuh_dashboard/opensearch_dashboards.yml`)**

```yaml
server.host: 0.0.0.0
server.port: 5601
opensearch.hosts: https://wazuh.indexer:9200
opensearch.ssl.verificationMode: certificate
opensearch.username: kibanaserver
opensearch.password: kibanaserver
opensearch.requestHeadersAllowlist: ["securitytenant","Authorization"]
opensearch_security.multitenancy.enabled: false
server.ssl.enabled: true
server.ssl.key: "/usr/share/wazuh-dashboard/certs/wazuh-dashboard-key.pem"
server.ssl.certificate: "/usr/share/wazuh-dashboard/certs/wazuh-dashboard.pem"
opensearch.ssl.certificateAuthorities: ["/usr/share/wazuh-dashboard/certs/root-ca.pem"]
uiSettings.overrides.defaultRoute: /app/wz-home
```

### 4.5 Démarrage de la stack

```bash
$ docker compose up -d
```

**Sortie (`evidence/03_docker_compose_up.txt`) :**
```
 Container wazuh-deploy-wazuh.indexer-1  Started
 Container wazuh-deploy-wazuh.manager-1  Started
 Container wazuh-deploy-wazuh.dashboard-1 Started
```

### 4.6 Initialisation de la sécurité OpenSearch

L'index de sécurité `.opendistro_security` doit être initialisé avec `securityadmin.sh` :

```bash
$ docker exec wazuh-deploy-wazuh.indexer-1 bash -c \
  "OPENSEARCH_JAVA_HOME=/usr/share/wazuh-indexer/jdk \
   /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
   -cd /usr/share/wazuh-indexer/opensearch-security/ \
   -nhnv \
   -cacert /usr/share/wazuh-indexer/certs/root-ca.pem \
   -cert /usr/share/wazuh-indexer/certs/admin.pem \
   -key /usr/share/wazuh-indexer/certs/admin-key.pem \
   -p 9200 -icl"
```

**Sortie (`evidence/06_securityadmin.txt`) :**
```
Clustername: wazuh-cluster
Clusterstate: GREEN
Number of nodes: 1
Number of data nodes: 1
.opendistro_security index does not exists, attempt to create it ... done (0-all replicas)
Populate config from /usr/share/wazuh-indexer/opensearch-security/
   SUCC: Configuration for 'config' created or updated
   SUCC: Configuration for 'roles' created or updated
   SUCC: Configuration for 'rolesmapping' created or updated
   SUCC: Configuration for 'internalusers' created or updated
   SUCC: Configuration for 'actiongroups' created or updated
   SUCC: Configuration for 'tenants' created or updated
   SUCC: Configuration for 'nodesdn' created or updated
Done with success
```

### 4.7 Vérification de l'indexer

```bash
$ curl -s -k -u admin:SecretPassword https://127.0.0.1:9200
```

**Sortie (`evidence/05_indexer_api.txt`) :**
```json
{
  "name": "wazuh.indexer",
  "cluster_name": "wazuh-cluster",
  "cluster_uuid": "abhiSbnoRcWso7D734JGXQ",
  "version": {
    "number": "7.10.2",
    "build_type": "rpm",
    "build_hash": "0aa3533d9a82a2a9acf03285cc47dfe264c5a15b",
    "build_date": "2024-10-28T15:29:00.446834Z",
    "build_snapshot": false,
    "lucene_version": "9.10.0"
  },
  "tagline": "The OpenSearch Project: https://opensearch.org/"
}
```

**Santé du cluster (`evidence/12_cluster_health.txt`) :**
```json
{
  "cluster_name": "wazuh-cluster",
  "status": "green",
  "number_of_nodes": 1,
  "number_of_data_nodes": 1,
  "active_primary_shards": 6,
  "active_shards": 6,
  "unassigned_shards": 0,
  "active_shards_percent_as_number": 100.0
}
```

### 4.8 Vérification de l'API Wazuh Manager

```bash
$ TOKEN=$(curl -s -k -u wazuh-wui:'MyS3cr37P450r.*-' \
    -X POST "https://127.0.0.1:55000/security/user/authenticate?raw=true")

$ curl -s -k -H "Authorization: Bearer $TOKEN" https://127.0.0.1:55000/
```

**Sortie (`evidence/08_wazuh_manager_api.txt`) :**
```json
{
  "data": {
    "title": "Wazuh API REST",
    "api_version": "4.9.2",
    "revision": 40921,
    "license_name": "GPL 2.0",
    "hostname": "wazuh.manager",
    "timestamp": "2026-03-06T12:28:01Z"
  },
  "error": 0
}
```

**Statut des daemons Wazuh (`evidence/09_manager_status.txt`) :**
```json
{
  "wazuh-analysisd": "running",
  "wazuh-authd":     "running",
  "wazuh-execd":     "running",
  "wazuh-logcollector": "running",
  "wazuh-monitord":  "running",
  "wazuh-remoted":   "running",
  "wazuh-syscheckd": "running",
  "wazuh-modulesd":  "running",
  "wazuh-db":        "running",
  "wazuh-apid":      "running"
}
```

### 4.9 Enregistrement et connexion de l'agent

**Installation de l'agent Wazuh sur Kali :**

```bash
$ curl -o /tmp/wazuh-agent.deb \
  "https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.9.2-1_amd64.deb"

$ WAZUH_MANAGER="127.0.0.1" WAZUH_AGENT_NAME="kali-forensic" \
  sudo dpkg -i /tmp/wazuh-agent.deb
```

**Sortie (`evidence/14_agent_install.txt`) :**
```
Préparation du dépaquetage de /tmp/wazuh-agent.deb ...
Dépaquetage de wazuh-agent (4.9.2-1) ...
Paramétrage de wazuh-agent (4.9.2-1) ...
```

**Enregistrement automatique via authd (port 1515) :**

```bash
$ sudo /var/ossec/bin/agent-auth -m 127.0.0.1 -p 1515 -A "kali-forensic"
```

**Sortie (`evidence/15_agent_key_import.txt`) :**
```
2026/03/06 13:29:41 agent-auth: INFO: Started (pid: 38005).
2026/03/06 13:29:41 agent-auth: INFO: Requesting a key from server: 127.0.0.1
2026/03/06 13:29:41 agent-auth: INFO: Using agent name as: kali-forensic
2026/03/06 13:29:41 agent-auth: INFO: Waiting for server reply
2026/03/06 13:29:41 agent-auth: INFO: Valid key received
```

**Clé enregistrée dans `/var/ossec/etc/client.keys` :**
```
002 kali-forensic any eba34dba56d1ea5498f33c10d00b2032693b634ced9454ea268cfa687768eceb
```

**Démarrage de l'agent :**

```bash
$ sudo systemctl start wazuh-agent
$ sudo systemctl status wazuh-agent --no-pager
```

**Sortie (`evidence/16_agent_status.txt`) :**
```
● wazuh-agent.service - Wazuh agent
     Active: active (running) since Fri 2026-03-06 13:29:55 CET; 10s ago
    Process: 38126 ExecStart=... wazuh-control start (code=exited, status=0/SUCCESS)
      Tasks: 40 (limit: 28334)
     Memory: 2.3G
             ├─38426 /var/ossec/bin/wazuh-execd
             ├─38445 /var/ossec/bin/wazuh-agentd
             ├─38465 /var/ossec/bin/wazuh-syscheckd
             ├─38475 /var/ossec/bin/wazuh-logcollector
             └─38498 /var/ossec/bin/wazuh-modulesd
```

### 4.10 Vérification des agents connectés

**Liste des agents via API (`evidence/10_agents_list.txt`) :**

```bash
$ curl -s -k -H "Authorization: Bearer $TOKEN" \
  "https://127.0.0.1:55000/agents?limit=10"
```

**Résultat :**
```json
{
  "data": {
    "affected_items": [
      {
        "id": "000",
        "name": "wazuh.manager",
        "status": "active",
        "version": "Wazuh v4.9.2",
        "os": {"name": "Amazon Linux", "platform": "amzn"}
      },
      {
        "id": "002",
        "name": "kali-forensic",
        "status": "active",
        "version": "Wazuh v4.9.2",
        "os": {"name": "Kali GNU/Linux", "platform": "kali", "version": "2025.4"},
        "ip": "127.0.0.1",
        "group": ["default"],
        "lastKeepAlive": "2026-03-06T12:30:29+00:00"
      }
    ],
    "total_affected_items": 2
  }
}
```

### 4.11 Alertes générées

Le SIEM a généré des alertes réelles dès la connexion de l'agent. Exemples issus de `evidence/19_alerts_sample.txt` :

| Timestamp | Règle | Niveau | Description | Agent |
|-----------|-------|--------|-------------|-------|
| 2026-03-06T12:30:06 | 19007 | 7 | SSH: Wrong Max authentication attempts | kali-forensic |
| 2026-03-06T12:30:06 | 19007 | 7 | SSH: Grace Time should be one minute or less | kali-forensic |
| 2026-03-06T12:30:06 | 19008 | 3 | Ensure passwords hashed with SHA-512 | kali-forensic |
| 2026-03-06T12:30:13 | 19005 | 9 | **SCA score < 30% (23/100)** | kali-forensic |
| 2026-03-06T12:30:16 | 510 | 7 | Host-based anomaly detection (rootcheck) | kali-forensic |
| 2026-03-06T12:33:40 | 502 | 3 | Wazuh server started | wazuh.manager |
| 2026-03-06T12:36:02 | 533 | 7 | **Listened ports changed (new port opened)** | kali-forensic |
| 2026-03-06T13:06:28 | 5402 | 3 | Successful sudo to ROOT executed | kali-forensic |
| 2026-03-06T13:06:28 | 5501 | 3 | PAM: Login session opened | kali-forensic |

**Statistiques analysisd (`evidence/18_analysisd_stats.txt`) :**
```json
{
  "total_events_decoded":    3019,
  "sca_events_decoded":      31,
  "rootcheck_events_decoded": 22,
  "syscheck_events_decoded":  5,
  "events_processed":        221,
  "events_received":         3023,
  "events_dropped":          0,
  "alerts_written":          50
}
```

> **50 alertes écrites, 0 événement perdu, cluster vert.**

### 4.12 État final du déploiement

**Conteneurs Docker (`evidence/04_containers_status.txt`) :**
```
NAME                             IMAGE                       STATUS
wazuh-deploy-wazuh.dashboard-1   wazuh/wazuh-dashboard:4.9.2 Up 7 minutes  (443->5601/tcp)
wazuh-deploy-wazuh.indexer-1     wazuh/wazuh-indexer:4.9.2   Up 11 minutes (9200/tcp)
wazuh-deploy-wazuh.manager-1     wazuh/wazuh-manager:4.9.2   Up 11 minutes (1514,1515,514/udp,55000/tcp)
```

**Utilisation des ressources (`evidence/20_docker_stats.txt`) :**
```
NAME                             CPU %   MEM USAGE / LIMIT
wazuh-deploy-wazuh.dashboard-1   0.17%   189.6MiB / 23.26GiB
wazuh-deploy-wazuh.manager-1     3.93%   565.3MiB / 23.26GiB
wazuh-deploy-wazuh.indexer-1     0.47%   1.429GiB / 23.26GiB
```

**Accès au dashboard Wazuh :**
- URL : `https://127.0.0.1:443`
- Identifiants : `admin` / `SecretPassword`
- Réponse HTTP : **302 (redirection vers /app/wz-home)**

---

## Annexe - Fichiers de preuves

| Fichier | Contenu |
|---------|---------|
| `evidence/01_docker_version.txt` | Version Docker et Docker Compose |
| `evidence/02_certs_generated.txt` | Liste des certificats TLS générés |
| `evidence/03_docker_compose_up.txt` | Sortie du `docker compose up` |
| `evidence/04_containers_status.txt` | État final des 3 conteneurs |
| `evidence/05_indexer_api.txt` | Réponse API OpenSearch |
| `evidence/06_securityadmin.txt` | Initialisation sécurité OpenSearch |
| `evidence/07_password_setup.txt` | Configuration mot de passe admin |
| `evidence/08_wazuh_manager_api.txt` | API Manager (token JWT + info) |
| `evidence/09_manager_status.txt` | Statut daemons Wazuh |
| `evidence/10_agents_list.txt` | Liste agents connectés (manager + kali-forensic) |
| `evidence/11_agent_register.txt` | Enregistrement agent via API |
| `evidence/12_cluster_health.txt` | Santé cluster OpenSearch (GREEN) |
| `evidence/13_indexer_indices.txt` | Indices OpenSearch |
| `evidence/14_agent_install.txt` | Installation agent sur Kali |
| `evidence/15_agent_key_import.txt` | Clé d'authentification agent |
| `evidence/16_agent_status.txt` | Statut systemd wazuh-agent |
| `evidence/17_agent_stats.txt` | Statistiques agent (2729 messages traités) |
| `evidence/18_analysisd_stats.txt` | Statistiques analysisd (50 alertes, 3019 events) |
| `evidence/19_alerts_sample.txt` | Échantillon d'alertes réelles générées |
| `evidence/20_docker_stats.txt` | Utilisation CPU/RAM des conteneurs |
| `wazuh-deploy/config/certs.yml` | Configuration certificats |
| `wazuh-deploy/config/wazuh_indexer/wazuh.indexer.yml` | Config OpenSearch indexer |
| `wazuh-deploy/config/wazuh_dashboard/opensearch_dashboards.yml` | Config dashboard |
| `wazuh-deploy/docker-compose.yml` | Stack Docker Compose complète |
