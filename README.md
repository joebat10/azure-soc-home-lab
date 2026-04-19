# 🛡️ Création d'un SOC + Honeynet dans Azure (Trafic réel)

![Architecture avant hardening](captures%20d'écran/00-architecture-avant.png)

---

## Introduction

Dans ce projet, j'ai construit un mini-honeynet sur Microsoft Azure et ingéré les logs de plusieurs ressources dans un Log Analytics Workspace, utilisé ensuite par Microsoft Sentinel pour construire des cartes d'attaque, déclencher des alertes et créer des incidents.

J'ai mesuré les métriques de sécurité dans un environnement non sécurisé pendant **24 heures**, puis appliqué des contrôles de sécurité pour renforcer l'environnement, mesuré à nouveau pendant **24 heures**, et comparé les résultats.

**Métriques collectées :**
- `SecurityEvent` — Logs Windows (EventID 4625 : échecs de connexion RDP/MSSQL)
- `Syslog` — Logs Linux (tentatives SSH échouées via LOG_AUTH)
- `SecurityAlert` — Alertes déclenchées par Microsoft Defender for Cloud
- `SecurityIncident` — Incidents créés automatiquement par Sentinel
- `AzureNetworkAnalytics_CL` — Flux malveillants autorisés par les NSG

---

## Composants de l'architecture

- Réseau virtuel Azure (VNet) — `soc-lab-vnet`
- Network Security Groups (NSG) — `SVR-CORPORATE-nsg`, `linux-vm-nsg`
- Machines virtuelles — `SVR-CORPORATE` (Windows Server + SQL Server 2022), `linux-vm` (Ubuntu 22.04 LTS)
- Log Analytics Workspace — `law-soc-lab`
- Microsoft Sentinel (SIEM + SOAR)
- Microsoft Defender for Cloud
- Azure Key Vault — `kv-soclab-joe`
- Azure Storage Account — `stsocjoe`

---

## Architecture AVANT Hardening

![Architecture avant](captures%20d'écran/00-architecture-avant.png)

Toutes les ressources ont été déployées et exposées à Internet sans restriction. Les machines virtuelles avaient leurs NSG et pare-feux internes entièrement ouverts — toute connexion entrante était autorisée. Le Key Vault et le Storage Account avaient leurs endpoints publics accessibles depuis n'importe quelle IP dans le monde.

---

## Cartes d'attaque — AVANT Hardening

### Tentatives RDP Windows — SVR-CORPORATE
![Windows RDP Failures](captures%20d'écran/08-attack-map-rdp.png)

### Tentatives SSH Linux — linux-vm
![Linux SSH Failures](captures%20d'écran/09-attack-map-linux-ssh.png)

### Tentatives MSSQL — SQL Server
![MSSQL Auth Failures](captures%20d'écran/10-attack-map-mssql.png)

### Flux NSG malveillants autorisés
![NSG Malicious Flows](captures%20d'écran/11-attack-map-nsg.png)

---

## Métriques AVANT Hardening

**Début de mesure :** *(à compléter — ex: 2025-04-18 14:00:00 UTC)*
**Fin de mesure :** *(à compléter — ex: 2025-04-19 14:00:00 UTC)*

| Métrique | Nombre |
|---|---|
| SecurityEvent (Windows) | **50 534** |
| Syslog (Linux) | **26 730** |
| SecurityAlert | **246** |
| SecurityIncident | **246** |
| AzureNetworkAnalytics_CL | *(table en cours de création)* |

> **Fait notable :** 4 152 tentatives de connexion RDP enregistrées depuis **11 IPs distinctes** ciblant **247 comptes différents** en moins de 24h d'exposition.

---

## Architecture APRÈS Hardening

![Architecture après](captures%20d'écran/13-architecture-apres.png)

Les NSG ont été restreints pour n'autoriser que le trafic depuis mon IP personnelle. L'accès public au Key Vault et au Storage Account a été désactivé. Les pare-feux intégrés de toutes les VMs ont été réactivés.

**Contrôles appliqués (basés sur NIST SP 800-53) :**

| Mesure | Description | Contrôle NIST |
|---|---|---|
| Suppression `DANGER_AllowAll` (NSG) | Suppression de toutes les règles permissives | SC-7 |
| Ajout `Allow_My_IP_Only` (NSG) | Accès restreint à l'IP admin uniquement | AC-17 |
| Pare-feu Windows réactivé | Profils Domain + Private + Public actifs | SC-7 |
| UFW Linux réactivé | SSH restreint à l'IP admin | SC-7 |
| Key Vault — accès public désactivé | Inaccessible depuis Internet | SC-7, AC-3 |
| Storage Account — accès public désactivé | Inaccessible depuis Internet | SC-7, AC-3 |

---

## Cartes d'attaque — APRÈS Hardening

Toutes les requêtes de carte d'attaque n'ont retourné aucun résultat — aucune activité malveillante détectée dans la fenêtre de 24h suivant l'application des contrôles de sécurité.

![Aucun résultat après hardening](captures%20d'écran/20-maps-apres-hardening.png)

---

## Métriques APRÈS Hardening

**Début de mesure :** *(à compléter)*
**Fin de mesure :** *(à compléter)*

| Métrique | Avant Hardening | Après Hardening | Variation |
|---|---|---|---|
| SecurityEvent (Windows) | 50 534 | *(à compléter)* | ↓ -??% |
| Syslog (Linux) | 26 730 | *(à compléter)* | ↓ -??% |
| SecurityAlert | 246 | *(à compléter)* | ↓ -??% |
| SecurityIncident | 246 | *(à compléter)* | ↓ -??% |
| AzureNetworkAnalytics_CL | — | *(à compléter)* | — |

---

## Requêtes KQL utilisées

> Fichier complet disponible dans [`queries/all-queries.kql`](queries/all-queries.kql)

```kql
-- Fenêtre de mesure (24h)
range x from 1 to 1 step 1
| project StartTime = ago(24h), StopTime = now()

-- Security Events Windows
SecurityEvent
| where TimeGenerated >= ago(24h)
| count

-- Syslog Linux
Syslog
| where TimeGenerated >= ago(24h)
| count

-- Alertes Defender for Cloud
SecurityAlert
| where DisplayName !startswith "CUSTOM" and DisplayName !startswith "TEST"
| where TimeGenerated >= ago(24h)
| count

-- Incidents Sentinel
SecurityIncident
| where TimeGenerated >= ago(24h)
| count

-- Flux NSG malveillants
AzureNetworkAnalytics_CL
| where FlowType_s == "MaliciousFlow" and AllowedInFlows_d > 0
| where TimeGenerated >= ago(24h)
| count
```

---

## Résumé

Un mini-honeynet a été construit sur Microsoft Azure. Les logs ont été ingérés dans un Log Analytics Workspace. Microsoft Sentinel a déclenché des alertes et créé des incidents basés sur ces logs. Les métriques ont été mesurées avant et après l'application des contrôles de sécurité, démontrant une réduction significative des événements et des incidents.

Les mesures de hardening appliquées sont conformes au framework **NIST SP 800-53** : restriction d'accès réseau (SC-7), contrôle des accès distants (AC-17), principe du moindre privilège (AC-6).

> Note : Si les ressources avaient été utilisées intensément par des utilisateurs légitimes après le hardening, davantage d'événements auraient pu être générés même avec les contrôles en place.

---

## Structure du dépôt

```
azure-soc-home-lab/
├── README.md
├── documents/
│   └── lab-documentation.md
├── queries/
│   └── all-queries.kql
├── workbooks/
│   ├── linux-ssh-auth-fail.json
│   ├── mssql-auth-fail.json
│   ├── nsg-malicious-allowed-in.json
│   └── windows-rdp-auth-fail.json
└── captures d'écran/
    ├── 00-architecture-avant.png
    ├── 01-resource-group.png
    ├── 02-eventviewer-4625.png
    ├── 03-sentinel-activation.png
    ├── 04-data-connector-ama.png
    ├── 05-kql-echecs-connexion.png
    ├── 06-kql-top-attaquants.png
    ├── 07-kql-password-spray.png
    ├── 08-attack-map-rdp.png
    ├── 09-attack-map-linux-ssh.png
    ├── 10-attack-map-mssql.png
    ├── 11-attack-map-nsg.png
    ├── 12-incidents-sentinel.png
    ├── 13-metriques-avant.png
    ├── 14-hardening-nsg-svr.png
    ├── 15-hardening-nsg-linux.png
    ├── 16-hardening-keyvault.png
    ├── 17-hardening-storage.png
    ├── 18-hardening-firewall-win.png
    ├── 19-hardening-ufw-linux.png
    └── 20-metriques-apres.png
```
