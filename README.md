# Building a Live SOC + Honeynet in Azure

## Introduction

In this project, I built a mini honeynet on Microsoft Azure by intentionally exposing virtual machines to the public internet. Logs from all resources were ingested into a Log Analytics Workspace, which Microsoft Sentinel used to build attack maps, trigger alerts, and create incidents.

I measured security metrics in the insecure environment for **24 hours**, then applied hardening controls, measured again for **24 hours**, and compared the results.

**Metrics collected:**
- `SecurityEvent` — Windows logs (EventID 4625: failed RDP/MSSQL logins)
- `Syslog` — Linux logs (failed SSH attempts via LOG_AUTH)
- `SecurityAlert` — Alerts triggered by Microsoft Defender for Cloud
- `SecurityIncident` — Incidents automatically created by Sentinel
- `AzureNetworkAnalytics_CL` — Malicious flows allowed through NSGs

---

## Architecture

**Resources deployed in Resource Group `SOC-Lab-RG` — France Central:**

| Resource | Name | Role |
|---|---|---|
| Virtual Network | `soc-lab-vnet` | Shared network for all VMs |
| Windows Server VM | `SVR-CORPORATE` | Honeypot — RDP + SQL Server exposed |
| Linux VM | `linux-vm` | Honeypot — SSH exposed |
| NSG | `SVR-CORPORATE-nsg` | Network firewall for Windows VM |
| NSG | `linux-vm-nsg` | Network firewall for Linux VM |
| Log Analytics Workspace | `law-soc-lab` | Central log database |
| Microsoft Sentinel | — | SIEM built on top of LAW |
| Key Vault | `kv-soclab-joe` | Secret storage (honeypot + hardened) |
| Storage Account | `stsocjoe` | Blob storage with diagnostic logs |
| Storage Account | `socflowlogsjoe` | VNet Flow Logs storage |

---

## Phase 1 — Deploy the Honeypot Infrastructure

### Step 1 — Windows VM: SVR-CORPORATE

Created a Windows Server VM intentionally exposed to the internet to attract RDP and MSSQL brute-force attacks.

**Configuration:**

| Setting | Value |
|---|---|
| Resource Group | `SOC-Lab-RG` |
| VM Name | `SVR-CORPORATE` |
| Region | France Central |
| Image | Windows Server 2022 Datacenter |
| Size | Standard_B2s |
| Username | `socadmin` |
| Public inbound ports | RDP (3389) |
| Virtual Network | `soc-lab-vnet` |

**Disable Windows Firewall (honeypot phase):**

Connected via RDP → `Win+R` → `wf.msc` → "Windows Defender Firewall Properties" → Set all three profiles (Domain, Private, Public) to **Off**.

**Open NSG (honeypot phase):**

Added inbound rule `DANGER_AllowAll` on `SVR-CORPORATE-nsg`:

| Field | Value |
|---|---|
| Source | Any |
| Source port | * |
| Destination | Any |
| Destination port | * |
| Protocol | Any |
| Action | Allow |
| Priority | 100 |

---

### Step 2 — SQL Server 2022 on SVR-CORPORATE

Installed SQL Server on the Windows VM to expose port 1433 as an additional attack surface.

**Installation steps:**
1. RDP into `SVR-CORPORATE`
2. Download SQL Server 2022 Developer (free) from microsoft.com
3. Install → Basic → accept license
4. Open SSMS → connect with Windows Authentication
5. Enable SQL Server Authentication mode: right-click server → Properties → Security → SQL Server and Windows Authentication
6. Enable the `sa` account: Security → Logins → right-click `sa` → Properties → Status: Enabled, set password `cyberlab242@`
7. Restart SQL Server service

This makes the VM a target for MSSQL brute-force attacks visible in Sentinel.

---

### Step 3 — Linux VM: linux-vm

Created an Ubuntu VM exposed to the internet to attract SSH brute-force attacks.

**Configuration:**

| Setting | Value |
|---|---|
| Resource Group | `SOC-Lab-RG` |
| VM Name | `linux-vm` |
| Region | France Central |
| Image | Ubuntu Server 22.04 LTS |
| Size | Standard_B1s |
| Username | `adminsoc` |
| Auth type | Password |
| Public inbound ports | SSH (22) |
| Virtual Network | `soc-lab-vnet` (same as SVR-CORPORATE) |

**Both VMs on the same VNet** so they can communicate internally while both being accessible from the internet.

**Disable Linux Firewall (honeypot phase):**

```bash
ssh adminsoc@<linux-vm-public-ip>
sudo ufw status
sudo ufw disable
# Output: Firewall stopped and disabled on system startup
```

**Open NSG (honeypot phase):**

Added same `DANGER_AllowAll` rule on `linux-vm-nsg` (same settings as SVR-CORPORATE-nsg, priority 100).

---

### Step 4 — Log Analytics Workspace

Created the central log database that all resources send their logs to.

- Search "Log Analytics workspaces" → Create
- Name: `law-soc-lab`
- Resource Group: `SOC-Lab-RG`
- Region: France Central

---

### Step 5 — Microsoft Sentinel

Deployed Sentinel on top of the Log Analytics Workspace.

- Search "Microsoft Sentinel" → Create
- Select workspace `law-soc-lab` → Add

Sentinel is the SIEM layer: it ingests all logs from the workspace, runs KQL-based detection rules, creates incidents, and displays attack maps.

---

### Step 6 — Connect Windows VM to Sentinel (Security Events)

- Sentinel → Content Hub → "Windows Security Events via AMA" → Install → Open connector page
- Create data collection rule `dcr-windows`:
  - Resources: `SVR-CORPORATE`
  - Collect: **All Security Events** (captures EventID 4625 — failed logins)

---

### Step 7 — Connect Linux VM to Sentinel (Syslog)

- Sentinel → Content Hub → "Syslog" → Install → Open connector page
- Create data collection rule `dcr-linux-syslog`:
  - Resources: `linux-vm`
  - Collect: `LOG_AUTH` and `LOG_AUTHPRIV` (SSH failed attempts)

Syslog is Linux's standard logging system. Failed SSH attempts appear in LOG_AUTH — the Linux equivalent of Windows EventID 4625.

---

### Step 8 — Key Vault with Diagnostic Logging

Created `kv-soclab-joe` to simulate a real enterprise secret store and log all access attempts.

- Key vault name: `kv-soclab-joe`
- Region: France Central | Pricing: Standard
- Diagnostic setting `ds-keyvault`:
  - Logs: AuditEvent
  - Destination: `law-soc-lab`

Every secret access attempt (read, write, failure) is now forwarded to the workspace where Sentinel can alert on suspicious activity.

---

### Step 9 — Storage Account with Diagnostic Logging

Created `stsocjoe` to simulate enterprise blob storage and detect unauthorized data access.

- Storage account name: `stsocjoe`
- Region: France Central | Redundancy: LRS
- Diagnostic setting on blob `ds-storage-blob`:
  - Logs: StorageRead, StorageWrite, StorageDelete
  - Destination: `law-soc-lab`

---

### Step 10 — Microsoft Defender for Cloud

Enabled Defender to generate security alerts forwarded to Sentinel.

- Environment Settings → `law-soc-lab` workspace
- Defender plans enabled:
  - **Servers → On**
  - **SQL servers on machines → On**
  - All others → Off

---

### Step 11 — Import Sentinel Analytics Rules

Imported pre-built KQL detection rules from `Sentinel-Analytics-Rules(KQL Alert Queries).json`.

- Sentinel → Analytics → Import → select JSON file

Rules active after import:
- Brute Force ATTEMPT - Windows
- Brute Force ATTEMPT - Linux SSH
- Brute Force ATTEMPT - MS SQL Server
- Possible Privilege Escalation
- Malicious NSG Inbound Flow Allowed

---

### Step 12 — GeoIP Watchlist

Uploaded `geoip-summarized.csv` (~54,000 IP ranges with GPS coordinates) as a Sentinel Watchlist to plot attacker origins on a world map.

- Sentinel → Watchlist → New
- Name/Alias: `geoip`
- SearchKey: `network`
- Upload: `geoip-summarized.csv`

---

### Step 13 — Import Attack Map Workbooks

Imported 4 Azure Workbooks that display live attack maps using KQL + GeoIP data:

| Workbook | What it monitors |
|---|---|
| `windows-rdp-auth-fail.json` | RDP brute-force attempts on SVR-CORPORATE |
| `linux-ssh-auth-fail.json` | SSH brute-force attempts on linux-vm |
| `mssql-auth-fail.json` | SQL Server login failures on port 1433 |
| `nsg-malicious-allowed-in.json` | Malicious traffic allowed by NSGs |

Workbook JSON files are in the [`workbooks/`](workbooks/) folder.

---

## Phase 2 — Let the Honeynet Run (24 Hours)

Left the environment fully exposed with no changes. Both VMs had public IPs, all NSG rules were open, and all firewalls were disabled.

**What happened during this time:**
Automated bots and scanners on the internet discovered the VMs within minutes of deployment. RDP brute-force tools started cycling through credential lists targeting port 3389. SSH scanners hit port 22 continuously. MSSQL scanners targeted port 1433.

---

## Phase 3 — Metrics BEFORE Hardening

Ran the 6 KQL measurement queries after 24 hours of exposure.

| Metric | Count |
|---|---|
| SecurityEvent (Windows) | **50,534** |
| Syslog (Linux) | **26,730** |
| SecurityAlert | **246** |
| SecurityIncident | **246** |
| AzureNetworkAnalytics_CL | *(table populating)* |

> **Notable:** 4,152 RDP login attempts from **11 distinct IPs** targeting **247 different accounts** in under 24 hours.

---

## Phase 4 — Hardening (NIST SP 800-53)

### A — Re-enable Windows Firewall on SVR-CORPORATE

RDP into `SVR-CORPORATE` → `Win+R` → `wf.msc` → "Windows Defender Firewall Properties" → Set all three profiles (Domain, Private, Public) to **On** → Apply.

### B — Re-enable Linux Firewall on linux-vm

```bash
ssh adminsoc@<linux-vm-public-ip>
sudo ufw enable
sudo ufw allow from <MY_IP> to any port 22
sudo ufw status verbose
```

### C — Lock Down NSG of SVR-CORPORATE

1. Portal → Network Security Groups → `SVR-CORPORATE-nsg`
2. Delete rule `DANGER_AllowAll`
3. Add new rule `Allow_My_IP_Only`:

| Field | Value |
|---|---|
| Source | IP Addresses |
| Source IP | `88.188.66.199` (personal IP) |
| Destination port | * |
| Protocol | Any |
| Action | Allow |
| Priority | 100 |

Also added specific rules for RDP (3389) and MSSQL (1433) restricted to personal IP only.

### D — Lock Down NSG of linux-vm

1. Portal → Network Security Groups → `linux-vm-nsg`
2. Delete rule `Danger_Allow`
3. Add `Allow_My_IP_Only` (SSH port 22, source: personal IP, priority 100)

### E — Disable Public Access to Key Vault

- Key Vault `kv-soclab-joe` → Networking → Public network access → **Disabled** → Save

### F — Disable Public Access to Storage Account

- Storage Account `stsocjoe` → Networking → Public network access → **Disabled** → Proceed → Save

---

## Phase 5 — Let the Secured Environment Run (24 Hours)

Left the hardened environment running for 24 hours without any changes. With NSGs locked to personal IP, firewalls active, and public access to Key Vault and Storage Account disabled — no external traffic could reach the resources.

---

## Phase 6 — Metrics AFTER Hardening

| Metric | Before | After | Change |
|---|---|---|---|
| SecurityEvent (Windows) | 50,534 | *(to complete)* | ↓ |
| Syslog (Linux) | 26,730 | *(to complete)* | ↓ |
| SecurityAlert | 246 | *(to complete)* | ↓ |
| SecurityIncident | 246 | *(to complete)* | ↓ |
| AzureNetworkAnalytics_CL | — | *(to complete)* | — |

Attack maps returned no results after hardening — no malicious activity detected in the 24-hour post-hardening window.

---

## KQL Queries Used

Full query file: [`queries/all-queries.kql`](queries/all-queries.kql)

```kql
-- Time window
range x from 1 to 1 step 1
| project StartTime = ago(24h), StopTime = now()

-- Windows Security Events
SecurityEvent
| where TimeGenerated >= ago(24h)
| count

-- Linux Syslog
Syslog
| where TimeGenerated >= ago(24h)
| count

-- Defender Alerts
SecurityAlert
| where DisplayName !startswith "CUSTOM" and DisplayName !startswith "TEST"
| where TimeGenerated >= ago(24h)
| count

-- Sentinel Incidents
SecurityIncident
| where TimeGenerated >= ago(24h)
| count

-- NSG Malicious Flows
AzureNetworkAnalytics_CL
| where FlowType_s == "MaliciousFlow" and AllowedInFlows_d > 0
| where TimeGenerated >= ago(24h)
| count

-- Top attacking IPs
SecurityEvent
| where EventID == 4625
| summarize Attempts = count() by IpAddress
| order by Attempts desc
| render barchart

-- Password Spray detection (1 IP targets many accounts)
SecurityEvent
| where EventID == 4625
| summarize DistinctAccounts = dcount(Account), TotalAttempts = count() by IpAddress
| where DistinctAccounts > 5
| order by TotalAttempts desc
```

---

## Summary

A mini honeynet was constructed in Microsoft Azure. Logs from Windows and Linux VMs, SQL Server, Key Vault, and Storage Account were ingested into a Log Analytics Workspace. Microsoft Sentinel triggered alerts and created incidents based on those logs.

After 24 hours of exposure, the environment collected **50,534 Windows security events** and **26,730 Linux syslogs**, with **4,152 RDP brute-force attempts** from 11 IPs targeting 247 accounts. Hardening measures based on **NIST SP 800-53** controls were then applied, resulting in a significant reduction of all security metrics in the following 24-hour window.

---

## Repository Structure

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
└── screenshots/
    ├── 01-resource-group.png
    ├── 02-svr-corporate-vm.png
    ├── 03-sql-server-install.png
    ├── 04-linux-vm.png
    ├── 05-nsg-danger-allow.png
    ├── 06-sentinel-activation.png
    ├── 07-data-connector-windows.png
    ├── 08-data-connector-linux.png
    ├── 09-keyvault-diagnostic.png
    ├── 10-storage-diagnostic.png
    ├── 11-analytics-rules.png
    ├── 12-geoip-watchlist.png
    ├── 13-workbooks-all.png
    ├── 14-attack-map-rdp.png
    ├── 15-attack-map-ssh.png
    ├── 16-attack-map-mssql.png
    ├── 17-attack-map-nsg.png
    ├── 18-incidents-before.png
    ├── 19-metrics-before.png
    ├── 20-hardening-firewall-windows.png
    ├── 21-hardening-ufw-linux.png
    ├── 22-hardening-nsg-svr.png
    ├── 23-hardening-nsg-linux.png
    ├── 24-hardening-keyvault.png
    ├── 25-hardening-storage.png
    ├── 26-attack-maps-after.png
    └── 27-metrics-after.png
```
