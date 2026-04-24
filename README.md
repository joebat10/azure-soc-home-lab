# Building a Live SOC + Honeynet in Azure

![Architecture](screenshots/00-architecture.png)

## Introduction

In this project, I built a mini honeynet on Microsoft Azure by intentionally exposing virtual machines to the public internet. Logs from all resources were ingested into a Log Analytics Workspace, which Microsoft Sentinel used to build attack maps, trigger alerts, and create incidents.

I measured security metrics in the insecure environment for **24 hours**, then applied hardening controls based on **NIST SP 800-53**, measured again for **24 hours**, and compared the results.

**Metrics collected:**
- `SecurityEvent` — Windows logs (EventID 4625: failed RDP/MSSQL logins)
- `Syslog` — Linux logs (failed SSH attempts via LOG_AUTH)
- `SecurityAlert` — Alerts triggered by Microsoft Defender for Cloud
- `SecurityIncident` — Incidents automatically created by Sentinel
- `AzureNetworkAnalytics_CL` — Malicious flows allowed through NSGs

---

## Architecture & Resources

**Resource Group:** `SOC-Lab-RG` | **Region:** France Central

| Resource | Name | Purpose |
|---|---|---|
| Virtual Network | `soc-lab-vnet` | Shared private network |
| Windows VM | `SVR-CORPORATE` | Honeypot — RDP + SQL Server |
| Linux VM | `linux-vm` | Honeypot — SSH |
| NSG | `SVR-CORPORATE-nsg` | Cloud firewall — Windows VM |
| NSG | `linux-vm-nsg` | Cloud firewall — Linux VM |
| Log Analytics Workspace | `law-soc-lab` | Central log database |
| Microsoft Sentinel | — | SIEM built on LAW |
| Key Vault | `kv-socxxxx` | Secret storage |
| Storage Account | `stsocxxxx` | Blob storage |

---

## Phase 1 — Deploy the Honeypot Infrastructure

### Step 1 — Windows VM: SVR-CORPORATE

Deployed a Windows Server 2022 VM with RDP (port 3389) open to the internet. The NSG was intentionally configured to allow all inbound traffic.

**NSG rule `DANGER_AllowAll` — honeypot phase:**

![NSG Danger Allow rule](screenshots/01-nsg-danger-allow-rule.png)

| Field | Value |
|---|---|
| Source | Any |
| Source port | * |
| Destination | Any |
| Destination port | * |
| Protocol | Any |
| Action | Allow |
| Priority | 100 |

Windows Defender Firewall was disabled on all 3 profiles (Domain, Private, Public) via `wf.msc`.

---

### Step 2 — SQL Server 2022 on SVR-CORPORATE

Installed SQL Server 2022 Developer (free edition) on `SVR-CORPORATE` to expose port 1433 as an additional attack surface for MSSQL brute-force attacks.

**Download SQL Server:**

![SQL Server Download](screenshots/15-sql-server-download.png)

**Install SQL Server:**

![SQL Server Install](screenshots/15b-sql-server-install.png)

![SQL Server Setup](screenshots/15c-sql-server-setup.png)

![SQL Server Config](screenshots/15d-sql-server-config.png)

**Install SSMS and connect:**

![SSMS Install](screenshots/15e-ssms-install.png)

![SSMS Connection](screenshots/15f-ssms-connection.png)

Enabled SQL Server Authentication mode and the `sa` account so that MSSQL login attempts from the internet are captured in the logs.

---

### Step 3 — Linux VM: linux-vm

Deployed Ubuntu 22.04 LTS with SSH (port 22) open. Same VNet as `SVR-CORPORATE` so both VMs communicate internally while being reachable from the internet.

**VM creation:**

![Linux VM creation](screenshots/13-linux-vm-creation.png)

![Linux VM networking](screenshots/13b-linux-vm-networking.png)

![Linux VM deployed](screenshots/13c-linux-vm-deployed.png)

**Linux firewall disabled:**

![UFW disable](screenshots/14-linux-ufw-disable.png)

```bash
ssh adminsoc@<linux-vm-ip>
sudo ufw disable
# Output: Firewall stopped and disabled on system startup
```

Same `DANGER_AllowAll` rule added to `linux-vm-nsg`.

---

### Step 4 — Generate Test Events (EventID 4625)

To verify logs were flowing correctly, we intentionally triggered failed login attempts to confirm EventID 4625 was captured.

**Generating test failed logins:**

**Inspecting in Event Viewer (EventID 4625):**

![Event Viewer 4625](screenshots/03-eventviewer-4625.png)

![Event Viewer list](screenshots/03b-eventviewer-4625-list.png)

`Windows Logs → Security → Filter → EventID 4625` — every failed login attempt appears here with the source IP, targeted account, and timestamp.

---

## Phase 2 — Configure Microsoft Sentinel

### Step 5 — Log Analytics Workspace

Created `law-soc-lab` — the central database that receives all logs from all resources.

![Log Analytics Workspace](screenshots/04-log-analytics-workspace.png)

![LAW creation](screenshots/04b-law-creation.png)

---

### Step 6 — Microsoft Sentinel Activation

Deployed Microsoft Sentinel on top of `law-soc-lab`. Sentinel is the SIEM layer — it ingests logs, runs KQL-based detection rules 24/7, creates incidents, and powers attack map dashboards.

![Sentinel search](screenshots/05-sentinel-search-portal.png)

![Sentinel select workspace](screenshots/05b-sentinel-select-workspace.png)

![Sentinel dashboard](screenshots/05c-sentinel-dashboard.png)

---

### Step 7 — Data Connector: Windows Security Events (AMA)

Connected `SVR-CORPORATE` to the workspace via Azure Monitor Agent. Configured to collect **All Security Events** — this captures EventID 4625 (failed logins) and all other security events.

![Data Connector AMA setup](screenshots/06-data-connector-ama-setup.png)

![Data Connector Windows](screenshots/06b-data-connector-windows.png)

![All Security Events selected](screenshots/06c-all-security-events-selected.png)

![Data Connector configured](screenshots/06d-data-connector-configured.png)

---

### Step 8 — Data Connector: Linux Syslog

Connected `linux-vm` via the Syslog connector, collecting `LOG_AUTH` and `LOG_AUTHPRIV`. This captures failed SSH login attempts — the Linux equivalent of Windows EventID 4625.

---

### Step 9 — Key Vault Diagnostic Logging

Created `kv-soclab-joe` and enabled diagnostic logs so every secret access attempt is forwarded to `law-soc-lab`.

![Key Vault diagnostic setting](screenshots/16-keyvault-diagnostic-setting.png)

![Key Vault audit log config](screenshots/16b-keyvault-auditlog-config.png)

Diagnostic setting `ds-keyvault`: Logs → `AuditEvent` → Send to `law-soc-lab`.

---

### Step 10 — Storage Account Diagnostic Logging

Created `stsocjoe` and enabled blob diagnostic logs to capture all read/write/delete operations.

![Storage diagnostic setting](screenshots/17-storage-diagnostic-setting.png)

![Storage logs config](screenshots/17b-storage-logs-config.png)

![Storage account saved](screenshots/17c-storage-account-saved.png)

Diagnostic setting `ds-storage-blob`: `StorageRead`, `StorageWrite`, `StorageDelete` → Send to `law-soc-lab`.

---

### Step 11 — GeoIP Watchlist

Uploaded `geoip-summarized.csv` (~54,000 IP ranges with GPS coordinates) as a Sentinel Watchlist. This is used by all attack map workbooks to translate attacker IPs into countries on a world map.

![GeoIP download](screenshots/10-geoip-download.png)

![GeoIP import complete](screenshots/10b-geoip-import-done.png)

![GeoIP countries query](screenshots/10c-geoip-countries-query.png)

Watchlist alias: `geoip` | SearchKey: `network`

---

### Step 12 — Import Sentinel Analytics Rules

Imported `Sentinel-Analytics-Rules(KQL Alert Queries).json` — a set of pre-built KQL detection rules that automatically create incidents when attack patterns are detected.

![Analytics rules import](screenshots/12-analytics-rules-import.png)

![Analytics rules imported](screenshots/12b-analytics-rules-imported.png)

![Analytics rules active list](screenshots/12c-analytics-rules-active-list.png)

Rules active after import:
- Brute Force ATTEMPT — Windows
- Brute Force ATTEMPT — Linux SSH
- Brute Force ATTEMPT — MS SQL Server
- Possible Privilege Escalation
- Malicious NSG Inbound Flow Allowed

---

### Step 13 — Import Attack Map Workbooks

Imported 4 Azure Workbooks from the [`workbooks/`](workbooks/) folder. These create live world-map attack visualizations using KQL + GeoIP data.

![Workbooks list](screenshots/11-workbooks-list.png)

![Workbook editor](screenshots/11b-workbook-editor.png)

![Workbook attack map](screenshots/11c-workbook-attack-map.png)

![All workbooks overview](screenshots/11d-all-workbooks-overview.png)

| Workbook | Monitors |
|---|---|
| `windows-rdp-auth-fail.json` | RDP brute-force on SVR-CORPORATE |
| `linux-ssh-auth-fail.json` | SSH brute-force on linux-vm |
| `mssql-auth-fail.json` | SQL Server login failures (port 1433) |
| `nsg-malicious-allowed-in.json` | Malicious traffic allowed by NSGs |

---

## Phase 3 — Honeynet Exposed for 24 Hours

Left both VMs fully exposed with no changes. Automated bots discovered the VMs within minutes and launched continuous RDP, SSH, and MSSQL brute-force attacks.

![Timestamp before hardening](screenshots/18-timestamp-before-hardening.png)

---

## Phase 4 — Metrics BEFORE Hardening

### KQL Query 1 — All Failed Logins

![KQL query all attacks](screenshots/07-kql-query1-all-attacks.png)

![KQL results graph](screenshots/07b-kql-results-graph.png)

```kql
SecurityEvent
| where EventID == 4625
| project TimeGenerated, Account, IpAddress, LogonType
| order by TimeGenerated desc
```

### KQL Query 2 — Top Attacking IPs (after 24h)

![KQL after 24h](screenshots/08-kql-query2-after-24h.png)

![KQL top attackers barchart](screenshots/08b-kql-top-attackers-barchart.png)

```kql
SecurityEvent
| where EventID == 4625
| summarize Attempts = count() by IpAddress
| order by Attempts desc
| render barchart
```

### KQL Query 3 — Password Spray Detection

![Password Spray detection](screenshots/09-kql-password-spray-detection.png)

```kql
SecurityEvent
| where EventID == 4625
| summarize DistinctAccounts = dcount(Account), TotalAttempts = count() by IpAddress
| where DistinctAccounts > 5
| order by TotalAttempts desc
```

Password Spray = 1 IP targeting many different accounts with common passwords — harder to detect than brute force because it stays under lockout thresholds.

### Security Event Counts

![SecurityEvent count](screenshots/18b-metrics-security-events.png)

![Syslog count](screenshots/18c-metrics-syslog.png)

![Incidents count](screenshots/18d-metrics-incidents.png)

![Sentinel incidents list](screenshots/18e-sentinel-incidents-list.png)

| Metric | Count |
|---|---|
| **SecurityEvent (Windows)** | **50,534** |
| **Syslog (Linux)** | **26,730** |
| **SecurityAlert** | **246** |
| **SecurityIncident** | **246** |
| AzureNetworkAnalytics_CL | *(populating)* |

> **4,152 RDP login attempts** from **11 distinct IPs** targeting **247 different accounts** in under 24 hours.

### Attack Maps Before Hardening

**Windows RDP — SVR-CORPORATE:**

![RDP Attack Map](screenshots/19-attack-map-rdp-windows.png)

**Linux SSH — linux-vm:**

![Linux SSH Attack Map](screenshots/19b-attack-map-linux-ssh.png)

![Linux SSH Attack Map detail](screenshots/19c-attack-map-linux-ssh-detail.png)

**MSSQL — SQL Server (port 1433):**

![MSSQL Attack Map](screenshots/19d-attack-map-mssql.png)

---

## Phase 5 — Hardening (NIST SP 800-53)

### A — Re-enable Windows Firewall on SVR-CORPORATE

`Win+R` → `wf.msc` → Windows Defender Firewall Properties → Set all 3 profiles to **On**.

![Windows Firewall profiles](screenshots/20-hardening-windows-firewall-profiles.png)

![Windows Firewall turning on](screenshots/20b-hardening-windows-firewall-on.png)

![Windows Firewall done](screenshots/20c-hardening-windows-firewall-done.png)

---

### B — Re-enable Linux Firewall on linux-vm

![Linux SSH connect](screenshots/21-hardening-linux-ssh-connect.png)

![UFW commands](screenshots/21b-hardening-ufw-commands.png)

![UFW status](screenshots/21c-hardening-ufw-status.png)

```bash
sudo ufw enable
sudo ufw allow from <MY_IP> to any port 22
sudo ufw status verbose
```

---

### C — Lock Down NSG — SVR-CORPORATE *(SC-7 Boundary Protection)*

**Delete rule `DANGER_AllowAll`:**

![Delete DANGER rule](screenshots/22-hardening-nsg-delete-danger.png)

**Add restricted rule:**

![New NSG rule](screenshots/22b-hardening-nsg-new-rule.png)

| Field | Value |
|---|---|
| Source | IP Addresses — `88.188.66.199` (personal IP only) |
| Destination port | * |
| Protocol | Any |
| Action | Allow |
| Priority | 100 |
| Name | `Allow_My_IP_Only` |

**MSSQL restriction:**

![MSSQL NSG rule](screenshots/22c-hardening-nsg-mssql-rule.png)

---

### D — Lock Down NSG — linux-vm *(SC-7)*

![Linux NSG hardening](screenshots/23-hardening-nsg-linux-vm.png)

![Linux NSG rule](screenshots/23b-hardening-nsg-linux-rule.png)

![Allow My IP Linux](screenshots/23c-hardening-allow-my-ip.png)

Deleted `Danger_Allow` — added `Allow_My_IP_Only` restricting SSH port 22 to personal IP only.

---

### E — Disable Public Access — Key Vault *(SC-7, AC-3)*

![Key Vault disabled](screenshots/24-hardening-keyvault-disabled.png)

![Key Vault network settings](screenshots/24b-hardening-keyvault-network.png)

![Key Vault confirm](screenshots/24c-hardening-keyvault-confirm.png)

`kv-soclab-joe` → Networking → Public network access → **Disabled** → Save.

---

### F — Disable Public Access — Storage Account *(SC-7, AC-3)*

![Storage Account disabled](screenshots/25-hardening-storage-disabled.png)

`stsocjoe` → Networking → Public network access → **Disabled** → Proceed → Save.

---

## Phase 6 — Secured Environment for 24 Hours

![Timestamp after hardening](screenshots/26-timestamp-after-hardening.png)

![Timestamp after detail](screenshots/26b-timestamp-after-detail.png)

Left the hardened environment running for 24 hours without any changes. With NSGs locked to personal IP, firewalls active on all VMs, and public access disabled on Key Vault and Storage Account — virtually no external traffic reached the resources.

---

## Phase 7 — Metrics AFTER Hardening

![Metrics after security events](screenshots/27-metrics-after-security-events.png)

![Metrics after alerts](screenshots/27b-metrics-after-security-alerts.png)

![Metrics after incidents](screenshots/27c-metrics-after-incidents.png)

![Metrics after syslog](screenshots/27d-metrics-after-syslog.png)

**Attack maps after hardening — all returned zero results:**

![RDP map after](screenshots/27e-attack-map-rdp-after.png)

![SSH map after](screenshots/27f-attack-map-ssh-after.png)

![Incidents after hardening](screenshots/27g-incidents-after-hardening.png)

| Metric | Before Hardening | After Hardening | Change |
|---|---|---|---|
| SecurityEvent (Windows) | 50,534 | *(complete)* | ↓ |
| Syslog (Linux) | 26,730 | *(complete)* | ↓ |
| SecurityAlert | 246 | *(complete)* | ↓ |
| SecurityIncident | 246 | *(complete)* | ↓ |
| AzureNetworkAnalytics_CL | — | *(complete)* | — |

---

## Summary

A mini honeynet was built on Microsoft Azure. Both `SVR-CORPORATE` (Windows Server 2022 + SQL Server 2022) and `linux-vm` (Ubuntu 22.04) were intentionally exposed to the public internet with no firewall protection. Logs from both VMs, Key Vault `kv-soclab-joe`, and Storage Account `stsocjoe` were ingested into Log Analytics Workspace `law-soc-lab`.

Microsoft Sentinel automatically triggered **246 alerts** and created **246 incidents** in 24 hours, with **50,534 Windows security events** and **4,152 RDP brute-force attempts** from 11 IPs targeting 247 accounts.

Hardening measures aligned with **NIST SP 800-53** (SC-7, AC-17, AC-6) were then applied, eliminating virtually all external attack traffic in the following 24-hour window. Attack maps returned zero results after hardening.

---

## KQL Queries Reference

Full file: [`queries/all-queries.kql`](queries/all-queries.kql)

```kql
-- Time window
range x from 1 to 1 step 1 | project StartTime = ago(24h), StopTime = now()

-- SecurityEvent count
SecurityEvent | where TimeGenerated >= ago(24h) | count

-- Syslog count
Syslog | where TimeGenerated >= ago(24h) | count

-- Security Alerts
SecurityAlert
| where DisplayName !startswith "CUSTOM" and DisplayName !startswith "TEST"
| where TimeGenerated >= ago(24h) | count

-- Incidents
SecurityIncident | where TimeGenerated >= ago(24h) | count

-- NSG Malicious Flows
AzureNetworkAnalytics_CL
| where FlowType_s == "MaliciousFlow" and AllowedInFlows_d > 0
| where TimeGenerated >= ago(24h) | count

-- Top attacking IPs
SecurityEvent | where EventID == 4625
| summarize Attempts = count() by IpAddress
| order by Attempts desc | render barchart

-- Password Spray
SecurityEvent | where EventID == 4625
| summarize DistinctAccounts = dcount(Account), Total = count() by IpAddress
| where DistinctAccounts > 5 | order by Total desc
```

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
    ├── 00-architecture.png
    ├── 01-nsg-danger-allow-rule.png
    ├── 02-generate-test-events.png
    ├── 03-eventviewer-4625.png
    ├── 03b-eventviewer-4625-list.png
    ├── 04-log-analytics-workspace.png
    ├── 04b-law-creation.png
    ├── 05-sentinel-search-portal.png
    ├── 05b-sentinel-select-workspace.png
    ├── 05c-sentinel-dashboard.png
    ├── 06-data-connector-ama-setup.png
    ├── 06b-data-connector-windows.png
    ├── 06c-all-security-events-selected.png
    ├── 06d-data-connector-configured.png
    ├── 07-kql-query1-all-attacks.png
    ├── 07b-kql-results-graph.png
    ├── 08-kql-query2-after-24h.png
    ├── 08b-kql-top-attackers-barchart.png
    ├── 09-kql-password-spray-detection.png
    ├── 10-geoip-download.png
    ├── 10b-geoip-import-done.png
    ├── 10c-geoip-countries-query.png
    ├── 11-workbooks-list.png
    ├── 11b-workbook-editor.png
    ├── 11c-workbook-attack-map.png
    ├── 11d-all-workbooks-overview.png
    ├── 12-analytics-rules-import.png
    ├── 12b-analytics-rules-imported.png
    ├── 12c-analytics-rules-active-list.png
    ├── 13-linux-vm-creation.png
    ├── 13b-linux-vm-networking.png
    ├── 13c-linux-vm-deployed.png
    ├── 14-linux-ufw-disable.png
    ├── 15-sql-server-download.png
    ├── 15b-sql-server-install.png
    ├── 15c-sql-server-setup.png
    ├── 15d-sql-server-config.png
    ├── 15e-ssms-install.png
    ├── 15f-ssms-connection.png
    ├── 16-keyvault-diagnostic-setting.png
    ├── 16b-keyvault-auditlog-config.png
    ├── 17-storage-diagnostic-setting.png
    ├── 17b-storage-logs-config.png
    ├── 17c-storage-account-saved.png
    ├── 18-timestamp-before-hardening.png
    ├── 18b-metrics-security-events.png
    ├── 18c-metrics-syslog.png
    ├── 18d-metrics-incidents.png
    ├── 18e-sentinel-incidents-list.png
    ├── 19-attack-map-rdp-windows.png
    ├── 19b-attack-map-linux-ssh.png
    ├── 19c-attack-map-linux-ssh-detail.png
    ├── 19d-attack-map-mssql.png
    ├── 20-hardening-windows-firewall-profiles.png
    ├── 20b-hardening-windows-firewall-on.png
    ├── 20c-hardening-windows-firewall-done.png
    ├── 21-hardening-linux-ssh-connect.png
    ├── 21b-hardening-ufw-commands.png
    ├── 21c-hardening-ufw-status.png
    ├── 22-hardening-nsg-delete-danger.png
    ├── 22b-hardening-nsg-new-rule.png
    ├── 22c-hardening-nsg-mssql-rule.png
    ├── 23-hardening-nsg-linux-vm.png
    ├── 23b-hardening-nsg-linux-rule.png
    ├── 23c-hardening-allow-my-ip.png
    ├── 24-hardening-keyvault-disabled.png
    ├── 24b-hardening-keyvault-network.png
    ├── 24c-hardening-keyvault-confirm.png
    ├── 25-hardening-storage-disabled.png
    ├── 26-timestamp-after-hardening.png
    ├── 26b-timestamp-after-detail.png
    ├── 27-metrics-after-security-events.png
    ├── 27b-metrics-after-security-alerts.png
    ├── 27c-metrics-after-incidents.png
    ├── 27d-metrics-after-syslog.png
    ├── 27e-attack-map-rdp-after.png
    ├── 27f-attack-map-ssh-after.png
    └── 27g-incidents-after-hardening.png
```
