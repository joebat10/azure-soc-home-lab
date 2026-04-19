# Building a Live SOC + Honeynet in Azure

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

## Architecture

![Architecture](screenshots/00-architecture-schema.png)

**Resources — Resource Group `SOC-Lab-RG` | France Central:**

| Resource | Name | Role |
|---|---|---|
| Virtual Network | `soc-lab-vnet` | Shared network |
| Windows VM | `SVR-CORPORATE` | Honeypot — RDP + SQL Server |
| Linux VM | `linux-vm` | Honeypot — SSH |
| NSG | `SVR-CORPORATE-nsg` | Cloud firewall Windows VM |
| NSG | `linux-vm-nsg` | Cloud firewall Linux VM |
| Log Analytics Workspace | `law-soc-lab` | Central log database |
| Microsoft Sentinel | — | SIEM |
| Key Vault | `kv-soclab-joe` | Secret store |
| Storage Account | `stsocjoe` | Blob storage |

---

## Phase 1 — Deploy the Honeypot Infrastructure

### Windows VM — SVR-CORPORATE

Windows Server 2022 VM with SQL Server 2022 installed, intentionally exposed on RDP (3389) and MSSQL (1433).

**NSG rule added — honeypot phase:**

![NSG Danger Allow](screenshots/01-nsg-firewall-rules.png)

Rule `DANGER_AllowAll` at priority 100 — all inbound traffic from anywhere, on any port, allowed.

Windows Defender Firewall disabled via `wf.msc` on all 3 profiles (Domain, Private, Public).

### Linux VM — linux-vm

Ubuntu 22.04 LTS, SSH (port 22) exposed. Same VNet as SVR-CORPORATE.

Linux firewall disabled: `sudo ufw disable`

Same `DANGER_AllowAll` rule added to `linux-vm-nsg`.

---

## Phase 2 — Configure Microsoft Sentinel

### Log Analytics Workspace

![Log Analytics Workspace](screenshots/03-log-analytics-workspace.png)

Created `law-soc-lab` — the central database receiving all logs from all resources.

### Sentinel Activation

![Sentinel Activation](screenshots/04-sentinel-activation.png)

![Sentinel Add Workspace](screenshots/04b-sentinel-add-workspace.png)

Microsoft Sentinel deployed on top of `law-soc-lab`. It ingests logs, runs KQL-based detection rules, creates incidents, and displays attack maps.

### Data Connector — Windows Security Events

![Data Connector AMA](screenshots/05-data-connector-ama.png)

![All Security Events](screenshots/05b-all-security-events.png)

Connected `SVR-CORPORATE` via AMA. Collecting **All Security Events** — includes EventID 4625 (failed logins).

### Data Connector — Linux Syslog

Connected `linux-vm` via Syslog connector collecting `LOG_AUTH` and `LOG_AUTHPRIV`. This captures failed SSH attempts — the Linux equivalent of Windows EventID 4625.

### GeoIP Watchlist

![GeoIP Import](screenshots/09-geoip-watchlist-import.png)

Uploaded `geoip-summarized.csv` (~54,000 IP ranges with GPS coordinates) as a Sentinel Watchlist. Used by all attack map workbooks to geolocate attackers on a world map.

### Attack Map Workbooks

![Workbooks](screenshots/10-workbooks-sentinel.png)

![All Workbooks](screenshots/10b-all-workbooks.png)

Imported 4 Azure Workbooks from the [`workbooks/`](workbooks/) folder:

| Workbook | What it monitors |
|---|---|
| `windows-rdp-auth-fail.json` | RDP brute-force on SVR-CORPORATE |
| `linux-ssh-auth-fail.json` | SSH brute-force on linux-vm |
| `mssql-auth-fail.json` | SQL Server login failures (port 1433) |
| `nsg-malicious-allowed-in.json` | Malicious traffic allowed by NSGs |

---

## Phase 3 — Honeynet Exposed for 24 Hours

![Start Time Before](screenshots/11-timestamp-before-hardening.png)

Left both VMs fully exposed with no changes for 24 hours. Automated bots discovered the VMs within minutes and started RDP, SSH, and MSSQL brute-force attacks continuously.

---

## Phase 4 — Metrics BEFORE Hardening

### KQL Detection Queries

**Query 1 — All failed logins (EventID 4625):**

![KQL Attacks](screenshots/06-kql-query1-attacks.png)

![KQL Graph](screenshots/06b-kql-results-graph.png)

**Query 2 — Top attacking IPs:**

![Top Attackers](screenshots/07-kql-top-attackers-ip.png)

**Query 3 — Password Spray detection:**

![Password Spray](screenshots/08-kql-password-spray.png)

### Security Event Counts

![SecurityEvent](screenshots/12-metrics-security-events.png)

![Syslog](screenshots/12b-metrics-syslog.png)

![Incidents Before](screenshots/12c-incidents-before-hardening.png)

| Metric | Count |
|---|---|
| SecurityEvent (Windows) | **50,534** |
| Syslog (Linux) | **26,730** |
| SecurityAlert | **246** |
| SecurityIncident | **246** |
| AzureNetworkAnalytics_CL | *(populating)* |

> **Notable:** 4,152 RDP login attempts from **11 distinct IPs** targeting **247 different accounts** in under 24 hours.

### Attack Maps Before Hardening

**Windows RDP — SVR-CORPORATE:**

![RDP Attack Map](screenshots/13-attack-map-rdp-windows.png)

**Linux SSH — linux-vm:**

![Linux SSH Attack Map](screenshots/14-attack-map-linux-ssh.png)

**MSSQL — SQL Server:**

![MSSQL Attack Map](screenshots/15-attack-map-mssql.png)

---

## Phase 5 — Hardening (NIST SP 800-53)

### A — Re-enable Windows Firewall — SVR-CORPORATE

![Windows Firewall](screenshots/16-hardening-firewall-windows.png)

`Win+R` → `wf.msc` → Domain + Private + Public profiles → **On** → Apply.

### B — Re-enable Linux Firewall — linux-vm

![Linux SSH](screenshots/17-hardening-ssh-linux-vm.png)

![UFW Commands](screenshots/17b-hardening-ufw-commands.png)

```bash
sudo ufw enable
sudo ufw allow from <MY_IP> to any port 22
sudo ufw status verbose
```

### C — Lock Down NSG — SVR-CORPORATE

![Delete DANGER rule](screenshots/18-hardening-nsg-delete-danger-rule.png)

Deleted rule `DANGER_AllowAll`.

![New NSG rule](screenshots/18b-hardening-nsg-new-rule.png)

Added `Allow_My_IP_Only` — personal IP `88.188.66.199` only, priority 100.

![MSSQL rule](screenshots/18c-hardening-nsg-mssql-rule.png)

Additional rule restricting MSSQL (1433) to personal IP only.

### D — Lock Down NSG — linux-vm

![Linux NSG](screenshots/19-hardening-nsg-linux-vm.png)

![Allow My IP Linux](screenshots/19b-hardening-nsg-allow-my-ip.png)

Deleted `Danger_Allow` — added `Allow_My_IP_Only` (SSH port 22, personal IP only, priority 100).

### E — Disable Public Access — Key Vault

![Key Vault Disabled](screenshots/20-hardening-keyvault-disabled.png)

`kv-soclab-joe` → Networking → Public network access → **Disabled** → Save.

### F — Disable Public Access — Storage Account

![Storage Disabled](screenshots/20b-hardening-storage-disabled.png)

`stsocjoe` → Networking → Public network access → **Disabled** → Proceed → Save.

---

## Phase 6 — Secured Environment for 24 Hours

![Start Time After](screenshots/21-timestamp-after-hardening.png)

Left the hardened environment running 24 hours. With NSGs locked to personal IP, firewalls active, and public access disabled — no external traffic reached the resources.

---

## Phase 7 — Metrics AFTER Hardening

![Metrics After](screenshots/22-metrics-after-security-events.png)

**Attack maps after hardening — no results returned:**

![RDP After](screenshots/23-attack-map-rdp-after.png)

![SSH After](screenshots/24-attack-map-ssh-after.png)

![Incidents After](screenshots/25-incidents-after-hardening.png)

| Metric | Before | After | Change |
|---|---|---|---|
| SecurityEvent (Windows) | 50,534 | *(complete after 24h)* | ↓ |
| Syslog (Linux) | 26,730 | *(complete after 24h)* | ↓ |
| SecurityAlert | 246 | *(complete after 24h)* | ↓ |
| SecurityIncident | 246 | *(complete after 24h)* | ↓ |
| AzureNetworkAnalytics_CL | — | *(complete after 24h)* | — |

---

## Summary

A mini honeynet was built on Microsoft Azure. Logs from `SVR-CORPORATE` (Windows Server + SQL Server 2022), `linux-vm` (Ubuntu 22.04), `kv-soclab-joe`, and `stsocjoe` were ingested into `law-soc-lab`. Microsoft Sentinel triggered 246 alerts and created 246 incidents automatically in 24 hours.

After hardening with NIST SP 800-53 controls (SC-7 boundary protection, AC-17 remote access, AC-6 least privilege), attack maps returned zero results and event volumes dropped significantly.

---

## KQL Queries

Full file: [`queries/all-queries.kql`](queries/all-queries.kql)

```kql
SecurityEvent | where TimeGenerated >= ago(24h) | count
Syslog | where TimeGenerated >= ago(24h) | count
SecurityAlert | where DisplayName !startswith "CUSTOM" | where TimeGenerated >= ago(24h) | count
SecurityIncident | where TimeGenerated >= ago(24h) | count
SecurityEvent | where EventID == 4625
| summarize Attempts = count() by IpAddress | order by Attempts desc | render barchart
SecurityEvent | where EventID == 4625
| summarize DistinctAccounts = dcount(Account), Total = count() by IpAddress
| where DistinctAccounts > 5 | order by Total desc
```
