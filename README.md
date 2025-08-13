# Windows EventID Coverage Checker for Microsoft Sentinel

This script audits your **Microsoft Sentinel** scheduled analytics to find:
- Which **Windows Security EventIDs** your rules reference
- Whether those EventIDs are actually **ingested** (from `SecurityEvent` and/or `WindowsEvent`)
- A **full XPath** you can paste into a DCR to ingest all required EventIDs
- A consolidated view of **missing / present / ingested-but-unused** EventIDs
- Optional billed volume (in **MB**) for **ingested-but-unused** EventIDs over a chosen window

It’s designed to be low-risk and additive to your current workflow.

## What it checks

- Parses analytic rule queries (workspace or exported ARM templates)
- Detects EventIDs referenced in queries where the table is `SecurityEvent` or `WindowsEvent`
- Compares against what you’ve ingested (SecurityEvent-only, combined, or UNION over a lookback period)
- Prints:
  - Per-rule coverage (Present / Missing)
  - Consolidated lists
  - **Full DCR XPath** for all required EventIDs
  - Optional billable size (MB) for unused EventIDs

## Run it in Azure Cloud Shell (recommended)

1. Open **Azure Cloud Shell** (PowerShell).
2. Sign in (device code flow—no hardcoded tenant details):
   ```powershell
   Connect-AzAccount -UseDeviceAuthentication -TenantId <tenantId>
    ````

* Go to [https://microsoft.com/devicelogin](https://microsoft.com/devicelogin)
* Enter the device code shown in the shell
* Complete sign-in

3. Pick the subscription you want to scan:

   ```powershell
   Select-AzSubscription -SubscriptionId <subscriptionId>
   ```
4. Upload the script or create it in Cloud Shell:

   ```powershell
   nano windows_events_checker_plus.ps1
   ```

   Paste the script content, press `CTRL+O`, `Enter`, then `CTRL+X`.

## Quick start (autoCheck mode)

Minimal (SecurityEvent only, default 7-day lookback):

```powershell
./windows_events_checker_plus.ps1 `
  -useAutoCheck `
  -subscriptionId <subscriptionId> `
  -workspaceId <workspaceId> `
  -resourceGroupName <resourceGroupName> `
  -workspaceName <workspaceName>
```

SecurityEvent **+** WindowsEvent (separate queries, same lookback as `-timespan`):

```powershell
./windows_events_checker_plus.ps1 `
  -useAutoCheck `
  -subscriptionId <subscriptionId> `
  -workspaceId <workspaceId> `
  -resourceGroupName <resourceGroupName> `
  -workspaceName <workspaceName> `
  -CheckWindowsEvent
```

**UNION** of SecurityEvent + WindowsEvent over 90 days:

```powershell
./windows_events_checker_plus.ps1 `
  -useAutoCheck `
  -subscriptionId <subscriptionId> `
  -workspaceId <workspaceId> `
  -resourceGroupName <resourceGroupName> `
  -workspaceName <workspaceName> `
  -UseUnion `
  -UnionTimespan 90
```

Add billed volume table (MB) for **ingested-but-unused** EventIDs over the last 45 days:

```powershell
./windows_events_checker_plus.ps1 `
  -useAutoCheck `
  -subscriptionId <subscriptionId> `
  -workspaceId <workspaceId> `
  -resourceGroupName <resourceGroupName> `
  -workspaceName <workspaceName> `
  -UseUnion -UnionTimespan 90 `
  -UnusedVolumeDays 45
```

> Tip: All placeholders are **yours to fill** (`<tenantId>`, `<subscriptionId>`, `<workspaceId>`, `<resourceGroupName>`, `<workspaceName>`). Nothing is hardcoded.

## Parameters (core)

| Parameter            | Required              | Purpose                                                          |
| -------------------- | --------------------- | ---------------------------------------------------------------- |
| `-useAutoCheck`      | Yes (choose one mode) | Pulls rules directly from your workspace                         |
| `-useArmTemplates`   | Yes (choose one mode) | Scans exported rule templates from a folder                      |
| `-subscriptionId`    | Yes                   | Subscription GUID for the Sentinel workspace                     |
| `-workspaceId`       | Yes                   | Log Analytics Workspace ID (GUID)                                |
| `-resourceGroupName` | Yes (autoCheck)       | Resource group containing the workspace                          |
| `-workspaceName`     | Yes (autoCheck)       | Workspace name                                                   |
| `-timespan`          | No (default 7)        | Lookback (days) for SecurityEvent/WindowsEvent distinct EventIDs |
| `-CheckWindowsEvent` | No                    | Include `WindowsEvent` alongside `SecurityEvent`                 |
| `-UseUnion`          | No                    | UNION both tables across a separate window                       |
| `-UnionTimespan`     | No (default 90)       | UNION lookback (days)                                            |
| `-UnusedVolumeDays`  | No (default 30)       | Window (days) for billed volume (MB) of **unused** EventIDs      |

## Output at a glance

* **ASCII banner** (credits)
* **Per-rule** EventIDs (by **rule name**) and their **Present/Missing** coverage
* **Consolidated View**:

  * Needed & MISSING
  * Needed & PRESENT
  * Ingested but UNUSED
* **XPath**: a single expression that includes **all required EventIDs**
* **Billed Volume (MB)** for **ingested-but-unused** EventIDs over your chosen window

## Notes

* You need permissions to read Sentinel alert rules and run Log Analytics queries.
* The **XPath** targets the Security log channel (DCR mapping applies).
* Regex is intentionally conservative; sanity check EventIDs if you see false positives from complex lists.

If you want, I can also generate a starter `.gitignore` and commit scaffolding (license, sample screenshots folder, etc.).
```
