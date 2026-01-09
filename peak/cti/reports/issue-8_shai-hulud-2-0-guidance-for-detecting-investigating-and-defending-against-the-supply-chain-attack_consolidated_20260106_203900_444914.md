# Shai-Hulud 2.0: Guidance for detecting, investigating, and defending against the supply chain attack

## 📋 Report Metadata

**Issue:** [#8](https://github.com/apps-dfir/Security-Operations/issues/8)<br>
**Analyst:** Apramey 'Apps' Shurpali<br>
**Generated:** 2026-01-06 20:39:00 UTC<br>
**Sources Processed:** 1<br>
**OCR Enabled:** Yes

## 📚 Sources

1. [Shai-Hulud 2.0: Guidance for detecting, investigating, and defending against the supply chain attack](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/)

## 📊 Report Summary

**Total Unique IOCs:** 19<br>
**High Confidence IOCs:** 14<br>
**MITRE ATT&CK Techniques:** 8<br>
**Images with OCR Data:** 7<br>
**Previously Seen IOCs:** 5<br>
**Breakdown:** URLs: 1, Domains: 15, Commands: 3

## 🔄 Previously Seen IOCs

> The following IOCs were found in previous reports. This may indicate shared infrastructure, ongoing campaigns, or related threat activity.

| IOC | Type | Previous Reports |
|-----|------|------------------|
| `Node[.]js` | DOMAINS | [#1: Unit42 Blogs](../../issues/1), [#3: Multiple Threat Actors Exploit React2Shell (CVE-2025-55182)](../../issues/3), [#6: CISA-PDF Reports & Links](../../issues/6) |
| `bun[.]exe` | DOMAINS | [#1: Unit42 Blogs](../../issues/1) |
| `cmd[.]exe` | DOMAINS | [#1: Unit42 Blogs](../../issues/1), [#3: Multiple Threat Actors Exploit React2Shell (CVE-2025-55182)](../../issues/3) |
| `node[.]exe` | DOMAINS | [#1: Unit42 Blogs](../../issues/1), [#3: Multiple Threat Actors Exploit React2Shell (CVE-2025-55182)](../../issues/3) |
| `package[.]json` | DOMAINS | [#3: Multiple Threat Actors Exploit React2Shell (CVE-2025-55182)](../../issues/3) |

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

- 🟢 `hxxps://bun[.]sh/install` [[1]](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/)

### Domains

- 🟢 `Runner[.]Listener` [[1]](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/)
- 🟢 `bun[.]sh` [[1]](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/)
- 🟢 `hint[.]strategy` [[1]](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/)
- 🟢 `left[.]SourceNodeId` [[1]](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/)
- 🟢 `left[.]TargetNodeId` [[1]](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/)
- 🟢 `left[.]identityNodeId` [[1]](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/)
- 🟢 `reddit[.]com` [[1]](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/)
- 🟢 `right[.]NodeId` [[1]](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/)
- 🟢 `right[.]identityNodeId` [[1]](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/)
- 🟢 `sha1hulud-scan[.]sh` [[1]](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/)
- 🔴 `Node[.]js` *(Seen 4x: Issue #1, #3, #6)* [[1]](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/)
- 🔴 `bun[.]exe` *(Seen 2x: Issue #1)* [[1]](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/)
- 🔴 `cmd[.]exe` *(Seen 3x: Issue #1, #3)* [[1]](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/)
- 🔴 `node[.]exe` *(Seen 3x: Issue #1, #3)* [[1]](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/)
- 🔴 `package[.]json` *(Seen 2x: Issue #3)* [[1]](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/)

### Command Lines

🟢 Command:
```
DeviceProcessEvents | where FileName has_any ("bash","Runner.Listener","cmd.exe") | where ProcessCommandLine has 'SHA1HULUD' and not (ProcessCommandLine has_any('malicious','grep','egrep',"checknpm","sha1hulud-checker-ado","sha1hulud-checker-ado"," sha1hulud-checker-github","sha1hulud-checker","sha1hulud-scanner","go-detector","SHA1HULUD_IMMEDIATE_ACTIONS.md","SHA1HULUD_COMPREHENSIVE_REPORT.md","reddit.com","sha1hulud-scan.sh"))
```
Sources: [[1]](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/)

🟢 Command:
```
or (ProcessCommandLine in~ ("sh", "dash", "bash") and ProcessCommandLine has_any ("which bun", ".bashrc && echo $PATH", "https://bun.sh/install"))
```
Sources: [[1]](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/)

🟢 Command:
```
| where  (ProcessCommandLine has "--name SHA1HULUD" ) or (ParentProcessName == "node" and (ProcessName == "bash" or ProcessName == "dash" or ProcessName == "sh") and ProcessCommandLine has "curl -fsSL https://bun.sh/install | bash")
```
Sources: [[1]](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/)

## 🎯 MITRE ATT&CK Techniques

| Technique | Sources |
|-----------|---------|
| T1059.007: JavaScript | [1](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/) |
| T1213.003: Code Repositories | [1](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/) |
| T1485: Data Destruction | [1](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/) |
| T1589.001: Credentials | [1](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/) |
| T1592.002: Software | [1](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/) |
| T1593.001: Social Media | [1](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/) |
| T1593.003: Code Repositories | [1](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/) |
| T1656: Impersonation | [1](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/) |

## 📄 Source Details

> Expand each source for detailed information extracted from that article.

<details>
<summary><strong>Source 1: Shai-Hulud 2.0: Guidance for detecting, investigating, and defending against the supply chain attack</strong></summary>

**URL:** https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/

**IOCs from this source:** 19<br>
**MITRE techniques:** 8

**Excerpt:**
> The Shai‑Hulud 2.0 supply chain attack represents one of the most significant cloud-native ecosystem compromises observed recently. Attackers maliciously modified hundreds of publicly available packages, targeting developer environments, continuous integration and continuous delivery (CI/CD) pipelines, and cloud-connected workloads to harvest credentials and configuration secrets. The Shai‑Hulud 2.0 campaign builds on earlier supply chain compromises but introduces more automation, faster propag...

</details>

## 🔍 OCR Extracted Content

> Images extracted from source documents with OCR text. Click to expand each image.

<details>
<summary><strong>Image 1</strong> from shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack</summary>

**View Image:** [url_img_001_112fec798b78.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_001_112fec798b78.png)

**Extracted Text:**
> = Microsoft

</details>

<details>
<summary><strong>Image 4</strong> from shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack</summary>

**View Image:** [url_img_004_e08ec60f65e5.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_004_e08ec60f65e5.png)

**Extracted Text:**
> —  aoaa'

</details>

<details>
<summary><strong>Image 5</strong> from shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack</summary>

**View Image:** [url_img_005_ee68bb40b40e.webp](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_005_ee68bb40b40e.webp)

**IOCs Found:**
- `bun.sh`
- `runner.listener`

**Extracted Text:**
> (7) 7"  Initial  access  tl  Execution  cr  Execution  Credential access  S  Exfiltration  1. Compromised npm package executes node setup_bun.js.  2. setup_bun,js looks for Bun runtime installation presence. If not present, a benign Bun executable is installed using PowerShell command powershell -c “irm bun.sh/install.ps1|iex" or Curl command curl -fsSL hxxps[://]bun[.]sh/install.  3. Bun executes a malicious bundled file bun_environment.js.  & bun_environment.js downloads and installs GitHub Ac...

</details>

<details>
<summary><strong>Image 6</strong> from shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack</summary>

**View Image:** [url_img_006_8addf9dac57e.webp](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_006_8addf9dac57e.webp)

**Extracted Text:**
> @ noc8yzpdii4sjwe957 vic © wach  ° coione (BEBE) sou  T7254. 2weeks 292 ©  @ =  torvalds Linus Torvalds On  and, OR  a  ¥ Fok @® |) sw @  Sha1-Hulud: The Second Coming.  Ae Aetiviy Yr Ostars © Owatching ¥ Oforks  Report repository  Releases  Norelaces publhed  Packages  No packages published  Contributors 2  Q osm  @ sores ns onus

</details>

<details>
<summary><strong>Image 7</strong> from shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack</summary>

**View Image:** [url_img_007_7f7af2d2f063.webp](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_007_7f7af2d2f063.webp)

**Extracted Text:**
> Home > Microsoft Defender for Cloud | Recommendations > Containers running in Azure should not include compromised packages  “W open query = View recommendation for al resources  High controller Risk level © Resource  Recommendation owner % Suggested:   initat Access Read more Drive-by Compromise (11189)  exploit Public-Facing Applicaton (11190) Show more  Controller details Controller name sample-deployment Pod sample-pod-abcl23 Image details, Image URI  Digest sha2Siabedet234867690 mage tags...

</details>

<details>
<summary><strong>Image 8</strong> from shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack</summary>

**View Image:** [url_img_008_e96c2f47f4b4.webp](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_008_e96c2f47f4b4.webp)

**Extracted Text:**
> Home > Microsoft Defender for Cloud | Recommendations >  GitHub repositories should have Shai-Hulud 2.0 compromised packages findings resolved  ‘V open query Y 2 View recommendation for all resources  High & 0 Unassigned Risk level © Resource Status Description  This repository contains dependencies linked to the Shai-Hulud  2. 0 supply chain attack. which actively harvests CI/CD credentials and self-  propagates to downstream projects. To prevent system compromise, immediately remove the malici...

</details>

<details>
<summary><strong>Image 10</strong> from shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack</summary>

**View Image:** [url_img_010_04b9d5a1844a.webp](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_010_04b9d5a1844a.webp)

**Extracted Text:**
> P. Search resources, services, and docs (6+/)  Home > Microsoft Defender for Cloud  Microsoft Defender for Cloud | Cloud Security Explorer ~ x  + e + Sowing 4 subscriptions  << @ Sharequay lnk £ Download csv report Guides Feecback CY Debug pane V  « \ General  * © oveniew Sv  4 sup ax  = Recommendations  What would you  Templates  ‘Attack path analysis WW cearal 7  Security alerts  Inventory [name VY] tauals ~ [@accordprojectrtemplate-e... |x Remove  Cloud Security Explorer  Workbooks [vesion Vi...

</details>

**OCR Summary:** 7 images processed with text extracted

---

*Generated by PEAK CTI v3.0 Multi-Source Consolidated Report*
*2026-01-06 20:39:00 UTC*