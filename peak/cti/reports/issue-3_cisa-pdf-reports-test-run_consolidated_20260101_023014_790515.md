# CISA PDF Reports - Test Run

## 📋 Report Metadata

**Issue:** [#3](https://github.com/apps-dfir/Security-Operations/issues/3)<br>
**Analyst:** Apramey 'Apps' Shurpali<br>
**Generated:** 2026-01-01 02:30:14 UTC<br>
**Sources Processed:** 3<br>
**OCR Enabled:** Yes

## 🔄 Common Indicators (Seen in Previous Reports)

> These IOCs have been observed in previous PEAK CTI reports, indicating potential threat actor overlap or shared infrastructure.

### Domains

| IOC | Seen Count | Previous Reports |
|-----|------------|------------------|
| `System[.]Net` | 2 | [Unit42 Blogs - URL Test Run](https://github.com/apps-dfir/Security-Operations/issues/1) |
| `ntdsutil[.]exe` | 2 | [Unit42 Blogs - URL Test Run](https://github.com/apps-dfir/Security-Operations/issues/1) |
| `powershell[.]exe` | 2 | [Unit42 Blogs - URL Test Run](https://github.com/apps-dfir/Security-Operations/issues/1) |
| `rundll32[.]exe` | 2 | [Unit42 Blogs - URL Test Run](https://github.com/apps-dfir/Security-Operations/issues/1) |

### Summary

- **Total Common IOCs:** 4
- **High Prevalence (3+ reports):** 0

## 📚 Sources

1. [CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
2. [aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
3. [aa25-163a-ransomware-simplehelp-rmm-compromise.pdf](inputs/aa25-163a-ransomware-simplehelp-rmm-compromise.pdf)

## 📊 Report Summary

**Total Unique IOCs:** 351<br>
**High Confidence IOCs:** 330<br>
**MITRE ATT&CK Techniques:** 48<br>
**Images with OCR Data:** 52<br>
**Breakdown:** CVEs: 6, URLs: 20, Domains: 243, IPs: 65, SHA256: 9, SHA1: 3, MD5: 3, Paths: 2

## Executive Summary (Analyst Fill-In)

### Key Takeaways
- What happened (1-2 bullets)
- Who/what is affected (orgs, sectors, regions)
- Why it matters to us (risk / exposure / priority)

### Initial Assessment
- Confidence level: (low/med/high)
- Recommended actions: (monitor / hunt / block / brief)

## 🔍 Consolidated Indicators of Compromise

> IOCs are deduplicated across sources. Confidence: 🟢 HIGH | 🟡 MEDIUM | 🔴 LOW

### CVEs

- 🟢 `CVE-2020-12641` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `CVE-2020-35730` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `CVE-2021-44026` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `CVE-2023-23397` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `CVE-2023-38831` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `CVE-2024-57727` [[3]](inputs/aa25-163a-ransomware-simplehelp-rmm-compromise.pdf)

### URLs

- 🟢 `hxxp://localhost:8080` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `hxxps://aka[.]ms/CVE-2023-23397ScriptDoc` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `hxxps://blogs[.]microsoft[.]com/on-the-issues/2022/06/22/defending-ukraine-early-lessons-from-the` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `hxxps://cert[.]gov[.]ua/article/6276894` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `hxxps://cert[.]ssi[.]gouv[.]fr/cti/CERTFR-2023-CTI-009` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `hxxps://cert[.]ssi[.]gouv[.]fr/cti/CERTFR-2025-CTI-007` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `hxxps://github[.]com/Neo23x0/signature-base/blob/master/yara/gen_impacket_tools[.]yar` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `hxxps://go[.]recordedfuture[.]com/hubfs/reports/CTA-RU-2024-0530[.]pdf` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `hxxps://media[.]defense[.]gov/2021/Feb/25/2002588479/-1` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `hxxps://media[.]defense[.]gov/2021/Jul/01/2002753896/-1` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `hxxps://media[.]defense[.]gov/2022/Jun/22/2003021689/-1` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `hxxps://media[.]defense[.]gov/2023/Oct/05/2003314578/-1` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `hxxps://media[.]defense[.]gov/2024/Feb/27/2003400753/-1/-1/0/CSA-Russian-Actors-Use-Routers` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `hxxps://media[.]defense[.]gov/2024/Jul/31/2003515137/-1` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `hxxps://news[.]sophos[.]com/en-us/2025/05/27/dragonforce-actors-target-simplehelp` [[3]](inputs/aa25-163a-ransomware-simplehelp-rmm-compromise.pdf)
- 🟢 `hxxps://pages[.]nist[.]gov/800-63` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `hxxps://securityintelligence[.]com/x-force/itg05-ops-leverage-israel-hamas-conflict-lures-to-deliver` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `hxxps://simple-help[.]com/allversions` [[3]](inputs/aa25-163a-ransomware-simplehelp-rmm-compromise.pdf)
- 🟢 `hxxps://www[.]justice[.]gov/archives/opa/pr/justice-department-conducts-court-authorized` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `hxxps://www[.]wojsko-polskie[.]pl/woc/articles/aktualnosci-w/detecting-malicious-activity-against` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)

### Domains

- 🟢 `000[.]pe` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `1cooldns[.]com` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `42web[.]io` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `4cloud[.]click` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `4ginfosource[.]com` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `Address[.]IPAddressToString` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `Authorizev[.]site` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `Computeryrati[.]site` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `Contemteny[.]site` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `Cryptography[.]DataProtectionScope` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `DC3[.]DCISE` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `DC3[.]Information` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `Dilemmadu[.]site` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `Fanlumpactiras[.]pw` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `Faulteyotk[.]site` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `Forbidstow[.]site` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `Fragnantbui[.]shop` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `Freckletropsao[.]pw` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `Get-GPPPassword[.]py` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `Goalyfeastz[.]site` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `Hemispheredodnkkl[.]pw` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `Medicinebuckerrysa[.]pw` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `Mockbin[.]org` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `Musclefarelongea[.]pw` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `Musicallyageop[.]pw` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `NTDS[.]dit` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `Opposezmny[.]site` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `Ownerbuffersuperw[.]pw` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `Password[.]Length` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `Pinkipinevazzey[.]pw` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `Prefixes[.]Add` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `Request[.]RemoteEndPoint` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `Seallysl[.]site` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `Servicedny[.]site` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `System[.]Net` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `System[.]Security` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `Tirechinecarpet[.]pw` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `Webhook[.]site` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `accesscan[.]org` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `advennture[.]top` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `aka[.]ms` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `alfathdoor[.]com` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `ashoke[.]kumar` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `bfv[.]bund` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `bhpcapital[.]com` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `bis[.]cz` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `blast-hubs[.]com` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `blastikcn[.]com` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `blogs[.]microsoft` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `bnd[.]bund` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `bplanka[.]com` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `bsi[.]bund` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `bugildbett[.]top` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `bumbleshrimp[.]com` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `calc[.]war` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `calmingtefxtures[.]run` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `camdvr[.]org` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `casacam[.]net` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `castmaxw[.]run` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `cert[.]gov` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `cert[.]incident` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `cert[.]ssi` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `changeaie[.]top` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `cisa[.]gov` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf) [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf) [[3]](inputs/aa25-163a-ransomware-simplehelp-rmm-compromise.pdf)
- 🟢 `citydisco[.]bet` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `citywand[.]live` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `cjlaspcorne[.]icu` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `clarmodq[.]top` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `climatologfy[.]top` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `coastalareabank[.]com` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `collapimga[.]fun` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `cosmicgold469[.]co` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `cryptography[.]protectdata` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `cyber[.]gc` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `cyber[.]gov` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `cyber[.]int` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `cyber[.]nsa` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `cyber[.]threats` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `ddnsfree[.]com` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `ddnsgeek[.]com` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `ddnsguru[.]com` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `decreaserid[.]world` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `drawzhotdog[.]shop` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `dsfljsdfjewf[.]info` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `dynuddns[.]com` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `dynuddns[.]net` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `earthsymphzony[.]today` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `easyfwdr[.]digital` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `email[.]cz` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `equatorf[.]run` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `esccapewz[.]run` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `featureccus[.]shop` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `ferromny[.]digital` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `foresctwhispers[.]top` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `franch1[.]lanka` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `free[.]nf` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `freeddns[.]org` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `frge[.]io` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `friendseforever[.]help` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `furthert[.]run` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `galxnetb[.]today` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `generalmills[.]pro` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `ghostreedmnu[.]shop` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `github[.]com` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `glize[.]com` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `go[.]recordedfuture` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `goldenloaduae[.]com` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `gouv[.]fr` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `governoagoal[.]pw` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `great-site[.]net` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `gutterydhowi[.]shop` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `hbclife[.]in` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `hemispherexz[.]top` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `holidamyup[.]today` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `hoyoverse[.]blog` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `htardwarehu[.]icu` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `infinityfreeapp[.]com` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `ironloxp[.]live` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `jawdedmirror[.]run` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `jowinjoinery[.]icu` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `jrxsafer[.]top` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `kesug[.]com` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `latchclan[.]shop` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `latitudert[.]live` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `ldap-dump[.]py` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `legenassedk[.]top` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `liftally[.]top` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `lonfgshadow[.]live` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `longitudde[.]digital` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `loseyourip[.]com` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `lovestoblog[.]com` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `mail-online[.]dk` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `media[.]defense` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `mercharena[.]biz` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `metalsyo[.]digital` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `mockbin[.]io` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `mocky[.]io` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `mrodularmall[.]top` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `msn[.]com` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `mybiolink[.]io` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `mysynology[.]net` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `mywire[.]org` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `naturewsounds[.]help` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `navstarx[.]shop` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `ncsc[.]gov` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `nestlecompany[.]pro` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `news[.]sophos` [[3]](inputs/aa25-163a-ransomware-simplehelp-rmm-compromise.pdf)
- 🟢 `ngrok[.]io` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `nighetwhisper[.]top` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `nsa[.]gov` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `nukib[.]gov` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `offensivedzvju[.]shop` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `ooguy[.]com` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `oreheatq[.]live` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `os[.]popen` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `owlflright[.]digital` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `pages[.]nist` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `paleboreei[.]biz` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `pasteflawwed[.]world` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `penetratebatt[.]pw` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `pepperiop[.]digital` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `pipedream[.]net` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `piratetwrath[.]run` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `plantainklj[.]run` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `polskie[.]pl` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `pomelohgj[.]top` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `portugalmail[.]pt` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `puerrogfh[.]live` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `quavabvc[.]top` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `quietswtreams[.]life` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `quilltayle[.]live` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `rambutanvcx[.]run` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `regencyservice[.]in` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `reinforcenh[.]shop` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `reliabledmwqj[.]shop` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `rf[.]gd` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `ria[.]ee` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `rodformi[.]run` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `salaccgfa[.]top` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `scenarisacri[.]top` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `securityintelligence[.]com` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `seizedsentec[.]online` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `seznam[.]cz` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `shiningrstars[.]help` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `sighbtseeing[.]shop` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `simple-help[.]com` [[3]](inputs/aa25-163a-ransomware-simplehelp-rmm-compromise.pdf)
- 🟢 `skw[.]gov` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `smeltingt[.]run` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `sp800-63b[.]html` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `spacedbv[.]world` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `ssi[.]gouv` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `starcloc[.]bet` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `starofliught[.]top` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `starrynsightsky[.]icu` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `steelixr[.]live` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `stogeneratmns[.]shop` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `stormlegue[.]com` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `strawpeasaen[.]fun` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `targett[.]top` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `touvrlane[.]bet` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `tracnquilforest[.]life` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `travewlio[.]shop` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `triplooqp[.]world` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `tsc-me[.]com` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `ukwwfze[.]com` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `urlbae[.]com` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `us[.]af` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `valisluureamet[.]ee` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `vanadrink[.]com` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `vikram[.]anand` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `vozmeatillu[.]shop` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `wallkedsleeoi[.]shop` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `webhookapp[.]com` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `webredirect[.]org` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `weldorae[.]digital` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `wizzsolutions[.]com` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `wuaze[.]com` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `www[.]justice` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `www[.]wojsko` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `xayfarer[.]live` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `ywmedici[.]top` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `zestmodp[.]top` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🔴 `21[.]PDF` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🔴 `22[.]PDF` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🔴 `ADExplorer[.]exe` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🔴 `CLEAR[.]PDF` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🔴 `CTA-RU-2024-0530[.]pdf` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🔴 `LummaC2[.]exe` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🔴 `Roadmap[.]zip` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🔴 `Zeyilname[.]zip` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🔴 `aaa[.]exe` [[3]](inputs/aa25-163a-ransomware-simplehelp-rmm-compromise.pdf)
- 🔴 `bbb[.]exe` [[3]](inputs/aa25-163a-ransomware-simplehelp-rmm-compromise.pdf)
- 🔴 `edge[.]exe` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🔴 `iphlpapi[.]dll` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🔴 `msedge[.]exe` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🔴 `ntdsutil[.]exe` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🔴 `powershell[.]exe` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🔴 `rund1132[.]exe` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🔴 `rundll32[.]exe` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🔴 `serverconfig[.]xml` [[3]](inputs/aa25-163a-ransomware-simplehelp-rmm-compromise.pdf)
- 🔴 `serviceconfig[.]xml` [[3]](inputs/aa25-163a-ransomware-simplehelp-rmm-compromise.pdf)
- 🔴 `war[.]zip` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🔴 `winhttp[.]dll` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)

### IP Addresses

- 🟢 `103[.]97[.]203[.]29` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `109[.]95[.]151[.]207` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `124[.]168[.]91[.]178` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `138[.]199[.]59[.]43` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `147[.]135[.]209[.]245` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `159[.]196[.]128[.]120` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `162[.]210[.]194[.]2` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `178[.]235[.]191[.]182` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `178[.]37[.]97[.]243` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `185[.]234[.]235[.]69` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `192[.]162[.]174[.]67` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `192[.]162[.]174[.]94` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `194[.]126[.]178[.]8` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `194[.]187[.]180[.]20` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `207[.]244[.]71[.]84` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `209[.]14[.]71[.]127` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `212[.]127[.]78[.]170` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `213[.]134[.]184[.]167` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `213[.]32[.]252[.]221` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `31[.]135[.]199[.]145` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `31[.]42[.]4[.]138` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `46[.]112[.]70[.]252` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `46[.]248[.]185[.]236` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `64[.]176[.]67[.]117` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `64[.]176[.]69[.]196` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `64[.]176[.]70[.]18` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `64[.]176[.]70[.]238` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `64[.]176[.]71[.]201` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `70[.]34[.]242[.]220` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `70[.]34[.]243[.]226` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `70[.]34[.]244[.]100` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `70[.]34[.]245[.]215` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `70[.]34[.]252[.]168` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `70[.]34[.]252[.]186` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `70[.]34[.]252[.]222` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `70[.]34[.]253[.]13` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `70[.]34[.]253[.]247` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `70[.]34[.]254[.]245` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `79[.]184[.]25[.]198` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `79[.]185[.]5[.]142` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `83[.]10[.]46[.]174` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `83[.]168[.]66[.]145` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `83[.]168[.]78[.]27` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `83[.]168[.]78[.]31` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `83[.]168[.]78[.]55` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `83[.]23[.]130[.]49` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `83[.]29[.]138[.]115` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `89[.]64[.]70[.]69` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `90[.]156[.]4[.]204` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `91[.]149[.]202[.]215` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `91[.]149[.]203[.]73` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `91[.]149[.]219[.]158` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `91[.]149[.]219[.]23` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `91[.]149[.]223[.]130` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `91[.]149[.]253[.]118` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `91[.]149[.]253[.]198` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `91[.]149[.]253[.]20` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `91[.]149[.]253[.]204` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `91[.]149[.]254[.]75` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `91[.]149[.]255[.]122` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `91[.]149[.]255[.]19` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `91[.]149[.]255[.]195` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `91[.]221[.]88[.]76` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `93[.]105[.]185[.]139` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `95[.]215[.]76[.]209` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)

### File Hashes

**SHA256:**
- 🟢 `19CC41A0A056E503CC2137E19E952814FBDF14F8D83F799AEA9B96ABFF11EFBB` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `2F31D00FEEFE181F2D8B69033B382462FF19C35367753E6906ED80F815A7924F` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `325daeb781f3416a383343820064c8e98f2e31753cd71d76a886fe0dbb4fe59a` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `4D74F8E12FF69318BE5EB383B4E56178817E84E83D3607213160276A7328AB5D` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `76e4962b8ccd2e6fd6972d9c3264ccb6738ddb16066588dfcb223222aaa88f3c` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `7a35008a1a1ae3d093703c3a34a21993409af42eb61161aad1b6ae4afa8bbb70` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `a9e9d7770ff948bb65c0db24431f75dd934a803181afa22b6b014fac9a162dab` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `b287c0bc239b434b90eef01bcbd00ff48192b7cbeb540e568b8cdcdc26f90959` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `ca47c8710c4ffb4908a42bd986b14cddcca39e30bb0b11ed5ca16fe8922a468b` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)

**SHA1:**
- 🟢 `1239288A5876C09D9F0A67BCFD645735168A7C80` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `3B267FA5E1D1B18411C22E97B367258986E871E5` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `B66DA4280C6D72ADCC68330F6BD793DF56A853CB` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)

**MD5:**
- 🟢 `4AFDC05708B8B39C82E60ABE3ACE55DB` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `C7610AE28655D6C1BCE88B5D09624FEF` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)
- 🟢 `E05DF8EE759E2C955ACC8D8A47A08F42` [[2]](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf)

### Windows Paths

- 🟢 `C:\Windows\system32\ntdsutil.exe` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)
- 🟢 `C:\temp\[a-z]{3` [[1]](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf)

## 🎯 MITRE ATT&CK Techniques

| Technique | Sources |
|-----------|---------|
| T1012: Query Registry | [2](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf) |
| T1021.001: Remote Desktop Protocol | [3](inputs/aa25-163a-ransomware-simplehelp-rmm-compromise.pdf) |
| T1021: Remote Services | [3](inputs/aa25-163a-ransomware-simplehelp-rmm-compromise.pdf) |
| T1027: Obfuscated Files or Information | [2](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf) |
| T1036: Masquerading | [2](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf) |
| T1056: Input Capture | [1](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf) |
| T1059.003: Command and Scripting Interpreter | [1](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf) |
| T1059.005: Command and Scripting Interpreter | [1](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf) |
| T1059: Command and Scripting Interpreter | [1](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf) |
| T1071.001: Application Layer Protocol | [2](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf) |
| T1076: Remote Desktop Protocol | [3](inputs/aa25-163a-ransomware-simplehelp-rmm-compromise.pdf) |
| T1082: System Information Discovery | [2](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf) |
| T1090.003: Proxy | [1](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf) |
| T1104: Multi-Stage Channels | [1](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf) |
| T1105: Ingress Tool Transfer | [2](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf) |
| T1106: Native API | [2](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf) |
| T1110.001: Brute Force | [1](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf) |
| T1110.003: Brute Force | [1](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf) |
| T1111: Multi-Factor Authentication Interception | [1](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf) |
| T1114: Email Collection | [1](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf) |
| T1119: Automated Collection | [2](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf) |
| T1133: External Remote Services | [1](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf) |
| T1140: Deobfuscate/Decode Files or Information | [2](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf) |
| T1176.001: Browser Extensions | [2](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf) |
| T1187: Forced Authentication | [1](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf) |
| T1190: Exploit Public-Facing Application | [1](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf) |
| T1192: Spearphishing Link | [2](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf) |
| T1199: Trusted Relationship | [1](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf) |
| T1204.001: User Execution | [1](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf) |
| T1204.002: User Execution | [1](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf) |
| T1217: Browser Information Discovery | [2](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf) |
| T1566.001: Phishing | [1](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf), [2](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf) |
| T1566.002: Phishing | [1](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf), [2](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf) |
| T1566: Phishing | [1](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf), [2](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf) |
| T1573: Encrypted Channel | [1](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf) |
| T1584.008: Network Devices | [2](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf) |
| T1586.002: Compromise Accounts | [1](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf) |
| T1586.003: Compromise Accounts | [1](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf) |
| T1588.006: Vulnerabilities | [2](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf), [3](inputs/aa25-163a-ransomware-simplehelp-rmm-compromise.pdf) |
| T1589.002: Gather Victim Identity Information | [1](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf) |
| T1591.002: Gather Victim Org Information | [1](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf) |
| T1591.004: Gather Victim Org Information | [1](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf) |
| T1591: Gather Victim Org Information | [1](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf) |
| T1598.003: Spearphishing Link | [2](inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf) |
| T1627.001:  | [1](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf) |
| T1627:  | [1](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf) |
| T1659: Content Injection | [1](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf) |
| T1665: Hide Infrastructure | [1](inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf) |

## 📄 Source Details

> Expand each source for detailed information extracted from that article.

<details>
<summary><strong>Source 1: CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf</strong></summary>

**URL:** inputs/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf

**IOCs from this source:** 208<br>
**MITRE techniques:** 30

**Excerpt:**
> Joint Cybersecurity Ad visory TLP:CLEAR Russian GRU Targeting Western Logistics Entities and Technology Companies Executive Summary This joint cybersecurity advisory (CSA) highlights a Russian state-sponsored cyber campaign targeting Western logistics entities and technology companies. This includes those involved in the coordination, transport, and delivery of foreign assistance to Ukraine. Since 2022, Western logistics entities and IT companies have faced an elevated risk of targeting by the R...

</details>

<details>
<summary><strong>Source 2: aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf</strong></summary>

**URL:** inputs/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf

**IOCs from this source:** 135<br>
**MITRE techniques:** 18

**Excerpt:**
> TLP:CLEAR Co-Authored by: Product ID: AA25-141B May 21, 2025 Threat Actors Deploy LummaC2 Malware to Exfiltrate Sensitive Data from Organizations Summary The Federal Bureau of Investigation (FBI) and the Cybersecurity and Infrastructure Security Agency (CISA) are releasing this joint advisory to disseminate known tactics, techniques, and procedures (TTPs) and indicators of compromise (IOCs) associated with threat actors deploying the LummaC2 information stealer (infostealer) malware. LummaC2 mal...

</details>

<details>
<summary><strong>Source 3: aa25-163a-ransomware-simplehelp-rmm-compromise.pdf</strong></summary>

**URL:** inputs/aa25-163a-ransomware-simplehelp-rmm-compromise.pdf

**IOCs from this source:** 10<br>
**MITRE techniques:** 4

**Excerpt:**
> TLP:CLEAR Co-Authored by: Product ID: AA25-163A June 12, 2025 Ransomware Actors Exploit Unpatched SimpleHelp Remote Monitoring and Management to Compromise Utility Billing Software Provider Summary The Cybersecurity and Infrastructure Security Agency (CISA) is releasing this advisory in response to ransomware actors leveraging unpatched instances of a vulnerability in SimpleHelp Remote Monitoring and Management (RMM) to compromise customers of a utility billing software provider. This incident r...

</details>

## 🔍 OCR Extracted Content

> Images extracted from source documents with OCR text. Click to expand each image.

<details>
<summary><strong>Page 1</strong> from CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf</summary>

**View Image:** [CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_001.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_001.png)

**Extracted Text:**
> Joint Cybersecurity Advisory  TLP:CLEAR  National Cyber Ww) BEE nae B ee Centre WY BND Informationstechnik  putt of GHO  Bundesamt fur Verfassungsschutz  qustRALIAN [el] Semmpiastonsseaurty contr cola sous des wh  SIGNALS oe Establishment Canada t6lécommunications Canada Fi + DANISH DEFENCE Canadian Centre Centre canadien ae for Cyber Security pour la cybersdeurité aoe’ INTELLIGENCE SERVICE  ‘Australian Signals Directorate  Ex #8 Estonian Foreign REPUBLIQUE Intelligence Service FRANCAISE Eealité...

</details>

<details>
<summary><strong>Page 2</strong> from CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf</summary>

**View Image:** [CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_002.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_002.png)

**Extracted Text:**
> Russian GRU  geting Western Logistics Entities and Technology Companies  TLP:CLEAR  This cyber espionage-oriented campaign targeting logistics entities and technology companies uses a mix of previously disclosed TTPs and is likely connected to these actors’ wide scale targeting of IP cameras in Ukraine and bordering NATO nations.  The following authors and co-sealers are releasing this CSA:  e United States National Security Agency (NSA)  e United States Federal Bureau of Investigation (FBI)  e...

</details>

<details>
<summary><strong>Page 3</strong> from CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf</summary>

**View Image:** [CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_003.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_003.png)

**Extracted Text:**
> Russian GRU geting Western Logistics Entities and Technology Companies  TLP:CLEAR  Introduction  For over two years, the Russian GRU 85'" GTsSS, military unit 26165—commonly known in the cybersecurity community as APT28, Fancy Bear, Forest Blizzard, BlueDelta, and a variety of other identifiers—has conducted this campaign using a mix of known tactics, techniques, and procedures (TTPs), including reconstituted password spraying capabilities, spearphishing, and modification of Microsoft Exchange m...

</details>

<details>
<summary><strong>Page 4</strong> from CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf</summary>

**View Image:** [CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_004.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_004.png)

**Extracted Text:**
> Russian GRU geting Western Logistics Entities and Technology Companies  TLP:CLEAR  ties to the primary target, exploiting trust relationships to attempt to gain additional access [T1199].  The actors also conducted reconnaissance on at least one entity involved in the production of industrial control system (ICS) components for railway management, though a successful compromise was not confirmed [TA0043].  The countries with targeted entities include the following, as illustrated in Figure 1:  e...

</details>

<details>
<summary><strong>Page 5</strong> from CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf</summary>

**View Image:** [CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_005.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_005.png)

**IOCs Found:**
- `msn.com`

**Extracted Text:**
> Russian GRU geting Western Logistics Entities and Technology Companies  TLP:CLEAR  The actors abused vulnerabilities associated with a range of brands and models of small office/home office (SOHO) devices to facilitate covert cyber operations, as well as proxy malicious activity via devices with geolocation in proximity to the target [T1665].  [2]  Credential Guessing/Brute Force  Unit 26165 actors’ credential guessing [T1110.001] operations in this campaign exhibit some similar characteristics...

</details>

<details>
<summary><strong>Page 6</strong> from CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf</summary>

**View Image:** [CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_006.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_006.png)

**Extracted Text:**
> Russian GRU Targeting Western Logistics Entities and Technology Companies  TLP:CLEAR  e Dynu  e Mocky  e Pipedream  e Mockbin[.Jorg  The actors also used spearphishing to deliver malware (including HEADLACE and MASEPIE) executables [T1204.002] delivered via third-party services and redirectors T1566.002], scripts in a mix of languages [T1059] (including BAT [T1059.003] and VBScript [T1059.005)) and links to hosted shortcuts [T1204.001].  CVE Usage  Throughout this campaign, GRU unit 26165 weapon...

</details>

<details>
<summary><strong>Page 7</strong> from CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf</summary>

**View Image:** [CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_007.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_007.png)

**IOCs Found:**
- `ntdsutil.exe`
- `ntds.dit`
- `adexplorer.exe`
- `get-gpppassword.py`
- `idap-dump.py`

**Extracted Text:**
> Russian GRU geting Western Logistics Entities and Technology Companies  TLP:CLEAR  Directory NTDS.dit domain databases [T1003.003] using native Active Directory Domain Services commands, such as in Figure 2: Example Active Directory Domain Services command:  C:\Windows \system32\ntdsutil.exe “activate instance ntds" ifm "create full C:\temp\[a-z]{3}" quit quit  Figure 2: Example Active Directory Domain Services command Additionally, GRU unit 26165 actors used the tools Certipy and ADExplorer.exe...

</details>

<details>
<summary><strong>Page 8</strong> from CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf</summary>

**View Image:** [CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_008.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_008.png)

**Extracted Text:**
> Russian GRU geting Western Logistics Entities and Technology Companies  TLP:CLEAR  e travel route, and ¢ cargo contents.  In at least one instance, the actors attempted to use voice phishing [T1566.004] to gain access to privileged accounts by impersonating IT staff.  Malware  Unit 26165’s use of malware in this campaign ranged from gaining initial access to establishing persistence and exfiltrating data. In some cases, the attack chain resulted in multiple pieces of malware being deployed in su...

</details>

<details>
<summary><strong>Page 9</strong> from CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf</summary>

**View Image:** [CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_009.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_009.png)

**Extracted Text:**
> Russian GRU geting Western Logistics Entities and Technology Companies  TLP:CLEAR  instances, the actors used periodic EWS queries [T1119] to collect new emails sent and received since the last data exfiltration [T1029]. The actors typically used infrastructure in close geographic proximity to the victim. Long gaps between exfiltration, the use of trusted and legitimate protocols, and the use of local infrastructure allowed for long-term collection of sensitive data to go undetected.  Connection...

</details>

<details>
<summary><strong>Page 10</strong> from CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf</summary>

**View Image:** [CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_010.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_010.png)

**Extracted Text:**
> Russian GRU geting Western Logistics Entities and Technology Companies  TLP:CLEAR  Successful RTSP 200 OK responses contained a snapshot of the IP camera's image and IP camera metadata such as video codec, resolution, and other properties depending on the IP camera's configuration.  From a sample available to the authoring agencies of over 10,000 cameras targeted via this effort, the geographic distribution of victims showed a strong focus on cameras in Ukraine and border countries, as shown in...

</details>

<details>
<summary><strong>Page 11</strong> from CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf</summary>

**View Image:** [CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_011.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_011.png)

**Extracted Text:**
> Russian GRU geting Western Logistics Entities and Technology Companies  TLP:CLEAR  e Utilize endpoint, detection, and response (EDR) and other cybersecurity solutions on all systems, prioritizing high value systems with large amounts of sensitive data such as mail servers and domain controllers [D3-PM] first.  = Perform threat and attack modeling to understand how sensitive systems may be compromised within an organization’s specific architecture and security controls. Use this to develop a moni...

</details>

<details>
<summary><strong>Page 12</strong> from CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf</summary>

**View Image:** [CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_012.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_012.png)

**Extracted Text:**
> Russian GRU Targeting Western Logistics Entities and Technology Companies  TLP:CLEAR  investigation. Most organizations should not need to allow incoming traffic, especially logins to systems, from VPN services [D3-NAM].  e Educate users to only use approved corporate systems for relevant government and military business and avoid the use of personal accounts on cloud email providers to conduct official business. Network administrators should also audit both email and web request logs to detect...

</details>

<details>
<summary><strong>Page 13</strong> from CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf</summary>

**View Image:** [CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_013.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_013.png)

**Extracted Text:**
> Russian GRU geting Western Logistics Entities and Technology Companies  TLP:CLEAR  e Implement other mitigations for privileged accounts: including limiting the number of admin accounts, considering using hardware MFA tokens, and regularly reviewing all privileged user accounts [D3-JFAPA].  e Separate privileged accounts by role and alert on misuse of privileged accounts [D3- UAP]. For example, email administrator accounts should be different from domain administrator accounts.  e Reduce relianc...

</details>

<details>
<summary><strong>Page 14</strong> from CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf</summary>

**View Image:** [CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_014.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_014.png)

**Extracted Text:**
> Russian GRU geting Western Logistics Entities and Technology Companies  TLP:CLEAR  e Ensure IP cameras are currently supported. Replace devices that are out of support.  e Apply security patches and firmware updates to all IP cameras [D3-SU].  e Disable remote access to the IP camera, if unnecessary [D3-ITF].  e Ensure cameras are protected by a security appliance, if possible, such as by using a firewall to prevent communication with the camera from IP addresses not on an allowlist [D3-NAM].  e...

</details>

<details>
<summary><strong>Page 15</strong> from CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf</summary>

**View Image:** [CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_015.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_015.png)

**Extracted Text:**
> Russian GRU geting Western Logistics Entities and Technology Companies  TLP:CLEAR  e wevtutil — A legitimate Windows executable used by threat actors to delete event logs  e vssadmin —A legitimate Windows executable possibly used by threat actors to make a copy of the server's C: drive  e ADexplorer — A legitimate window executable to view, edit, and backup Active Directory Certificate Services  e OpenSSH — The Windows version of a legitimate open source SSH client  e schtasks — A legitimate Win...

</details>

<details>
<summary><strong>Page 16</strong> from CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf</summary>

**View Image:** [CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_016.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_016.png)

**IOCs Found:**
- `ntdsutil.exe`
- `m.salim`
- `ashoke.kumar`
- `edge.exe`
- `vikram.anand`
- `franch1.lanka`
- `get-gpppassword.py`
- `idap-dump.py`

**Extracted Text:**
> Russian GRU Targeting Western Logistics Entities and Technology Companies  TLP:CLEAR  Malicious scripts  e Certipy — An open source python tool for enumerating and abusing Active Directory Certificate Services  e Get-GPPPassword.py — An open source python script for finding insecure passwords stored in Group Policy Preferences  e Idap-dump.py — A script for enumerating user accounts and other information in Active Directory  e Hikvision backdoor string: “YWRtaW46MTEk”  Suspicious command lines...

</details>

<details>
<summary><strong>Page 17</strong> from CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf</summary>

**View Image:** [CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_017.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_017.png)

**IOCs Found:**
- `war.zip`
- `roadmap.zip`
- `zeyilname.zip`
- `calc.war`

**Extracted Text:**
> Russian GRU geting Western Logistics Entities and Technology Companies  TLP:CLEAR  Commonly Used Webmail Providers  e portugalmaill.]pt e  mail-online[.Jdk e email[.Jcz  e seznam[.Jcz  Malicious Archive Filenames Involving CVE-2023-38831  e  calc.war.zip  e news_week_6.zip  e Roadmap.zip  e¢ SEDE-PV-2023-10-09-1_EN.zip e war.zip  e Zeyilname.zip  Brute Forcing IP Addresses Disclaimer: These IP addresses date June 2024 through August 2024. The authoring  agencies recommend organizations investiga...

</details>

<details>
<summary><strong>Page 18</strong> from CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf</summary>

**View Image:** [CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_018.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_018.png)

**IOCs Found:**
- `system.net`
- `address.ipaddresstostring`
- `prefixes.add`
- `request.remoteendpoint`
- `powershell.exe`

**Extracted Text:**
> Russian GRU eting Western Logistics Entities and Technology Companies  TLP:CLEAR  Detections  Customized NTLM listener  rule APT28_NTLM_LISTENER { meta:  description = "Detects NTLM listeners including APT28's custom one"  strings:  $command_1 = "start-process powershell.exe -WindowStyle hidden"  $command_2 = "New-Object System.Net .HttpListener”  "Prefixes.Add('http://localhost :8080/')"  $command_3  -match ‘Authorization GetValues( ‘Authorization’ )" $command_6 = "Request.RemoteEndPoint.Addres...

</details>

<details>
<summary><strong>Page 19</strong> from CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf</summary>

**View Image:** [CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_019.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_019.png)

**IOCs Found:**
- `password.length`
- `msedge.exe`

**Extracted Text:**
> Russian GRU Targeting Western Logistics Entities and Technology Companies  TLP:CLEAR  HEADLACE shortcut  rule APT28_HEADLACE SHORTCUT { meta:  description = "Detects the HEADLACE backdoor shortcut dropper. Rule is meant for threat hunting."  strings: $type = "[InternetShortcut]" ascii nocase $url = "file://" $edge = "msedge.exe" $icon = "IconFile" condition: all of them  HEADLACE credential dialogbox phishing  rule APT28_HEADLACE_CREDENTIALDIALOG {  meta: description = "Detects scripts used by A...

</details>

<details>
<summary><strong>Page 20</strong> from CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf</summary>

**View Image:** [CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_020.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_020.png)

**IOCs Found:**
- `msedge.exe`

**Extracted Text:**
> Russian GRU Targeting Western Logistics Entities and Technology Companies  TLP:CLEAR  HEADLACE core script  rule APT28_HEADLACE_CORE { meta:  description = "Detects HEADLACE core batch scripts"  strings: $chcp = "chcp 65001" ascii $headless = "start \"\" msedge --headless=new --disable-gpu" ascii $command_1 = "taskkill /im msedge.exe /f" ascii $command_2 = “whoami>\"%programdata%" ascii  $command_3 timeout" ascii  $command_4 = "copy \"%programdata%\\" ascii  $non_generic_del_1 = "del /q /f \"%pr...

</details>

<details>
<summary><strong>Page 21</strong> from CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf</summary>

**View Image:** [CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_021.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_021.png)

**IOCs Found:**
- `cryptography.protectdata`
- `system.security`

**Extracted Text:**
> Russian GRU Targeting Western Logistics Entities and Technology Companies  TLP:CLEAR  MASEPIE  rule APT28_MASEPIE { meta:  description = "Detects MASEPIE python script"  strings: $masepie_unique_1 = "os. popen( 'whoami').read()"  $masepie_unique_2 lif message == ‘check'"  $masepie_unique_3 = “elif message == ‘send_file':" $masepie_unique_4 = “elif message == ‘get_file'" $masepie_unique_5 = “enc_mes(‘ok'" $masepie_unique_6 = "Bad command! '.encode(‘ascii'" $masepie_unique_7 = "{user}{SEPARATOR}{k...

</details>

<details>
<summary><strong>Page 22</strong> from CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf</summary>

**View Image:** [CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_022.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_022.png)

**Extracted Text:**
> Russian GRU Targeting Western Logistics Entities and Technology Companies  TLP:CLEAR PSEXEC rule GENERIC_PSEXEC { meta: description = "Detects SysInternals PSEXEC executable" strings: $sysinternals_1 = "SYSINTERNALS SOFTWARE LICENCE TERMS” $sysinternals_2 /accepteula" $sysinternals_3 = "Software\\Sysinternals” $network_1 = "\\\\%s\\IPC$" $network_2 \\\\%s \\ADMING \ \%s" $network_3 = "\\Device\\LanmanRedirector\\%s\\ipc$" $psexec_1 = "PSEXESVC" $psexec_2 = "PSEXEC-{}-" $psexec_3 = "Copying %s to...

</details>

<details>
<summary><strong>Page 23</strong> from CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf</summary>

**View Image:** [CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_023.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_023.png)

**IOCs Found:**
- `github.com`
- `uoo158036-21.pdf`
- `gouv.fr`
- `www.wojsko`
- `polskie.pl`
- `media.defense`
- `aka.ms`
- `blogs.microsoft`
- `cert.ssi`

**Extracted Text:**
> Russian GRU geting Western Logistics Entities and Technology Companies  TLP:CLEAR  Cybersecurity Industry Tracking  The cybersecurity industry provides overlapping cyber threat intelligence, |OCs, and mitigation recommendations related to GRU unit 26165 cyber actors. While not all encompassing, the following are the most notable threat group names related under MITRE ATT&CK G0007 and commonly used within the cybersecurity community:  ° APT28 [14]  e Fancy Bear [14]  e Forest Blizzard [14] e Blue...

</details>

<details>
<summary><strong>Page 24</strong> from CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf</summary>

**View Image:** [CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_024.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_024.png)

**IOCs Found:**
- `tlp-clear.pdf`
- `cert.gov`
- `uoo17091520.pdf`
- `sp800-63b.html`
- `www.justice`
- `go.recordedfuture`
- `uoo115131-21.pdf`
- `securityintelligence.com`
- `pages.nist`
- `media.defense`

**Extracted Text:**
> Russian GRU Targeting Western Logistics Entities and Technology Companies  TLP:CLEAR  7] IBM. Israel-Hamas Conflict Lures to Deliver Headlace Malware. 2023. https://securityintelligence.com/x-force/itg05-ops-leverage-israel-hamas-conflict-lures-to-deliver- headlace-malware/  8] CERT-UA. APT28: From Initial Attack to Creating Domain Controller Threats in an Hour. 2023. https://cert.gov.ua/article/6276894  9] NSA. Embracing a Zero Trust Security Model. 2021. https://media.defense.gov/2021/Feb/25/2...

</details>

<details>
<summary><strong>Page 25</strong> from CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf</summary>

**View Image:** [CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_025.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_025.png)

**IOCs Found:**
- `cisa.gov`
- `nukib.gov`
- `cyber.threats`
- `ssi.qouv`
- `cyber.gov`
- `cyber.int`
- `bfv.bund`
- `skw.gov`
- `cyber.gc`
- `us.af`

**Extracted Text:**
> Russian GRU Targeting Western Logistics Entities and Technology Companies  TLP:CLEAR  Contact  United States organizations  e National Security Agency (NSA)  Cybersecurity Report Feedback: CybersecurityReports@nsa.gov Defense Industrial Base Inquiries and Cybersecurity Services: DIB_Defense@cyber.nsa.gov  Media Inquiries / Press Desk: NSA Media Relations: 443-634-0721, MediaRelations@nsa.gov  «Cybersecurity and Infrastructure Security Agency (CISA) and Federal Bureau of Investigation (FBI) U.S....

</details>

<details>
<summary><strong>Page 26</strong> from CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf</summary>

**View Image:** [CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_026.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_026.png)

**Extracted Text:**
> Russian GRU Targeting Western Logistics Entities and Technology Companies  TLP:CLEAR  Appendix A: MITRE ATT&CK tactics and techniques  See Table 2 through Table 14 for all the threat actor tactics and techniques referenced  in this advisory.  Table 2: Reconnaissance  Tactic/Technique Title ID Use Conducted reconnaissance on at least one entity Reconnaissance TA0043 involved in the production of ICS components for railway management. Gather Victim Identity T1589.002 Conducted contact information...

</details>

<details>
<summary><strong>Page 27</strong> from CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf</summary>

**View Image:** [CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_027.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_027.png)

**Extracted Text:**
> Russian GRU Targeting Western Logistics Entities and Technology Companies  TLP:CLEAR Tactic/Technique Title ID Use Exploit Public-Facing Exploited public vulnerabilities and SQL injection to gain 1 T1190 Par my Application — initial access to targeted entities. Content Injection T1659 Leveraged a WinRAR vulnerability allowing for the —— execution of arbitrary code embedded in an archive. Table 5: Execution Tactic/Technique Title ID Use User Execution: Malicious Link | T1204.001 Used malicious li...

</details>

<details>
<summary><strong>Page 28</strong> from CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf</summary>

**View Image:** [CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_028.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_028.png)

**IOCs Found:**
- `idap-dump.py`
- `ntds.dit`
- `get-gpppassword.py`

**Extracted Text:**
> Russian GRU Targeting Western Logistics Entities and Technology Companies  Table 8: Credential access  TLP:CLEAR  Tactic/Technique Title ID Use Sent requests with Base64-encoded credentials for the Brute Force T1110 RTSP server, which included publicly documented —=— default credentials, and likely were generic attempts to brute force access to the devices. Brute Force: Password T1110,001 Used credential guessing to gain initial access to Guessing —————=_| targeted entities. Brute Force: Passwor...

</details>

<details>
<summary><strong>Page 29</strong> from CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf</summary>

**View Image:** [CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_029.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_029.png)

**Extracted Text:**
> Russian GRU Targeting Western Logistics Entities and Technology Companies  Table 12: Lateral movement  TLP:CLEAR  Tactic/Technique Title ID Use Used native commands and open source tools, such as Lateral Movement TAO008 Impacket and PsExec, to move laterally within the environment. REMISLS SENTESSE ETE 71021.001 | Moved laterally within the network using RDP. Desktop Protocol Table 13: Collection Tactic/Technique Title ID Use Email Collection 71114 Retrieved sensitive data from email servers. Em...

</details>

<details>
<summary><strong>Page 30</strong> from CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf</summary>

**View Image:** [CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_030.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_030.png)

**Extracted Text:**
> Russian GRU Targeting Western Logistics Entities and Technology Companies  TLP:CLEAR  Appendix B: CVEs exploited Table 15: Exploited CVE information  CVE Vendor/Product Detai  Allows execution of arbitrary code when a user attempts to view a benign file within a ZIP archive. External actors could send specially crafted emails that cause a connection from the victim to an untrusted location of the actor’s control, leaking the Net-NTLMv2 hash of the victim that the actor could then relay to anothe...

</details>

<details>
<summary><strong>Page 31</strong> from CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf</summary>

**View Image:** [CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_031.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_031.png)

**Extracted Text:**
> Russian GRU Targeting Western Logistics Entities and Technology Companies  TLP:CLEAR  Appendix C: MITRE D3FEND Countermeasures  Table 16: MITRE D3FEND countermeasures  Countermeasure Title ID Detai  Employ appropriate network segmentation. Disable Universal Plug and Play (UPnP), Peer-to-Peer (P2P), and Anonymous Visit features on IP cameras and routers.  Limit access and utilize additional attributes (Such as device information, environment, and access path) when Access Mediation D3-AMED | makin...

</details>

<details>
<summary><strong>Page 32</strong> from CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf</summary>

**View Image:** [CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_032.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_032.png)

**Extracted Text:**
> Russian GRU T  geting Western Logistics Entities and Technology Companies  TLP:CLEAR  Network Access Mediation  D3-NAM  Do not allow incoming traffic, especially logins to systems, from public VPN services. Where possible, logins from public VPNs, including exit nodes in the same country as target systems, should be blocked or, if allowed, alerted on for further investigation. Ensure cameras and other Internet of Things devices are protected by a security appliance, if possible.  DNS Denylisting...

</details>

<details>
<summary><strong>Page 33</strong> from CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf</summary>

**View Image:** [CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_033.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/CSA_RUSSIAN_GRU_TARGET_LOGISTICS_page_033.png)

**Extracted Text:**
> Russian GRU geting Western Logistics Entities and Technology Companies  TLP:CLEAR  Review all authentication activity for remote access to User Behavior Analysis D3-UBA make sure it is valid and expected. Investigate any unexpected or unusual activity.  UIO0/157019-25 | PP-25-2107 | May 2025 Ver. 1.0 TLP:CLEAR} 33

</details>

<details>
<summary><strong>Page 1</strong> from aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf</summary>

**View Image:** [aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations_page_001.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations_page_001.png)

**IOCs Found:**
- `cisa.gov`

**Extracted Text:**
> JOINT  CYBERSECURITY  ADVISORY s aa ? TLP:CLEAR  Co-Authored by: ID: AA25-141B May 21, 2025  Threat Actors Deploy LummaC2 Malware to Exfiltrate Sensitive Data from Organizations  Summary  The Federal Bureau of Investigation (FBI) and the Cybersecurity and Infrastructure Security Agency (CISA) are releasing this joint advisory to disseminate known tactics, techniques, and procedures (TTPs) and indicators of compromise (IOCs) associated with threat actors deploying the LummaC2 information stealer...

</details>

<details>
<summary><strong>Page 2</strong> from aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf</summary>

**View Image:** [aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations_page_002.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations_page_002.png)

**Extracted Text:**
> CYBERSECURITY ADVISORY  TLP:CLEAR) FBI | CISA  Overview  LummaC2 malware first appeared for sale on multiple Russian-language speaking cybercriminal forums in 2022. Threat actors frequently use spearphishing hyperlinks and attachments to deploy LummaC2 malware payloads [T1566.001, T1566.002]. Additionally, threat actors rely on unsuspecting users to execute the payload by clicking a fake Completely Automated Public Turing Test to tell Computers and Humans Apart (CAPTCHA). The CAPTCHA contains in...

</details>

<details>
<summary><strong>Page 3</strong> from aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf</summary>

**View Image:** [aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations_page_003.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations_page_003.png)

**IOCs Found:**
- `pinkipinevazzey.pw`
- `119.0.0.0`

**Extracted Text:**
> CYBERSECURITY ADVISORY  TLP:CLEAR) FBI | CISA  Do you want to run a malware ? , (Crypt build to disable this message)  Figure 2. Message Box  If the user selects No, the malware will exit. If the user selects Yes, the malware will move on to its next routine, which decrypts its callback Command and Control (C2) domains [T1140]. A list of observed domains is included in the Indicators of Compromise section.  After each domain is decoded, the implant will attempt a POST request [T107 1.001] (see F...

</details>

<details>
<summary><strong>Page 4</strong> from aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf</summary>

**View Image:** [aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations_page_004.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations_page_004.png)

**IOCs Found:**
- `pinkipinevazzey.pw`
- `119.0.0.0`

**Extracted Text:**
> CYBERSECURITY ADVISORY  TLP:CLEAR) FBI | CISA  ffer); 406C7 ) xBO9406C7) ¢  Figure 5. User and Computer Name Check  The hashing routine was not identified as a standard algorithm; however, it is a simple routine that converts a Unicode string to a 32-bit hexadecimal value.  If the username hash is equal to the value @x56CF7626, then the computer name is queried. If the computer name queried is seven characters long, then the name is hashed and checked against the hard- coded value of @xB@94@6C7....

</details>

<details>
<summary><strong>Page 5</strong> from aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf</summary>

**View Image:** [aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations_page_005.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations_page_005.png)

**Extracted Text:**
> CYBERSECURITY ADVISOR  TLP:CLEAR) FBI | CISA  700447DF3 mov 100447DE5 lea 100447DEB sub , O447DFE mov [espt17B0h+1pDst], eax :00447E01 mov 100447E05 call  ecx  Figure 8. Parsing of ¢ JSON Value C2 Instructions  Each array object that contains the JSON key value of t will be evaluated as a command opcode, resulting in the C2 instructions in the subsections below.  1. Opcode @ - Steal Data Generic  This command allows five fields to be defined when stealing data, offering the most flexibility. The...

</details>

<details>
<summary><strong>Page 6</strong> from aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf</summary>

**View Image:** [aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations_page_006.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations_page_006.png)

**IOCs Found:**
- `rund1132.exe`
- `pund1132.exe`

**Extracted Text:**
> CYBERSECURITY ADVISOR  TLP:CLEAR) FBI | CISA  3. Opcode 2 - Steal Browser Data (Mozilla)  This command is identical to Opcode 1; however, this option seems to be utilized solely for Mozilla browser data (see Table 3).  Table 3. Opcode 2 Options  p Path to steal from  Zz Name of Browser - Output  4. Opcode 3 - Download a File  This command contains three options: a URL, file extension, and execution type. The configuration can specify a remote file with u to download and create the extension spec...

</details>

<details>
<summary><strong>Page 7</strong> from aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf</summary>

**View Image:** [aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations_page_007.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations_page_007.png)

**IOCs Found:**
- `cmd.exe`

**Extracted Text:**
> CYBERSECURITY ADVISORY  TLP:CLEAR) FBI | CISA  6. Delete Self  If the configuration JSON file has a key of “ad” and its value is “true,” the malware will enter a routine to delete itself.  The command shown in Figure 9 will be decoded and executed for self-deletion.  cmd.exe /c timeout /nobreak /t 3 & fsutil file setZeroData offset=0 length=%lu \"%s\" & erase \"%s\" & exit  Figure 9. Self-Deletion Command Line  Figure 10 depicts the above command line during execution.  Figure 10. Decoded Comman...

</details>

<details>
<summary><strong>Page 8</strong> from aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf</summary>

**View Image:** [aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations_page_008.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations_page_008.png)

**IOCs Found:**
- `profile.info`
- `places.sqlite`
- `lummac2.exe`
- `cookies.aqlite`
- `dp.txt`
- `key4.db`
- `cert9.db`
- `c7610ae28655d6c1bce88b5d09624fef`

**Extracted Text:**
> CYBERSECURITY ADVISOR  TLP:CLEAR) FBI | CISA  \Local Extension Settings\ /Extensions/  History  Login Data  Login Data For Account  History  Web Data  Network\Cookies  \Local Storage\leveldb  /BrowserDB  \Local State  dp.txt  Slocalappdata’\ Packages  microsoft .windowscommunicationsapps* \LocalState\Indexed\LiveComm  Mail Clients\Standart Win 10 Mail Slocalappdatas\Microsoft\Windows Mail\Local Folders Mail Clients\Standart Win 10 Mail AlternativePath appdata’\Thunderbird\ Profiles Thunderbird...

</details>

<details>
<summary><strong>Page 9</strong> from aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf</summary>

**View Image:** [aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations_page_009.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations_page_009.png)

**IOCs Found:**
- `4d74f8e12ff69318be5eb383b4e56178817e84e83d3607213160276a7328ab5d`
- `ca47c8710c4ffb4908a42bd986b14cddcca39e30bb0b11ed5ca16fe8922a468b`
- `iphlpapi.dll`
- `winhttp.dll`

**Extracted Text:**
> CYBERSECURITY ADVISORY  TLP:CLEAR) FBI | CISA  cutables  19CC41A0A056E503CC2137E19E952814FBDF14F8D83F7 99AEAQBOGABFF11EFBB (November 2023)  SHA256  2F31DOOFEEFE181F2D8B69033B382462FF19C35367 753E6906ED80F815A7924F  (LummaC2. exe from November 2023)  SHA256  4D74F8E12FF69318BE5EB383B4E56178817E84E83D3607213160276A7328AB5D SHA256  325daeb781f3416a383343820064c8e98f2e31753cd7 1d76a886feOdbb4fe59a SHA256  76e4962b8ccd2e6fd697 2d9c3264ccb67 38ddb16066588dfcb223222aaa88sf3c SHA256  7a35008a 1a1ae3d093...

</details>

<details>
<summary><strong>Page 10</strong> from aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf</summary>

**View Image:** [aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations_page_010.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations_page_010.png)

**IOCs Found:**
- `mercharenal.jbiz`
- `paleboreeif.jbiz`

**Extracted Text:**
> CYBERSECURITY ADVISORY  = vozmeatillu[.Jshop  = — shiningrstars[.Jhelp = penetratebatt[.Jpw  = drawzhotdog[.Jshop = mercharenal.Jbiz = pasteflawwed[.]world = generalmills[.]pro = citywand[.]live = hoyoverse[.]blog = nestlecompany[.]Jpro = esccapewz[.Jrun = dsfljsdfjewf[.]info = naturewsounds[.]help  = travewlio[.Jshop  = decreaserid[.Jworld  = — stormlegue[.Jcom  = touvrlane[.]bet  = governoagoall.]pw  = paleboreeif.Jbiz  = calmingtefxtures[.Jrun = foresctwhispers[.]top = tracnquilforestl.]life...

</details>

<details>
<summary><strong>Page 11</strong> from aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf</summary>

**View Image:** [aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations_page_011.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations_page_011.png)

**Extracted Text:**
> CYBERSECURITY ADVISORY  TLP:CLEAR) FBI | CISA Table 8. Initial Access  Use  Technique Title |e |  Phishing T1566 Phishing:  Spearphishing 71566.001 Attachment  Phishing: 11566.002  Spearphishing Link  TeohriqueTite | 1D  Obfuscated Files or  . T1027 Information Masquerading T1036 Deobfuscate/Decode 11140  Files or Information  TeohriqueTie | 1D |  Query Registry 71012  Browser Information  . 71217 Discovery  Automated Collection 71119  Page 11 of 14 | Product ID: AA25-141B  Threat actors deliver...

</details>

<details>
<summary><strong>Page 12</strong> from aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf</summary>

**View Image:** [aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations_page_012.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations_page_012.png)

**Extracted Text:**
> CYBERSECURITY ADVISOR  TLP:CLEAR) FBI | CISA  Table 12. Command and Control  Technique Title | Use  Application Layer Protocol: Web Protocols  71071.001 Threat actors used LummaC2 malware to attempt POST requests.  Threat actors used LummaC2 malware to transfer a remote file to  Ingress Tool Transfer 71105 compromised systems.  Table 13. Exfiltration  TechriqueTite | 1D | Use  Threat actors used LummaC2 malware to exfiltrate sensitive user Exfiltration TAOO10 information, including traditional c...

</details>

<details>
<summary><strong>Page 13</strong> from aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf</summary>

**View Image:** [aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations_page_013.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations_page_013.png)

**Extracted Text:**
> CYBERSECURITY ADVISORY  TLP:CLEAR) FBI | CISA  Implement application controls to manage and control execution of software, including allowlisting remote access programs. Application controls should prevent installation and execution of portable versions of unauthorized remote access and other software. A properly configured application allowlisting solution will block any unlisted application execution. Allowlisting is important because antivirus solutions may fail to detect the execution of mal...

</details>

<details>
<summary><strong>Page 14</strong> from aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations.pdf</summary>

**View Image:** [aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations_page_014.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/aa25-141b-threat-actors-deploy-lummac2-malware-to-exfiltrate-sensitive-data-from-organizations_page_014.png)

**IOCs Found:**
- `cisa.gov`

**Extracted Text:**
> CYBERSECURITY ADVISORY  TLP:CLEAR) FBI | CISA  5. Repeat the process for all security technologies to obtain a set of comprehensive performance data.  6. Tune your security program, including people, processes, and technologies, based on the data generated by this process.  The FBI and CISA recommend continually testing your security program, at scale, in a production environment to ensure optimal performance against the MITRE ATT&CK techniques identified in this advisory.  Reporting  Your organ...

</details>

<details>
<summary><strong>Page 1</strong> from aa25-163a-ransomware-simplehelp-rmm-compromise.pdf</summary>

**View Image:** [aa25-163a-ransomware-simplehelp-rmm-compromise_page_001.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/aa25-163a-ransomware-simplehelp-rmm-compromise_page_001.png)

**IOCs Found:**
- `cisa.gov`

**Extracted Text:**
> CYBERSECURITY  ADVISORY Wl ay ites  Co-Authored by: Product ID: AA25-163A June 12, 2025  Ransomware Actors Exploit Unpatched SimpleHelp Remote Monitoring and Management to Compromise Utility Billing Software Provider  Summary  The Cybersecurity and Infrastructure Security Agency (CISA) is releasing this advisory in response to ransomware actors leveraging unpatched instances of a vulnerability in SimpleHelp Remote Monitoring and Management (RMM) to compromise customers of a utility billing softw...

</details>

<details>
<summary><strong>Page 2</strong> from aa25-163a-ransomware-simplehelp-rmm-compromise.pdf</summary>

**View Image:** [aa25-163a-ransomware-simplehelp-rmm-compromise_page_002.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/aa25-163a-ransomware-simplehelp-rmm-compromise_page_002.png)

**IOCs Found:**
- `serviceconfig.xml`

**Extracted Text:**
> CYBERSECURITY ADVISORY  TLP:CLEAR' CISA  Mitigations  CISA recommends organizations implement the mitigations below to respond to emerging ransomware activity exploiting SimpleHelp software. These mitigations align with the Cross-Sector Cybersecurity Performance Goals (CPGs) developed by CISA and the National Institute of Standards and Technology (NIST). The CPGs provide a minimum set of practices and protections that CISA and NIST recommend all organizations implement. CISA and NIST based the C...

</details>

<details>
<summary><strong>Page 3</strong> from aa25-163a-ransomware-simplehelp-rmm-compromise.pdf</summary>

**View Image:** [aa25-163a-ransomware-simplehelp-rmm-compromise_page_003.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/aa25-163a-ransomware-simplehelp-rmm-compromise_page_003.png)

**IOCs Found:**
- `simple-help.com`
- `aaa.exe`
- `cisa.gov`

**Extracted Text:**
> CYBERSECURITY ADVISORY  TLP:CLEAR' CISA  SimpleHelp Server  Determine the version of any SimpleHelp server by performing an HTTP query against it. Add /allversions (e.g., https: //simple-help.com/allversions) to query the URL for the version page. This page will list the running version.  If an unpatched SimpleHelp version 5.5.7 or earlier is confirmed on a system, organizations should conduct threat hunting actions for evidence of compromise and continuously monitor for unusual inbound and outb...

</details>

**OCR Summary:** 52 images processed with text extracted

---

*Generated by PEAK CTI v3.0 Multi-Source Consolidated Report*
*2026-01-01 02:30:14 UTC*

<!-- FILE_HASHES: ee86f910566aad98a37f32f075cd4bc9d4e469efa60b318ecde75c47e93e2f52,15b9706d95a9d8390b207164ee22286ae5cbcba7552f6acf80bf1d7a6d39376a,51dc012731248b5b30255e0768ef9da241f77f66a19012472587b624a13d2e04 -->