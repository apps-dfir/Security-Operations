# PEAK CTI - Automated Cyber Threat Intelligence Pipeline

**Version 3.0** | Multi-Source Processing | IOC Confidence Scoring | MITRE ATT&CK Extraction | OCR Extraction

---

## What is PEAK CTI?

PEAK CTI automates the extraction of threat intelligence from security articles and documents. Submit URLs or files via GitHub Issues, and the system automatically extracts IOCs, extracts MITRE ATT&CK techniques, and generates analyst-ready reports.

---

## How to Use

### Step 1: Submit Threat Intelligence

1. Go to **Issues** → **New Issue**
2. Select **"PEAK CTI Multi-Source Submission"** template
3. Fill in the form:

```markdown
### Sources (up to 5)

1. https://unit42.paloaltonetworks.com/ransomhouse-encryption-upgrade/
2. https://securelist.com/honeymyte-kernel-mode-rootkit/118590/
3. inputs/cisa-advisory.pdf

### Analyst

YourName

### Enable OCR

yes
```

4. Click **Submit new issue**

### Step 2: Wait for Processing

The workflow automatically:
- Checks for duplicate sources (skips already-processed URLs/files)
- Fetches and parses each source
- Extracts IOCs with confidence scoring
- Extracts MITRE ATT&CK techniques
- Runs OCR on images (if enabled)
- Generates a consolidated markdown report
- Creates a Pull Request

Processing typically takes 2-5 minutes depending on source count and OCR.

### Step 3: Review the Report

1. Go to **Pull Requests**
2. Open the PR created by the workflow
3. Review the generated report:
   - Check HIGH confidence IOCs first
   - Verify MITRE technique mappings
   - Review any OCR-extracted content
4. Add analyst notes in the Executive Summary section
5. **Approve and Merge** to archive the report

### Step 4: Search Historical Reports

All merged reports are stored in `peak/cti/reports/` and searchable:

```bash
# Find reports mentioning a domain
grep -r "evil.com" peak/cti/reports/

# Find reports with specific hash
grep -r "abc123def456" peak/cti/reports/
```

---

## Uploading PDF/DOCX Files

For documents not available via URL:

1. Upload file to `peak/cti/inputs/` directory in the repository
2. Reference it in your issue as `inputs/filename.pdf`

```markdown
### Sources (up to 5)

1. inputs/cisa-advisory-2025.pdf
2. inputs/internal-malware-analysis.docx
3. https://example.com/article
```

---

## Supported Sources

| Source Type | Examples | Notes |
|-------------|----------|-------|
| Web Articles | `https://unit42.paloaltonetworks.com/...` | Most threat intel blogs work |
| PDF Documents | `inputs/report.pdf` | Upload to inputs/ first |
| Word Documents | `inputs/analysis.docx` | Upload to inputs/ first |

### Known Limitations

- **Medium.com** - Not supported due to anti-scraping measures. Save as PDF instead.
- **Paywalled content** - Cannot access content behind logins
- **Very large PDFs** - May timeout; split into smaller files

---

## Extracted IOC Types

| Type | Description | Example |
|------|-------------|---------|
| SHA256 | 64-character file hashes | `a1b2c3d4e5f6...` |
| SHA1 | 40-character file hashes | `a1b2c3d4e5...` |
| MD5 | 32-character file hashes | `a1b2c3d4...` |
| IPv4 | IP addresses | `192.168.1.1` |
| Domains | Fully qualified domain names | `malware.evil.com` |
| URLs | Full HTTP/HTTPS URLs | `https://evil.com/payload` |
| CVEs | Vulnerability identifiers | `CVE-2024-12345` |
| Windows Paths | File system paths | `C:\Windows\System32\evil.dll` |
| Command Lines | Shell/PowerShell commands | `powershell -enc ...` |

---

## IOC Confidence Scoring

Every IOC is scored to help prioritize analyst review:

| Level | Indicator | Meaning |
|-------|-----------|---------|
| 🟢 HIGH | 90-100% | Strong indicator - prioritize for SIEM |
| 🟡 MEDIUM | 60-89% | Likely valid - verify before use |
| 🔴 LOW | 1-59% | Possible false positive - manual review |

**Scoring factors:**
- Pattern strength and format validation
- Known false positive filtering (e.g., `setup.exe`, `readme.txt`)
- Context validation

---

## Report Structure

Generated reports include:

1. **Report Metadata** - Issue link, analyst, timestamp, source count
2. **Executive Summary** - Empty section for analyst notes
3. **Indicators of Compromise** - Grouped by type with confidence scores
4. **Common Indicators** - IOCs seen in previous reports (with links)
5. **MITRE ATT&CK Techniques** - Mapped techniques with tactic categories
6. **OCR Extracted Content** - Text from images (if OCR enabled)
7. **Source Details** - Collapsible sections with full content per source
8. **References** - Links to all source URLs

---

## Repository Structure

```
Security-Operations/
├── README.md                    ← You are here
├── .github/
│   ├── ISSUE_TEMPLATE/          # Issue submission form
│   └── workflows/               # GitHub Actions workflows
└── peak/cti/
    ├── inputs/                  # Upload PDF/DOCX files here
    ├── reports/                 # Generated reports (after merge)
    ├── data/                    # IOC database, MITRE data
    ├── dashboard/               # Analytics dashboard
    ├── peak_reporter/           # Core Python modules
    └── scripts/                 # Utility scripts
```

---

## Initial Setup (Repository Admins)

### 1. Create Personal Access Token

1. Go to GitHub **Settings** → **Developer settings** → **Personal access tokens** → **Tokens (classic)**
2. Click **Generate new token (classic)**
3. Select scope: `repo` (full control)
4. Copy the token

### 2. Add Repository Secret

1. Go to repository **Settings** → **Secrets and variables** → **Actions**
2. Click **New repository secret**
3. Name: `PEAK_BOT_PAT`
4. Value: Paste the token
5. Click **Add secret**

### 3. Test the System

1. Create a new issue using the PEAK CTI template
2. Add a test URL (e.g., any threat intel blog post)
3. Submit and verify the workflow runs
4. Check that a PR is created with the report

---

## Troubleshooting

### Workflow Not Running

- Verify the issue has the `multi-source` label (auto-applied by template)
- Check that `PEAK_BOT_PAT` secret is configured
- Review Actions tab for error logs

### No IOCs Extracted

- Source may use unusual formatting
- Try enabling OCR if IOCs are in images
- Check workflow logs for parsing errors

### Duplicate Source Detected

- The system prevents reprocessing of already-analyzed sources
- This is intentional to avoid duplicate reports
- Submit different sources or check existing reports

### Medium.com Articles

Medium blocks automated access. Workaround:
1. Open article in browser
2. Print to PDF (Ctrl/Cmd + P → Save as PDF)
3. Upload PDF to `inputs/` folder
4. Reference as `inputs/medium-article.pdf`

---

## Dashboard

An interactive dashboard is available at `peak/cti/dashboard/index.html` showing:
- Reports timeline
- IOC distribution by type
- MITRE technique frequency
- Common IOCs across reports

View locally or enable GitHub Pages to host.

---

## Credits

### Methodology and Inspiration

- **THOR Collective** - Threat hunting methodology and structured analysis frameworks
- **Sydney Marrone and Team** - Inspiration for threat hunting documentation patterns

### Frameworks and Data Sources

- **MITRE ATT&CK®** - Adversarial tactics, techniques, and common knowledge framework
- **MITRE Corporation** - Enterprise ATT&CK dataset for technique mapping

### Technology Stack

- **Playwright** - Browser automation for JavaScript-heavy sites
- **Tesseract OCR** - Optical character recognition
- **pdfplumber** - PDF text extraction
- **python-docx** - Word document parsing

---

## License

MIT License - See [LICENSE](LICENSE) file for details.

---

## Future Enhancements

The following capabilities are planned but not yet implemented:

- Email address extraction
- IPv6 address extraction
- YARA rule name extraction
- Registry key extraction
- Executable filename extraction
- Threat actor profile management

---

*PEAK CTI v3.0 - Empowering security teams with automated threat intelligence processing*
