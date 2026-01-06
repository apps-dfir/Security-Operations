# PEAK CTI

**P**rocessing and **E**xtraction for **A**nalyst **K**nowledge - **C**yber **T**hreat **I**ntelligence

An automated threat intelligence processing pipeline that extracts IOCs and MITRE ATT&CK techniques from security articles and documents.

## What It Does

- Fetches and parses threat intelligence articles from URLs
- Processes uploaded PDFs and documents with OCR support
- Extracts IOCs (IPs, domains, URLs, hashes, CVEs) with extraction quality scoring
- Extracts MITRE ATT&CK technique references from source text
- Deduplicates across sources and tracks previously processed content
- Generates consolidated markdown reports for analyst review
- Maintains a live dashboard with analytics

## Quick Start

### 1. Create an Issue

Go to **Issues > New Issue** and select the **PEAK CTI Multi-Source Submission** template.

Add your sources:
```
1. <url-to-threat-report>
2. <url-to-advisory>
3. inputs/vendor-report.pdf
```

### 2. Submit and Wait

The GitHub Actions workflow will:
- Fetch the latest MITRE ATT&CK data
- Download and parse each source
- Extract IOCs and techniques
- Generate a consolidated report
- Create a Pull Request

### 3. Review and Merge

Check the PR for extraction accuracy, add analyst notes, and merge.

## Installation

### Requirements

- GitHub repository with Actions enabled
- Personal Access Token (PAT) with `repo` scope

### Setup

1. **Fork or clone this repository**

2. **Create a PAT**
   - GitHub Settings > Developer settings > Personal access tokens > Tokens (classic)
   - Generate with `repo` scope
   - Copy the token

3. **Add the secret**
   - Repository Settings > Secrets and variables > Actions
   - New secret: `PEAK_BOT_PAT`
   - Paste your token

4. **Enable GitHub Pages** (optional, for dashboard)
   - Settings > Pages
   - Source: Deploy from branch
   - Branch: `main`, Folder: `/docs`

## Usage

### Supported Sources

| Type | How to Reference |
|------|------------------|
| URLs | Direct URL (most security blogs work) |
| PDFs | `inputs/filename.pdf` (upload to inputs folder first) |
| DOCX | `inputs/filename.docx` |
| Text | `inputs/filename.txt` |

### Uploading Files

1. Add files to `peak/cti/inputs/`
2. Reference as `inputs/filename.pdf` in your submission

PDF files are tracked with Git LFS.

### IOC Extraction Quality

Each IOC is scored based on how cleanly it was extracted from the source text. This is NOT a threat score or indicator of maliciousness.

| Badge | Level | What It Means |
|-------|-------|---------------|
| 🟢 | HIGH | Clean regex match, well-formed indicator |
| 🟡 | MEDIUM | Probable IOC, worth reviewing |
| 🔴 | LOW | Weak pattern match, likely false positive (e.g., `setup.exe` parsed as domain) |

A LOW score means the extraction is suspect, not that the threat is minor. A HIGH score means we're confident it's a real IOC, not that it's dangerous.

### Report Sections

Generated reports include:

- **Executive Summary** - Analyst fill-in for key findings
- **Workflow Feedback** - Section for extraction quality notes
- **Consolidated IOCs** - Deduplicated indicators with source links
- **MITRE ATT&CK Techniques** - Extracted technique IDs
- **Source Details** - Per-source extraction breakdown
- **Processing Stats** - Word counts, OCR stats, metrics

## Project Structure
```
.github/
  workflows/
    peak_cti_multi_source.yml    # Main workflow
  ISSUE_TEMPLATE/
    peak_cti_multi_source.yml    # Submission template

docs/
  dashboard.html                  # Live dashboard
  metrics.json                    # Dashboard data

peak/cti/
  generate_consolidated_report.py # Main entry point
  
  peak_reporter/                  # Core modules
    article_parser.py             # URL fetching
    file_parser.py                # Document parsing
    ioc_extract.py                # IOC extraction
    mitre.py                      # MITRE technique lookup
    ocr.py                        # Image text extraction
  
  scripts/                        # Utilities
    generate_dashboard.py         # Dashboard generator
    build_ioc_database.py         # IOC database builder
    correlate_iocs.py             # Cross-report analysis
  
  data/
    ioc_database.json             # Persistent IOC store
    enterprise-attack.json        # MITRE data (auto-downloaded)
  
  reports/                        # Generated reports
  inputs/                         # Uploaded documents
```

## Configuration

### Workflow Behavior

Each run:
1. Downloads latest MITRE ATT&CK Enterprise data
2. Checks sources against IOC database for duplicates
3. Processes all valid sources
4. Updates IOC database and dashboard
5. Creates PR for review

### Branch Protection

Works with protected branches. The workflow creates PRs instead of direct commits. Ensure `PEAK_BOT_PAT` has PR creation permissions.

## Troubleshooting

**Workflow fails at duplicate check**
- Ensure `peak/cti/data/ioc_database.json` exists

**No IOCs extracted from URL**
- Some sites block scraping (Medium, paywalled content)
- Save as PDF and upload instead

**Dashboard not updating**
- Check workflow completed successfully
- Verify GitHub Pages points to `/docs`

## Credits

Built with inspiration and methodology from:

- THOR Collective - Threat hunting community and methodology
- Sydney Marrone / Nebulock - Hunt documentation patterns
- MITRE ATT&CK - Adversarial techniques framework
- ioc-fanger - IOC defanging library

## License

MIT

---

PEAK CTI v3.2