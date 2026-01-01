# PEAK CTI - Technical Documentation

This directory contains the core PEAK CTI system. For usage instructions, see the main [README.md](../../README.md).

---

## Directory Structure

```
cti/
├── generate_consolidated_report.py  # Main entry point
├── requirements.txt                 # Python dependencies
├── peak_reporter/                   # Core Python modules
├── scripts/                         # Utility scripts
├── data/                            # MITRE data, IOC database
├── inputs/                          # User-uploaded files
├── reports/                         # Generated reports
└── dashboard/                       # Analytics dashboard
```

---

## Core Components

### generate_consolidated_report.py

Main orchestrator that coordinates report generation.

```bash
python generate_consolidated_report.py \
  --sources-json data/multi_source_inputs.json \
  --analyst "Analyst Name" \
  --enable-ocr "true" \
  --issue-number "42" \
  --issue-title "Report Title" \
  --issue-url "https://github.com/org/repo/issues/42" \
  --repo-url "https://github.com/org/repo"
```

### peak_reporter/

Core Python modules:
- `article_parser.py` - Web article extraction
- `file_parser.py` - PDF/DOCX parsing
- `ioc_extract.py` - IOC extraction with scoring
- `mitre.py` - MITRE ATT&CK mapping
- `ocr.py` - Image OCR processing

### scripts/

Utility scripts:
- `build_ioc_database.py` - Build IOC index
- `check_source_duplicate.py` - Duplicate detection
- `correlate_iocs.py` - IOC prevalence analysis
- `generate_dashboard.py` - Dashboard generation
- `cleanup_report.py` - Remove empty sections

---

## Local Development

### Setup

```bash
cd peak/cti
pip install -r requirements.txt
python -m playwright install chromium
```

### Test Article Extraction

```bash
python scripts/debug_article_extraction.py \
  --url "https://unit42.paloaltonetworks.com/article"
```

---

## Known Limitations

**Medium.com Articles**

Medium's anti-scraping measures block automated extraction.

**Workaround:**
1. Open article in browser
2. Print to PDF (Ctrl+P → Save as PDF)
3. Upload to `inputs/` folder
4. Reference as `inputs/article.pdf`

---

## Dependencies

Key packages from `requirements.txt`:

| Package | Purpose |
|---------|---------|
| playwright | JavaScript page rendering |
| beautifulsoup4 | HTML parsing |
| pdfplumber | PDF text extraction |
| pytesseract | OCR processing |
| python-docx | DOCX parsing |

---

*For usage instructions, see the main [README.md](../../README.md)*
