# peak_reporter/ - Core Processing Modules

This directory contains the core Python modules that power PEAK CTI's threat intelligence processing.

---

## Module Overview

| Module | Purpose |
|--------|---------|
| `article_parser.py` | Extract content from web articles |
| `file_parser.py` | Parse PDF and DOCX documents |
| `ioc_extract.py` | Extract and score IOCs |
| `mitre.py` | Extracts MITRE ATT&CK techniques |
| `ocr.py` | OCR processing for images |
| `defang_handler.py` | Defang/refang IOC utilities |
| `multi_source_handler.py` | Parse multi-source input |
| `document_generator.py` | Format report output |
| `render_url_to_pdf.py` | Convert URLs to PDF |

---

## article_parser.py

Extracts text content from web articles using Playwright for JavaScript rendering.

### Usage

```python
from peak_reporter.article_parser import fetch_article

result = fetch_article("https://unit42.paloaltonetworks.com/article")
print(result.title)
print(result.text)
```

### Supported Sites

Works with most threat intel blogs:
- Unit42, Securelist, The DFIR Report
- Microsoft Security Blog, Google TAG
- Substack and custom blogs

**Not Supported:**
- **Medium.com** - Anti-scraping measures block extraction. Save as PDF instead.

---

## file_parser.py

Parses PDF and Word documents to extract text.

### Usage

```python
from peak_reporter.file_parser import parse_file

text = parse_file("inputs/report.pdf")  # Auto-detects type
```

### Supported Formats

- PDF (via pdfplumber)
- DOCX (via python-docx)
- TXT, MD (direct read)

---

## ioc_extract.py

Extracts IOCs from text and assigns confidence scores.

### Usage

```python
from peak_reporter.ioc_extract import extract_iocs_with_confidence

scored = extract_iocs_with_confidence(text)
for ioc in scored.sha256:
    print(f"{ioc.value} ({ioc.confidence_label})")
```

### Currently Supported IOC Types

| Type | Pattern |
|------|---------|
| `sha256` | 64-character hex strings |
| `sha1` | 40-character hex strings |
| `md5` | 32-character hex strings |
| `ipv4` | Standard IP addresses |
| `domains` | Fully qualified domain names |
| `urls` | HTTP/HTTPS URLs |
| `cves` | CVE-YYYY-NNNNN format |
| `win_paths` | Windows file paths |
| `command_lines` | Shell/PowerShell commands |

---

## .py

Extracts MITRE techniques from content.

### Usage

```python
from peak_reporter.mitre import extract_techniques

result = extract_techniques(text)
for technique in result.techniques:
    print(f"{technique.id}: {technique.name}")
```

### Data Source

Uses `data/enterprise-attack.json` from MITRE's official STIX bundle.

---

## ocr.py

Performs OCR on images extracted from articles and PDFs.

### Usage

```python
from peak_reporter.ocr import run_ocr_on_images

results = run_ocr_on_images(images)
for result in results:
    print(result.text)
```

### Requirements

- Tesseract OCR (`apt-get install tesseract-ocr`)
- poppler-utils (`apt-get install poppler-utils`)

---

## defang_handler.py

Utilities for defanging IOCs (making them safe for display).

### Usage

```python
from peak_reporter.defang_handler import defang_ioc, refang_ioc

safe = defang_ioc("evil.com")      # "evil[.]com"
original = refang_ioc("evil[.]com") # "evil.com"
```

---

## multi_source_handler.py

Parses multi-source input from GitHub Issue forms.

### Usage

```python
from peak_reporter.multi_source_handler import parse_multi_source_input

sources = parse_multi_source_input(issue_body)
# [{'type': 'url', 'value': 'https://...'}, ...]
```

---

*For complete system documentation, see the main [README.md](../../../README.md)*
