# PEAK CTI Scripts

Post-processing scripts for PEAK CTI reports and dashboard generation.

## Scripts Overview

### build_ioc_database.py

Builds a searchable JSON database from all PEAK CTI reports. Extracts and indexes:

- **IOCs**: IPv4, domains, URLs, SHA256, SHA1, MD5, CVEs
- **MITRE ATT&CK Techniques**: From report tables and bold format
- **Threat Actors**: Multi-vendor naming convention support
- **Metadata**: Report dates, sources, issue numbers

**Threat Actor Extraction**

Supports automatic extraction using multiple naming conventions:

| Vendor | Naming Convention | Examples |
|--------|------------------|----------|
| Microsoft | Weather themes by nation-state | Midnight Blizzard, Volt Typhoon, Mint Sandstorm |
| CrowdStrike | Animal themes by nation-state | Fancy Bear, Cozy Bear, Charming Kitten |
| Palo Alto Unit 42 | Constellation/Zodiac themes | Jolly Scorpius, Stately Taurus, Spectral Libra |
| CISA/Mandiant | Alphanumeric designations | APT28, APT29, UNC1234, DEV-0123 |
| Proofpoint | TA designations | TA505, TA444, TA406 |
| Common Names | Industry-standard names | Lazarus, Sandworm, Turla, LockBit |

Also extracts attribution phrases like "tracked as", "attributed to", and "operated by".

```bash
python3 scripts/build_ioc_database.py \
  --reports-dir reports \
  --output data/ioc_database.json
```

### generate_dashboard.py

Generates an interactive HTML dashboard with Chart.js. Features:

- Dynamic color scaling based on hit counts (higher counts = more prominent colors)
- MITRE ATT&CK technique visualization
- Threat actor attribution chart (appears when actors are detected)
- IOC distribution donut chart with type breakdown
- Cross-report IOC correlation table
- Extraction confidence breakdown (HIGH/MEDIUM/LOW)
- Recent reports summary table

```bash
python3 scripts/generate_dashboard.py \
  --database data/ioc_database.json \
  --output-html dashboard/index.html \
  --output-stats STATS.md \
  --repo-url "https://github.com/your-org/your-repo"
```

### tag_overlapping_iocs.py

Tags IOCs that appear in multiple reports for correlation analysis. Handles defanged IOC formats (e.g., `domain[.]com` matches `domain.com`).

```bash
python3 scripts/tag_overlapping_iocs.py \
  --report reports/issue-XX_report.md \
  --database data/ioc_database.json \
  --in-place
```

### correlate_iocs.py

Adds correlation sections to reports showing related reports based on shared IOCs.

```bash
python3 scripts/correlate_iocs.py \
  --report reports/issue-XX_report.md \
  --database data/ioc_database.json \
  --repo-url "https://github.com/your-org/your-repo"
```

### check_source_duplicate.py

Checks if a source URL or file has already been processed to prevent duplicates.

```bash
python3 scripts/check_source_duplicate.py \
  --url "https://example.com/blog/article" \
  --database data/ioc_database.json
```

### update_actor_profile.py

Updates threat actor profile JSON files in the profiles directory with new IOCs and report references.

```bash
python3 scripts/update_actor_profile.py \
  --actor "Lazarus" \
  --report reports/issue-XX_report.md \
  --profiles-dir profiles
```

### cleanup_report.py

Post-processing cleanup for generated reports. Removes empty sections and fixes formatting issues.

```bash
python3 scripts/cleanup_report.py --report reports/issue-XX_report.md --in-place
```

## Workflow Integration

These scripts are called automatically by the GitHub Actions workflow in this order:

1. `check_source_duplicate.py` - Before processing
2. Report generation (main script)
3. `build_ioc_database.py` - Index new report
4. `tag_overlapping_iocs.py` - Add cross-report tags
5. `correlate_iocs.py` - Add correlation section
6. `generate_dashboard.py` - Update dashboard

## Database Schema

The IOC database (`data/ioc_database.json`) structure:

```json
{
  "metadata": {
    "generated": "2026-01-06T00:00:00",
    "total_reports": 10,
    "total_iocs": 500
  },
  "reports": {
    "reports/issue-XX_report.md": {
      "metadata": {
        "title": "Report Title",
        "issue_number": 42,
        "processed_date": "2026-01-06",
        "source_urls": ["https://..."],
        "mitre_techniques": [
          {"technique_id": "T1566", "technique_name": "Phishing"}
        ],
        "threat_actors": ["APT28", "Fancy Bear"]
      },
      "iocs": {
        "ipv4": ["1.2.3.4"],
        "domains": ["malware.com"],
        "sha256": ["abc123..."]
      }
    }
  },
  "ioc_index": {
    "ipv4:1.2.3.4": [{"report": "...", "issue_number": 42, "title": "..."}]
  },
  "sources": {
    "https://source-url.com/article": "reports/issue-XX_report.md"
  }
}
```
