# Changelog

All notable changes to PEAK CTI.

## [3.2.0] - 2026-01-06

### Added
- IOC overlap detection in report generation
  - "Previously Seen IOCs" section showing indicators found in prior reports
  - Links to related reports for campaign correlation
  - Cross-references IOC database during report generation
- Workflow concurrency lock to prevent race conditions
  - Queues simultaneous submissions instead of parallel processing
  - Prevents IOC database conflicts when multiple PRs are created
- PR rebase reminder in pull request body
  - Warns reviewers to update branch before merging
  - Ensures IOC database includes all previously merged reports

### Changed
- Switched dashboard from Plotly to Chart.js for better numeric axis handling
- Muted slate color palette across all charts
- Removed axis titles and in-chart annotations for cleaner visuals

### Fixed
- X-axis no longer interprets integers as Unix timestamps
- Confidence chart displays correctly as stacked bar

## [3.1.0] - 2026-01-06

### Added
- Threat actor extraction with multi-vendor naming conventions
  - Microsoft: Weather themes (Blizzard, Typhoon, Sandstorm, Sleet)
  - CrowdStrike: Animal themes (Bear, Panda, Kitten, Chollima, Spider)
  - Palo Alto Unit 42: Constellation themes (Scorpius, Taurus, Libra)
  - CISA/Mandiant: APT, UNC, DEV designations
  - Proofpoint: TA designations
  - Common names: Lazarus, Sandworm, LockBit, etc.
- Attribution phrase extraction ("tracked as", "attributed to", "operated by")
- Threat Actor Attribution chart in dashboard
- Dynamic color scaling based on hit counts

### Changed
- MITRE technique name threshold lowered from 14 to 8 characters
- Dashboard styling updated for SOC display use

### Fixed
- MITRE extraction now handles table format (| T1234: Name |)
- IOC overlap tagging now matches defanged indicators (Next[.]js matches next.js)

## [3.0.0] - 2026-01-05

### Added
- Multi-source batch processing via GitHub Issues
- Consolidated reports combining multiple URLs/PDFs
- IOC confidence scoring with visual badges
- Cross-report IOC correlation and tagging
- Interactive dashboard with analytics
- Duplicate source detection
- PDF and image OCR support

### Changed
- Migrated from single-source to multi-source workflow
- Report format updated with source attribution tables
- IOC sections now include confidence indicators

## [2.0.0] - 2025-12-15

### Added
- MITRE ATT&CK technique extraction
- IOC database with search index
- Dashboard generation
- GitHub Actions automation

### Changed
- Restructured as installable package

## [1.0.0] - 2025-11-01

### Added
- Initial release
- URL parsing and IOC extraction
- Markdown report generation
- Basic defanging support