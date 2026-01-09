# Changelog

All notable changes to PEAK CTI.

## [3.3.0] - 2026-01-08

### Added
- MITRE ATT&CK technique validation (P1+P2+P3)
  - P1: Filters deprecated and revoked techniques against current ATT&CK schema
  - P1: Validates technique IDs exist in enterprise-attack.json
  - P2: Resolves correct sub-technique names (e.g., "Steganography" not "Obfuscated Files")
  - P3: Optional LLM-assisted context validation (personal repo only)
- Extraction warnings section in reports
  - Shows deprecated techniques that were removed (e.g., T1063, T1093)
  - Shows invalid technique IDs that don't exist in ATT&CK
  - Shows context mismatches when LLM validation is enabled
- LLM MITRE Validation toggle in issue template
  - Opt-in per submission
  - Requires ANTHROPIC_API_KEY secret for personal repo
  - Gracefully disabled in enterprise (no anthropic package)
- LLM-suggested techniques section in reports
  - Infers missing techniques from attack narrative
  - Includes confidence level (HIGH/MEDIUM)

### Changed
- MITRE section now displays parent:sub-technique format (e.g., "Process Injection: Process Hollowing")
- Report summary includes LLM validation status when used

### Fixed
- Sub-technique names no longer show parent name only (T1027.003 shows "Steganography")
- Deprecated techniques (T1063, T1093) no longer appear in reports

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