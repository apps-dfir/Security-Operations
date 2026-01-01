# scripts/ - Utility Scripts

Utility scripts for PEAK CTI operations and maintenance.

---

## Scripts

| Script | Purpose | Used By |
|--------|---------|---------|
| `build_ioc_database.py` | Build IOC index from reports | Workflow |
| `check_source_duplicate.py` | Check for duplicate sources | Workflow |
| `correlate_iocs.py` | Add prevalence info to reports | Workflow |
| `generate_dashboard.py` | Generate HTML dashboard | Workflow |
| `tag_overlapping_iocs.py` | Tag IOCs across sources | Workflow |
| `cleanup_report.py` | Remove empty report sections | Workflow |
| `debug_article_extraction.py` | Test article parsing | Manual |
| `update_actor_profile.py` | Manage threat actor profiles | Manual |

---

## Manual Usage

### Debug Article Extraction

Test URL parsing without running full workflow:

```bash
python scripts/debug_article_extraction.py \
  --url "https://unit42.paloaltonetworks.com/article"
```

### Rebuild IOC Database

Regenerate database from all reports:

```bash
python scripts/build_ioc_database.py \
  --reports-dir reports \
  --output data/ioc_database.json
```

### Regenerate Dashboard

Manually rebuild dashboard:

```bash
python scripts/generate_dashboard.py \
  --reports-dir reports \
  --database data/ioc_database.json \
  --output-html dashboard/index.html \
  --output-stats STATS.md \
  --repo-url "https://github.com/your-org/repo"
```

---

*For usage instructions, see the main [README.md](../../../README.md)*
