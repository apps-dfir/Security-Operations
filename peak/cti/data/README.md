# data/ - Data Files

System data files used by PEAK CTI.

## Contents

| File | Purpose |
|------|---------|
| `enterprise-attack.json` | MITRE ATT&CK framework data |
| `ioc_database.json` | Index of IOCs across all reports |
| `dashboard_metrics.json` | Dashboard statistics |
| `ocr_images/` | Images extracted during OCR |

## Updating MITRE Data

```bash
curl -L "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json" \
  -o data/enterprise-attack.json
```

---

*For usage instructions, see the main [README.md](../../../README.md)*
