# PEAK CTI - Technical Documentation

## Structure

```
cti/
├── generate_consolidated_report.py  # Main entry point
├── requirements.txt
├── peak_reporter/                   # Core modules
├── scripts/                         # Utilities
├── data/                            # MITRE data, IOC database
├── inputs/                          # User uploads
├── reports/                         # Generated reports
└── dashboard/                       # Analytics
```

## Local Development

```bash
cd peak/cti
pip install -r requirements.txt
python -m playwright install chromium
```
