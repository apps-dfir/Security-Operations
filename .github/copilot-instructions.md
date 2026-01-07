# GitHub Copilot Code Review Instructions
## Project Context
This is PEAK CTI, a GitHub-native threat intelligence processing toolkit. It automates IOC extraction, MITRE ATT&CK technique mapping, and report generation from security articles and PDFs.
## Pre-Merge Check (Important!)
**Always check if the branch is behind `main`.**
If this PR modifies any of these files:
- `peak/cti/data/ioc_database.json`
- `docs/metrics.json`
- `peak/cti/STATS.md`
- `peak/cti/dashboard/index.html`
Remind the author:
>  **Before merging:** Please click “Update branch” if this branch is behind `main`. This ensures the IOC database includes all previously merged reports and prevents data loss.
## Code Review Focus Areas
### Security (High Priority)
- Flag any hardcoded credentials, API keys, or secrets
- Check for path traversal vulnerabilities in file handling
- Ensure user inputs are sanitized before use in shell commands
- Verify IOC defanging is applied before display (URLs, IPs, domains)
### Python Best Practices
- Ensure proper exception handling (no bare `except:`)
- Check for resource leaks (unclosed files, connections)
- Verify type hints are consistent with actual usage
- Flag any use of `eval()`, `exec()`, or `subprocess.shell=True`
### PEAK CTI Specific
- IOC extraction regex patterns should be precise (avoid false positives)
- MITRE technique IDs must match format `T####` or `T####.###`
- Report markdown must use proper defanging: `[.]` for dots, `hxxp` for http
- Confidence scoring should follow HIGH/MEDIUM/LOW labels only
- Database operations should handle missing files gracefully
### GitHub Actions Workflows
- Ensure secrets are accessed via `${{ secrets.* }}` only
- Check for proper error handling and exit codes
- Verify conditional steps use correct syntax
- Flag any `continue-on-error: true` without justification
## Review Style
- Be concise and actionable
- Prioritize security issues over style issues
- Suggest fixes with code examples when possible
- Flag potential false positives in IOC extraction logic
