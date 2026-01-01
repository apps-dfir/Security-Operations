# .github/ - GitHub Configuration

## Workflows

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `peak_cti_multi_source.yml` | Issue with `multi-source` label | Main report generation |
| `update_dashboard.yml` | Manual | Rebuild dashboard |
| `update_ioc_database.yml` | Manual | Rebuild IOC database |

## Issue Templates

| Template | Purpose |
|----------|---------|
| `peak_cti_multi_source.yml` | Submit sources for CTI processing |

## Required Secret

| Name | Purpose |
|------|---------|
| `PEAK_BOT_PAT` | Personal Access Token with `repo` scope |

---

*For usage instructions, see the main [README.md](../README.md)*
