#!/usr/bin/env python3
"""
PEAK CTI Dashboard Generator
Threat intelligence dashboard using Chart.js

Version: 3.2.0
"""

import json
import re
from pathlib import Path
from datetime import datetime
from collections import defaultdict
import argparse


def load_ioc_database(db_path: Path) -> dict:
    if not db_path.exists():
        return {"metadata": {}, "reports": {}, "ioc_index": {}}
    with open(db_path) as f:
        return json.load(f)


def extract_report_date(report_path: str) -> str:
    match = re.search(r'_(\d{8})_', report_path)
    if match:
        date_str = match.group(1)
        return f"{date_str[:4]}-{date_str[4:6]}"
    return "Unknown"


def calculate_metrics(database: dict) -> dict:
    reports = database.get("reports", {})
    
    total_reports = len(reports)
    total_iocs = sum(
        len(r.get("iocs", {}).get("ipv4", [])) +
        len(r.get("iocs", {}).get("domains", [])) +
        len(r.get("iocs", {}).get("urls", [])) +
        len(r.get("iocs", {}).get("sha256", [])) +
        len(r.get("iocs", {}).get("sha1", [])) +
        len(r.get("iocs", {}).get("md5", [])) +
        len(r.get("iocs", {}).get("cves", []))
        for r in reports.values()
    )
    
    reports_by_month = defaultdict(int)
    for report_path in reports.keys():
        month = extract_report_date(report_path)
        if month != "Unknown":
            reports_by_month[month] += 1
    
    ioc_types = defaultdict(int)
    for report in reports.values():
        iocs = report.get("iocs", {})
        for ioc_type, items in iocs.items():
            ioc_types[ioc_type] += len(items)
    
    confidence_counts = {"high": 0, "medium": 0, "low": 0}
    ioc_confidence_map = {}
    
    for report_path, report in reports.items():
        report_content = ""
        full_path = Path("reports") / Path(report_path).name
        if full_path.exists():
            report_content = full_path.read_text()
        
        for ioc_type, iocs in report.get("iocs", {}).items():
            for ioc in iocs:
                if ioc in ioc_confidence_map:
                    continue
                conf = "medium"
                if report_content:
                    ioc_escaped = re.escape(ioc)
                    if re.search(rf"🟢.*{ioc_escaped}|{ioc_escaped}.*🟢", report_content):
                        conf = "high"
                    elif re.search(rf"🔴.*{ioc_escaped}|{ioc_escaped}.*🔴", report_content):
                        conf = "low"
                ioc_confidence_map[ioc] = conf
    
    for conf in ioc_confidence_map.values():
        confidence_counts[conf] += 1
    
    mitre_counts = defaultdict(int)
    mitre_names = {}
    for report in reports.values():
        meta = report.get("metadata", {})
        for tech in meta.get("mitre_techniques", []):
            tid = tech.get("technique_id", "")
            tname = tech.get("technique_name", "")
            if tid:
                mitre_counts[tid] += 1
                if tname and tid not in mitre_names:
                    mitre_names[tid] = tname
    
    top_techniques = sorted(mitre_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    
    actor_counts = defaultdict(int)
    for report in reports.values():
        meta = report.get("metadata", {})
        for actor in meta.get("threat_actors", []):
            if actor:
                actor_counts[actor] += 1
    
    top_actors = sorted(actor_counts.items(), key=lambda x: x[1], reverse=True)[:12]
    
    ioc_report_count = defaultdict(lambda: {"count": 0, "type": "", "confidence": "medium"})
    for report_path, report in reports.items():
        for ioc_type, iocs in report.get("iocs", {}).items():
            for ioc in iocs:
                ioc_report_count[ioc]["count"] += 1
                ioc_report_count[ioc]["type"] = ioc_type
                if ioc in ioc_confidence_map:
                    ioc_report_count[ioc]["confidence"] = ioc_confidence_map[ioc]
    
    common_iocs = [
        {"ioc": ioc, "count": data["count"], "type": data["type"], "confidence": data["confidence"]}
        for ioc, data in ioc_report_count.items()
        if data["count"] >= 2
    ]
    common_iocs.sort(key=lambda x: (-x["count"], x["confidence"] != "high"))
    
    recent_reports = []
    for report_path, report in sorted(reports.items(), reverse=True)[:10]:
        meta = report.get("metadata", {})
        source_count = len(meta.get("source_urls", [])) + len(meta.get("source_files", []))
        if meta.get("source_url"):
            source_count = max(source_count, 1)
        if source_count == 0:
            source_count = 1
        recent_reports.append({
            "path": report_path,
            "title": meta.get("title", Path(report_path).stem),
            "date": meta.get("processed_date", ""),
            "source_count": source_count,
            "ioc_count": sum(len(v) for v in report.get("iocs", {}).values())
        })
    
    return {
        "generated": datetime.now().isoformat(),
        "total_reports": total_reports,
        "total_iocs": total_iocs,
        "reports_by_month": dict(sorted(reports_by_month.items())),
        "iocs_by_type": dict(ioc_types),
        "ioc_confidence": confidence_counts,
        "ioc_prevalence": {"common_iocs": len(common_iocs), "top_common": common_iocs[:20]},
        "mitre_techniques": dict(mitre_counts),
        "mitre_names": mitre_names,
        "top_techniques": top_techniques,
        "threat_actors": dict(actor_counts),
        "top_actors": top_actors,
        "recent_reports": recent_reports
    }


def generate_dashboard_html(metrics: dict, repo_url: str = "") -> str:
    months = list(metrics["reports_by_month"].keys())[-12:]
    month_counts = [metrics["reports_by_month"].get(m, 0) for m in months]
    
    ioc_types = list(metrics["iocs_by_type"].keys())
    ioc_counts = [metrics["iocs_by_type"].get(t, 0) for t in ioc_types]
    type_labels = {"ipv4": "IPv4", "domains": "Domains", "urls": "URLs", "sha256": "SHA256", "sha1": "SHA1", "md5": "MD5", "cves": "CVEs"}
    ioc_labels = [type_labels.get(t, t.upper()) for t in ioc_types]
    
    tech_data = []
    for tid, count in metrics["top_techniques"][:8]:
        name = metrics.get("mitre_names", {}).get(tid, "")
        label = f"{tid}: {name[:20]}..." if len(name) > 20 else f"{tid}: {name}" if name else tid
        tech_data.append({"label": label, "count": count})
    
    actor_data = metrics.get("top_actors", [])[:10]
    
    common_iocs_rows = ""
    for item in metrics["ioc_prevalence"]["top_common"][:15]:
        conf = item["confidence"].upper()
        conf_class = f"conf-{item['confidence']}"
        ioc_display = item['ioc'][:55] + '...' if len(item['ioc']) > 55 else item['ioc']
        common_iocs_rows += f'<tr><td class="ioc-cell"><code>{ioc_display}</code></td><td>{item["type"].upper()}</td><td class="count-cell">{item["count"]}</td><td><span class="conf-badge {conf_class}">{conf}</span></td></tr>'
    
    recent_reports_rows = ""
    for report in metrics["recent_reports"][:8]:
        title = report["title"][:40] + "..." if len(report["title"]) > 40 else report["title"]
        recent_reports_rows += f'<tr><td class="title-cell">{title}</td><td>{report["date"][:10] if report["date"] else "N/A"}</td><td class="count-cell">{report["source_count"]}</td><td class="count-cell">{report["ioc_count"]}</td></tr>'
    
    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PEAK CTI Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
    <style>
        :root {{
            --bg-primary: #09090b;
            --bg-card: #18181b;
            --border: #27272a;
            --text: #fafafa;
            --text-muted: #71717a;
            --slate-400: #94a3b8;
            --slate-500: #64748b;
            --slate-600: #475569;
            --slate-700: #334155;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
            background: var(--bg-primary);
            color: var(--text);
            line-height: 1.5;
            min-height: 100vh;
        }}
        .container {{ max-width: 1500px; margin: 0 auto; padding: 24px; }}
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 16px 0 24px;
            border-bottom: 1px solid var(--border);
            margin-bottom: 24px;
        }}
        .logo {{ font-size: 20px; font-weight: 600; }}
        .logo span {{ color: var(--text-muted); font-weight: 400; }}
        .version {{ background: var(--bg-card); border: 1px solid var(--border); padding: 3px 8px; border-radius: 4px; font-size: 11px; color: var(--text-muted); margin-left: 12px; }}
        .header-meta {{ color: var(--text-muted); font-size: 12px; text-align: right; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }}
        .stat-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
        }}
        .stat-card.highlight {{ border-color: var(--slate-600); }}
        .stat-label {{ font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 6px; }}
        .stat-value {{ font-size: 32px; font-weight: 700; }}
        .charts-grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; margin-bottom: 24px; }}
        .chart-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
        }}
        .chart-card.wide {{ grid-column: span 2; }}
        .chart-card h3 {{ font-size: 12px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 16px; font-weight: 500; }}
        .chart-container {{ position: relative; height: 260px; }}
        .chart-container.short {{ height: 200px; }}
        .tables-grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; }}
        .table-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
        }}
        .table-card h3 {{ font-size: 12px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 16px; font-weight: 500; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
        th {{ text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border); color: var(--text-muted); font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 500; }}
        td {{ padding: 8px 10px; border-bottom: 1px solid #1f1f23; color: #a1a1aa; }}
        tr:last-child td {{ border-bottom: none; }}
        .ioc-cell code {{ font-family: 'SF Mono', Monaco, monospace; font-size: 11px; background: var(--bg-primary); padding: 2px 5px; border-radius: 3px; }}
        .title-cell {{ color: var(--text); font-weight: 500; }}
        .count-cell {{ text-align: center; font-weight: 600; color: var(--text); }}
        .conf-badge {{ padding: 2px 8px; border-radius: 3px; font-size: 10px; font-weight: 600; }}
        .conf-high {{ background: #14532d; color: #4ade80; }}
        .conf-medium {{ background: #422006; color: #fb923c; }}
        .conf-low {{ background: #450a0a; color: #f87171; }}
        .empty {{ text-align: center; padding: 40px; color: var(--text-muted); }}
        footer {{ text-align: center; padding: 20px; color: var(--text-muted); font-size: 11px; margin-top: 24px; border-top: 1px solid var(--border); }}
        footer a {{ color: var(--slate-400); text-decoration: none; }}
        @media (max-width: 1000px) {{
            .stats-grid {{ grid-template-columns: repeat(2, 1fr); }}
            .charts-grid, .tables-grid {{ grid-template-columns: 1fr; }}
            .chart-card.wide {{ grid-column: span 1; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <span class="logo">PEAK CTI <span>Dashboard</span></span>
                <span class="version">v3.2</span>
            </div>
            <div class="header-meta">
                <div>Threat Intelligence Operations</div>
                <div>{datetime.now().strftime('%Y-%m-%d %H:%M UTC')}</div>
            </div>
        </header>
        
        <div class="stats-grid">
            <div class="stat-card"><div class="stat-label">Total Reports</div><div class="stat-value">{metrics['total_reports']}</div></div>
            <div class="stat-card highlight"><div class="stat-label">Total IOCs</div><div class="stat-value">{metrics['total_iocs']}</div></div>
            <div class="stat-card"><div class="stat-label">MITRE Techniques</div><div class="stat-value">{len(metrics['mitre_techniques'])}</div></div>
            <div class="stat-card"><div class="stat-label">Threat Actors</div><div class="stat-value">{len(metrics['threat_actors'])}</div></div>
        </div>
        
        <div class="charts-grid">
            <div class="chart-card">
                <h3>Reports Timeline</h3>
                <div class="chart-container"><canvas id="timelineChart"></canvas></div>
            </div>
            <div class="chart-card">
                <h3>IOC Distribution</h3>
                <div class="chart-container"><canvas id="iocChart"></canvas></div>
            </div>
            <div class="chart-card">
                <h3>Confidence Distribution</h3>
                <div class="chart-container short"><canvas id="confChart"></canvas></div>
            </div>
            <div class="chart-card">
                <h3>Top MITRE ATT&CK Techniques</h3>
                <div class="chart-container"><canvas id="mitreChart"></canvas></div>
            </div>
            {f'<div class="chart-card wide"><h3>Threat Actor Attribution</h3><div class="chart-container short"><canvas id="actorChart"></canvas></div></div>' if actor_data else ''}
        </div>
        
        <div class="tables-grid">
            <div class="table-card">
                <h3>Cross-Report IOC Correlation</h3>
                <table>
                    <thead><tr><th>Indicator</th><th>Type</th><th>Reports</th><th>Confidence</th></tr></thead>
                    <tbody>{common_iocs_rows if common_iocs_rows else '<tr><td colspan="4" class="empty">No cross-report IOCs</td></tr>'}</tbody>
                </table>
            </div>
            <div class="table-card">
                <h3>Recent Intelligence Reports</h3>
                <table>
                    <thead><tr><th>Report</th><th>Date</th><th>Sources</th><th>IOCs</th></tr></thead>
                    <tbody>{recent_reports_rows if recent_reports_rows else '<tr><td colspan="4" class="empty">No reports</td></tr>'}</tbody>
                </table>
            </div>
        </div>
        
        <footer>PEAK CTI v3.2.0{f' | <a href="{repo_url}">Repository</a>' if repo_url else ''}</footer>
    </div>
    
    <script>
        Chart.defaults.color = '#71717a';
        Chart.defaults.borderColor = '#27272a';
        Chart.defaults.font.family = "-apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif";
        
        const slateColors = ['#475569', '#64748b', '#94a3b8', '#334155', '#1e293b', '#0f172a', '#cbd5e1', '#e2e8f0'];
        
        // Timeline
        new Chart(document.getElementById('timelineChart'), {{
            type: 'bar',
            data: {{
                labels: {json.dumps(months)},
                datasets: [{{ data: {json.dumps(month_counts)}, backgroundColor: '#475569', borderRadius: 3 }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{ legend: {{ display: false }} }},
                scales: {{
                    x: {{ grid: {{ display: false }} }},
                    y: {{ beginAtZero: true, ticks: {{ stepSize: 1 }} }}
                }}
            }}
        }});
        
        // IOC Distribution
        new Chart(document.getElementById('iocChart'), {{
            type: 'doughnut',
            data: {{
                labels: {json.dumps(ioc_labels)},
                datasets: [{{ data: {json.dumps(ioc_counts)}, backgroundColor: slateColors.slice(0, {len(ioc_labels)}), borderWidth: 0 }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                cutout: '60%',
                plugins: {{ legend: {{ position: 'right', labels: {{ boxWidth: 12, padding: 12 }} }} }}
            }}
        }});
        
        // Confidence
        new Chart(document.getElementById('confChart'), {{
            type: 'bar',
            data: {{
                labels: [''],
                datasets: [
                    {{ label: 'HIGH', data: [{metrics['ioc_confidence']['high']}], backgroundColor: '#475569' }},
                    {{ label: 'MEDIUM', data: [{metrics['ioc_confidence']['medium']}], backgroundColor: '#64748b' }},
                    {{ label: 'LOW', data: [{metrics['ioc_confidence']['low']}], backgroundColor: '#94a3b8' }}
                ]
            }},
            options: {{
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{ legend: {{ position: 'bottom', labels: {{ boxWidth: 12, padding: 16 }} }} }},
                scales: {{
                    x: {{ stacked: true, grid: {{ display: false }} }},
                    y: {{ stacked: true, display: false }}
                }}
            }}
        }});
        
        // MITRE
        const mitreLabels = {json.dumps([t['label'] for t in tech_data])};
        const mitreCounts = {json.dumps([t['count'] for t in tech_data])};
        new Chart(document.getElementById('mitreChart'), {{
            type: 'bar',
            data: {{
                labels: mitreLabels,
                datasets: [{{ data: mitreCounts, backgroundColor: '#475569', borderRadius: 2 }}]
            }},
            options: {{
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{ legend: {{ display: false }} }},
                scales: {{
                    x: {{ beginAtZero: true, ticks: {{ stepSize: 1 }}, grid: {{ display: false }} }},
                    y: {{ grid: {{ display: false }} }}
                }}
            }}
        }});
        
        // Actors
        const actorEl = document.getElementById('actorChart');
        if (actorEl) {{
            const actorLabels = {json.dumps([a[0] for a in actor_data])};
            const actorCounts = {json.dumps([a[1] for a in actor_data])};
            new Chart(actorEl, {{
                type: 'bar',
                data: {{
                    labels: actorLabels,
                    datasets: [{{ data: actorCounts, backgroundColor: '#475569', borderRadius: 2 }}]
                }},
                options: {{
                    indexAxis: 'y',
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{ legend: {{ display: false }} }},
                    scales: {{
                        x: {{ beginAtZero: true, ticks: {{ stepSize: 1 }}, grid: {{ display: false }} }},
                        y: {{ grid: {{ display: false }} }}
                    }}
                }}
            }});
        }}
    </script>
</body>
</html>'''
    
    return html


def generate_empty_dashboard() -> str:
    return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>PEAK CTI Dashboard</title>
    <style>
        body { font-family: system-ui, sans-serif; background: #09090b; color: #fafafa; min-height: 100vh; display: flex; align-items: center; justify-content: center; margin: 0; }
        .empty { text-align: center; }
        .logo { font-size: 24px; font-weight: 600; margin-bottom: 8px; }
        .logo span { color: #71717a; font-weight: 400; }
        p { color: #71717a; }
    </style>
</head>
<body>
    <div class="empty">
        <div class="logo">PEAK CTI <span>Dashboard</span></div>
        <p>No data available. Submit an issue to get started.</p>
    </div>
</body>
</html>'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", default="data/ioc_database.json")
    parser.add_argument("--output", default="dashboard/index.html")
    parser.add_argument("--output-html")
    parser.add_argument("--output-stats")
    parser.add_argument("--reports-dir", default="reports")
    parser.add_argument("--repo-url", default="")
    args = parser.parse_args()
    
    output_path = Path(args.output_html if args.output_html else args.output)
    db_path = Path(args.database)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    database = load_ioc_database(db_path)
    
    if not database.get("reports"):
        html = generate_empty_dashboard()
        metrics = {"total_reports": 0, "total_iocs": 0, "mitre_techniques": {}, "threat_actors": {}, "ioc_confidence": {"high": 0, "medium": 0, "low": 0}, "top_techniques": [], "top_actors": [], "iocs_by_type": {}, "mitre_names": {}, "recent_reports": [], "ioc_prevalence": {"top_common": []}}
    else:
        metrics = calculate_metrics(database)
        html = generate_dashboard_html(metrics, args.repo_url)
    
    output_path.write_text(html)
    print(f"Dashboard: {output_path}")
    
    if args.output_stats:
        stats = f"""# PEAK CTI Statistics

Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}

| Metric | Value |
|--------|-------|
| Reports | {metrics['total_reports']} |
| IOCs | {metrics['total_iocs']} |
| MITRE Techniques | {len(metrics['mitre_techniques'])} |
| Threat Actors | {len(metrics['threat_actors'])} |

## Confidence

| Level | Count |
|-------|-------|
| HIGH | {metrics['ioc_confidence']['high']} |
| MEDIUM | {metrics['ioc_confidence']['medium']} |
| LOW | {metrics['ioc_confidence']['low']} |
"""
        Path(args.output_stats).write_text(stats)


if __name__ == "__main__":
    main()
