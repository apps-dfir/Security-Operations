#!/usr/bin/env python3
"""
PEAK CTI - Enhanced Dashboard Generator

Generates an interactive HTML dashboard using Plotly with:
- MITRE ATT&CK TTP tracking
- IOC statistics by type
- Threat Actor profiles
- Report timeline and counts
- Quick stats summary
"""
import json
import re
from pathlib import Path
from datetime import datetime
from collections import defaultdict
import argparse


def collect_comprehensive_metrics(reports_dir: Path, database_path: Path) -> dict:
    """Collect comprehensive metrics for dashboard."""
    metrics = {
        'generated': datetime.now().isoformat(),
        'total_reports': 0,
        'total_iocs': 0,
        'total_sources': 0,
        
        # Timeline data
        'reports_by_month': {},
        'reports_by_week': {},
        
        # IOC breakdown
        'iocs_by_type': {
            'ipv4': 0,
            'domains': 0,
            'urls': 0,
            'sha256': 0,
            'sha1': 0,
            'md5': 0,
            'cves': 0,
        },
        
        # IOC Prevalence tracking
        'ioc_prevalence': {
            'common_iocs': 0,  # Seen in 2+ reports
            'high_prevalence': 0,  # Seen in 3+ reports
            'top_common': [],  # Top 10 most common IOCs with report links
        },
        
        # MITRE data
        'mitre_tactics': {},
        'mitre_techniques': {},
        'top_techniques': [],
        
        # Threat actors (extracted from report titles/content)
        'threat_actors': {},
        
        # Recent reports
        'recent_reports': [],
        
        # Sources
        'sources_by_type': {'url': 0, 'file': 0},
    }
    
    # Load database if exists
    if database_path.exists():
        with open(database_path) as f:
            db = json.load(f)
            metrics['total_reports'] = db.get('metadata', {}).get('total_reports', 0)
            metrics['total_iocs'] = db.get('metadata', {}).get('total_iocs', 0)
            metrics['total_sources'] = len(db.get('sources', {}))
            
            # Count IOCs by type and track prevalence
            ioc_index = db.get('ioc_index', {})
            prevalence_list = []
            
            for ioc_key, reports in ioc_index.items():
                ioc_type = ioc_key.split(':')[0] if ':' in ioc_key else 'unknown'
                ioc_value = ioc_key.split(':', 1)[1] if ':' in ioc_key else ioc_key
                
                if ioc_type in metrics['iocs_by_type']:
                    metrics['iocs_by_type'][ioc_type] += 1
                
                # Track prevalence
                count = len(reports)
                if count >= 2:
                    metrics['ioc_prevalence']['common_iocs'] += 1
                    prevalence_list.append({
                        'ioc_type': ioc_type,
                        'ioc_value': ioc_value,
                        'count': count,
                        'reports': [r.get('title', 'Unknown')[:30] for r in reports[:5]]
                    })
                if count >= 3:
                    metrics['ioc_prevalence']['high_prevalence'] += 1
            
            # Sort and get top 10 common IOCs
            prevalence_list.sort(key=lambda x: x['count'], reverse=True)
            metrics['ioc_prevalence']['top_common'] = prevalence_list[:10]
    
    # Process reports
    report_files = sorted(reports_dir.glob('issue-*.md'), reverse=True)
    
    # Known threat actors to look for
    known_actors = [
        'APT28', 'APT29', 'APT41', 'Lazarus', 'Kimsuky', 'Sandworm',
        'Scattered Spider', 'ALPHV', 'BlackCat', 'LockBit', 'Clop',
        'FIN7', 'FIN11', 'UNC', 'TA', 'Volt Typhoon', 'Salt Typhoon',
        'Midnight Blizzard', 'Cozy Bear', 'Fancy Bear', 'GRU',
        'LummaStealer', 'LummaC2', 'DarkGate', 'QakBot', 'Emotet',
    ]
    
    for report in report_files:
        content = report.read_text(encoding='utf-8')
        
        # Extract date
        date_match = re.search(r'\*\*Generated:\*\* (\d{4}-\d{2}-\d{2})', content)
        if date_match:
            date_str = date_match.group(1)
            month = date_str[:7]  # YYYY-MM
            week = f"{date_str[:4]}-W{int(date_str[8:10])//7+1:02d}"
            
            metrics['reports_by_month'][month] = metrics['reports_by_month'].get(month, 0) + 1
            metrics['reports_by_week'][week] = metrics['reports_by_week'].get(week, 0) + 1
        
        # Extract MITRE techniques
        # Format: T1234 or T1234.001 (with or without markdown bold)
        techniques = re.findall(r'\b(T\d{4}(?:\.\d{3})?)\b', content)
        for tech in techniques:
            metrics['mitre_techniques'][tech] = metrics['mitre_techniques'].get(tech, 0) + 1
        
        # Extract tactics from technique IDs or explicit mentions
        tactics_found = re.findall(r'(?:Initial Access|Execution|Persistence|Privilege Escalation|Defense Evasion|Credential Access|Discovery|Lateral Movement|Collection|Command and Control|Exfiltration|Impact)', content)
        for tactic in tactics_found:
            metrics['mitre_tactics'][tactic] = metrics['mitre_tactics'].get(tactic, 0) + 1
        
        # Extract threat actors
        for actor in known_actors:
            if actor.lower() in content.lower():
                metrics['threat_actors'][actor] = metrics['threat_actors'].get(actor, 0) + 1
        
        # Recent reports (last 10)
        if len(metrics['recent_reports']) < 10:
            title_match = re.search(r'^# (.+)$', content, re.MULTILINE)
            issue_match = re.search(r'\*\*Issue:\*\*\s*\[?#?(\d+)', content)
            
            metrics['recent_reports'].append({
                'filename': report.name,
                'title': title_match.group(1) if title_match else report.stem,
                'issue': int(issue_match.group(1)) if issue_match else 0,
                'date': date_str if date_match else 'Unknown',
            })
    
    # Sort techniques by count
    sorted_techniques = sorted(
        metrics['mitre_techniques'].items(),
        key=lambda x: x[1],
        reverse=True
    )
    metrics['top_techniques'] = sorted_techniques[:15]
    
    return metrics


def generate_stats_table(metrics: dict) -> str:
    """Generate markdown stats table for README."""
    
    # Top threat actors
    top_actors = sorted(metrics['threat_actors'].items(), key=lambda x: x[1], reverse=True)[:5]
    actors_str = ', '.join([f"{a[0]} ({a[1]})" for a in top_actors]) if top_actors else 'None tracked yet'
    
    # Top techniques  
    top_techs = metrics['top_techniques'][:5]
    techs_str = ', '.join([f"{t[0]} ({t[1]})" for t in top_techs]) if top_techs else 'None tracked yet'
    
    # Common IOCs
    prevalence = metrics.get('ioc_prevalence', {})
    common_count = prevalence.get('common_iocs', 0)
    high_prev = prevalence.get('high_prevalence', 0)
    
    # Build common IOCs table
    common_iocs_md = ""
    top_common = prevalence.get('top_common', [])
    if top_common:
        common_iocs_md = "\n| IOC | Type | Seen In | Reports |\n|-----|------|---------|---------|"
        for ioc in top_common[:5]:
            ioc_val = ioc.get('ioc_value', '')[:20]
            if len(ioc.get('ioc_value', '')) > 20:
                ioc_val = f"{ioc_val[:8]}...{ioc.get('ioc_value', '')[-8:]}"
            ioc_type = ioc.get('ioc_type', '').upper()
            count = ioc.get('count', 0)
            reports = ', '.join(ioc.get('reports', [])[:2])
            common_iocs_md += f"\n| `{ioc_val}` | {ioc_type} | {count} | {reports} |"
    else:
        common_iocs_md = "\n*No common IOCs detected yet*"
    
    table = f"""## 📊 PEAK CTI Statistics

| Metric | Value |
|--------|-------|
| **Total Reports** | {metrics['total_reports']} |
| **Total IOCs** | {metrics['total_iocs']} |
| **Sources Indexed** | {metrics['total_sources']} |
| **Common IOCs** | {common_count} |
| **High Prevalence (3+)** | {high_prev} |
| **Last Updated** | {metrics['generated'][:19]} |

### IOC Breakdown

| Type | Count |
|------|-------|
| IPv4 Addresses | {metrics['iocs_by_type'].get('ipv4', 0)} |
| Domains | {metrics['iocs_by_type'].get('domains', 0)} |
| URLs | {metrics['iocs_by_type'].get('urls', 0)} |
| SHA256 Hashes | {metrics['iocs_by_type'].get('sha256', 0)} |
| SHA1 Hashes | {metrics['iocs_by_type'].get('sha1', 0)} |
| MD5 Hashes | {metrics['iocs_by_type'].get('md5', 0)} |
| CVEs | {metrics['iocs_by_type'].get('cves', 0)} |

### 🔄 Common IOCs Across Reports

IOCs seen in multiple reports indicate potential threat actor overlap or shared infrastructure.
{common_iocs_md}

### Top MITRE Techniques

{techs_str}

### Tracked Threat Actors

{actors_str}

---
*Auto-generated by PEAK CTI Dashboard*
"""
    return table


def generate_html_dashboard(metrics: dict, repo_url: str = "") -> str:
    """Generate interactive HTML dashboard with Plotly."""
    
    # Prepare data for charts
    months = sorted(metrics['reports_by_month'].keys())
    month_counts = [metrics['reports_by_month'][m] for m in months]
    
    ioc_types = list(metrics['iocs_by_type'].keys())
    ioc_counts = [metrics['iocs_by_type'][t] for t in ioc_types]
    
    tech_names = [t[0] for t in metrics['top_techniques']]
    tech_counts = [t[1] for t in metrics['top_techniques']]
    
    tactic_names = list(metrics['mitre_tactics'].keys())
    tactic_counts = [metrics['mitre_tactics'][t] for t in tactic_names]
    
    actor_names = list(metrics['threat_actors'].keys())[:10]
    actor_counts = [metrics['threat_actors'][a] for a in actor_names]
    
    # Recent reports HTML
    recent_html = ""
    for r in metrics['recent_reports']:
        issue_link = f"{repo_url}/issues/{r['issue']}" if repo_url and r['issue'] else "#"
        recent_html += f"""
        <tr>
            <td><a href="{issue_link}">#{r['issue']}</a></td>
            <td>{r['title'][:50]}{'...' if len(r['title']) > 50 else ''}</td>
            <td>{r['date']}</td>
        </tr>"""
    
    # Common IOCs HTML
    common_iocs_html = ""
    for ioc in metrics['ioc_prevalence'].get('top_common', [])[:10]:
        ioc_value = ioc.get('ioc_value', '')
        # Truncate long IOCs
        display_ioc = ioc_value if len(ioc_value) <= 20 else f"{ioc_value[:8]}...{ioc_value[-8:]}"
        ioc_type = ioc.get('ioc_type', 'unknown').upper()
        count = ioc.get('count', 0)
        reports = ioc.get('reports', [])
        reports_str = ', '.join(reports[:3])
        if len(reports) > 3:
            reports_str += f' +{len(reports)-3} more'
        
        common_iocs_html += f"""
        <tr>
            <td><code>{display_ioc}</code></td>
            <td>{ioc_type}</td>
            <td>{count} reports</td>
            <td>{reports_str}</td>
        </tr>"""
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PEAK CTI Dashboard</title>
    <script src="https://cdn.plot.ly/plotly-2.27.0.min.js"></script>
    <style>
        :root {{
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --border-color: #30363d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --accent-blue: #58a6ff;
            --accent-green: #3fb950;
            --accent-purple: #a371f7;
            --accent-orange: #d29922;
            --accent-red: #f85149;
        }}
        
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        
        header {{
            text-align: center;
            padding: 30px 0;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 30px;
        }}
        
        header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            background: linear-gradient(90deg, var(--accent-blue), var(--accent-purple));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 24px;
            text-align: center;
            transition: transform 0.2s, box-shadow 0.2s;
        }}
        
        .stat-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        }}
        
        .stat-value {{
            font-size: 2.5em;
            font-weight: bold;
            color: var(--accent-blue);
            margin-bottom: 8px;
        }}
        
        .stat-card:nth-child(2) .stat-value {{ color: var(--accent-green); }}
        .stat-card:nth-child(3) .stat-value {{ color: var(--accent-purple); }}
        .stat-card:nth-child(4) .stat-value {{ color: var(--accent-orange); }}
        
        .stat-label {{
            color: var(--text-secondary);
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .charts-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .chart-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 20px;
        }}
        
        .chart-card h3 {{
            margin-bottom: 15px;
            color: var(--text-primary);
            font-size: 1.1em;
        }}
        
        .full-width {{
            grid-column: 1 / -1;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }}
        
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}
        
        th {{
            background: var(--bg-tertiary);
            color: var(--text-secondary);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.8em;
            letter-spacing: 1px;
        }}
        
        td a {{
            color: var(--accent-blue);
            text-decoration: none;
        }}
        
        td a:hover {{
            text-decoration: underline;
        }}
        
        footer {{
            text-align: center;
            padding: 30px;
            color: var(--text-secondary);
            border-top: 1px solid var(--border-color);
            margin-top: 30px;
        }}
        
        @media (max-width: 768px) {{
            .charts-grid {{
                grid-template-columns: 1fr;
            }}
            .stats-grid {{
                grid-template-columns: repeat(2, 1fr);
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🎯 PEAK CTI Dashboard</h1>
            <p>Cyber Threat Intelligence Analytics</p>
            <p style="color: var(--text-secondary); font-size: 0.9em;">Last updated: {metrics['generated'][:19]}</p>
        </header>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{metrics['total_reports']}</div>
                <div class="stat-label">Total Reports</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{metrics['total_iocs']:,}</div>
                <div class="stat-label">IOCs Tracked</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{len(metrics['mitre_techniques'])}</div>
                <div class="stat-label">MITRE Techniques</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{len(metrics['threat_actors'])}</div>
                <div class="stat-label">Threat Actors</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: var(--accent-red);">{metrics['ioc_prevalence']['common_iocs']}</div>
                <div class="stat-label">Common IOCs</div>
            </div>
        </div>
        
        <div class="charts-grid">
            <div class="chart-card">
                <h3>📈 Reports Over Time</h3>
                <div id="timeline-chart"></div>
            </div>
            
            <div class="chart-card">
                <h3>🎯 IOC Distribution</h3>
                <div id="ioc-chart"></div>
            </div>
            
            <div class="chart-card">
                <h3>⚔️ Top MITRE Techniques</h3>
                <div id="technique-chart"></div>
            </div>
            
            <div class="chart-card">
                <h3>🏴‍☠️ Threat Actors</h3>
                <div id="actor-chart"></div>
            </div>
            
            <div class="chart-card full-width">
                <h3>🔄 Common IOCs Across Reports</h3>
                <p style="color: var(--text-secondary); margin-bottom: 15px;">IOCs seen in multiple reports - potential threat actor overlap or shared infrastructure</p>
                <table>
                    <thead>
                        <tr>
                            <th>IOC</th>
                            <th>Type</th>
                            <th>Seen In</th>
                            <th>Reports</th>
                        </tr>
                    </thead>
                    <tbody>
                        {common_iocs_html if common_iocs_html else '<tr><td colspan="4" style="text-align:center;color:var(--text-secondary)">No common IOCs yet</td></tr>'}
                    </tbody>
                </table>
            </div>
            
            <div class="chart-card full-width">
                <h3>📋 Recent Reports</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Issue</th>
                            <th>Title</th>
                            <th>Date</th>
                        </tr>
                    </thead>
                    <tbody>
                        {recent_html if recent_html else '<tr><td colspan="3" style="text-align:center;color:var(--text-secondary)">No reports yet</td></tr>'}
                    </tbody>
                </table>
            </div>
        </div>
        
        <footer>
            <p>Generated by PEAK CTI v3.0 | Powered by Plotly</p>
        </footer>
    </div>
    
    <script>
        const plotlyConfig = {{
            responsive: true,
            displayModeBar: false
        }};
        
        const plotlyLayout = {{
            paper_bgcolor: 'rgba(0,0,0,0)',
            plot_bgcolor: 'rgba(0,0,0,0)',
            font: {{ color: '#c9d1d9', family: '-apple-system, BlinkMacSystemFont, Segoe UI, Helvetica, Arial' }},
            margin: {{ l: 50, r: 30, t: 30, b: 50 }},
            xaxis: {{ gridcolor: '#30363d', linecolor: '#30363d' }},
            yaxis: {{ gridcolor: '#30363d', linecolor: '#30363d' }}
        }};
        
        // Timeline Chart
        Plotly.newPlot('timeline-chart', [{{
            x: {json.dumps(months)},
            y: {json.dumps(month_counts)},
            type: 'scatter',
            mode: 'lines+markers',
            fill: 'tozeroy',
            line: {{ color: '#58a6ff', width: 3 }},
            marker: {{ size: 8, color: '#58a6ff' }},
            fillcolor: 'rgba(88, 166, 255, 0.1)'
        }}], {{
            ...plotlyLayout,
            xaxis: {{ ...plotlyLayout.xaxis, title: 'Month' }},
            yaxis: {{ ...plotlyLayout.yaxis, title: 'Reports' }}
        }}, plotlyConfig);
        
        // IOC Distribution Chart
        Plotly.newPlot('ioc-chart', [{{
            labels: {json.dumps(ioc_types)},
            values: {json.dumps(ioc_counts)},
            type: 'pie',
            hole: 0.4,
            marker: {{
                colors: ['#58a6ff', '#3fb950', '#a371f7', '#d29922', '#f85149', '#8b949e', '#79c0ff']
            }},
            textinfo: 'label+percent',
            textfont: {{ color: '#c9d1d9' }}
        }}], {{
            ...plotlyLayout,
            showlegend: false
        }}, plotlyConfig);
        
        // MITRE Techniques Chart
        Plotly.newPlot('technique-chart', [{{
            x: {json.dumps(tech_counts)},
            y: {json.dumps(tech_names)},
            type: 'bar',
            orientation: 'h',
            marker: {{
                color: {json.dumps(tech_counts)},
                colorscale: [[0, '#3fb950'], [0.5, '#d29922'], [1, '#f85149']]
            }}
        }}], {{
            ...plotlyLayout,
            yaxis: {{ ...plotlyLayout.yaxis, autorange: 'reversed' }},
            xaxis: {{ ...plotlyLayout.xaxis, title: 'Occurrences' }}
        }}, plotlyConfig);
        
        // Threat Actors Chart
        Plotly.newPlot('actor-chart', [{{
            x: {json.dumps(actor_names)},
            y: {json.dumps(actor_counts)},
            type: 'bar',
            marker: {{
                color: '#a371f7',
                line: {{ color: '#8b5cf6', width: 1 }}
            }}
        }}], {{
            ...plotlyLayout,
            xaxis: {{ ...plotlyLayout.xaxis, tickangle: -45 }},
            yaxis: {{ ...plotlyLayout.yaxis, title: 'Mentions' }}
        }}, plotlyConfig);
    </script>
</body>
</html>"""
    
    return html


def main():
    parser = argparse.ArgumentParser(description='Generate PEAK CTI Dashboard')
    parser.add_argument('--reports-dir', default='reports', help='Reports directory')
    parser.add_argument('--database', default='data/ioc_database.json', help='IOC database path')
    parser.add_argument('--output-html', default='dashboard/index.html', help='HTML dashboard output')
    parser.add_argument('--output-stats', default='STATS.md', help='Stats markdown output')
    parser.add_argument('--repo-url', default='', help='GitHub repo URL for links')
    args = parser.parse_args()
    
    print("📊 Generating PEAK CTI Dashboard...")
    
    # Collect metrics
    metrics = collect_comprehensive_metrics(
        Path(args.reports_dir),
        Path(args.database)
    )
    
    print(f"   Reports: {metrics['total_reports']}")
    print(f"   IOCs: {metrics['total_iocs']}")
    print(f"   Techniques: {len(metrics['mitre_techniques'])}")
    print(f"   Threat Actors: {len(metrics['threat_actors'])}")
    
    # Generate HTML dashboard
    html = generate_html_dashboard(metrics, args.repo_url)
    html_path = Path(args.output_html)
    html_path.parent.mkdir(parents=True, exist_ok=True)
    html_path.write_text(html, encoding='utf-8')
    print(f"✅ Dashboard: {html_path}")
    
    # Generate stats table
    stats_md = generate_stats_table(metrics)
    stats_path = Path(args.output_stats)
    stats_path.write_text(stats_md, encoding='utf-8')
    print(f"✅ Stats: {stats_path}")
    
    # Save metrics JSON for other tools
    metrics_path = Path('data/dashboard_metrics.json')
    metrics_path.parent.mkdir(parents=True, exist_ok=True)
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding='utf-8')
    print(f"✅ Metrics: {metrics_path}")
    
    return 0


if __name__ == '__main__':
    exit(main())
