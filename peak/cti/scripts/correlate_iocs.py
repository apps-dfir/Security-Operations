#!/usr/bin/env python3
"""
PEAK CTI - IOC Correlation and Prevalence Tracker

Analyzes IOCs in a report against the historical database to show:
- Which IOCs have been seen before
- Which reports/campaigns they appeared in
- Generates a "Common Indicators" section with prevalence data
"""
import json
import re
import sys
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional
import argparse

try:
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from peak_reporter.defang_handler import normalize_ioc_for_comparison
except ImportError:
    def normalize_ioc_for_comparison(ioc):
        return ioc.lower().strip()


@dataclass
class IOCMatch:
    """Represents an IOC match with historical data."""
    ioc_type: str  # sha256, md5, domain, ipv4, etc.
    ioc_value: str
    seen_count: int = 0
    reports: list = field(default_factory=list)  # List of {title, issue_number, report_path}
    
    @property
    def is_common(self) -> bool:
        return self.seen_count > 1
    
    def report_titles(self) -> list[str]:
        return [r.get('title', 'Unknown') for r in self.reports]


def load_database(db_path: Path) -> dict:
    """Load the IOC database."""
    if not db_path.exists():
        return {'ioc_index': {}, 'reports': {}, 'metadata': {}}
    
    with open(db_path) as f:
        return json.load(f)


def extract_iocs_from_report(report_path: Path) -> dict:
    """Extract IOCs from a report file."""
    content = report_path.read_text(encoding='utf-8')
    iocs = defaultdict(list)
    
    lines = content.split('\n')
    current_section = None
    current_subsection = None
    
    for line in lines:
        # Detect sections
        if '### CVEs' in line:
            current_section = 'cves'
            current_subsection = None
        elif '### Domains' in line:
            current_section = 'domains'
            current_subsection = None
        elif '### IP Addresses' in line or '### IPv4' in line:
            current_section = 'ipv4'
            current_subsection = None
        elif '### URLs' in line:
            current_section = 'urls'
            current_subsection = None
        elif '### File Hashes' in line:
            current_section = 'hashes'
            current_subsection = None
        elif '**SHA256:**' in line or '#### SHA256' in line:
            current_section = 'hashes'
            current_subsection = 'sha256'
        elif '**SHA1:**' in line or '#### SHA1' in line:
            current_section = 'hashes'
            current_subsection = 'sha1'
        elif '**MD5:**' in line or '#### MD5' in line:
            current_section = 'hashes'
            current_subsection = 'md5'
        elif line.startswith('## ') and not line.startswith('### '):
            current_section = None
            current_subsection = None
        
        # Extract IOC values
        if current_section and '`' in line:
            match = re.search(r'`([^`]+)`', line)
            if match:
                value = match.group(1).strip()
                
                if current_section == 'hashes' and current_subsection:
                    iocs[current_subsection].append(value)
                elif current_section != 'hashes':
                    iocs[current_section].append(value)
    
    return dict(iocs)


def correlate_iocs(report_iocs: dict, database: dict, current_report_path: str = None) -> list[IOCMatch]:
    """
    Correlate report IOCs against the database.
    Returns list of IOCMatch objects for IOCs seen in other reports.
    """
    matches = []
    ioc_index = database.get('ioc_index', {})
    
    for ioc_type, ioc_values in report_iocs.items():
        for ioc_value in ioc_values:
            normalized = normalize_ioc_for_comparison(ioc_value)
            db_key = f"{ioc_type}:{normalized}"
            
            if db_key in ioc_index:
                historical = ioc_index[db_key]
                
                # Filter out current report if provided
                if current_report_path:
                    historical = [h for h in historical if h.get('report') != current_report_path]
                
                if historical:
                    match = IOCMatch(
                        ioc_type=ioc_type,
                        ioc_value=ioc_value,
                        seen_count=len(historical) + 1,  # +1 for current report
                        reports=historical
                    )
                    matches.append(match)
    
    # Sort by seen_count descending
    matches.sort(key=lambda x: x.seen_count, reverse=True)
    return matches


def generate_prevalence_section(matches: list[IOCMatch], repo_url: str = "") -> str:
    """
    Generate markdown section showing IOC prevalence.
    
    Example output:
    ## 🔄 Common Indicators (Seen in Previous Reports)
    
    | IOC | Type | Seen In | Reports |
    |-----|------|---------|---------|
    | `abc123...` | SHA256 | 3 reports | Scattered Spider, LummaC2, ... |
    """
    if not matches:
        return ""
    
    lines = [
        "## 🔄 Common Indicators (Seen in Previous Reports)",
        "",
        "> These IOCs have been observed in previous PEAK CTI reports, indicating potential threat actor overlap or shared infrastructure.",
        "",
    ]
    
    # Group by type
    by_type = defaultdict(list)
    for m in matches:
        by_type[m.ioc_type].append(m)
    
    # Type display names
    type_names = {
        'sha256': 'SHA256 Hashes',
        'sha1': 'SHA1 Hashes', 
        'md5': 'MD5 Hashes',
        'domains': 'Domains',
        'ipv4': 'IP Addresses',
        'urls': 'URLs',
        'cves': 'CVEs',
    }
    
    # Generate tables by type
    for ioc_type, type_matches in by_type.items():
        type_name = type_names.get(ioc_type, ioc_type.upper())
        lines.append(f"### {type_name}")
        lines.append("")
        lines.append("| IOC | Seen Count | Previous Reports |")
        lines.append("|-----|------------|------------------|")
        
        for m in type_matches[:20]:  # Limit to 20 per type
            # Truncate long IOCs
            display_ioc = m.ioc_value
            if len(display_ioc) > 20:
                display_ioc = f"{display_ioc[:8]}...{display_ioc[-8:]}"
            
            # Build report links
            report_links = []
            for r in m.reports[:5]:  # Show up to 5 reports
                title = r.get('title', 'Unknown')
                # Truncate long titles
                if len(title) > 30:
                    title = title[:27] + "..."
                
                issue_num = r.get('issue_number')
                if issue_num and repo_url:
                    report_links.append(f"[{title}]({repo_url}/issues/{issue_num})")
                elif issue_num:
                    report_links.append(f"{title} (#{issue_num})")
                else:
                    report_links.append(title)
            
            if len(m.reports) > 5:
                report_links.append(f"+{len(m.reports) - 5} more")
            
            reports_str = ", ".join(report_links) if report_links else "Unknown"
            
            lines.append(f"| `{display_ioc}` | {m.seen_count} | {reports_str} |")
        
        lines.append("")
    
    # Summary stats
    total_common = len(matches)
    high_prevalence = sum(1 for m in matches if m.seen_count >= 3)
    
    lines.append("### Summary")
    lines.append("")
    lines.append(f"- **Total Common IOCs:** {total_common}")
    lines.append(f"- **High Prevalence (3+ reports):** {high_prevalence}")
    lines.append("")
    
    return "\n".join(lines)


def generate_prevalence_badge(ioc_value: str, ioc_type: str, database: dict) -> str:
    """
    Generate a prevalence badge for an IOC.
    Returns: "🔴 COMMON (3)" or "" if not seen before
    """
    normalized = normalize_ioc_for_comparison(ioc_value)
    db_key = f"{ioc_type}:{normalized}"
    
    ioc_index = database.get('ioc_index', {})
    if db_key in ioc_index:
        count = len(ioc_index[db_key])
        if count >= 3:
            return f"🔴 COMMON ({count})"
        elif count >= 2:
            return f"🟠 SEEN ({count})"
        elif count >= 1:
            return f"🟡 PREV ({count})"
    return ""


def inject_prevalence_into_report(report_path: Path, database: dict, repo_url: str = "") -> str:
    """
    Read a report and inject prevalence information.
    Returns the modified report content.
    """
    content = report_path.read_text(encoding='utf-8')
    
    # Extract IOCs from the report
    report_iocs = extract_iocs_from_report(report_path)
    
    # Correlate with database
    matches = correlate_iocs(report_iocs, database, str(report_path))
    
    if not matches:
        return content  # No common IOCs found
    
    # Generate prevalence section
    prevalence_section = generate_prevalence_section(matches, repo_url)
    
    # Find insertion point - after IOCs section, before MITRE or Summary
    # Look for ## 🛡️ MITRE or ## Summary or ## 📚 Sources
    insertion_patterns = [
        r'(## 🛡️ MITRE)',
        r'(## MITRE)',
        r'(## Summary)',
        r'(## 📚 Sources)',
        r'(## 📄 Source Details)',
        r'(---\s*\n\*Generated by PEAK)',
    ]
    
    for pattern in insertion_patterns:
        match = re.search(pattern, content)
        if match:
            insert_pos = match.start()
            content = content[:insert_pos] + prevalence_section + "\n" + content[insert_pos:]
            break
    else:
        # If no insertion point found, append before footer
        if '---' in content:
            last_hr = content.rfind('---')
            content = content[:last_hr] + prevalence_section + "\n" + content[last_hr:]
        else:
            content += "\n" + prevalence_section
    
    return content


def get_prevalence_stats(database: dict) -> dict:
    """
    Get prevalence statistics from the database.
    Returns stats for dashboard display.
    """
    ioc_index = database.get('ioc_index', {})
    
    stats = {
        'total_unique_iocs': len(ioc_index),
        'common_iocs': 0,  # Seen in 2+ reports
        'high_prevalence': 0,  # Seen in 3+ reports
        'by_type': defaultdict(lambda: {'total': 0, 'common': 0}),
        'top_common': [],  # Top 10 most common IOCs
    }
    
    prevalence_list = []
    
    for ioc_key, reports in ioc_index.items():
        parts = ioc_key.split(':', 1)
        if len(parts) != 2:
            continue
        
        ioc_type, ioc_value = parts
        count = len(reports)
        
        stats['by_type'][ioc_type]['total'] += 1
        
        if count >= 2:
            stats['common_iocs'] += 1
            stats['by_type'][ioc_type]['common'] += 1
            prevalence_list.append({
                'ioc_type': ioc_type,
                'ioc_value': ioc_value,
                'count': count,
                'reports': [r.get('title', 'Unknown') for r in reports[:5]]
            })
        
        if count >= 3:
            stats['high_prevalence'] += 1
    
    # Sort by count and get top 10
    prevalence_list.sort(key=lambda x: x['count'], reverse=True)
    stats['top_common'] = prevalence_list[:10]
    stats['by_type'] = dict(stats['by_type'])
    
    return stats


def main():
    parser = argparse.ArgumentParser(description='IOC Correlation and Prevalence Tracker')
    parser.add_argument('--report', required=True, help='Report file to analyze')
    parser.add_argument('--database', default='data/ioc_database.json', help='IOC database path')
    parser.add_argument('--repo-url', default='', help='GitHub repo URL for links')
    parser.add_argument('--in-place', action='store_true', help='Modify report in place')
    parser.add_argument('--output', help='Output file (if not in-place)')
    parser.add_argument('--stats-only', action='store_true', help='Only output prevalence stats')
    args = parser.parse_args()
    
    report_path = Path(args.report)
    db_path = Path(args.database)
    
    if not report_path.exists():
        print(f"❌ Report not found: {report_path}")
        return 1
    
    # Load database
    database = load_database(db_path)
    
    if args.stats_only:
        # Just output prevalence statistics
        stats = get_prevalence_stats(database)
        print(json.dumps(stats, indent=2))
        return 0
    
    print(f"🔍 Analyzing IOC prevalence for: {report_path.name}")
    
    # Extract IOCs
    report_iocs = extract_iocs_from_report(report_path)
    total_iocs = sum(len(v) for v in report_iocs.values())
    print(f"   Found {total_iocs} IOCs in report")
    
    # Correlate
    matches = correlate_iocs(report_iocs, database, str(report_path))
    print(f"   Common IOCs (seen before): {len(matches)}")
    
    if matches:
        # Show top matches
        print(f"\n   Top common IOCs:")
        for m in matches[:5]:
            titles = ", ".join(m.report_titles()[:3])
            print(f"   - {m.ioc_type}:{m.ioc_value[:16]}... ({m.seen_count}x) - {titles}")
    
    # Generate modified report
    modified_content = inject_prevalence_into_report(report_path, database, args.repo_url)
    
    # Output
    if args.in_place:
        report_path.write_text(modified_content, encoding='utf-8')
        print(f"\n✅ Updated report in place: {report_path}")
    elif args.output:
        output_path = Path(args.output)
        output_path.write_text(modified_content, encoding='utf-8')
        print(f"\n✅ Written to: {output_path}")
    else:
        # Print to stdout
        print("\n" + "="*60)
        print(modified_content)
    
    return 0


if __name__ == '__main__':
    exit(main())
