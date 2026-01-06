#!/usr/bin/env python3
"""PEAK CTI - IOC Overlap Tagger"""
import json
import re
from pathlib import Path
from collections import defaultdict
import argparse

def find_overlapping_iocs(report_path, database):
    """Find IOCs that appear in multiple reports."""
    overlaps = defaultdict(list)
    report_key = str(report_path)
    
    if report_key not in database['reports']:
        return overlaps
    
    report_iocs = database['reports'][report_key].get('iocs', {})
    
    for ioc_type, ioc_list in report_iocs.items():
        for ioc_value in ioc_list:
            ioc_key = f"{ioc_type}:{ioc_value}"
            occurrences = database['ioc_index'].get(ioc_key, [])
            others = [o for o in occurrences if o['report'] != report_key]
            if others:
                overlaps[ioc_value] = others
    
    return overlaps

def tag_iocs(report_path, overlaps):
    """Add overlap tags to report."""
    content = report_path.read_text(encoding='utf-8')
    
    for ioc_value, occurrences in overlaps.items():
        count = len(occurrences) + 1
        issues = [str(o.get('issue_number', '?')) for o in occurrences[:5] if o.get('issue_number')]
        
        if issues:
            tag = f" *(Seen {count}x: Issue #{', #'.join(issues)})*"
            
            # Create pattern that matches both refanged and defanged versions
            # Escape special regex chars, then make dots optional [.]
            escaped = re.escape(ioc_value)
            # Handle defanged dots: domain.com -> domain[.]com
            defanged_pattern = escaped.replace(r'\.', r'(?:\[\.\]|\.)')
            # Also handle case insensitivity for the IOC value
            pattern = rf'(- [🟢🟡🔴] `{defanged_pattern}`)'
            content = re.sub(pattern, rf'\1{tag}', content, flags=re.IGNORECASE)
    
    return content

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', required=True)
    parser.add_argument('--database', default='data/ioc_database.json')
    parser.add_argument('--in-place', action='store_true')
    args = parser.parse_args()
    
    report_path = Path(args.report)
    database_path = Path(args.database)
    
    if not database_path.exists():
        print("No database - skipping")
        return 0
    
    with open(database_path) as f:
        database = json.load(f)
    
    overlaps = find_overlapping_iocs(report_path, database)
    
    if not overlaps:
        print("No overlapping IOCs")
        return 0
    
    print(f"Found {len(overlaps)} overlapping IOCs")
    
    tagged_content = tag_iocs(report_path, overlaps)
    
    if args.in_place:
        report_path.write_text(tagged_content, encoding='utf-8')
        print(f"Tagged {len(overlaps)} IOCs")
    
    return 0

if __name__ == '__main__':
    exit(main())
