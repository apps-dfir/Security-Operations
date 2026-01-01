#!/usr/bin/env python3
"""PEAK CTI - Actor Profile Updater"""
import json
import re
from pathlib import Path
from datetime import datetime
import argparse

def load_or_create_profile(profiles_dir, actor_name):
    """Load or create actor profile."""
    profile_path = profiles_dir / f"{actor_name.lower()}.json"
    
    if profile_path.exists():
        with open(profile_path) as f:
            return json.load(f)
    
    return {
        'actor_name': actor_name.upper(),
        'first_seen': datetime.now().date().isoformat(),
        'last_updated': datetime.now().isoformat(),
        'reports': [],
        'techniques': {},
    }

def extract_from_report(report_path):
    """Extract data from report."""
    content = report_path.read_text(encoding='utf-8')
    
    data = {'title': '', 'issue_number': None, 'techniques': []}
    
    title_match = re.search(r'^# (.+)$', content, re.MULTILINE)
    if title_match:
        data['title'] = title_match.group(1).strip()
    
    issue_match = re.search(r'\*\*Issue:\*\* (\d+)', content)
    if issue_match:
        data['issue_number'] = int(issue_match.group(1))
    
    data['techniques'] = re.findall(r'- \*\*([T]\d{4}\.?\d*)\*\*', content)
    
    return data

def update_profile(profile, report_data):
    """Update profile with report data."""
    if report_data['issue_number']:
        if not any(r['issue'] == report_data['issue_number'] for r in profile['reports']):
            profile['reports'].append({
                'issue': report_data['issue_number'],
                'title': report_data['title'],
                'date': datetime.now().isoformat(),
            })
    
    for tech in report_data['techniques']:
        if tech not in profile['techniques']:
            profile['techniques'][tech] = {'count': 0}
        profile['techniques'][tech]['count'] += 1
    
    profile['last_updated'] = datetime.now().isoformat()
    return profile

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--actor', required=True)
    parser.add_argument('--report', required=True)
    parser.add_argument('--profiles-dir', default='profiles')
    args = parser.parse_args()
    
    profiles_dir = Path(args.profiles_dir)
    profiles_dir.mkdir(parents=True, exist_ok=True)
    
    profile = load_or_create_profile(profiles_dir, args.actor)
    report_data = extract_from_report(Path(args.report))
    profile = update_profile(profile, report_data)
    
    profile_path = profiles_dir / f"{args.actor.lower()}.json"
    with open(profile_path, 'w') as f:
        json.dump(profile, f, indent=2)
    
    print(f"✅ Updated profile: {profile_path}")
    return 0

if __name__ == '__main__':
    exit(main())
