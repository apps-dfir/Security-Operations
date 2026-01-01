#!/usr/bin/env python3
"""PEAK CTI - IOC Database Builder

Builds a searchable database of IOCs from PEAK CTI reports.
Supports both single-source and consolidated multi-source report formats.
"""
import json
import re
import sys
from pathlib import Path
from datetime import datetime
from collections import defaultdict
import argparse

try:
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from peak_reporter.defang_handler import normalize_ioc_for_comparison
except ImportError:
    def normalize_ioc_for_comparison(ioc):
        return ioc.lower().strip()


def extract_metadata(report_path):
    """Extract metadata from report (handles both single and consolidated formats)."""
    content = report_path.read_text(encoding='utf-8')
    metadata = {
        'report_path': str(report_path),
        'report_name': report_path.name,
        'title': None,
        'issue_number': None,
        'source_url': None,
        'source_urls': [],  # For multi-source reports
        'source_files': [],  # For file-based sources
        'file_hashes': [],  # SHA256 hashes of source files
    }
    
    # Title from first H1
    title_match = re.search(r'^# (.+)$', content, re.MULTILINE)
    if title_match:
        metadata['title'] = title_match.group(1).strip()
    
    # Issue number - try multiple formats
    # Format 1: **Issue:** #123 or **Issue:** [#123](url)
    issue_match = re.search(r'\*\*Issue:\*\*\s*\[?#?(\d+)', content)
    if issue_match:
        metadata['issue_number'] = int(issue_match.group(1))
    
    # Single source URL - Format: **Source:** [title](url) or **Source URL:** url
    source_match = re.search(r'\*\*Source(?:\s*URL)?:\*\*\s*(?:\[.*?\]\()?(https?://[^\s\)]+)', content)
    if source_match:
        metadata['source_url'] = source_match.group(1)
    
    # Multi-source URLs - Format: ## 📚 Sources followed by numbered list
    sources_section = re.search(r'## 📚 Sources\s*\n(.*?)(?=\n##|\Z)', content, re.DOTALL)
    if sources_section:
        # Match URLs: [title](url) format
        for match in re.finditer(r'\d+\.\s*\[.*?\]\((https?://[^\)]+)\)', sources_section.group(1)):
            metadata['source_urls'].append(match.group(1))
        
        # Match file paths: [filename](inputs/...) or just inputs/...
        # Format: 1. [filename.pdf](inputs/filename.pdf) or 1. inputs/filename.pdf
        for match in re.finditer(r'\d+\.\s*(?:\[.*?\]\()?(inputs/[^\s\)\]]+)', sources_section.group(1)):
            metadata['source_files'].append(match.group(1))
    
    # Extract file hashes if present
    # Format: <!-- FILE_HASHES: sha256_1,sha256_2,... -->
    hash_match = re.search(r'<!-- FILE_HASHES:\s*([a-f0-9,]+)\s*-->', content)
    if hash_match:
        metadata['file_hashes'] = [h.strip() for h in hash_match.group(1).split(',') if h.strip()]
    
    return metadata


def extract_iocs(report_path):
    """Extract IOCs from report (handles both formats with confidence badges)."""
    content = report_path.read_text(encoding='utf-8')
    iocs = defaultdict(list)
    
    lines = content.split('\n')
    current_section = None
    current_subsection = None
    
    for line in lines:
        # Main sections
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
        elif '### Windows Paths' in line:
            current_section = 'windows_paths'
            current_subsection = None
        elif '### Command Lines' in line:
            current_section = 'command_lines'
            current_subsection = None
        # Hash subsections
        elif '**SHA256:**' in line or '### SHA-256' in line:
            current_section = 'hashes'
            current_subsection = 'sha256'
        elif '**SHA1:**' in line or '### SHA-1' in line:
            current_section = 'hashes'
            current_subsection = 'sha1'
        elif '**MD5:**' in line or '### MD5' in line:
            current_section = 'hashes'
            current_subsection = 'md5'
        # End of IOC sections
        elif line.startswith('## ') and not line.startswith('### '):
            current_section = None
            current_subsection = None
        
        # Extract IOC value from line (handles confidence badges)
        # Format: - 🟢 `value` [[1]](url) or - `value` [[1]](url)
        if current_section and '`' in line:
            match = re.search(r'`([^`]+)`', line)
            if match:
                value = normalize_ioc_for_comparison(match.group(1))
                
                if current_section == 'hashes' and current_subsection:
                    iocs[current_subsection].append(value)
                elif current_section != 'hashes':
                    iocs[current_section].append(value)
    
    return {k: sorted(list(set(v))) for k, v in iocs.items()}


def build_database(reports_dir):
    """Build IOC database from all reports."""
    database = {
        'metadata': {
            'generated': datetime.now().isoformat(),
            'total_reports': 0,
            'total_iocs': 0,
        },
        'ioc_index': defaultdict(list),
        'reports': {},
        'sources': {},
    }
    
    for report_path in sorted(reports_dir.glob('issue-*.md')):
        print(f"  Processing {report_path.name}")
        
        metadata = extract_metadata(report_path)
        iocs = extract_iocs(report_path)
        
        report_key = str(report_path)
        database['reports'][report_key] = {
            'metadata': metadata,
            'iocs': iocs,
        }
        
        # Index single source URL
        if metadata['source_url']:
            normalized_url = metadata['source_url'].rstrip('/')
            database['sources'][normalized_url] = report_key
        
        # Index multi-source URLs
        for url in metadata['source_urls']:
            normalized_url = url.rstrip('/')
            database['sources'][normalized_url] = report_key
        
        # Index file hashes (SHA256)
        for file_hash in metadata.get('file_hashes', []):
            if file_hash and len(file_hash) == 64:  # Valid SHA256
                database['sources'][f"sha256:{file_hash}"] = report_key
        
        # Build IOC index
        for ioc_type, ioc_list in iocs.items():
            for ioc_value in ioc_list:
                ioc_key = f"{ioc_type}:{ioc_value}"
                database['ioc_index'][ioc_key].append({
                    'report': report_key,
                    'issue_number': metadata['issue_number'],
                    'title': metadata['title'],
                })
    
    database['metadata']['total_reports'] = len(database['reports'])
    database['metadata']['total_iocs'] = len(database['ioc_index'])
    database['ioc_index'] = dict(database['ioc_index'])
    
    return database


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--reports-dir', default='reports')
    parser.add_argument('--output', default='data/ioc_database.json')
    parser.add_argument('--pretty', action='store_true')
    args = parser.parse_args()
    
    reports_dir = Path(args.reports_dir)
    if not reports_dir.exists():
        print(f"❌ Directory not found: {reports_dir}")
        return 1
    
    print("Building IOC database...")
    database = build_database(reports_dir)
    
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w') as f:
        json.dump(database, f, indent=2 if args.pretty else None)
    
    print(f"\n✅ Database built: {output_path}")
    print(f"   Reports: {database['metadata']['total_reports']}")
    print(f"   Unique IOCs: {database['metadata']['total_iocs']}")
    print(f"   Source URLs indexed: {len(database['sources'])}")
    
    return 0


if __name__ == '__main__':
    exit(main())
