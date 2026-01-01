#!/usr/bin/env python3
"""PEAK CTI - Source Duplicate Checker

Supports:
- URL duplicate detection (normalized URLs)
- File duplicate detection (SHA256 hash of file content)
"""
import json
import sys
import hashlib
from pathlib import Path
from urllib.parse import urlparse
import argparse


def normalize_url(url):
    """Normalize URL for comparison."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc.lower()}{parsed.path.rstrip('/')}"


def compute_file_hash(file_path: Path) -> str:
    """Compute SHA256 hash of a file."""
    if not file_path.exists():
        return ""
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            sha256.update(chunk)
    return sha256.hexdigest()


def check_duplicate(source: str, database_path: Path, is_file: bool = False, inputs_dir: Path = None):
    """Check if source (URL or file) exists in database."""
    if not database_path.exists():
        return {'is_duplicate': False}
    
    with open(database_path) as f:
        database = json.load(f)
    
    sources_index = database.get('sources', {})
    
    if is_file:
        # For files, compute SHA256 and check against hash index
        if inputs_dir is None:
            inputs_dir = Path('inputs')
        
        # Resolve file path
        file_path = Path(source)
        if not file_path.exists():
            # Try under inputs directory
            file_path = inputs_dir / Path(source).name
        if not file_path.exists() and source.startswith('inputs/'):
            file_path = Path(source)
        
        if not file_path.exists():
            return {'is_duplicate': False, 'error': f'File not found: {source}'}
        
        file_hash = compute_file_hash(file_path)
        lookup_key = f"sha256:{file_hash}"
        
        if lookup_key in sources_index:
            report_path = sources_index[lookup_key]
            metadata = database['reports'].get(report_path, {}).get('metadata', {})
            return {
                'is_duplicate': True,
                'report_path': report_path,
                'issue_number': metadata.get('issue_number'),
                'title': metadata.get('title'),
                'match_type': 'file_hash',
                'file_hash': file_hash,
            }
        
        return {'is_duplicate': False, 'file_hash': file_hash}
    
    else:
        # URL duplicate check
        normalized = normalize_url(source)
        
        if normalized in sources_index:
            report_path = sources_index[normalized]
            metadata = database['reports'].get(report_path, {}).get('metadata', {})
            return {
                'is_duplicate': True,
                'report_path': report_path,
                'issue_number': metadata.get('issue_number'),
                'title': metadata.get('title'),
                'match_type': 'url',
            }
        
        return {'is_duplicate': False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', help='URL to check (for URL sources)')
    parser.add_argument('--file', help='File path to check (for file sources)')
    parser.add_argument('--issue-number', type=int, required=True)
    parser.add_argument('--database', default='data/ioc_database.json')
    parser.add_argument('--inputs-dir', default='inputs', help='Directory containing input files')
    parser.add_argument('--github-output', help='GitHub Actions output file')
    parser.add_argument('--quiet', '-q', action='store_true', help='Suppress output (exit code only)')
    args = parser.parse_args()
    
    if not args.url and not args.file:
        print("ERROR: Either --url or --file must be provided")
        sys.exit(1)
    
    is_file = bool(args.file)
    source = args.file if is_file else args.url
    
    result = check_duplicate(
        source=source,
        database_path=Path(args.database),
        is_file=is_file,
        inputs_dir=Path(args.inputs_dir)
    )
    
    if result.get('error') and not args.quiet:
        print(f"⚠️  Warning: {result['error']}")
    
    if result['is_duplicate']:
        if not args.quiet:
            match_type = result.get('match_type', 'unknown')
            print(f"\n🔴 DUPLICATE DETECTED! (matched by {match_type})")
            print(f"   Report: {result['report_path']}")
            print(f"   Issue: #{result.get('issue_number', 'unknown')}")
            print(f"   Title: {result.get('title', 'unknown')}")
            if result.get('file_hash'):
                print(f"   SHA256: {result['file_hash']}")
        
        if args.github_output:
            with open(args.github_output, 'a') as f:
                f.write(f"duplicate=true\n")
                f.write(f"report_path={result['report_path']}\n")
                if result.get('file_hash'):
                    f.write(f"file_hash={result['file_hash']}\n")
        
        sys.exit(1)
    else:
        if not args.quiet:
            print("✅ No duplicate - proceeding")
            if result.get('file_hash'):
                print(f"   SHA256: {result['file_hash']}")
        
        if args.github_output:
            with open(args.github_output, 'a') as f:
                f.write(f"duplicate=false\n")
                if result.get('file_hash'):
                    f.write(f"file_hash={result['file_hash']}\n")
        
        sys.exit(0)


if __name__ == '__main__':
    main()
