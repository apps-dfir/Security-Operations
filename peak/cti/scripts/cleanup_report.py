#!/usr/bin/env python3
"""
PEAK CTI Report Cleanup Script

Post-processes generated markdown reports to:
1. Remove empty IOC sections (e.g., "### SHA-256" with "- (none)")
2. Remove empty OCR image sections that have no extracted content
3. Collapse consecutive empty lines
4. Optionally remove analyst fill-in templates if requested
5. Add summary statistics at the top

Usage:
    python scripts/cleanup_report.py --input reports/issue-5_report.md --output reports/issue-5_report_clean.md
    python scripts/cleanup_report.py --input reports/issue-5_report.md --in-place
    python scripts/cleanup_report.py --input reports/issue-5_report.md --in-place --remove-templates
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import List, Tuple


def _count_iocs(content: str) -> dict[str, int]:
    """Count non-empty IOCs in the report."""
    counts = {
        'cves': 0,
        'urls': 0,
        'domains': 0,
        'ipv4': 0,
        'sha256': 0,
        'sha1': 0,
        'md5': 0,
        'windows_paths': 0,  # Fixed: was 'win_paths'
        'command_lines': 0,
        'mitre_techniques': 0,
        'ocr_images': 0,
    }
    
    # Count each IOC type by finding non-(none) items
    for section in ['CVEs', 'URLs', 'Domains', 'IPv4', 'SHA-256', 'SHA-1', 'MD5', 'Windows Paths', 'Command Lines']:
        pattern = rf'###+ {re.escape(section)}\n(.*?)(?=\n###|\n##|\Z)'
        matches = re.findall(pattern, content, re.DOTALL)
        for match in matches:
            # Count lines that start with "- " and are not "(none)"
            items = [line for line in match.split('\n') if line.strip().startswith('- ') and '(none)' not in line.lower()]
            key = section.lower().replace(' ', '_').replace('-', '')
            counts[key] += len(items)
    
    # Count MITRE techniques
    mitre_pattern = r'### Techniques Identified.*?\n(.*?)(?=\n###|\n##|\Z)'
    matches = re.findall(mitre_pattern, content, re.DOTALL)
    for match in matches:
        items = [line for line in match.split('\n') if line.strip().startswith('- **T')]
        counts['mitre_techniques'] += len(items)
    
    # Count OCR images that have content
    ocr_pattern = r'### Image \d+\n(.*?)(?=\n### Image |\n## |\Z)'
    matches = re.findall(ocr_pattern, content, re.DOTALL)
    for match in matches:
        # Only count if there's actual OCR text (not just "No OCR text extracted")
        if 'No OCR text extracted' not in match and '```text' in match:
            counts['ocr_images'] += 1
    
    return counts


def _remove_empty_ioc_sections(content: str) -> str:
    """Remove IOC confidence subsections that have no items."""
    
    # Pattern: #### HIGH/MEDIUM/LOW Confidence with no items following
    pattern = r'####\s+(HIGH|MEDIUM|LOW)\s+Confidence\s*\n+(?=####|###|##|\Z)'
    content = re.sub(pattern, '', content)
    
    return content


def _remove_empty_ocr_images(content: str) -> str:
    """Remove OCR image sections that have no useful content."""
    
    # Pattern for an image section with no OCR text or only error
    pattern = r'### Image \d+\n\n(?:.*?\n)*?(?:_No OCR text extracted from this image\._|OCR Error:.*?)\n+(?=### Image |\n## |\Z)'
    
    content = re.sub(pattern, '', content, flags=re.DOTALL)
    
    # If all images removed, also remove the parent section header
    if '### Image' not in content and '## OCR Evidence (Per Image, Auto)' in content:
        content = re.sub(
            r'## OCR Evidence \(Per Image, Auto\)\n+_OCR was not enabled for this run\._\n+',
            '',
            content
        )
    
    return content


def _remove_empty_sections(content: str) -> str:
    """Remove entire sections that have no content."""
    
    # Pattern: ## heading followed only by subsections with (none)
    sections_to_check = [
        'Observables From Article (Auto)',
        'Observables From OCR (Auto)',
    ]
    
    for section in sections_to_check:
        # Check if section exists and has only (none) entries
        pattern = rf'## {re.escape(section)}\n+((?:###.*?\n+- \(none\)\n+)+)'
        matches = re.findall(pattern, content, re.DOTALL)
        
        for match in matches:
            # If the match contains only (none) entries and no other content
            if '- (none)' in match and not re.search(r'- [^(]', match):
                # Remove the entire section
                content = re.sub(
                    rf'## {re.escape(section)}\n+(?:###.*?\n+- \(none\)\n+)+',
                    f'## {section}\n\n_No observables extracted._\n\n',
                    content,
                    count=1
                )
    
    return content


def _collapse_blank_lines(content: str) -> str:
    """Collapse multiple consecutive blank lines into maximum of 2."""
    content = re.sub(r'\n{4,}', '\n\n\n', content)
    return content


def _remove_analyst_templates(content: str) -> str:
    """Remove analyst fill-in template sections (optional, for final reports)."""
    
    # Remove Executive Summary template
    content = re.sub(
        r'## Executive Summary \(Analyst Fill-In\)\n+### Key Takeaways\n.*?### Initial Assessment\n.*?(?=\n##)',
        '',
        content,
        flags=re.DOTALL
    )
    
    # Remove Analyst Notes template
    content = re.sub(
        r'## Analyst Notes / Validation \(Fill-In\)\n+.*?(?=\n##|\Z)',
        '',
        content,
        flags=re.DOTALL
    )
    
    return content


def _renumber_ocr_images(content: str) -> str:
    """Renumber OCR image sections sequentially after removal of empty ones."""
    
    # Find all image sections
    image_sections = re.findall(r'### Image \d+', content)
    
    # Replace with sequential numbers
    counter = 1
    for old_heading in image_sections:
        content = content.replace(old_heading, f'### Image {counter}', 1)
        counter += 1
    
    return content


def _add_summary_stats(content: str, counts: dict[str, int]) -> str:
    """Add a summary statistics section at the top of the report (after metadata)."""
    
    # Find where to insert (after the metadata section, before first ##)
    insertion_point = content.find('\n\n## ')
    
    if insertion_point == -1:
        return content  # Can't find insertion point, skip
    
    # Build summary
    summary_lines = ['## 📊 Report Summary\n']
    
    total_iocs = (
        counts['cves'] + counts['urls'] + counts['domains'] + counts['ipv4'] +
        counts['sha256'] + counts['sha1'] + counts['md5'] + counts['windows_paths'] +
        counts['command_lines']
    )
    
    summary_lines.append(f"**Total IOCs Extracted:** {total_iocs}<br>")
    
    if counts['mitre_techniques'] > 0:
        summary_lines.append(f"**MITRE ATT&CK Techniques:** {counts['mitre_techniques']}<br>")
    
    if counts['ocr_images'] > 0:
        summary_lines.append(f"**Images with OCR Data:** {counts['ocr_images']}<br>")
    
    # Breakdown
    ioc_breakdown = []
    if counts['cves']: ioc_breakdown.append(f"CVEs: {counts['cves']}")
    if counts['urls']: ioc_breakdown.append(f"URLs: {counts['urls']}")
    if counts['domains']: ioc_breakdown.append(f"Domains: {counts['domains']}")
    if counts['ipv4']: ioc_breakdown.append(f"IPs: {counts['ipv4']}")
    if counts['sha256']: ioc_breakdown.append(f"SHA256: {counts['sha256']}")
    if counts['sha1']: ioc_breakdown.append(f"SHA1: {counts['sha1']}")
    if counts['md5']: ioc_breakdown.append(f"MD5: {counts['md5']}")
    if counts['command_lines']: ioc_breakdown.append(f"Commands: {counts['command_lines']}")
    
    if ioc_breakdown:
        summary_lines.append(f"**Breakdown:** {', '.join(ioc_breakdown)}")
    
    summary_lines.append('')  # Blank line
    
    summary_text = '\n'.join(summary_lines)
    
    # Insert before first ##
    content = content[:insertion_point] + '\n' + summary_text + content[insertion_point:]
    
    return content


def cleanup_report(
    input_content: str,
    remove_empty_iocs: bool = True,
    remove_empty_ocr: bool = True,
    remove_empty_sections: bool = True,
    collapse_blanks: bool = True,
    remove_templates: bool = False,
    add_summary: bool = True,
    renumber_images: bool = True,
) -> str:
    """
    Main cleanup function.
    
    Args:
        input_content: Raw markdown report content
        remove_empty_iocs: Remove IOC sections with only (none)
        remove_empty_ocr: Remove OCR images with no content
        remove_empty_sections: Remove entire sections with no data
        collapse_blanks: Collapse excessive blank lines
        remove_templates: Remove analyst fill-in templates
        add_summary: Add summary statistics at top
        renumber_images: Renumber OCR images sequentially
    
    Returns:
        Cleaned markdown content
    """
    
    content = input_content
    
    # Count IOCs before cleanup (for summary)
    counts = _count_iocs(content) if add_summary else {}
    
    if remove_empty_iocs:
        content = _remove_empty_ioc_sections(content)
    
    if remove_empty_ocr:
        content = _remove_empty_ocr_images(content)
    
    if renumber_images:
        content = _renumber_ocr_images(content)
    
    if remove_empty_sections:
        content = _remove_empty_sections(content)
    
    if remove_templates:
        content = _remove_analyst_templates(content)
    
    if collapse_blanks:
        content = _collapse_blank_lines(content)
    
    if add_summary and any(counts.values()):
        content = _add_summary_stats(content, counts)
    
    return content


def main() -> int:
    ap = argparse.ArgumentParser(description='Cleanup PEAK CTI reports by removing empty sections')
    ap.add_argument('--input', required=True, help='Input report path')
    ap.add_argument('--output', help='Output report path (default: overwrite input)')
    ap.add_argument('--in-place', action='store_true', help='Modify file in place')
    ap.add_argument('--remove-templates', action='store_true', 
                    help='Remove analyst fill-in templates (for final reports)')
    ap.add_argument('--no-summary', action='store_true', 
                    help='Skip adding summary statistics')
    ap.add_argument('--keep-empty-iocs', action='store_true',
                    help='Keep empty IOC sections')
    ap.add_argument('--keep-empty-ocr', action='store_true',
                    help='Keep empty OCR image sections')
    args = ap.parse_args()
    
    input_path = Path(args.input)
    
    if not input_path.exists():
        print(f"Error: Input file not found: {input_path}")
        return 1
    
    # Determine output path
    if args.in_place:
        output_path = input_path
    elif args.output:
        output_path = Path(args.output)
    else:
        # Default: input with _clean suffix
        output_path = input_path.with_name(input_path.stem + '_clean.md')
    
    # Read input
    content = input_path.read_text(encoding='utf-8')
    
    # Cleanup
    cleaned = cleanup_report(
        content,
        remove_empty_iocs=not args.keep_empty_iocs,
        remove_empty_ocr=not args.keep_empty_ocr,
        remove_empty_sections=True,
        collapse_blanks=True,
        remove_templates=args.remove_templates,
        add_summary=not args.no_summary,
        renumber_images=True,
    )
    
    # Write output
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(cleaned, encoding='utf-8')
    
    print(f"✅ Cleaned report written to: {output_path}")
    
    # Stats
    original_lines = len(content.split('\n'))
    cleaned_lines = len(cleaned.split('\n'))
    print(f"📊 Original: {original_lines} lines → Cleaned: {cleaned_lines} lines ({original_lines - cleaned_lines} removed)")
    
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
