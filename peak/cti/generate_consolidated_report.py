#!/usr/bin/env python3
"""
Generate a single consolidated report from multiple sources.
Each source's IOCs are attributed with hyperlinks back to the original article.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

from peak_reporter.article_parser import fetch_article_or_file
from peak_reporter.ocr import run_ocr_from_map
from peak_reporter.mitre import extract_mitre_techniques, MitreSection
from peak_reporter.ioc_extract import extract_iocs_with_confidence, ScoredIOC


@dataclass
class SourceData:
    """Data extracted from a single source."""
    url: str
    title: str
    text: str
    iocs: dict  # IOCs extracted from this source
    mitre: MitreSection
    ocr_results: list = field(default_factory=list)
    file_hash: str = ""  # SHA256 hash for file sources


@dataclass 
class ConsolidatedInputs:
    """Inputs for consolidated report generation."""
    report_title: str
    analyst: str
    issue_number: Optional[int]
    issue_url: Optional[str]
    sources: list[SourceData]
    ocr_enabled: bool = False


def _slugify(s: str) -> str:
    s = (s or "").lower()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    return s.strip("-") or "report"


def _is_url(s: str) -> bool:
    return bool(re.match(r"^https?://", (s or "").strip(), flags=re.I))


def _compute_file_hash(file_path: str) -> str:
    """Compute SHA256 hash of a file. Returns empty string if file doesn't exist."""
    p = Path(file_path)
    if not p.exists():
        # Try resolving as inputs/filename
        p = Path('inputs') / Path(file_path).name
    if not p.exists() and file_path.startswith('inputs/'):
        p = Path(file_path)
    
    if not p.exists():
        return ""
    
    sha256 = hashlib.sha256()
    with open(p, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            sha256.update(chunk)
    return sha256.hexdigest()


def process_source(
    url: str, 
    enable_ocr: bool = False, 
    max_ocr_images: int = 120,
    ocr_output_dir: Path = None,
    repo_base_url: str = ""
) -> SourceData:
    """Process a single source URL/file and extract all data including OCR."""
    print(f"  Processing: {url}")
    
    article = fetch_article_or_file(url)
    
    # OCR processing
    ocr_results = []
    if enable_ocr:
        if ocr_output_dir is None:
            ocr_output_dir = Path("data/ocr_images")
        ocr_output_dir.mkdir(parents=True, exist_ok=True)
        
        # Import enhanced OCR functions
        from peak_reporter.ocr import (
            extract_images_from_pdf,
            extract_images_from_url,
            run_ocr_on_images,
            OCRResult
        )
        
        images_info = []
        
        # Extract images based on source type
        if not _is_url(url):
            # PDF file - extract pages as images
            pdf_path = Path(url)
            if not pdf_path.exists():
                pdf_path = Path('inputs') / Path(url).name
            if pdf_path.exists() and pdf_path.suffix.lower() == '.pdf':
                images_info = extract_images_from_pdf(
                    pdf_path, 
                    ocr_output_dir,
                    dpi=150,
                    max_pages=max_ocr_images
                )
        else:
            # URL - try to extract images from HTML
            if article.html:
                images_info = extract_images_from_url(
                    url,
                    article.html,
                    ocr_output_dir,
                    max_images=min(50, max_ocr_images)
                )
        
        # Run OCR on extracted images
        if images_info:
            ocr_results = run_ocr_on_images(
                images_info,
                repo_base_url=repo_base_url,
                images_subpath="peak/cti/data/ocr_images"
            )
        
        # Legacy: also check for prefetched image map
        map_path = Path("data/prefetched_images/image_map.json")
        if map_path.exists() and not images_info:
            from peak_reporter.ocr import run_ocr_from_map
            legacy_results = run_ocr_from_map(map_path, max_images=max_ocr_images)
            # Convert to list format expected by rest of code
            ocr_results = legacy_results
    
    # Extract IOCs with confidence scoring
    iocs_obj = extract_iocs_with_confidence(article.text or "")
    
    # Convert to dict with ScoredIOC objects preserved
    iocs = {
        'cves': iocs_obj.cves,
        'urls': iocs_obj.urls,
        'domains': iocs_obj.domains,
        'ipv4': iocs_obj.ipv4,
        'sha256': iocs_obj.sha256,
        'sha1': iocs_obj.sha1,
        'md5': iocs_obj.md5,
        'windows_paths': iocs_obj.win_paths,
        'command_lines': iocs_obj.command_lines,
    }
    
    # Extract MITRE
    mitre_path = Path("data/enterprise-attack.json")
    mitre = extract_mitre_techniques(
        article_text=article.text or "",
        ocr_results=ocr_results if isinstance(ocr_results, list) and ocr_results and isinstance(ocr_results[0], dict) else [],
        mitre_json_path=mitre_path if mitre_path.exists() else None,
    )
    
    # Compute file hash for file inputs (not URLs)
    file_hash = ""
    if not _is_url(url):
        file_hash = _compute_file_hash(url)
        if file_hash:
            print(f"    SHA256: {file_hash[:16]}...")
    
    return SourceData(
        url=url,
        title=article.title or "Unknown Title",
        text=article.text or "",
        iocs=iocs,
        mitre=mitre,
        ocr_results=ocr_results,
        file_hash=file_hash,
    )


def build_consolidated_markdown(inputs: ConsolidatedInputs) -> str:
    """Build a single consolidated markdown report from multiple sources."""
    lines: list[str] = []
    
    # Header
    lines.append(f"# {inputs.report_title}")
    lines.append("")
    
    # Metadata
    lines.append("## 📋 Report Metadata")
    lines.append("")
    if inputs.issue_number:
        if inputs.issue_url:
            lines.append(f"**Issue:** [#{inputs.issue_number}]({inputs.issue_url})<br>")
        else:
            lines.append(f"**Issue:** #{inputs.issue_number}<br>")
    lines.append(f"**Analyst:** {inputs.analyst or 'Unknown'}<br>")
    lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}<br>")
    lines.append(f"**Sources Processed:** {len(inputs.sources)}<br>")
    lines.append(f"**OCR Enabled:** {'Yes' if inputs.ocr_enabled else 'No'}")
    lines.append("")
    
    # Source Index with hyperlinks
    lines.append("## 📚 Sources")
    lines.append("")
    for idx, src in enumerate(inputs.sources, 1):
        lines.append(f"{idx}. [{src.title}]({src.url})")
    lines.append("")
    
    # Consolidated Report Summary
    total_iocs = 0
    total_mitre = set()
    total_ocr_images = 0
    
    # IOC aggregation with source tracking and confidence
    # Structure: ioc_value -> {'sources': [urls], 'confidence': label, 'score': int}
    consolidated_iocs = {
        'cves': {},
        'urls': {},
        'domains': {},
        'ipv4': {},
        'sha256': {},
        'sha1': {},
        'md5': {},
        'windows_paths': {},
        'command_lines': {},
    }
    
    for src in inputs.sources:
        for ioc_type, iocs_list in src.iocs.items():
            if ioc_type in consolidated_iocs:
                for scored_ioc in iocs_list:
                    # ScoredIOC has: value, confidence_score, confidence_label, reason
                    ioc_value = scored_ioc.value
                    if ioc_value not in consolidated_iocs[ioc_type]:
                        consolidated_iocs[ioc_type][ioc_value] = {
                            'sources': [],
                            'confidence': scored_ioc.confidence_label,
                            'score': scored_ioc.confidence_score,
                            'reason': scored_ioc.reason
                        }
                    if src.url not in consolidated_iocs[ioc_type][ioc_value]['sources']:
                        consolidated_iocs[ioc_type][ioc_value]['sources'].append(src.url)
                    # Keep highest confidence score
                    if scored_ioc.confidence_score > consolidated_iocs[ioc_type][ioc_value]['score']:
                        consolidated_iocs[ioc_type][ioc_value]['confidence'] = scored_ioc.confidence_label
                        consolidated_iocs[ioc_type][ioc_value]['score'] = scored_ioc.confidence_score
        
        total_mitre.update(t.id for t in src.mitre.techniques)
        # Handle both OCRResult objects and dict format
        for r in src.ocr_results:
            text = r.text if hasattr(r, 'text') else r.get('text', '') if isinstance(r, dict) else ''
            if text and text.strip():
                total_ocr_images += 1
    
    # Count unique IOCs (only HIGH confidence for summary, but show all in report)
    high_conf_count = 0
    for ioc_type, iocs_dict in consolidated_iocs.items():
        total_iocs += len(iocs_dict)
        high_conf_count += len([v for v in iocs_dict.values() if v['confidence'] == 'HIGH'])
    
    # Build breakdown
    breakdown_parts = []
    if consolidated_iocs['cves']: breakdown_parts.append(f"CVEs: {len(consolidated_iocs['cves'])}")
    if consolidated_iocs['urls']: breakdown_parts.append(f"URLs: {len(consolidated_iocs['urls'])}")
    if consolidated_iocs['domains']: breakdown_parts.append(f"Domains: {len(consolidated_iocs['domains'])}")
    if consolidated_iocs['ipv4']: breakdown_parts.append(f"IPs: {len(consolidated_iocs['ipv4'])}")
    if consolidated_iocs['sha256']: breakdown_parts.append(f"SHA256: {len(consolidated_iocs['sha256'])}")
    if consolidated_iocs['sha1']: breakdown_parts.append(f"SHA1: {len(consolidated_iocs['sha1'])}")
    if consolidated_iocs['md5']: breakdown_parts.append(f"MD5: {len(consolidated_iocs['md5'])}")
    if consolidated_iocs['windows_paths']: breakdown_parts.append(f"Paths: {len(consolidated_iocs['windows_paths'])}")
    if consolidated_iocs['command_lines']: breakdown_parts.append(f"Commands: {len(consolidated_iocs['command_lines'])}")
    
    breakdown = ", ".join(breakdown_parts) if breakdown_parts else "None"
    
    lines.append("## 📊 Report Summary")
    lines.append("")
    lines.append(f"**Total Unique IOCs:** {total_iocs}<br>")
    lines.append(f"**High Confidence IOCs:** {high_conf_count}<br>")
    lines.append(f"**MITRE ATT&CK Techniques:** {len(total_mitre)}<br>")
    if inputs.ocr_enabled:
        lines.append(f"**Images with OCR Data:** {total_ocr_images}<br>")
    lines.append(f"**Breakdown:** {breakdown}")
    lines.append("")
    
    # Executive Summary
    lines.append("## Executive Summary (Analyst Fill-In)")
    lines.append("")
    lines.append("### Key Takeaways")
    lines.append("- What happened (1-2 bullets)")
    lines.append("- Who/what is affected (orgs, sectors, regions)")
    lines.append("- Why it matters to us (risk / exposure / priority)")
    lines.append("")
    lines.append("### Initial Assessment")
    lines.append("- Confidence level: (low/med/high)")
    lines.append("- Recommended actions: (monitor / hunt / block / brief)")
    lines.append("")
    
    # Consolidated IOCs with source attribution
    lines.append("## 🔍 Consolidated Indicators of Compromise")
    lines.append("")
    lines.append("> IOCs are deduplicated across sources. Confidence: 🟢 HIGH | 🟡 MEDIUM | 🔴 LOW")
    lines.append("")
    
    def _confidence_badge(confidence: str) -> str:
        """Return emoji badge for confidence level."""
        if confidence == 'HIGH':
            return '🟢'
        elif confidence == 'MEDIUM':
            return '🟡'
        else:
            return '🔴'
    
    def _format_ioc_with_sources_and_confidence(ioc: str, ioc_data: dict, sources: list[SourceData]) -> str:
        """Format an IOC with hyperlinked source numbers and confidence badge."""
        source_refs = []
        for url in ioc_data['sources']:
            for idx, src in enumerate(sources, 1):
                if src.url == url:
                    source_refs.append(f"[[{idx}]]({url})")
                    break
        badge = _confidence_badge(ioc_data['confidence'])
        return f"- {badge} `{ioc}` {' '.join(source_refs)}"
    
    # CVEs (always high confidence)
    if consolidated_iocs['cves']:
        lines.append("### CVEs")
        lines.append("")
        for ioc, ioc_data in sorted(consolidated_iocs['cves'].items()):
            lines.append(_format_ioc_with_sources_and_confidence(ioc, ioc_data, inputs.sources))
        lines.append("")
    
    # URLs
    if consolidated_iocs['urls']:
        lines.append("### URLs")
        lines.append("")
        for ioc, ioc_data in sorted(consolidated_iocs['urls'].items()):
            # Defang URLs for safety
            defanged = ioc.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")
            lines.append(_format_ioc_with_sources_and_confidence(defanged, ioc_data, inputs.sources))
        lines.append("")
    
    # Domains - sort by confidence (HIGH first)
    if consolidated_iocs['domains']:
        lines.append("### Domains")
        lines.append("")
        # Sort: HIGH confidence first, then alphabetically
        sorted_domains = sorted(
            consolidated_iocs['domains'].items(),
            key=lambda x: (0 if x[1]['confidence'] == 'HIGH' else 1 if x[1]['confidence'] == 'MEDIUM' else 2, x[0])
        )
        for ioc, ioc_data in sorted_domains:
            defanged = ioc.replace(".", "[.]")
            lines.append(_format_ioc_with_sources_and_confidence(defanged, ioc_data, inputs.sources))
        lines.append("")
    
    # IPs - sort by confidence
    if consolidated_iocs['ipv4']:
        lines.append("### IP Addresses")
        lines.append("")
        sorted_ips = sorted(
            consolidated_iocs['ipv4'].items(),
            key=lambda x: (0 if x[1]['confidence'] == 'HIGH' else 1 if x[1]['confidence'] == 'MEDIUM' else 2, x[0])
        )
        for ioc, ioc_data in sorted_ips:
            defanged = ioc.replace(".", "[.]")
            lines.append(_format_ioc_with_sources_and_confidence(defanged, ioc_data, inputs.sources))
        lines.append("")
    
    # Hashes
    has_hashes = consolidated_iocs['sha256'] or consolidated_iocs['sha1'] or consolidated_iocs['md5']
    if has_hashes:
        lines.append("### File Hashes")
        lines.append("")
        
        if consolidated_iocs['sha256']:
            lines.append("**SHA256:**")
            for ioc, ioc_data in sorted(consolidated_iocs['sha256'].items()):
                lines.append(_format_ioc_with_sources_and_confidence(ioc, ioc_data, inputs.sources))
            lines.append("")
        
        if consolidated_iocs['sha1']:
            lines.append("**SHA1:**")
            for ioc, ioc_data in sorted(consolidated_iocs['sha1'].items()):
                lines.append(_format_ioc_with_sources_and_confidence(ioc, ioc_data, inputs.sources))
            lines.append("")
        
        if consolidated_iocs['md5']:
            lines.append("**MD5:**")
            for ioc, ioc_data in sorted(consolidated_iocs['md5'].items()):
                lines.append(_format_ioc_with_sources_and_confidence(ioc, ioc_data, inputs.sources))
            lines.append("")
    
    # Windows Paths
    if consolidated_iocs['windows_paths']:
        lines.append("### Windows Paths")
        lines.append("")
        for ioc, ioc_data in sorted(consolidated_iocs['windows_paths'].items()):
            lines.append(_format_ioc_with_sources_and_confidence(ioc, ioc_data, inputs.sources))
        lines.append("")
    
    # Command Lines
    if consolidated_iocs['command_lines']:
        lines.append("### Command Lines")
        lines.append("")
        for ioc, ioc_data in consolidated_iocs['command_lines'].items():
            source_refs = []
            for url in ioc_data['sources']:
                for idx, src in enumerate(inputs.sources, 1):
                    if src.url == url:
                        source_refs.append(f"[[{idx}]]({url})")
                        break
            badge = _confidence_badge(ioc_data['confidence'])
            lines.append(f"{badge} Command:")
            lines.append(f"```")
            lines.append(ioc)
            lines.append(f"```")
            lines.append(f"Sources: {' '.join(source_refs)}")
            lines.append("")
    
    # MITRE ATT&CK consolidated
    if total_mitre:
        lines.append("## 🎯 MITRE ATT&CK Techniques")
        lines.append("")
        
        # Collect all techniques with sources
        technique_sources: dict[str, list[str]] = {}
        for src in inputs.sources:
            for tech in src.mitre.techniques:
                tech_id = tech.id
                tech_name = tech.name
                key = f"{tech_id}: {tech_name}"
                if key not in technique_sources:
                    technique_sources[key] = []
                if src.url not in technique_sources[key]:
                    technique_sources[key].append(src.url)
        
        lines.append("| Technique | Sources |")
        lines.append("|-----------|---------|")
        for tech_key in sorted(technique_sources.keys()):
            source_refs = []
            for url in technique_sources[tech_key]:
                for idx, src in enumerate(inputs.sources, 1):
                    if src.url == url:
                        source_refs.append(f"[{idx}]({url})")
                        break
            lines.append(f"| {tech_key} | {', '.join(source_refs)} |")
        lines.append("")
    
    # Per-Source Details (collapsed)
    lines.append("## 📄 Source Details")
    lines.append("")
    lines.append("> Expand each source for detailed information extracted from that article.")
    lines.append("")
    
    for idx, src in enumerate(inputs.sources, 1):
        lines.append(f"<details>")
        lines.append(f"<summary><strong>Source {idx}: {src.title}</strong></summary>")
        lines.append("")
        lines.append(f"**URL:** {src.url}")
        lines.append("")
        
        # Source-specific IOC counts
        src_ioc_count = sum(len(v) for v in src.iocs.values())
        lines.append(f"**IOCs from this source:** {src_ioc_count}<br>")
        lines.append(f"**MITRE techniques:** {len(src.mitre.techniques)}")
        lines.append("")
        
        # Brief excerpt
        if src.text:
            excerpt = src.text[:500].replace('\n', ' ').strip()
            if len(src.text) > 500:
                excerpt += "..."
            lines.append("**Excerpt:**")
            lines.append(f"> {excerpt}")
            lines.append("")
        
        lines.append("</details>")
        lines.append("")
    
    # OCR Extracted Content Section (if OCR was enabled and results exist)
    all_ocr_results = []
    for src in inputs.sources:
        if src.ocr_results:
            # Handle both OCRResult objects and legacy dict format
            for ocr in src.ocr_results:
                if hasattr(ocr, 'text'):
                    all_ocr_results.append(ocr)
                elif isinstance(ocr, dict) and ocr.get('text'):
                    all_ocr_results.append(ocr)
    
    if all_ocr_results and inputs.ocr_enabled:
        lines.append("## 🔍 OCR Extracted Content")
        lines.append("")
        lines.append("> Images extracted from source documents with OCR text. Click to expand each image.")
        lines.append("")
        
        for idx, ocr in enumerate(all_ocr_results[:50], 1):  # Limit to 50 images
            # Handle both OCRResult objects and dict format
            if hasattr(ocr, 'image_path'):
                img_path = ocr.image_path
                img_url = ocr.image_url
                source_file = ocr.source_file
                page_num = ocr.page_number
                text = ocr.text
                iocs = ocr.iocs_found if hasattr(ocr, 'iocs_found') else []
            else:
                img_path = ocr.get('local_path', '')
                img_url = ocr.get('image_url', '')
                source_file = ocr.get('source_file', '')
                page_num = ocr.get('page_number', 0)
                text = ocr.get('text', '')
                iocs = []
            
            if not text:
                continue
            
            img_name = Path(img_path).name if img_path else f"image_{idx}"
            label = f"Page {page_num}" if page_num else f"Image {idx}"
            source_name = Path(source_file).name if source_file else "Unknown"
            
            lines.append(f"<details>")
            lines.append(f"<summary><strong>{label}</strong> from {source_name}</summary>")
            lines.append("")
            
            # Image link if available
            if img_url:
                lines.append(f"**View Image:** [{img_name}]({img_url})")
                lines.append("")
            
            # IOCs found in this image
            if iocs:
                lines.append("**IOCs Found:**")
                for ioc in iocs[:10]:
                    lines.append(f"- `{ioc}`")
                lines.append("")
            
            # OCR text (truncated)
            text_preview = text[:500].replace('\n', ' ').strip()
            if len(text) > 500:
                text_preview += "..."
            lines.append("**Extracted Text:**")
            lines.append(f"> {text_preview}")
            lines.append("")
            
            lines.append("</details>")
            lines.append("")
        
        # OCR Summary
        images_with_text = sum(1 for o in all_ocr_results if (hasattr(o, 'text') and o.text) or (isinstance(o, dict) and o.get('text')))
        lines.append(f"**OCR Summary:** {images_with_text} images processed with text extracted")
        lines.append("")
    
    # Footer
    lines.append("---")
    lines.append("")
    lines.append(f"*Generated by PEAK CTI v3.0 Multi-Source Consolidated Report*")
    lines.append(f"*{datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}*")
    
    # Hidden comment with file hashes for duplicate detection
    file_hashes = [src.file_hash for src in inputs.sources if src.file_hash]
    if file_hashes:
        lines.append("")
        lines.append(f"<!-- FILE_HASHES: {','.join(file_hashes)} -->")
    
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate consolidated report from multiple sources")
    ap.add_argument("--sources-json", required=True, help="Path to JSON file with sources list")
    ap.add_argument("--analyst", default="")
    ap.add_argument("--enable-ocr", default="false")
    ap.add_argument("--issue-number", default="")
    ap.add_argument("--issue-title", default="")
    ap.add_argument("--issue-url", default="")
    ap.add_argument("--repo-url", default="", help="GitHub repo URL for image links")
    ap.add_argument("--max-ocr-images", type=int, default=120)
    args = ap.parse_args()
    
    enable_ocr = str(args.enable_ocr).strip().lower() == "true"
    
    # Load sources
    sources_path = Path(args.sources_json)
    if not sources_path.exists():
        print(f"ERROR: Sources file not found: {sources_path}")
        return 1
    
    sources_data = json.loads(sources_path.read_text())
    sources_list = sources_data.get('sources', [])
    
    if not sources_list:
        print("ERROR: No sources found in JSON file")
        return 1
    
    print(f"\n{'='*70}")
    print(f"CONSOLIDATED MULTI-SOURCE REPORT GENERATION")
    print(f"{'='*70}")
    print(f"Total sources: {len(sources_list)}")
    print(f"Analyst: {args.analyst}")
    print(f"OCR enabled: {enable_ocr}")
    print(f"{'='*70}\n")
    
    # Process each source
    processed_sources: list[SourceData] = []
    failed_sources: list[str] = []
    
    for idx, src in enumerate(sources_list, 1):
        source_type = src.get('type', 'url')
        source_value = src.get('value', '')
        
        print(f"\n[{idx}/{len(sources_list)}] Processing [{source_type}]: {source_value}")
        
        try:
            # process_source handles both URLs and file paths via fetch_article_or_file
            source_data = process_source(
                source_value, 
                enable_ocr, 
                args.max_ocr_images,
                ocr_output_dir=Path("data/ocr_images"),
                repo_base_url=args.repo_url
            )
            processed_sources.append(source_data)
            print(f"  ✅ Success: {source_data.title}")
        except Exception as e:
            print(f"  ❌ Failed: {e}")
            failed_sources.append(source_value)
    
    if not processed_sources:
        print("\nERROR: All sources failed to process!")
        return 1
    
    print(f"\n{'='*70}")
    print(f"SUMMARY: {len(processed_sources)}/{len(sources_list)} sources processed successfully")
    if failed_sources:
        print(f"Failed sources:")
        for url in failed_sources:
            print(f"  - {url}")
    print(f"{'='*70}\n")
    
    # Build consolidated report
    inputs = ConsolidatedInputs(
        report_title=args.issue_title or "PEAK CTI Consolidated Report",
        analyst=args.analyst or "",
        issue_number=int(args.issue_number) if str(args.issue_number).isdigit() else None,
        issue_url=args.issue_url or None,
        sources=processed_sources,
        ocr_enabled=enable_ocr,
    )
    
    md = build_consolidated_markdown(inputs)
    
    # Write output
    out_dir = Path("reports")
    out_dir.mkdir(parents=True, exist_ok=True)
    
    ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    issue_part = f"issue-{inputs.issue_number}" if inputs.issue_number else "issue-manual"
    title_slug = _slugify(inputs.report_title)
    out_path = out_dir / f"{issue_part}_{title_slug}_consolidated_{ts}.md"
    
    out_path.write_text(md, encoding="utf-8")
    print(f"\n✅ Consolidated report written to: {out_path}")
    print(str(out_path))
    
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
