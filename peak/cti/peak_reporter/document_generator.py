"""
PEAK CTI - Document Generator with Confidence Scoring (Production v2.0)

This module generates markdown reports with IOC confidence scores displayed.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List

from .ioc_extract import extract_iocs_with_confidence, ScoredIOC
from .mitre import MitreSection


@dataclass
class ReportInputs:
    title: str
    source_url: str
    analyst: str
    issue_number: int | None
    issue_url: str | None
    article_text: str
    ocr_results: list[dict]
    ocr_enabled: bool
    mitre: MitreSection


def _group_by_confidence(iocs: List[ScoredIOC]) -> dict[str, List[ScoredIOC]]:
    """Group IOCs by confidence level."""
    grouped = {"HIGH": [], "MEDIUM": [], "LOW": []}
    for ioc in iocs:
        grouped[ioc.confidence_label].append(ioc)
    return grouped


def _render_iocs_with_confidence(
    iocs_by_type: dict[str, List[ScoredIOC]],
    header_prefix: str = "###",
) -> list[str]:
    """
    Render IOCs grouped by confidence level.
    
    Format:
    ### Domains
    
    #### HIGH Confidence
    - `evil.com`
    
    #### MEDIUM Confidence
    - `suspicious.tk` *(commonly abused TLD)*
    
    #### LOW Confidence
    - `Files.txt` *(file extension .txt; no TLD)*
    """
    out: list[str] = []
    
    ioc_labels = {
        'cves': 'CVEs',
        'urls': 'URLs',
        'domains': 'Domains',
        'ipv4': 'IPv4',
        'sha256': 'SHA-256',
        'sha1': 'SHA-1',
        'md5': 'MD5',
        'win_paths': 'Windows Paths',
        'command_lines': 'Command Lines',
    }
    
    for key, label in ioc_labels.items():
        if key not in iocs_by_type:
            continue
            
        iocs = iocs_by_type[key]
        if not iocs:
            continue
        
        # Section header
        out.append(f"{header_prefix} {label}")
        out.append("")
        
        # Group by confidence
        grouped = _group_by_confidence(iocs)
        
        # Render each confidence level that has IOCs
        for conf_level in ["HIGH", "MEDIUM", "LOW"]:
            conf_iocs = grouped[conf_level]
            if not conf_iocs:
                continue
            
            out.append(f"#### {conf_level} Confidence")
            for ioc in conf_iocs:
                # Format: - `value` *(reason)*
                if ioc.reason and ioc.reason != f"valid {label}" and ioc.reason != "standard domain":
                    out.append(f"- `{ioc.value}` *({ioc.reason})*")
                else:
                    out.append(f"- `{ioc.value}`")
            out.append("")
    
    return out


def _sanitize_pdf_text_for_cti(text: str) -> str:
    """Remove PDF structural noise while keeping analyst-relevant content."""
    if not text:
        return ""

    cleaned: list[str] = []

    for line in text.splitlines():
        l = line.strip()
        if not l:
            continue

        low = l.lower()

        # Drop known PDF / Adobe / XML noise
        if any(x in low for x in (
            "adobe",
            "ns.adobe.com",
            "xap/",
            "rdf:",
            "<?xml",
            "<x:",
            "obj",
            "endobj",
            "stream",
            "endstream",
        )):
            continue

        # Require meaningful alphabetic content
        if sum(c.isalpha() for c in l) < 5:
            continue

        # Require mostly printable text
        printable = sum(c.isprintable() for c in l)
        if printable / max(len(l), 1) < 0.8:
            continue

        cleaned.append(l)

    return "\n".join(cleaned)


def build_markdown(inp: ReportInputs) -> str:
    """
    Build markdown report with IOC confidence scoring.
    
    This is the main entry point for report generation.
    """
    ts = datetime.now(timezone.utc).astimezone().replace(microsecond=0).isoformat(sep=" ")
    lines: list[str] = []

    lines.append(f"# {inp.title}")
    lines.append("")

    # Header metadata (hard line breaks)
    meta: list[str] = []
    meta.append(f"**Generated:** {ts}")
    if inp.analyst:
        meta.append(f"**Analyst:** {inp.analyst}")
    meta.append(f"**Source:** {inp.source_url}")
    if inp.issue_number is not None:
        meta.append(f"**Issue:** {inp.issue_number}")
    if inp.issue_url:
        meta.append(f"**Issue URL:** {inp.issue_url}")

    lines.append("<br>\n".join(meta))
    lines.append("")
    lines.append("")

    # Extract IOCs with confidence scoring
    article_text = inp.article_text or ""
    
    # PDF-specific sanitization
    if inp.source_url.lower().endswith(".pdf"):
        article_text = _sanitize_pdf_text_for_cti(article_text)
    
    iocs_article = extract_iocs_with_confidence(article_text)
    
    # Calculate summary statistics
    total_iocs = (
        len(iocs_article.cves) + len(iocs_article.urls) + len(iocs_article.domains) +
        len(iocs_article.ipv4) + len(iocs_article.sha256) + len(iocs_article.sha1) +
        len(iocs_article.md5) + len(iocs_article.command_lines)
    )
    
    # Count by type (non-zero only)
    breakdown_parts = []
    if iocs_article.cves: breakdown_parts.append(f"CVEs: {len(iocs_article.cves)}")
    if iocs_article.urls: breakdown_parts.append(f"URLs: {len(iocs_article.urls)}")
    if iocs_article.domains: breakdown_parts.append(f"Domains: {len(iocs_article.domains)}")
    if iocs_article.ipv4: breakdown_parts.append(f"IPs: {len(iocs_article.ipv4)}")
    if iocs_article.sha256: breakdown_parts.append(f"SHA256: {len(iocs_article.sha256)}")
    if iocs_article.sha1: breakdown_parts.append(f"SHA1: {len(iocs_article.sha1)}")
    if iocs_article.md5: breakdown_parts.append(f"MD5: {len(iocs_article.md5)}")
    if iocs_article.command_lines: breakdown_parts.append(f"Commands: {len(iocs_article.command_lines)}")
    
    breakdown = ", ".join(breakdown_parts) if breakdown_parts else "None"
    
    # OCR image count
    ocr_image_count = len([r for r in (inp.ocr_results or []) if r.get("text", "").strip()])
    
    lines.append("## 📊 Report Summary")
    lines.append("")
    lines.append(f"**Total IOCs Extracted:** {total_iocs}<br>")
    lines.append(f"**MITRE ATT&CK Techniques:** {len(inp.mitre.techniques)}<br>")
    if inp.ocr_enabled:
        lines.append(f"**Images with OCR Data:** {ocr_image_count}<br>")
    lines.append(f"**Breakdown:** {breakdown}")
    lines.append("")  # Add blank line after summary
    lines.append("")
    lines.append("")

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

    lines.append("## Observables From Article (Auto)")
    lines.append("")
    
    # Render IOCs with confidence grouping
    iocs_dict = {
        'cves': iocs_article.cves,
        'urls': iocs_article.urls,
        'domains': iocs_article.domains,
        'ipv4': iocs_article.ipv4,
        'sha256': iocs_article.sha256,
        'sha1': iocs_article.sha1,
        'md5': iocs_article.md5,
        'command_lines': iocs_article.command_lines,
    }
    
    lines.extend(_render_iocs_with_confidence(iocs_dict, header_prefix="###"))

    lines.append("## MITRE ATT&CK Mapping (Auto + Validate)")
    lines.append("")
    if not inp.mitre.enabled:
        lines.append("_MITRE mapping is not available for this run (enterprise-attack.json missing)._")
        lines.append("")
    else:
        if inp.mitre.techniques:
            lines.append("### Techniques Identified (Auto)")
            for t in inp.mitre.techniques:
                lines.append(f"- **{t.id}**{': ' + t.name if t.name else ''}")
            lines.append("")
        else:
            lines.append("_No techniques were auto-identified. Validate manually._")
            lines.append("")

    lines.append("### Mapping Notes")
    lines.append("- Auto-mapping is best-effort. Validate against the report and your telemetry.")
    lines.append("- Prefer techniques tied to observable behavior.")
    lines.append("")

    lines.append("## Observables From OCR (Auto)")
    lines.append("")
    if not inp.ocr_enabled:
        lines.append("_OCR was not enabled for this run._")
        lines.append("")
    else:
        ocr_text_all = "\n".join((r.get("text") or "") for r in inp.ocr_results or [])
        iocs_ocr = extract_iocs_with_confidence(ocr_text_all)
        
        if not ocr_text_all.strip():
            lines.append("_OCR was enabled, but no usable OCR text was extracted._")
            lines.append("")
        
        # Render OCR IOCs with confidence
        iocs_ocr_dict = {
            'cves': iocs_ocr.cves,
            'urls': iocs_ocr.urls,
            'domains': iocs_ocr.domains,
            'ipv4': iocs_ocr.ipv4,
            'sha256': iocs_ocr.sha256,
            'sha1': iocs_ocr.sha1,
            'md5': iocs_ocr.md5,
            'win_paths': iocs_ocr.win_paths,
            'command_lines': iocs_ocr.command_lines,
        }
        
        lines.extend(_render_iocs_with_confidence(iocs_ocr_dict, header_prefix="###"))

    lines.append("")
    lines.append("## OCR Evidence (Per Image, Auto)")
    lines.append("")
    if not inp.ocr_enabled:
        lines.append("_OCR was not enabled for this run._")
        lines.append("")
    else:
        for idx, r in enumerate(inp.ocr_results or [], start=1):
            lines.append(f"### Image {idx}")
            lines.append("")
            if r.get("image_url"):
                lines.append(f"**Image URL:** {r['image_url']}<br>")
            if r.get("local_path"):
                lines.append(f"**Local Path:** `{r['local_path']}`<br>")
            if r.get("sha256"):
                lines.append(f"**Image SHA-256:** `{r['sha256']}`<br>")
            if r.get("error"):
                lines.append(f"**OCR Error:** `{r['error']}`<br>")
            lines.append("")

            txt = (r.get("text") or "").strip()
            per_iocs = extract_iocs_with_confidence(txt)

            lines.append("#### Extracted From This Image (Auto)")
            lines.append("")
            
            # Render per-image IOCs with confidence
            per_iocs_dict = {
                'cves': per_iocs.cves,
                'urls': per_iocs.urls,
                'domains': per_iocs.domains,
                'ipv4': per_iocs.ipv4,
                'sha256': per_iocs.sha256,
                'sha1': per_iocs.sha1,
                'md5': per_iocs.md5,
                'win_paths': per_iocs.win_paths,
                'command_lines': per_iocs.command_lines,
            }
            
            lines.extend(_render_iocs_with_confidence(per_iocs_dict, header_prefix="#####"))

            lines.append("#### Raw OCR Text")
            lines.append("")
            if txt:
                lines.append("```text")
                lines.append(txt)
                lines.append("```")
            else:
                lines.append("_No OCR text extracted from this image._")
            lines.append("")

    lines.append("## Analyst Notes / Validation (Fill-In)")
    lines.append("")
    lines.append("### What We Validated In Telemetry")
    lines.append("- (hosts/users impacted)")
    lines.append("- (processes/paths/domains observed)")
    lines.append("")
    lines.append("### Suggested Hunts / Detections")
    lines.append("- Look for HIGH confidence domains/URLs in DNS/proxy logs")
    lines.append("- Search for command lines and LOLBAS usage")
    lines.append("- Validate file hashes in EDR telemetry")
    lines.append("- Review MEDIUM confidence IOCs for false positives")
    lines.append("")
    lines.append("### Decisions")
    lines.append("- Blocks added:")
    lines.append("- Notifications/briefings:")
    lines.append("- Follow-ups:")
    lines.append("")

    return "\n".join(lines).rstrip() + "\n"