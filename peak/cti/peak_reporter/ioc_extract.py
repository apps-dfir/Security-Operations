"""
PEAK CTI - IOC Extraction Module (Production v2.0)

This module extracts Indicators of Compromise (IOCs) from text with confidence scoring.
Includes improvements for reducing false positives and better analyst experience.

Features:
- Confidence scoring (HIGH/MEDIUM/LOW)
- Prose filtering for command lines
- Domain validation to filter filenames
- Deduplication and sorting
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import List
import re


@dataclass
class ScoredIOC:
    """An IOC with confidence metadata."""
    value: str
    confidence_score: int  # 0-100
    confidence_label: str  # HIGH, MEDIUM, LOW
    reason: str  # Why this score was assigned


@dataclass
class IOCs:
    """Collection of extracted IOCs (legacy format for backward compatibility)."""
    sha256: list[str]
    sha1: list[str]
    md5: list[str]
    ipv4: list[str]
    urls: list[str]
    domains: list[str]
    win_paths: list[str]
    command_lines: list[str]
    cves: list[str]


@dataclass
class IOCsWithConfidence:
    """Collection of IOCs with confidence scores."""
    sha256: List[ScoredIOC]
    sha1: List[ScoredIOC]
    md5: List[ScoredIOC]
    ipv4: List[ScoredIOC]
    urls: List[ScoredIOC]
    domains: List[ScoredIOC]
    win_paths: List[ScoredIOC]
    command_lines: List[ScoredIOC]
    cves: List[ScoredIOC]


def _get_confidence_label(score: int) -> str:
    """Convert numeric score to label."""
    if score >= 90:
        return "HIGH"
    elif score >= 60:
        return "MEDIUM"
    else:
        return "LOW"


def _score_domain(domain: str) -> tuple[int, str]:
    """
    Score a domain based on various heuristics to filter false positives.
    
    Returns: (score 0-100, reason)
    """
    domain_lower = domain.lower()
    score = 100
    reasons = []
    
    # File extensions (strong false positive indicators)
    file_extensions = [
        '.txt', '.exe', '.dll', '.sys', '.bat', '.cmd', '.ps1', '.vbs',
        '.js', '.jar', '.zip', '.rar', '.7z', '.tar', '.gz',
        '.doc', '.docx', '.xls', '.xlsx', '.pdf', '.jpg', '.png', '.gif',
        '.mp3', '.mp4', '.avi', '.json', '.xml', '.log', '.yaml', '.yml'
    ]
    
    for ext in file_extensions:
        if domain_lower.endswith(ext):
            score -= 85
            reasons.append(f"file extension {ext}")
            break
    
    # Common filename patterns
    if any(pattern in domain_lower for pattern in ['readme', 'config', 'setup', 'install', 'package-lock', 'yarn.lock', 'bundle']):
        score -= 70
        reasons.append("filename pattern")
    
    # No TLD separator
    if '.' not in domain:
        score -= 90
        reasons.append("no TLD")
    
    # Internal/example domains
    if any(x in domain_lower for x in ['localhost', 'local', 'internal', 'example.com', 'example.net']):
        score -= 80
        reasons.append("internal/example domain")
    
    # Very short
    if len(domain) < 4:
        score -= 40
        reasons.append("very short")
    
    # Common legit TLDs get boost
    if any(domain_lower.endswith(tld) for tld in ['.com', '.net', '.org', '.io']):
        score += 5
    
    # Suspicious TLDs
    if any(domain_lower.endswith(tld) for tld in ['.tk', '.ml', '.ga', '.xyz', '.top']):
        score += 15
        reasons.append("suspicious TLD")
    
    score = max(0, min(100, score))
    reason = "; ".join(reasons[:2]) if reasons else "standard domain"
    
    return score, reason


def _score_ip(ip: str) -> tuple[int, str]:
    """Score an IP address."""
    score = 100
    reasons = []
    
    octets = ip.split('.')
    
    # Private addresses
    if octets[0] == '10' or (octets[0] == '172' and 16 <= int(octets[1]) <= 31) or (octets[0] == '192' and octets[1] == '168'):
        score -= 70
        reasons.append("RFC 1918 private")
    
    # Localhost
    if ip.startswith('127.'):
        score -= 90
        reasons.append("localhost")
    
    # Common examples
    if ip in ['1.1.1.1', '8.8.8.8', '8.8.4.4']:
        score -= 50
        reasons.append("common example")
    
    score = max(0, min(100, score))
    reason = "; ".join(reasons) if reasons else "public IP"
    
    return score, reason


def _score_hash(hash_value: str, hash_type: str) -> tuple[int, str]:
    """Score a file hash."""
    score = 95
    reasons = []
    
    # All same character (placeholder)
    if len(set(hash_value.lower())) == 1:
        score = 20
        reasons.append("placeholder hash")
    
    reason = "; ".join(reasons) if reasons else f"valid {hash_type}"
    return score, reason


# Command line extraction pattern
_CMD_BIN_RE = re.compile(
    r"(?i)\b("
    r"powershell(?:\.exe)?|pwsh(?:\.exe)?|cmd(?:\.exe)?|wmic(?:\.exe)?|"
    r"rundll32(?:\.exe)?|regsvr32(?:\.exe)?|mshta(?:\.exe)?|wscript(?:\.exe)?|cscript(?:\.exe)?|"
    r"curl(?:\.exe)?|wget(?:\.exe)?|certutil(?:\.exe)?|bitsadmin(?:\.exe)?|"
    r"python(?:\.exe)?|perl(?:\.exe)?|bash|sh|zsh|ksh|"
    r"scp|ssh|nc|ncat|netcat|ftp|tftp|npm|yarn|pip|git"
    r")\b"
)


def _is_likely_prose(line: str) -> bool:
    """
    Detect if a line is prose (paragraph text) rather than a command.
    This prevents capturing sentences that mention "bash" or "SSH" as commands.
    """
    line = line.strip()
    
    # Very long lines with prose words
    if len(line) > 150:
        prose_words = ['the', 'this', 'that', 'these', 'those', 'and', 'but', 'or', 
                       'with', 'from', 'into', 'during', 'including', 'between']
        word_count = sum(1 for word in prose_words if f' {word} ' in line.lower())
        if word_count >= 3:
            return True
    
    # Sentence structure: Starts with capital, ends with period
    if line and line[0].isupper() and line.endswith('.') and line.count(' ') > 5:
        return True
    
    # Multiple sentences
    if '. ' in line or '! ' in line or '? ' in line:
        return True
    
    # Common prose phrases
    prose_phrases = [
        'This attack', 'The attack', 'Based on', 'Unit 42', 'Palo Alto',
        'threat actor', 'can lead to', 'may also', 'Additionally',
        'Immediately', 'Credential', 'represents a'
    ]
    if any(phrase in line for phrase in prose_phrases):
        return True
    
    return False


def _is_likely_command(line: str) -> bool:
    """Detect if a line is actually a command."""
    line = line.strip()
    
    # Shell prompts
    if line.startswith('$ ') or line.startswith('# ') or line.startswith('PS>') or line.startswith('C:\\>'):
        return True
    
    # Pipes and redirects
    if ' | ' in line or ' > ' in line or ' >> ' in line or ' && ' in line:
        return True
    
    # Command + flag pattern
    if re.search(r'^\w+\s+-{1,2}\w', line):
        return True
    
    # Known commands with subcommands
    words = line.split()
    if len(words) >= 2:
        commands = ['npm', 'yarn', 'git', 'curl', 'python', 'bash', 'ssh', 'docker', 'kubectl']
        if words[0].lower() in commands and (words[1].startswith('-') or words[1].islower()):
            return True
    
    return False


def _extract_command_lines(text: str) -> list[str]:
    """Extract command lines from text, filtering out prose."""
    text = (text or "").replace("\r\n", "\n")
    lines = [ln.strip() for ln in text.split("\n")]
    out: list[str] = []

    for ln in lines:
        if len(ln) < 8:
            continue
        if " " not in ln and "\t" not in ln:
            continue
        
        # CRITICAL: Filter out prose first
        if _is_likely_prose(ln):
            continue
        
        # Check for command keywords
        has_cmd_keyword = _CMD_BIN_RE.search(ln)
        has_win_path = re.search(r"(?i)\b[a-zA-Z]:\\[^\s:*?\"<>|]+", ln) and re.search(r"\s[-/]{1,2}\w", ln)
        
        if not has_cmd_keyword and not has_win_path:
            continue
        
        # Verify it's actually command-like
        if _is_likely_command(ln):
            out.append(ln)

    # Deduplicate
    seen = set()
    unique = []
    for cmd in out:
        if cmd not in seen:
            seen.add(cmd)
            unique.append(cmd)
    
    return unique[:200]


def _uniq(seq: list[str]) -> list[str]:
    """Deduplicate list while preserving order."""
    seen = set()
    out: list[str] = []
    for x in seq:
        x = (x or "").strip()
        if not x or x in seen:
            continue
        seen.add(x)
        out.append(x)
    return out


def _uniq_with_scores(items: List[ScoredIOC]) -> List[ScoredIOC]:
    """Deduplicate IOCs and keep highest score for duplicates."""
    seen = {}
    for item in items:
        key = item.value.lower()
        if key not in seen or item.confidence_score > seen[key].confidence_score:
            seen[key] = item
    
    # Sort by confidence (high to low), then alphabetically
    return sorted(seen.values(), key=lambda x: (-x.confidence_score, x.value.lower()))


# Main extraction functions

def _refang_text(text: str) -> str:
    """Refang common defanged patterns for IOC extraction."""
    result = text
    # Handle [.] -> .
    result = re.sub(r'\[\.\]', '.', result)
    # Handle hxxp -> http
    result = re.sub(r'\bhxxp(s?)\b', r'http\1', result, flags=re.I)
    # Handle [:]  -> :
    result = re.sub(r'\[:\]', ':', result)
    # Handle [@] -> @
    result = re.sub(r'\[@\]', '@', result)
    return result


def extract_iocs(text: str) -> IOCs:
    """
    Extract IOCs from text (legacy function for backward compatibility).
    Returns simple lists without confidence scores.
    Also handles defanged IOCs commonly found in threat intel articles.
    """
    text = text or ""
    
    # Refang text first to extract defanged IOCs
    refanged_text = _refang_text(text)
    
    sha256 = _uniq(re.findall(r"\b[a-fA-F0-9]{64}\b", refanged_text))
    sha1 = _uniq(re.findall(r"\b[a-fA-F0-9]{40}\b", refanged_text))
    md5 = _uniq(re.findall(r"\b[a-fA-F0-9]{32}\b", refanged_text))
    ipv4 = _uniq(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", refanged_text))
    urls = _uniq(re.findall(r"\bhttps?://[^\s<>\"]+\b", refanged_text, flags=re.I))
    domains = _uniq(re.findall(r"\b[a-z0-9][a-z0-9\-]{1,62}\.[a-z]{2,}\b", refanged_text, flags=re.I))
    win_paths = _uniq(re.findall(r"\b[a-zA-Z]:\\[^\s:*?\"<>|]+\b", refanged_text))
    cves = _uniq(re.findall(r"\bCVE-\d{4}-\d{4,7}\b", refanged_text, flags=re.I))
    command_lines = _extract_command_lines(refanged_text)
    
    return IOCs(
        sha256=sha256,
        sha1=sha1,
        md5=md5,
        ipv4=ipv4,
        urls=urls,
        domains=domains,
        win_paths=win_paths,
        command_lines=command_lines,
        cves=cves,
    )


def extract_iocs_with_confidence(text: str) -> IOCsWithConfidence:
    """
    Extract IOCs from text with confidence scoring.
    This is the enhanced version used by the new document generator.
    Also handles defanged IOCs commonly found in threat intel articles.
    """
    text = text or ""
    
    # Refang text first to extract defanged IOCs
    refanged_text = _refang_text(text)
    
    # Extract raw IOCs from refanged text
    sha256_raw = re.findall(r"\b[a-fA-F0-9]{64}\b", refanged_text)
    sha1_raw = re.findall(r"\b[a-fA-F0-9]{40}\b", refanged_text)
    md5_raw = re.findall(r"\b[a-fA-F0-9]{32}\b", refanged_text)
    ipv4_raw = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", refanged_text)
    urls_raw = re.findall(r"\bhttps?://[^\s<>\"]+\b", refanged_text, flags=re.I)
    domains_raw = re.findall(r"\b[a-z0-9][a-z0-9\-]{1,62}\.[a-z]{2,}\b", refanged_text, flags=re.I)
    win_paths_raw = re.findall(r"\b[a-zA-Z]:\\[^\s:*?\"<>|]+\b", refanged_text)
    cves_raw = re.findall(r"\bCVE-\d{4}-\d{4,7}\b", refanged_text, flags=re.I)
    command_lines_raw = _extract_command_lines(refanged_text)
    

    # Score each IOC type (fixed parameter order)
    sha256 = []
    for h in sha256_raw:
        score, reason = _score_hash(h, "SHA-256")
        sha256.append(ScoredIOC(h, score, _get_confidence_label(score), reason))
    
    sha1 = []
    for h in sha1_raw:
        score, reason = _score_hash(h, "SHA-1")
        sha1.append(ScoredIOC(h, score, _get_confidence_label(score), reason))
    
    md5 = []
    for h in md5_raw:
        score, reason = _score_hash(h, "MD5")
        md5.append(ScoredIOC(h, score, _get_confidence_label(score), reason))
    
    ipv4 = []
    for ip in ipv4_raw:
        score, reason = _score_ip(ip)
        ipv4.append(ScoredIOC(ip, score, _get_confidence_label(score), reason))
    
    urls = []
    for url in urls_raw:
        urls.append(ScoredIOC(url, 95, _get_confidence_label(95), "URL detected"))
    
    domains = []
    for d in domains_raw:
        score, reason = _score_domain(d)
        domains.append(ScoredIOC(d, score, _get_confidence_label(score), reason))
    
    win_paths = []
    for p in win_paths_raw:
        win_paths.append(ScoredIOC(p, 90, _get_confidence_label(90), "file path"))
    
    command_lines = []
    for cmd in command_lines_raw:
        command_lines.append(ScoredIOC(cmd, 95, _get_confidence_label(95), "command detected"))
    
    cves = []
    for cve in cves_raw:
        cves.append(ScoredIOC(cve, 100, _get_confidence_label(100), "valid CVE format"))
    # Deduplicate and sort
    return IOCsWithConfidence(
        sha256=_uniq_with_scores(sha256)[:200],
        sha1=_uniq_with_scores(sha1)[:200],
        md5=_uniq_with_scores(md5)[:200],
        ipv4=_uniq_with_scores(ipv4)[:200],
        urls=_uniq_with_scores(urls)[:200],
        domains=_uniq_with_scores(domains)[:200],
        win_paths=_uniq_with_scores(win_paths)[:200],
        command_lines=_uniq_with_scores(command_lines)[:200],
        cves=_uniq_with_scores(cves)[:200],
    )