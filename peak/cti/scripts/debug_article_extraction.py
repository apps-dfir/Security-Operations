#!/usr/bin/env python3
"""
Debug Article Extraction

This script helps diagnose why IOCs aren't being extracted from Unit42 articles.
It shows exactly what text the parser is capturing.
"""

import sys
from pathlib import Path

# Add peak/cti to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from peak_reporter.article_parser import fetch_article_or_file


def debug_article_extraction(url: str):
    """
    Fetch an article and show what was extracted.
    """
    print(f"Debugging article extraction for:")
    print(f"   {url}")
    print("=" * 80)
    
    try:
        article = fetch_article_or_file(url)
        
        print(f"\nSuccessfully fetched article")
        print(f"\nTitle: {article.title}")
        print(f"\nText Length: {len(article.text)} characters")
        print(f"HTML Length: {len(article.html)} characters")
        
        # Show first 2000 chars of extracted text
        print(f"\nFirst 2000 characters of extracted text:")
        print("-" * 80)
        print(article.text[:2000])
        print("-" * 80)
        
        # Check for common IOC patterns
        import re
        
        sha256_matches = re.findall(r'\b[a-fA-F0-9]{64}\b', article.text)
        domains = re.findall(r'\b[a-z0-9][a-z0-9\-]{1,62}\.[a-z]{2,}\b', article.text, re.I)
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', article.text)
        urls = re.findall(r'\bhttps?://[^\s<>"]+\b', article.text, re.I)
        
        print(f"\nQuick IOC Scan Results:")
        print(f"   SHA-256 hashes found: {len(sha256_matches)}")
        if sha256_matches:
            print(f"   Examples: {sha256_matches[:3]}")
        
        print(f"   Domains found: {len(domains)}")
        if domains:
            print(f"   Examples: {domains[:5]}")
        
        print(f"   IPs found: {len(ips)}")
        if ips:
            print(f"   Examples: {ips[:5]}")
            
        print(f"   URLs found: {len(urls)}")
        if urls:
            print(f"   Examples: {urls[:3]}")
        
        # Save full text for manual review
        output_file = Path("debug_article_text.txt")
        output_file.write_text(article.text, encoding='utf-8')
        print(f"\nFull extracted text saved to: {output_file}")
        
        # Diagnostic checks
        print(f"\nDiagnostics:")
        
        if len(article.text) < 1000:
            print("   WARNING: Text is very short (< 1000 chars)")
            print("   This suggests the parser couldn't extract the article content.")
            print("   Possible causes:")
            print("   - JavaScript-heavy page (content loaded dynamically)")
            print("   - Anti-scraping protection")
            print("   - Paywall or login required")
        
        if len(sha256_matches) == 0 and "malicious" in article.text.lower():
            print("   WARNING: Article mentions 'malicious' but no hashes found")
            print("   This suggests hashes might be in images or code blocks that weren't parsed")
        
        if len(article.html) > 0 and len(article.text) < len(article.html) / 10:
            print("   WARNING: Text is much shorter than HTML")
            print("   This suggests poor text extraction from HTML")
        
        print("\nDebug complete!")
        
    except Exception as e:
        print(f"\nError fetching article:")
        print(f"   {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python debug_article_extraction.py <URL>")
        print("\nExample:")
        print("  python debug_article_extraction.py <url-to-article>")
        sys.exit(1)
    
    url = sys.argv[1]
    debug_article_extraction(url)
