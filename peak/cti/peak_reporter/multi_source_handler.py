"""PEAK CTI - Multi-Source Handler"""
import re
from typing import List, Dict

def parse_multi_source_input(issue_body: str) -> List[Dict[str, str]]:
    """
    Parse multiple sources from issue body.
    Supports formats:
      - Numbered list: 1. https://example.com
      - Plain URLs on separate lines: https://example.com
      - Bullet points: - https://example.com
    """
    sources = []
    
    # Try to find ### Sources section first
    sources_match = re.search(
        r'### Sources.*?\n(.*?)(?=\n###|\Z)',
        issue_body,
        re.DOTALL | re.IGNORECASE
    )
    
    if not sources_match:
        # Fallback to ### Input for single source
        input_match = re.search(r'### Input.*?\n(.*?)(?=\n###|\Z)', issue_body, re.DOTALL)
        if input_match:
            value = input_match.group(1).strip()
            if value:
                return [{'type': 'url' if value.startswith('http') else 'file', 'value': value}]
        return []
    
    sources_text = sources_match.group(1)
    
    for line in sources_text.split('\n'):
        line = line.strip()
        if not line:
            continue
        
        # Try numbered format: 1. https://...
        numbered_match = re.match(r'^\d+\.\s+(.+)$', line)
        if numbered_match:
            value = numbered_match.group(1).strip()
        # Try bullet format: - https://...
        elif line.startswith('- '):
            value = line[2:].strip()
        # Try plain URL
        elif line.startswith('http'):
            value = line
        else:
            continue
        
        # Add if valid and under limit
        if value and len(sources) < 5:
            sources.append({
                'type': 'url' if value.startswith('http') else 'file',
                'value': value
            })
    
    return sources

if __name__ == '__main__':
    test = """
### Sources
1. https://example.com/article1
https://example.com/article2
- https://example.com/article3
"""
    sources = parse_multi_source_input(test)
    print(f"Parsed {len(sources)} sources")
    for s in sources:
        print(f"  - {s['value']}")
