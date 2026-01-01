"""PEAK CTI - Defanged IOC Handler"""
import re

def refang(ioc: str) -> str:
    """Convert defanged IOC to normal format."""
    refanged = ioc
    refanged = re.sub(r'\[\.]', '.', refanged, flags=re.IGNORECASE)
    refanged = re.sub(r'\[dot\]', '.', refanged, flags=re.IGNORECASE)
    refanged = re.sub(r'\(\.\)', '.', refanged, flags=re.IGNORECASE)
    refanged = re.sub(r'\[:\]', ':', refanged, flags=re.IGNORECASE)
    refanged = re.sub(r'\[/\]', '/', refanged, flags=re.IGNORECASE)
    refanged = re.sub(r'hxxps?://', lambda m: m.group(0).replace('hxxp', 'http'), refanged, flags=re.IGNORECASE)
    return refanged

def defang(ioc: str) -> str:
    """Convert normal IOC to defanged format."""
    defanged = ioc.replace('.', '[.]')
    defanged = defanged.replace('://', '[:]//') 
    defanged = defanged.replace('http', 'hxxp')
    return defanged

def is_defanged(ioc: str) -> bool:
    """Check if IOC is defanged."""
    patterns = [r'\[\.]', r'\[dot\]', r'\(\.\)', r'hxxps?://']
    return any(re.search(p, ioc, re.IGNORECASE) for p in patterns)

def normalize_ioc_for_comparison(ioc: str) -> str:
    """Normalize for comparison."""
    return refang(ioc).lower().strip()

if __name__ == '__main__':
    tests = [
        ("abc[.]com", "abc.com"),
        ("hxxp://evil[.]com", "http://evil.com"),
        ("1[.]1[.]1[.]1", "1.1.1.1"),
    ]
    for defanged, expected in tests:
        result = refang(defanged)
        print(f"{'✅' if result == expected else '❌'} {defanged} -> {result}")
