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
    
    # Extract processed date from filename
    # Format: issue-X_title_consolidated_YYYYMMDD_HHMMSS_microseconds.md
    date_match = re.search(r'_(\d{8})_\d{6}_\d+\.md$', str(report_path))
    if date_match:
        date_str = date_match.group(1)
        metadata['processed_date'] = f"{date_str[:4]}-{date_str[4:6]}-{date_str[6:8]}"
    else:
        metadata['processed_date'] = ''
    
    # Extract MITRE ATT&CK techniques from multiple formats
    mitre_techniques = []
    seen_techniques = set()
    
    # Format 1: Table format - | T1234: Name | or | T1234.001: Name |
    for match in re.finditer(r'\|\s*(T\d{4}(?:\.\d{3})?)[:\s]+([^|]+?)\s*\|', content):
        tech_id = match.group(1)
        tech_name = match.group(2).strip()
        if tech_id not in seen_techniques:
            seen_techniques.add(tech_id)
            mitre_techniques.append({
                'technique_id': tech_id,
                'technique_name': tech_name
            })
    
    # Format 2: Bold format - **T1234**: Name or - **T1234.001**: Name
    for match in re.finditer(r'\*\*(T\d{4}(?:\.\d{3})?)\*\*(?:[:\s]+([^\n]+))?', content):
        tech_id = match.group(1)
        tech_name = match.group(2).strip() if match.group(2) else ''
        if tech_id not in seen_techniques:
            seen_techniques.add(tech_id)
            mitre_techniques.append({
                'technique_id': tech_id,
                'technique_name': tech_name
            })
    
    metadata['mitre_techniques'] = mitre_techniques
    
    # Extract threat actors using multiple naming conventions
    threat_actors = extract_threat_actors(content)
    metadata['threat_actors'] = threat_actors
    
    return metadata


def extract_threat_actors(content):
    """
    Extract threat actor names from report content using multiple naming conventions.
    
    Supported naming conventions:
    - Microsoft: Weather themes (Blizzard=Russia, Typhoon=China, Sandstorm=Iran, Sleet=DPRK)
    - CrowdStrike: Animal themes (Bear=Russia, Panda=China, Kitten=Iran, Chollima=DPRK, Spider=eCrime)
    - Palo Alto Unit 42: Constellation/Zodiac themes (Scorpius, Taurus, Libra with adjective prefix)
    - CISA/Government: Standard APT numbering and UNC/DEV designations
    - Common names: Lazarus, Equation Group, Fancy Bear, etc.
    """
    found_actors = set()
    content_lower = content.lower()
    
    # =========================================================================
    # PATTERN-BASED EXTRACTION
    # Catches: "tracked as X", "attributed to X", "threat actor X", etc.
    # =========================================================================
    attribution_patterns = [
        r'(?:tracked\s+as|tracking\s+as)\s+["\']?([A-Z][A-Za-z0-9\-]+(?:\s+[A-Z][A-Za-z0-9\-]+)?)["\']?(?:\s|,|\.|\))',
        r'(?:attributed\s+to|attribution\s+to)\s+["\']?([A-Z][A-Za-z0-9\-]+(?:\s+[A-Z][A-Za-z0-9\-]+)?)["\']?(?:\s|,|\.|\))',
        r'(?:threat\s+actor|threat\s+group|apt\s+group)\s+(?:known\s+as\s+)?["\']?([A-Z][A-Za-z0-9\-]+(?:\s+[A-Z][A-Za-z0-9\-]+)?)["\']?(?:\s|,|\.|\))',
        r'(?:operated\s+by|conducted\s+by)\s+["\']?([A-Z][A-Za-z0-9\-]+(?:\s+[A-Z][A-Za-z0-9\-]+)?)["\']?(?:\s|,|\.|\))',
    ]
    
    for pattern in attribution_patterns:
        for match in re.finditer(pattern, content, re.IGNORECASE):
            actor = match.group(1).strip()
            # Filter out common false positives
            if len(actor) > 2 and len(actor) < 50:
                if not any(fp in actor.lower() for fp in ['the', 'this', 'that', 'these', 'their', 'north korea', 'china', 'russia', 'iran']):
                    found_actors.add(actor)
    
    # =========================================================================
    # APT NUMBERING (CISA/MITRE Standard)
    # Format: APT1, APT28, APT29, etc.
    # =========================================================================
    apt_pattern = r'\bAPT[-\s]?(\d{1,3})\b'
    for match in re.finditer(apt_pattern, content, re.IGNORECASE):
        found_actors.add(f"APT{match.group(1)}")
    
    # =========================================================================
    # UNC/DEV/TEMP DESIGNATIONS (Mandiant/Microsoft tracking)
    # Format: UNC1234, DEV-0123, TEMP.Name
    # =========================================================================
    tracking_patterns = [
        (r'\bUNC[-\s]?(\d{3,5})\b', 'UNC'),
        (r'\bDEV[-\s]?(\d{3,5})\b', 'DEV-'),
        (r'\bTEMP\.([A-Za-z]+)\b', 'TEMP.'),
    ]
    for pattern, prefix in tracking_patterns:
        for match in re.finditer(pattern, content, re.IGNORECASE):
            found_actors.add(f"{prefix}{match.group(1)}")
    
    # =========================================================================
    # MICROSOFT NAMING CONVENTION (Weather Themes)
    # Russia=Blizzard, China=Typhoon, Iran=Sandstorm, DPRK=Sleet, etc.
    # =========================================================================
    microsoft_actors = [
        # Russia (Blizzard)
        'Midnight Blizzard', 'Star Blizzard', 'Secret Blizzard', 'Forest Blizzard',
        'Seashell Blizzard', 'Aquatic Blizzard', 'Cadet Blizzard', 'Ember Blizzard',
        # China (Typhoon)
        'Volt Typhoon', 'Salt Typhoon', 'Flax Typhoon', 'Brass Typhoon', 'Silk Typhoon',
        'Charcoal Typhoon', 'Salmon Typhoon', 'Raspberry Typhoon', 'Circle Typhoon',
        'Canvas Typhoon', 'Granite Typhoon', 'Nylon Typhoon', 'Ginger Typhoon',
        'Mulberry Typhoon', 'Cinnamon Typhoon',
        # Iran (Sandstorm)
        'Mint Sandstorm', 'Peach Sandstorm', 'Cotton Sandstorm', 'Lemon Sandstorm',
        'Pumpkin Sandstorm', 'Crimson Sandstorm', 'Mango Sandstorm', 'Pink Sandstorm',
        'Hazel Sandstorm', 'Smoke Sandstorm',
        # DPRK (Sleet)
        'Diamond Sleet', 'Jade Sleet', 'Citrine Sleet', 'Onyx Sleet', 'Moonstone Sleet',
        'Sapphire Sleet', 'Emerald Sleet', 'Ruby Sleet', 'Opal Sleet',
        # Lebanon (Rain)
        'Mango Rain',
        # Turkey (Dust)
        'Marbled Dust', 'Silicon Dust',
        # Vietnam (Cane)
        'Canvas Cyclone',
        # Pakistan (Monsoon)
        'Transparent Tribe',
        # eCrime/Financially Motivated (Tempest)
        'Octo Tempest', 'Sangria Tempest', 'Pistachio Tempest', 'Periwinkle Tempest',
        'Vanilla Tempest', 'Manatee Tempest', 'Strawberry Tempest', 'Scattered Spider',
        # Storm designations (unattributed)
        'Storm-0501', 'Storm-0539', 'Storm-0558', 'Storm-0569', 'Storm-0978',
        'Storm-1101', 'Storm-1152', 'Storm-1175', 'Storm-1516', 'Storm-1567',
    ]
    
    for actor in microsoft_actors:
        if actor.lower() in content_lower:
            found_actors.add(actor)
    
    # Storm-#### pattern
    storm_pattern = r'\bStorm[-\s]?(\d{4})\b'
    for match in re.finditer(storm_pattern, content, re.IGNORECASE):
        found_actors.add(f"Storm-{match.group(1)}")
    
    # =========================================================================
    # CROWDSTRIKE NAMING CONVENTION (Animal Themes)
    # Russia=Bear, China=Panda, Iran=Kitten, DPRK=Chollima, eCrime=Spider
    # Pakistan=Leopard, India=Tiger, Vietnam=Buffalo, Syria=Jackal
    # =========================================================================
    crowdstrike_actors = [
        # Russia (Bear)
        'Fancy Bear', 'Cozy Bear', 'Voodoo Bear', 'Venomous Bear', 'Primitive Bear',
        'Energetic Bear', 'Berserk Bear', 'Gossamer Bear', 'Ember Bear', 'Callisto Bear',
        # China (Panda)
        'Gothic Panda', 'Emissary Panda', 'Wicked Panda', 'Mustang Panda', 'Aquatic Panda',
        'Judgement Panda', 'Pirate Panda', 'Stalker Panda', 'Stone Panda', 'Violet Panda',
        'Kryptonite Panda', 'Karma Panda', 'Anchor Panda', 'Deep Panda', 'Turbine Panda',
        'Hurricane Panda', 'Nightshade Panda', 'Vixen Panda', 'Wet Panda', 'Dagger Panda',
        # Iran (Kitten)
        'Charming Kitten', 'Clever Kitten', 'Magic Kitten', 'Pioneer Kitten', 'Remix Kitten',
        'Rocket Kitten', 'Static Kitten', 'Imperial Kitten', 'Nemesis Kitten', 'Tortoiseshell',
        # DPRK (Chollima)
        'Labyrinth Chollima', 'Ricochet Chollima', 'Silent Chollima', 'Stardust Chollima',
        'Velvet Chollima', 'Famous Chollima',
        # Pakistan (Leopard)
        'Mythic Leopard', 'Cosmic Leopard',
        # India (Tiger)
        'Viceroy Tiger', 'Quilted Tiger', 'Dropping Elephant',
        # Syria (Jackal)
        'Deadeye Jackal',
        # eCrime (Spider)
        'Wizard Spider', 'Mummy Spider', 'Pinchy Spider', 'Dungeon Spider', 'Graceful Spider',
        'Carbon Spider', 'Indrik Spider', 'Doppel Spider', 'Traveling Spider', 'Riddle Spider',
        'Bitwise Spider', 'Twisted Spider', 'Viking Spider', 'Salty Spider', 'Scully Spider',
        'Lunar Spider', 'Venom Spider', 'Punk Spider', 'Circus Spider', 'Alpha Spider',
        'Scattered Spider', 'Chatty Spider', 'Wandering Spider',
        # Other eCrime
        'Sprite Wolf', 'Helix Kitten',
    ]
    
    for actor in crowdstrike_actors:
        if actor.lower() in content_lower:
            found_actors.add(actor)
    
    # =========================================================================
    # PALO ALTO UNIT 42 NAMING CONVENTION (Constellation/Zodiac Themes)
    # Format: [Adjective] [Zodiac Sign] - e.g., Jolly Scorpius, Stately Taurus
    # =========================================================================
    unit42_actors = [
        # Scorpius (Ransomware groups)
        'Jolly Scorpius', 'Howling Scorpius', 'Ambitious Scorpius', 'Sly Scorpius',
        'Stately Scorpius', 'Wandering Scorpius', 'Muddled Scorpius', 'Spoiled Scorpius',
        'Sluggish Scorpius', 'Stumbling Scorpius', 'Slipshod Scorpius',
        # Taurus (China)
        'Stately Taurus', 'Alloy Taurus', 'Granite Taurus', 'Vanguard Taurus',
        'Vibrant Taurus', 'Nebulous Taurus', 'Plucky Taurus', 'Grayling Taurus',
        # Libra (Iran)
        'Spectral Libra', 'Magic Libra', 'Educated Libra', 'Verdant Libra',
        'Evasive Libra', 'Hairy Libra',
        # Gemini (DPRK)
        'Gleaming Gemini', 'Selective Gemini', 'Slow Gemini', 'Sapphire Gemini',
        # Pisces (Russia)
        'Fighting Pisces', 'Trident Pisces', 'Rainy Pisces', 'Static Pisces',
        'Secret Pisces', 'Slippery Pisces',
        # Other constellations
        'Playful Leo', 'Insidious Aquarius', 'Thief Aquarius', 'Imposing Aquarius',
        'Blazing Aries', 'Roaming Sagittarius', 'White Sagittarius',
    ]
    
    for actor in unit42_actors:
        if actor.lower() in content_lower:
            found_actors.add(actor)
    
    # =========================================================================
    # COMMON/LEGACY THREAT ACTOR NAMES
    # Well-known names that may not follow vendor conventions
    # =========================================================================
    common_actors = [
        # Russian Groups
        'Sandworm', 'Turla', 'Gamaredon', 'Nobelium', 'Dragonfly', 'Energetic Bear',
        'Shuckworm', 'Armageddon', 'Callisto', 'Cold River', 'Seaborgium', 'Blue Charlie',
        # Chinese Groups
        'Lazarus Group', 'Equation Group', 'Kimsuky', 'Hafnium', 'Winnti', 'BlackTech',
        'Cicada', 'Stone Panda', 'Naikon', 'Lotus Blossom', 'Tick', 'Tonto Team',
        'RedDelta', 'RedHotel', 'Earth Lusca', 'Earth Krahang', 'Earth Estries',
        # Iranian Groups
        'MuddyWater', 'OilRig', 'Shamoon', 'APT33', 'APT34', 'APT35', 'APT39',
        'Phosphorus', 'Cobalt Mirage', 'DEV-0270', 'Moses Staff', 'Agrius',
        # DPRK Groups
        'Lazarus', 'Kimsuky', 'Andariel', 'Bluenoroff', 'BeagleBoyz', 'TraderTraitor',
        'Stonefly', 'Reaper', 'ScarCruft', 'InkySquid', 'TA406', 'TA444', 'TA445',
        # eCrime Groups
        'FIN7', 'FIN8', 'FIN11', 'FIN12', 'FIN13',
        'Conti', 'REvil', 'DarkSide', 'BlackMatter', 'BlackCat', 'ALPHV', 'LockBit',
        'Hive', 'Royal', 'Cl0p', 'Clop', 'RansomHouse', 'RansomHub', 'Rhysida',
        'Akira', 'Play', 'Black Basta', 'BianLian', 'Medusa', 'Inc Ransom',
        'Vice Society', 'Cuba', 'Qilin', 'Hunters International', 'Meow', 'INC',
        'AvosLocker', 'Karakurt', 'Zeppelin', 'Yanluowang', 'Trigona', 'Snatch',
        # IAB/Access Brokers
        'Prophet Spider', 'Exotic Lily', 'DEV-0569', 'Raspberry Robin',
        # Other Notable Groups
        'Lapsus$', 'LAPSUS', 'Anonymous Sudan', 'Killnet', 'NoName057',
        'Dark Angels', 'Cactus', 'Money Message', 'Mallox', '8Base', 'Hunters',
    ]
    
    for actor in common_actors:
        # Case insensitive but preserve original casing in output
        if actor.lower() in content_lower:
            found_actors.add(actor)
    
    # =========================================================================
    # FIN GROUPS (Mandiant Financial Threat Groups)
    # =========================================================================
    fin_pattern = r'\bFIN[-\s]?(\d{1,2})\b'
    for match in re.finditer(fin_pattern, content, re.IGNORECASE):
        found_actors.add(f"FIN{match.group(1)}")
    
    # =========================================================================
    # TA GROUPS (Proofpoint Threat Actor Groups)
    # =========================================================================
    ta_pattern = r'\bTA[-\s]?(\d{3,4})\b'
    for match in re.finditer(ta_pattern, content, re.IGNORECASE):
        found_actors.add(f"TA{match.group(1)}")
    
    # =========================================================================
    # POST-PROCESSING: Clean up and deduplicate
    # =========================================================================
    cleaned_actors = set()
    for actor in found_actors:
        # Remove trailing punctuation
        actor = actor.strip().rstrip('.,;:')
        # Skip if too short or looks like noise
        if len(actor) >= 3 and not actor.lower() in ['the', 'and', 'for', 'with']:
            cleaned_actors.add(actor)
    
    return sorted(list(cleaned_actors))


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
        print(f"Directory not found: {reports_dir}")
        return 1
    
    print("Building IOC database...")
    database = build_database(reports_dir)
    
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w') as f:
        json.dump(database, f, indent=2 if args.pretty else None)
    
    print(f"\nDatabase built: {output_path}")
    print(f"   Reports: {database['metadata']['total_reports']}")
    print(f"   Unique IOCs: {database['metadata']['total_iocs']}")
    print(f"   Source URLs indexed: {len(database['sources'])}")
    
    return 0


if __name__ == '__main__':
    exit(main())
