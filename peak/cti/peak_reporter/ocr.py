from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field, asdict
from urllib.parse import urlparse

from PIL import Image
import pytesseract


@dataclass
class OCRResult:
    """Result from OCR processing with source linking."""
    image_path: str  # Local path to extracted image
    image_url: str = ""  # URL for viewing in repo (after push to main)
    source_file: str = ""  # Source PDF or URL
    page_number: int = 0  # Page number (for PDFs)
    image_index: int = 0  # Image index (for URLs)
    sha256: str = ""
    text: str = ""
    iocs_found: list = field(default_factory=list)  # IOCs extracted from this image
    error: str = ""
    
    def to_dict(self) -> dict:
        return asdict(self)


def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _sha256_file(path: Path) -> str:
    """Compute SHA256 of a file."""
    sha256 = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            sha256.update(chunk)
    return sha256.hexdigest()


def extract_images_from_pdf(
    pdf_path: Path,
    output_dir: Path,
    dpi: int = 150,
    max_pages: Optional[int] = None
) -> list[dict]:
    """
    Extract images from PDF pages using pdf2image.
    
    Returns list of dicts with:
      - local_path: path to extracted image
      - page_number: 1-indexed page number
      - source_file: original PDF path
    """
    try:
        from pdf2image import convert_from_path
    except ImportError:
        print("  ⚠️  pdf2image not installed, skipping PDF image extraction")
        return []
    
    output_dir.mkdir(parents=True, exist_ok=True)
    pdf_name = pdf_path.stem
    
    images_info = []
    
    try:
        # Convert PDF pages to images
        pages = convert_from_path(
            str(pdf_path),
            dpi=dpi,
            first_page=1,
            last_page=max_pages,
            fmt='png'
        )
        
        for i, page_img in enumerate(pages, 1):
            img_filename = f"{pdf_name}_page_{i:03d}.png"
            img_path = output_dir / img_filename
            page_img.save(str(img_path), 'PNG')
            
            images_info.append({
                'local_path': str(img_path),
                'page_number': i,
                'source_file': str(pdf_path),
            })
            
        print(f"  📄 Extracted {len(pages)} pages from {pdf_path.name}")
        
    except Exception as e:
        print(f"  ❌ PDF extraction failed: {e}")
    
    return images_info


def extract_images_from_url(
    url: str,
    html_content: str,
    output_dir: Path,
    max_images: int = 50
) -> list[dict]:
    """
    Extract and download images from HTML content.
    
    Returns list of dicts with:
      - local_path: path to downloaded image
      - image_index: index of image on page
      - source_file: original URL
      - original_url: image source URL
    """
    import requests
    from bs4 import BeautifulSoup
    
    output_dir.mkdir(parents=True, exist_ok=True)
    
    soup = BeautifulSoup(html_content, 'html.parser')
    img_tags = soup.find_all('img', src=True)
    
    images_info = []
    parsed_base = urlparse(url)
    base_url = f"{parsed_base.scheme}://{parsed_base.netloc}"
    
    for idx, img in enumerate(img_tags[:max_images], 1):
        src = img.get('src', '')
        if not src:
            continue
            
        # Skip tiny images (likely icons/trackers)
        width = img.get('width', '')
        height = img.get('height', '')
        if width and height:
            try:
                if int(width) < 100 or int(height) < 100:
                    continue
            except ValueError:
                pass
        
        # Resolve relative URLs
        if src.startswith('//'):
            src = f"{parsed_base.scheme}:{src}"
        elif src.startswith('/'):
            src = f"{base_url}{src}"
        elif not src.startswith('http'):
            src = f"{base_url}/{src}"
        
        # Skip data URLs and common non-content images
        if src.startswith('data:') or any(x in src.lower() for x in ['logo', 'icon', 'avatar', 'button', 'banner']):
            continue
        
        try:
            r = requests.get(src, timeout=10, headers={'User-Agent': 'PEAK-CTI/1.0'})
            r.raise_for_status()
            
            # Determine extension
            content_type = r.headers.get('content-type', '')
            if 'png' in content_type:
                ext = '.png'
            elif 'gif' in content_type:
                ext = '.gif'
            elif 'webp' in content_type:
                ext = '.webp'
            else:
                ext = '.jpg'
            
            # Save image
            img_hash = _sha256_bytes(r.content)[:12]
            img_filename = f"url_img_{idx:03d}_{img_hash}{ext}"
            img_path = output_dir / img_filename
            img_path.write_bytes(r.content)
            
            images_info.append({
                'local_path': str(img_path),
                'image_index': idx,
                'source_file': url,
                'original_url': src,
            })
            
        except Exception as e:
            continue  # Skip failed downloads silently
    
    if images_info:
        print(f"  🖼️  Downloaded {len(images_info)} images from URL")
    
    return images_info


def run_ocr_on_images(
    images_info: list[dict],
    repo_base_url: str = "",
    images_subpath: str = "peak/cti/data/ocr_images"
) -> list[OCRResult]:
    """
    Run OCR on extracted images and return results with source linking.
    
    Args:
        images_info: List of dicts from extract_images_from_pdf or extract_images_from_url
        repo_base_url: GitHub repo URL for generating viewable image links
        images_subpath: Path within repo where images will be stored
    
    Returns:
        List of OCRResult objects with extracted text and metadata
    """
    results = []
    
    for info in images_info:
        local_path = info.get('local_path', '')
        result = OCRResult(
            image_path=local_path,
            source_file=info.get('source_file', ''),
            page_number=info.get('page_number', 0),
            image_index=info.get('image_index', 0),
        )
        
        try:
            p = Path(local_path)
            if not p.exists():
                result.error = f"File not found: {local_path}"
                results.append(result)
                continue
            
            # Compute hash
            result.sha256 = _sha256_file(p)
            
            # Generate repo URL for the image
            if repo_base_url:
                img_name = p.name
                result.image_url = f"{repo_base_url}/blob/main/{images_subpath}/{img_name}"
            
            # Run OCR
            img = Image.open(p)
            txt = pytesseract.image_to_string(img) or ""
            result.text = txt.strip()
            
            # Extract IOCs from OCR text
            result.iocs_found = _extract_iocs_from_text(result.text)
            
        except Exception as e:
            result.error = str(e)
        
        results.append(result)
    
    # Summary
    successful = sum(1 for r in results if r.text and not r.error)
    with_iocs = sum(1 for r in results if r.iocs_found)
    print(f"  🔍 OCR complete: {successful}/{len(results)} images processed, {with_iocs} contain IOCs")
    
    return results


def _extract_iocs_from_text(text: str) -> list[str]:
    """Extract potential IOCs from OCR text."""
    iocs = []
    
    # IPv4
    ipv4_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    iocs.extend(re.findall(ipv4_pattern, text))
    
    # Hashes (MD5, SHA1, SHA256)
    hash_pattern = r'\b[a-fA-F0-9]{32,64}\b'
    for match in re.findall(hash_pattern, text):
        if len(match) in (32, 40, 64):
            iocs.append(match.lower())
    
    # Domains (simple pattern)
    domain_pattern = r'\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\b'
    for match in re.findall(domain_pattern, text):
        if '.' in match and not match[0].isdigit():
            iocs.append(match.lower())
    
    return list(set(iocs))[:20]  # Dedupe and limit


def run_ocr_from_map(map_path: Path, max_images: int = 120) -> list[dict]:
    """Legacy function for backward compatibility."""
    items = json.loads(map_path.read_text(encoding="utf-8"))
    out: list[dict] = []

    for it in items[:max_images]:
        image_url = it.get("image_url") or it.get("original_url") or ""
        local_path = it.get("local_path") or ""
        result = {"image_url": image_url, "local_path": local_path, "sha256": "", "text": "", "error": ""}

        try:
            p = Path(local_path)
            b = p.read_bytes()
            result["sha256"] = _sha256_bytes(b)
            img = Image.open(p)
            txt = pytesseract.image_to_string(img) or ""
            result["text"] = txt.strip()
        except Exception as e:
            result["error"] = str(e)

        out.append(result)

    return out


def generate_ocr_report_section(ocr_results: list[OCRResult], repo_base_url: str = "") -> str:
    """
    Generate markdown section for OCR results with image links.
    
    This creates a collapsible section showing:
    - Thumbnail links to each processed image
    - Extracted text from each image
    - IOCs found in each image
    """
    if not ocr_results:
        return ""
    
    lines = [
        "## 🔍 OCR Extracted Content",
        "",
        "> Images extracted from source documents with OCR text and IOCs.",
        ""
    ]
    
    # Group by source
    by_source = {}
    for r in ocr_results:
        src = r.source_file or "Unknown"
        if src not in by_source:
            by_source[src] = []
        by_source[src].append(r)
    
    for source, results in by_source.items():
        source_name = Path(source).name if not source.startswith('http') else source[:60]
        lines.append(f"### Source: {source_name}")
        lines.append("")
        
        for r in results:
            if r.error:
                continue
                
            # Image reference
            img_name = Path(r.image_path).name
            if r.page_number:
                label = f"Page {r.page_number}"
            else:
                label = f"Image {r.image_index}"
            
            lines.append(f"<details>")
            lines.append(f"<summary><strong>{label}</strong>: {img_name}</summary>")
            lines.append("")
            
            # Image link
            if r.image_url:
                lines.append(f"**View Image:** [{img_name}]({r.image_url})")
            else:
                lines.append(f"**Image:** `{img_name}`")
            lines.append("")
            
            # IOCs found
            if r.iocs_found:
                lines.append("**IOCs Found:**")
                for ioc in r.iocs_found[:10]:
                    lines.append(f"- `{ioc}`")
                lines.append("")
            
            # OCR text (truncated)
            if r.text:
                text_preview = r.text[:500].replace('\n', ' ').strip()
                if len(r.text) > 500:
                    text_preview += "..."
                lines.append("**Extracted Text:**")
                lines.append(f"> {text_preview}")
                lines.append("")
            
            lines.append("</details>")
            lines.append("")
    
    return "\n".join(lines)


def save_ocr_manifest(
    ocr_results: list[OCRResult],
    output_path: Path,
    issue_number: int = 0
) -> None:
    """Save OCR results manifest as JSON for tracking and validation."""
    manifest = {
        "issue_number": issue_number,
        "total_images": len(ocr_results),
        "images_with_text": sum(1 for r in ocr_results if r.text),
        "images_with_iocs": sum(1 for r in ocr_results if r.iocs_found),
        "total_iocs_found": sum(len(r.iocs_found) for r in ocr_results),
        "results": [r.to_dict() for r in ocr_results]
    }
    
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    print(f"  📋 OCR manifest saved: {output_path}")
