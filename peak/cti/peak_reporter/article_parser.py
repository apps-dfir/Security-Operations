from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import requests
from bs4 import BeautifulSoup
from readability import Document

from .file_parser import (
    SourceContent,
    guess_ext_from_url,
    is_url,
    load_source,
    load_source_as_text,
)
from .render_url_to_pdf import render_url_to_pdf

@dataclass
class Article:
    source: str
    title: str
    text: str
    html: str

def _visible_text_from_html(html: str) -> str:
    soup = BeautifulSoup(html or "", "lxml")
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    txt = soup.get_text("\n", strip=True)
    lines = [ln.strip() for ln in txt.splitlines()]
    lines = [ln for ln in lines if ln]
    return "\n".join(lines)

def _normalize_local_path(input_value: str) -> Path:
    # Accept:
    # - peak/cti/inputs/<file>
    # - inputs/<file>
    # - absolute/relative path
    raw = (input_value or "").strip()
    p = Path(raw)
    if raw.startswith("peak/cti/"):
        p = Path(raw.replace("peak/cti/", ""))
    return p

def fetch_article_or_file(input_value: str, timeout_s: int = 60) -> Article:
    input_value = (input_value or "").strip()

    inputs_dir = Path("inputs")
    cache_dir = Path("data/cache")
    cache_dir.mkdir(parents=True, exist_ok=True)

    if is_url(input_value):
        # If the URL is a direct file (pdf/docx/md/txt), treat it like a file input.
        ext = guess_ext_from_url(input_value)
        if ext in {".pdf", ".docx", ".md", ".txt"}:
            sc: SourceContent = load_source_as_text(input_value, inputs_dir, cache_dir)
            return Article(source=sc.source_label, title=Path(sc.source_label).name or input_value, text=sc.text, html="")

        # Otherwise treat as an HTML/article URL.
        r = requests.get(
            input_value,
            timeout=timeout_s,
            headers={"User-Agent": "Mozilla/5.0 (compatible; peak-reporter/1.0)"},
        )
        r.raise_for_status()
        html = r.text

        title = ""
        text = ""
        try:
            doc = Document(html)
            title = (doc.short_title() or "").strip()
            main_html = doc.summary(html_partial=True)
            text = _visible_text_from_html(main_html)
            if not text:
                raise ValueError("Empty readability text")
        except Exception:
            soup = BeautifulSoup(html, "lxml")
            title = (soup.title.get_text(strip=True) if soup.title else "").strip() or "Untitled"
            text = _visible_text_from_html(html)

        # HTML fallback: if text is suspiciously small, render the page to PDF
        # and parse with Docling (layout-aware + OCR support).
        if len((text or "").strip()) < 1200:
            try:
                rendered_pdf = cache_dir / "rendered_url.pdf"
                render_url_to_pdf(input_value, rendered_pdf)

                try:
                    from docling.document_converter import DocumentConverter  # type: ignore

                    converter = DocumentConverter()
                    result = converter.convert(str(rendered_pdf))
                    md = (result.document.export_to_markdown() or "").strip()
                    if md:
                        # Keep the HTML title if we got one; otherwise fall back.
                        return Article(source=input_value, title=title or input_value, text=md, html=html)
                except Exception:
                    pass
            except Exception:
                # If fallback fails, keep the original extracted text.
                pass

        return Article(source=input_value, title=title or input_value, text=text, html=html)

    p = _normalize_local_path(input_value)
    if not p.exists():
        raise FileNotFoundError(f"Input file not found: {input_value} (resolved to {p})")

    # For local files, route through the shared file loader so PDF/DOCX/MD
    # all normalize consistently.
    sc = load_source(str(p), inputs_dir, cache_dir)
    return Article(source=input_value, title=p.name, text=sc.text, html="")

# -------------------- Input source router (URL or repo file) --------------------

def parse_input_source(source: str, inputs_dir: Path, cache_dir: Path) -> SourceContent:
    """If source is a file (txt/md/docx/pdf) return its text; if it's an article URL return empty text."""
    source = (source or "").strip()
    if not source:
        return SourceContent(text="", source_label=source)

    if is_url(source):
        ext = guess_ext_from_url(source)
        if ext in {".txt", ".md", ".pdf", ".docx"}:
            return load_source_as_text(source, inputs_dir, cache_dir)
        # Not a direct file URL; let the HTML article parser handle it.
        return SourceContent(text="", source_label=source)

    # repo file path
    return load_source_as_text(source, inputs_dir, cache_dir)
