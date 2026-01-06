from __future__ import annotations

from pathlib import Path


def render_url_to_pdf(url: str, out_pdf: Path, timeout_ms: int = 60000) -> Path:
    """Render a URL in headless Chromium and save a 'print to PDF' capture.

    This is used as a fallback when normal HTML extraction yields very little
    usable text (e.g., JS-heavy pages, lazy-loaded content, odd layouts).
    """
    out_pdf.parent.mkdir(parents=True, exist_ok=True)

    # Playwright is installed by the workflow when OCR is enabled.
    from playwright.sync_api import sync_playwright  # type: ignore

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(url, wait_until="networkidle", timeout=timeout_ms)

        # Give any late async rendering a moment.
        page.wait_for_timeout(1500)

        page.pdf(
            path=str(out_pdf),
            format="A4",
            print_background=True,
        )
        browser.close()

    return out_pdf
