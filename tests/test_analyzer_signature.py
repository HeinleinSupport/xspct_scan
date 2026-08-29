# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>

"""Digital signature (VBA/OOXML/PDF) analyzer tests."""

import base64
import hashlib
import io
import struct
import zipfile

import pytest

import xspct_scan.daemon as xspct
from tests.conftest import (
    _HAS_PYMUPDF,
    PDF_CLEAN,
    _pymupdf,
)


def _make_test_cert_key(
    tmp_path,
    *,
    not_valid_before=None,
    not_valid_after=None,
    key_usage=None,
    issuer_name=None,
):
    """Write a self-signed RSA-2048 test cert/key pair to *tmp_path*.

    Returns ``(key_file, cert_file, cert)`` where the first two are str
    paths suitable for ``pyhanko.sign.signers.SimpleSigner.load`` and
    *cert* is the parsed ``cryptography`` certificate object.

    *not_valid_before*/*not_valid_after* and *key_usage* (a
    ``cryptography.x509.KeyUsage`` instance) let tests build certificates
    that are expired/not-yet-valid or that restrict signing usage.
    """
    import datetime as _dt

    from cryptography import x509 as _test_x509
    from cryptography.hazmat.primitives import hashes as _test_hashes
    from cryptography.hazmat.primitives import serialization as _test_serialization
    from cryptography.hazmat.primitives.asymmetric import rsa as _test_rsa
    from cryptography.x509.oid import NameOID as _NameOID

    key = _test_rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = _test_x509.Name(
        [_test_x509.NameAttribute(_NameOID.COMMON_NAME, "Test Signer")]
    )
    now = _dt.datetime.now(_dt.timezone.utc)
    builder = (
        _test_x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer_name or name)
        .public_key(key.public_key())
        .serial_number(_test_x509.random_serial_number())
        .not_valid_before(not_valid_before or now - _dt.timedelta(days=1))
        .not_valid_after(not_valid_after or now + _dt.timedelta(days=365))
    )
    if key_usage is not None:
        builder = builder.add_extension(key_usage, critical=True)
    cert = builder.sign(key, _test_hashes.SHA256())
    key_file = tmp_path / "key.pem"
    cert_file = tmp_path / "cert.pem"
    key_file.write_bytes(
        key.private_bytes(
            _test_serialization.Encoding.PEM,
            _test_serialization.PrivateFormat.TraditionalOpenSSL,
            _test_serialization.NoEncryption(),
        )
    )
    cert_file.write_bytes(cert.public_bytes(_test_serialization.Encoding.PEM))
    return str(key_file), str(cert_file), cert


def _make_vba_digsig_blob(key_file, cert_file):
    """Return a length-prefixed [MS-OSHARED] DigSigBlob signed with the test cert."""
    from pyhanko.sign.signers import SimpleSigner

    signer = SimpleSigner.load(key_file, cert_file)
    content_info = signer.sign_general_data(
        b"vba project hash bytes", "sha256", detached=False
    )
    cms_der = content_info.dump()
    return struct.pack("<I", len(cms_der)) + cms_der


def _make_ooxml_document_signature_zip(
    cert,
    key_file,
    cert_file,
    *,
    tampered=False,
    sign_manifest=True,
    transform_uri=None,
    signature_method="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    duplicate_package_object=False,
    additional_cert=None,
    unsigned_timestamp=None,
    unsigned_part=False,
    with_doctype=False,
):
    """Build a minimal signed .docx-like zip with an OOXML XML-DSig signature.

    The ``<Signature>`` tree is built in its FINAL position before any c14n
    digest is computed (never reparented afterwards) — reparenting a node
    with its own redundant namespace declaration silently corrupts lxml's
    canonicalization of descendants.
    """
    from cryptography.hazmat.primitives import hashes as _test_hashes
    from cryptography.hazmat.primitives import serialization as _test_serialization
    from cryptography.hazmat.primitives.asymmetric import padding as _test_padding
    from lxml import etree as _test_etree

    key = _test_serialization.load_pem_private_key(
        open(key_file, "rb").read(), password=None
    )
    cert_der = cert.public_bytes(_test_serialization.Encoding.DER)

    ds = "http://www.w3.org/2000/09/xmldsig#"

    def q(tag):
        return f"{{{ds}}}{tag}"

    doc_xml = b"<w:document xmlns:w='x'><w:body>Hello</w:body></w:document>"
    doc_digest = base64.b64encode(hashlib.sha256(doc_xml).digest()).decode()

    sig = _test_etree.Element(q("Signature"), nsmap={None: ds})
    signed_info = _test_etree.SubElement(sig, q("SignedInfo"))
    sig_value_el = _test_etree.SubElement(sig, q("SignatureValue"))
    key_info = _test_etree.SubElement(sig, q("KeyInfo"))
    x509_data = _test_etree.SubElement(key_info, q("X509Data"))
    _test_etree.SubElement(x509_data, q("X509Certificate")).text = base64.b64encode(
        cert_der
    ).decode()
    if additional_cert is not None:
        additional_der = additional_cert.public_bytes(_test_serialization.Encoding.DER)
        _test_etree.SubElement(x509_data, q("X509Certificate")).text = base64.b64encode(
            additional_der
        ).decode()

    obj = _test_etree.SubElement(sig, q("Object"), Id="idPackageObject")
    manifest = _test_etree.SubElement(obj, q("Manifest"))
    ref_part = _test_etree.SubElement(
        manifest, q("Reference"), URI="/word/document.xml?ContentType=xxx"
    )
    _test_etree.SubElement(
        ref_part, q("DigestMethod"), Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"
    )
    _test_etree.SubElement(ref_part, q("DigestValue")).text = doc_digest

    obj_c14n = _test_etree.tostring(obj, method="c14n")
    obj_digest = base64.b64encode(hashlib.sha256(obj_c14n).digest()).decode()

    if duplicate_package_object:
        duplicate = _test_etree.fromstring(_test_etree.tostring(obj))
        sig.append(duplicate)

    if unsigned_timestamp:
        mdssi = "http://schemas.openxmlformats.org/package/2006/digital-signature"
        unsigned_obj = _test_etree.SubElement(sig, q("Object"), Id="idUnsignedTime")
        signature_time = _test_etree.SubElement(
            unsigned_obj, f"{{{mdssi}}}SignatureTime"
        )
        _test_etree.SubElement(
            signature_time, f"{{{mdssi}}}Value"
        ).text = unsigned_timestamp

    if sign_manifest:
        ref_obj = _test_etree.SubElement(
            signed_info, q("Reference"), URI="#idPackageObject"
        )
        if transform_uri:
            transforms = _test_etree.SubElement(ref_obj, q("Transforms"))
            _test_etree.SubElement(transforms, q("Transform"), Algorithm=transform_uri)
        _test_etree.SubElement(
            ref_obj,
            q("DigestMethod"),
            Algorithm="http://www.w3.org/2001/04/xmlenc#sha256",
        )
        _test_etree.SubElement(ref_obj, q("DigestValue")).text = obj_digest
    _test_etree.SubElement(
        signed_info,
        q("SignatureMethod"),
        Algorithm=signature_method,
    )

    si_c14n = _test_etree.tostring(signed_info, method="c14n")
    sig_bytes = key.sign(si_c14n, _test_padding.PKCS1v15(), _test_hashes.SHA256())
    sig_value_el.text = base64.b64encode(sig_bytes).decode()

    sig_xml = _test_etree.tostring(sig)
    if with_doctype:
        sig_xml = b'<!DOCTYPE Signature [<!ENTITY injected "EXPANDED">]>' + sig_xml

    final_doc_xml = (
        b"<w:document xmlns:w='x'><w:body>TAMPERED</w:body></w:document>"
        if tampered
        else doc_xml
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("word/document.xml", final_doc_xml)
        if unsigned_part:
            z.writestr("word/unsigned-payload.xml", b"<payload>unsigned</payload>")
        z.writestr("_xmlsignatures/sig1.xml", sig_xml)
    return buf.getvalue()


@pytest.mark.skipif(not xspct.HAS_PYHANKO, reason="pyhanko not installed")
class TestAnalyzeSignatures:
    """Tests for the Stufe 5 signature-detection analyzer (VBA/OOXML/PDF)."""

    # -----------------------------------------------------------------------
    # VBA project signature — CMS parsing/validation (_parse_vba_digsig)
    # -----------------------------------------------------------------------

    def test_parse_vba_digsig_valid(self, daemon, tmp_path):
        key_file, cert_file, _cert = _make_test_cert_key(tmp_path)
        digsig = _make_vba_digsig_blob(key_file, cert_file)
        entry = daemon._parse_vba_digsig(digsig)
        assert entry is not None
        assert entry["present"] is True
        assert entry["type"] == "vba_project"
        assert entry["valid"] is True
        assert entry["trusted"] is False
        assert entry["covers_whole_document"] is False
        assert entry["key_usage_valid"] is True
        assert entry["cert_time_valid"] is True
        assert "Test Signer" in entry["signer"]
        assert entry["issuer_fingerprint"].startswith("sha256:")

    def test_parse_vba_digsig_too_short(self, daemon):
        assert daemon._parse_vba_digsig(b"\x00\x00") is None

    def test_parse_vba_digsig_garbage(self, daemon):
        assert daemon._parse_vba_digsig(struct.pack("<I", 4) + b"junk") is None

    # -----------------------------------------------------------------------
    # VBA project signature — OOXML zip member (vbaProjectSignature*.bin)
    # -----------------------------------------------------------------------

    def test_vba_signature_ooxml_zip_member(self, daemon, tmp_path):
        key_file, cert_file, _cert = _make_test_cert_key(tmp_path)
        digsig = _make_vba_digsig_blob(key_file, cert_file)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("word/document.xml", b"<w:document/>")
            z.writestr("word/vbaProject.bin", b"placeholder")
            z.writestr("word/vbaProjectSignature.bin", digsig)
        result = daemon.analyze_signatures(buf.getvalue(), "macro.docm")
        assert result is not None
        sigs = result["signatures"]
        assert any(s["type"] == "vba_project" for s in sigs)
        vba_entry = next(s for s in sigs if s["type"] == "vba_project")
        assert vba_entry["valid"] is True
        assert vba_entry["trusted"] is False

    # -----------------------------------------------------------------------
    # VBA project signature — OLE2 stream (_extract_ole_vba_signatures)
    # -----------------------------------------------------------------------

    def test_vba_signature_ole_stream(self, daemon, tmp_path, monkeypatch):
        key_file, cert_file, _cert = _make_test_cert_key(tmp_path)
        digsig = _make_vba_digsig_blob(key_file, cert_file)

        class _FakeOle:
            def __init__(self, streams):
                self._streams = streams

            def listdir(self, streams=True, storages=False):
                return [list(p) for p in self._streams]

            def openstream(self, path):
                return io.BytesIO(self._streams[tuple(path)])

            def close(self):
                pass

        fake = _FakeOle({("\x05DigitalSignature",): digsig})
        monkeypatch.setattr(xspct, "HAS_OLEFILE", True)
        monkeypatch.setattr(xspct._olefile, "isOleFile", lambda _b: True)
        monkeypatch.setattr(xspct._olefile, "OleFileIO", lambda _b: fake)

        result = daemon.analyze_signatures(b"not-really-ole-but-mocked", "macro.xls")
        assert result is not None
        sigs = result["signatures"]
        assert len(sigs) == 1
        assert sigs[0]["type"] == "vba_project"
        assert sigs[0]["valid"] is True

    # -----------------------------------------------------------------------
    # OOXML whole-document signature (XML-DSig)
    # -----------------------------------------------------------------------

    def test_ooxml_document_signature_valid(self, daemon, tmp_path):
        key_file, cert_file, cert = _make_test_cert_key(tmp_path)
        good = _make_ooxml_document_signature_zip(cert, key_file, cert_file)
        result = daemon.analyze_signatures(good, "good.docx")
        assert result is not None
        sigs = result["signatures"]
        assert len(sigs) == 1
        entry = sigs[0]
        assert entry["type"] == "ooxml_document"
        assert entry["valid"] is True
        assert entry["covers_whole_document"] is True
        assert entry["trusted"] is False
        assert entry["key_usage_valid"] is True
        assert entry["cert_time_valid"] is True
        assert "Test Signer" in entry["signer"]

    def test_ooxml_document_signature_tampered(self, daemon, tmp_path):
        key_file, cert_file, cert = _make_test_cert_key(tmp_path)
        tampered = _make_ooxml_document_signature_zip(
            cert, key_file, cert_file, tampered=True
        )
        result = daemon.analyze_signatures(tampered, "tampered.docx")
        assert result is not None
        sigs = result["signatures"]
        assert len(sigs) == 1
        entry = sigs[0]
        assert entry["type"] == "ooxml_document"
        assert entry["valid"] is False

    def test_ooxml_document_signature_requires_signed_package_manifest(
        self, daemon, tmp_path
    ):
        key_file, cert_file, cert = _make_test_cert_key(tmp_path)
        unsigned_manifest = _make_ooxml_document_signature_zip(
            cert, key_file, cert_file, sign_manifest=False
        )
        assert daemon.analyze_signatures(unsigned_manifest, "unsigned.docx") is None

    def test_ooxml_document_signature_rejects_unsupported_transform(
        self, daemon, tmp_path
    ):
        key_file, cert_file, cert = _make_test_cert_key(tmp_path)
        transformed = _make_ooxml_document_signature_zip(
            cert,
            key_file,
            cert_file,
            transform_uri="urn:xspct:unsupported-transform",
        )
        assert daemon.analyze_signatures(transformed, "transform.docx") is None

    def test_ooxml_document_signature_rejects_unsupported_signature_method(
        self, daemon, tmp_path
    ):
        key_file, cert_file, cert = _make_test_cert_key(tmp_path)
        unsupported_method = _make_ooxml_document_signature_zip(
            cert,
            key_file,
            cert_file,
            signature_method="urn:xspct:unsupported-signature-method",
        )
        assert daemon.analyze_signatures(unsupported_method, "method.docx") is None

    def test_ooxml_document_signature_rejects_duplicate_package_object_id(
        self, daemon, tmp_path
    ):
        key_file, cert_file, cert = _make_test_cert_key(tmp_path)
        duplicated = _make_ooxml_document_signature_zip(
            cert, key_file, cert_file, duplicate_package_object=True
        )
        assert daemon.analyze_signatures(duplicated, "duplicate.docx") is None

    def test_ooxml_document_signature_reports_incomplete_package_coverage(
        self, daemon, tmp_path
    ):
        key_file, cert_file, cert = _make_test_cert_key(tmp_path)
        document = _make_ooxml_document_signature_zip(
            cert, key_file, cert_file, unsigned_part=True
        )
        result = daemon.analyze_signatures(document, "subset.docx")
        entry = result["signatures"][0]
        assert entry["valid"] is True
        assert entry["covers_whole_document"] is False

    def test_ooxml_document_signature_rejects_doctype(self, daemon, tmp_path):
        key_file, cert_file, cert = _make_test_cert_key(tmp_path)
        document = _make_ooxml_document_signature_zip(
            cert, key_file, cert_file, with_doctype=True
        )
        assert daemon.analyze_signatures(document, "doctype.docx") is None

    def test_ooxml_document_signature_ignores_unsigned_timestamp(
        self, daemon, tmp_path
    ):
        key_file, cert_file, cert = _make_test_cert_key(tmp_path)
        document = _make_ooxml_document_signature_zip(
            cert,
            key_file,
            cert_file,
            unsigned_timestamp="2099-01-01T00:00:00Z",
        )
        result = daemon.analyze_signatures(document, "timestamp.docx")
        assert "timestamp" not in result["signatures"][0]

    def test_ooxml_issuer_fingerprint_requires_verified_issuer(self, daemon, tmp_path):
        from cryptography.hazmat.primitives import hashes as _test_hashes

        ca_dir = tmp_path / "ca"
        ca_dir.mkdir()
        _ca_key, _ca_file, ca_cert = _make_test_cert_key(ca_dir)
        key_file, cert_file, leaf_cert = _make_test_cert_key(
            tmp_path, issuer_name=ca_cert.subject
        )
        document = _make_ooxml_document_signature_zip(
            leaf_cert,
            key_file,
            cert_file,
            additional_cert=ca_cert,
        )
        result = daemon.analyze_signatures(document, "spoofed-issuer.docx")
        entry = result["signatures"][0]
        assert entry["issuer_fingerprint"] == (
            "sha256:" + leaf_cert.fingerprint(_test_hashes.SHA256()).hex()
        )

    def test_certificate_policy_parse_errors_fail_closed(self, daemon):
        class _BrokenAsn1Usage:
            @property
            def key_usage_value(self):
                raise ValueError("malformed KeyUsage")

        class _BrokenAsn1Time:
            @property
            def not_valid_before(self):
                raise ValueError("malformed validity")

        class _BrokenX509Usage:
            @property
            def extensions(self):
                raise ValueError("malformed extensions")

        class _BrokenX509Time:
            @property
            def not_valid_before_utc(self):
                raise ValueError("malformed validity")

        assert daemon._asn1_cert_key_usage_valid(_BrokenAsn1Usage()) is False
        assert daemon._asn1_cert_time_valid(_BrokenAsn1Time()) is False
        assert daemon._x509_cert_key_usage_valid(_BrokenX509Usage()) is False
        assert daemon._x509_cert_time_valid(_BrokenX509Time()) is False

    def test_ooxml_document_signature_expired_certificate_strict_mode(
        self, daemon, tmp_path, monkeypatch
    ):
        import datetime as _dt

        now = _dt.datetime.now(_dt.timezone.utc)
        key_file, cert_file, cert = _make_test_cert_key(
            tmp_path,
            not_valid_before=now - _dt.timedelta(days=30),
            not_valid_after=now - _dt.timedelta(days=1),
        )
        document = _make_ooxml_document_signature_zip(cert, key_file, cert_file)

        result = daemon.analyze_signatures(document, "expired.docx")
        entry = result["signatures"][0]
        assert entry["cert_time_valid"] is False
        assert entry["valid"] is True  # non-strict (default): crypto-only

        monkeypatch.setitem(
            xspct.config["xspct_analyzers"]["signature"], "strict", True
        )
        strict_result = daemon.analyze_signatures(document, "expired.docx")
        assert strict_result["signatures"][0]["valid"] is False

    def test_ooxml_document_signature_key_usage_restricted_strict_mode(
        self, daemon, tmp_path, monkeypatch
    ):
        from cryptography import x509 as _test_x509

        key_usage = _test_x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        )
        key_file, cert_file, cert = _make_test_cert_key(tmp_path, key_usage=key_usage)
        document = _make_ooxml_document_signature_zip(cert, key_file, cert_file)

        result = daemon.analyze_signatures(document, "restricted.docx")
        entry = result["signatures"][0]
        assert entry["key_usage_valid"] is False
        assert entry["valid"] is True  # non-strict (default): crypto-only

        monkeypatch.setitem(
            xspct.config["xspct_analyzers"]["signature"], "strict", True
        )
        strict_result = daemon.analyze_signatures(document, "restricted.docx")
        assert strict_result["signatures"][0]["valid"] is False

    def test_vba_signature_expired_certificate_strict_mode(
        self, daemon, tmp_path, monkeypatch
    ):
        import datetime as _dt

        now = _dt.datetime.now(_dt.timezone.utc)
        key_file, cert_file, _cert = _make_test_cert_key(
            tmp_path,
            not_valid_before=now - _dt.timedelta(days=30),
            not_valid_after=now - _dt.timedelta(days=1),
        )
        digsig = _make_vba_digsig_blob(key_file, cert_file)

        entry = daemon._parse_vba_digsig(digsig)
        assert entry["cert_time_valid"] is False
        assert entry["valid"] is True  # non-strict (default): crypto-only

        monkeypatch.setitem(
            xspct.config["xspct_analyzers"]["signature"], "strict", True
        )
        strict_entry = daemon._parse_vba_digsig(digsig)
        assert strict_entry["valid"] is False

    def test_cms_issuer_fingerprint_requires_verified_issuer(self, daemon, tmp_path):
        from cryptography.hazmat.primitives import hashes as _test_hashes
        from cryptography.hazmat.primitives import serialization as _test_serialization

        ca_dir = tmp_path / "ca"
        ca_dir.mkdir()
        _ca_key, _ca_file, ca_cert = _make_test_cert_key(ca_dir)
        key_file, cert_file, leaf_cert = _make_test_cert_key(
            tmp_path, issuer_name=ca_cert.subject
        )
        digsig = _make_vba_digsig_blob(key_file, cert_file)
        (cms_size,) = struct.unpack_from("<I", digsig, 0)
        signed_data = xspct._cms.ContentInfo.load(digsig[4 : 4 + cms_size])["content"]
        signed_data["certificates"].append(
            xspct._cms.CertificateChoices(
                name="certificate",
                value=xspct._asn1_x509.Certificate.load(
                    ca_cert.public_bytes(_test_serialization.Encoding.DER)
                ),
            )
        )
        signing_cert = next(
            choice.chosen
            for choice in signed_data["certificates"]
            if choice.chosen.dump()
            == leaf_cert.public_bytes(_test_serialization.Encoding.DER)
        )
        assert daemon._cms_issuer_fingerprint(signed_data, signing_cert) == (
            "sha256:" + leaf_cert.fingerprint(_test_hashes.SHA256()).hex()
        )

    def test_ooxml_document_signature_respects_zip_read_limit(
        self, daemon, tmp_path, monkeypatch
    ):
        key_file, cert_file, cert = _make_test_cert_key(tmp_path)
        document = _make_ooxml_document_signature_zip(cert, key_file, cert_file)
        with zipfile.ZipFile(io.BytesIO(document)) as z:
            limit = (
                sum(
                    z.getinfo(name).file_size
                    for name in ("_xmlsignatures/sig1.xml", "word/document.xml")
                )
                - 1
            )
        monkeypatch.setitem(xspct.config, "xspct_archive_max_size", limit)
        assert daemon.analyze_signatures(document, "oversize.docx") is None

    # -----------------------------------------------------------------------
    # PDF signature (PAdES) via a real pyhanko-signed fixture
    # -----------------------------------------------------------------------

    @pytest.mark.skipif(not _HAS_PYMUPDF, reason="pymupdf not installed")
    def test_pdf_signature_valid(self, daemon, tmp_path):
        from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
        from pyhanko.sign import signers as _signers

        key_file, cert_file, _cert = _make_test_cert_key(tmp_path)
        signer = _signers.SimpleSigner.load(key_file, cert_file)

        doc = _pymupdf.open()
        doc.new_page()
        plain_pdf = doc.tobytes()
        doc.close()

        writer = IncrementalPdfFileWriter(io.BytesIO(plain_pdf))
        signed_pdf = _signers.sign_pdf(
            writer,
            _signers.PdfSignatureMetadata(field_name="Sig1"),
            signer=signer,
        ).getvalue()

        result = daemon.analyze_signatures(signed_pdf, "signed.pdf")
        assert result is not None
        sigs = result["signatures"]
        assert len(sigs) == 1
        entry = sigs[0]
        assert entry["type"] == "pdf"
        assert entry["valid"] is True
        assert entry["trusted"] is False
        assert entry["key_usage_valid"] is True
        assert entry["cert_time_valid"] is True
        assert entry["covers_whole_document"] is True
        assert "Test Signer" in entry["signer"]

    # -----------------------------------------------------------------------
    # No-signature / non-container inputs
    # -----------------------------------------------------------------------

    def test_no_signature_returns_none(self, daemon):
        assert daemon.analyze_signatures(PDF_CLEAN, "clean.pdf") is None

    def test_empty_bytes_returns_none(self, daemon):
        assert daemon.analyze_signatures(b"", "empty.pdf") is None

    def test_disabled_when_pyhanko_missing(self, daemon, monkeypatch):
        monkeypatch.setattr(xspct, "HAS_PYHANKO", False)
        assert daemon.analyze_signatures(PDF_CLEAN, "clean.pdf") is None
