"""Unit tests for feeds/document_feed.py."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from feeds.document_feed import CHAR_LIMIT, _decode_text, _extract_pdf, process_uploads


# ── process_uploads ────────────────────────────────────────────────────────────

class TestProcessUploads:
    def test_returns_tuple(self):
        uploads = [{"filename": "test.txt", "content_type": "text/plain", "bytes": b"hello"}]
        result = process_uploads(uploads)
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_plain_text_success(self):
        uploads = [{"filename": "threat.txt", "content_type": "text/plain", "bytes": b"Ransomware detected"}]
        results, errors = process_uploads(uploads)
        assert len(results) == 1
        assert errors == []
        assert results[0]["type"] == "document_intel"
        assert results[0]["doc_type"] == "document"
        assert results[0]["source"] == "threat.txt"
        assert "Ransomware" in results[0]["content"]

    def test_markdown_file(self):
        uploads = [{"filename": "notes.md", "content_type": "text/markdown", "bytes": b"# APT Report\n\nIOC: 192.0.2.1"}]
        results, errors = process_uploads(uploads)
        assert len(results) == 1
        assert "APT" in results[0]["content"]

    def test_empty_bytes_skipped(self):
        uploads = [{"filename": "empty.txt", "content_type": "text/plain", "bytes": b""}]
        results, errors = process_uploads(uploads)
        assert results == []
        assert errors == []

    def test_empty_uploads_list(self):
        results, errors = process_uploads([])
        assert results == []
        assert errors == []

    def test_char_limit_enforced(self):
        large_content = "A" * (CHAR_LIMIT * 2)
        uploads = [{"filename": "large.txt", "content_type": "text/plain", "bytes": large_content.encode()}]
        results, errors = process_uploads(uploads)
        assert results[0]["char_count"] == CHAR_LIMIT
        assert len(results[0]["content"]) == CHAR_LIMIT

    def test_char_count_matches_content_length(self):
        uploads = [{"filename": "small.txt", "content_type": "text/plain", "bytes": b"Short content"}]
        results, _ = process_uploads(uploads)
        assert results[0]["char_count"] == len(results[0]["content"])

    def test_error_strings_never_in_results_content(self):
        """Error messages must never appear as intelligence content."""
        # Non-decodable bytes that will fail
        uploads = [{"filename": "binary.bin", "content_type": "application/octet-stream", "bytes": bytes(range(128, 256))}]
        results, errors = process_uploads(uploads)
        # If error occurred, it goes to errors list, not results
        for r in results:
            assert not r["content"].startswith("[Error")
            assert not r["content"].startswith("[pypdf")

    def test_pdf_detected_by_extension(self):
        with patch("feeds.document_feed._extract_pdf", return_value="PDF text") as mock_pdf:
            uploads = [{"filename": "report.pdf", "content_type": "application/octet-stream", "bytes": b"fake pdf"}]
            results, errors = process_uploads(uploads)
            mock_pdf.assert_called_once()
            assert results[0]["doc_type"] == "pdf"

    def test_pdf_detected_by_content_type(self):
        with patch("feeds.document_feed._extract_pdf", return_value="PDF text") as mock_pdf:
            uploads = [{"filename": "report", "content_type": "application/pdf", "bytes": b"fake pdf"}]
            results, errors = process_uploads(uploads)
            mock_pdf.assert_called_once()

    def test_decode_error_goes_to_errors_not_results(self):
        with patch("feeds.document_feed._decode_text", side_effect=ValueError("Cannot decode")):
            uploads = [{"filename": "bad.txt", "content_type": "text/plain", "bytes": b"data"}]
            results, errors = process_uploads(uploads)
            assert results == []
            assert len(errors) == 1
            assert errors[0]["source"] == "bad.txt"

    def test_pdf_error_goes_to_errors_not_results(self):
        with patch("feeds.document_feed._extract_pdf", side_effect=ValueError("pypdf not installed")):
            uploads = [{"filename": "doc.pdf", "content_type": "application/pdf", "bytes": b"fake"}]
            results, errors = process_uploads(uploads)
            assert results == []
            assert len(errors) == 1
            assert "doc.pdf" in errors[0]["source"]

    def test_multiple_files_errors_isolated(self):
        """An error in one file doesn't prevent processing of others."""
        with patch("feeds.document_feed._decode_text") as mock_decode:
            mock_decode.side_effect = [ValueError("bad"), "Good content"]
            uploads = [
                {"filename": "bad.txt", "content_type": "text/plain", "bytes": b"x"},
                {"filename": "good.txt", "content_type": "text/plain", "bytes": b"y"},
            ]
            results, errors = process_uploads(uploads)
            assert len(results) == 1
            assert len(errors) == 1
            assert results[0]["source"] == "good.txt"


# ── _decode_text ───────────────────────────────────────────────────────────────

class TestDecodeText:
    def test_utf8_success(self):
        assert _decode_text(b"hello world", "test.txt") == "hello world"

    def test_utf8_unicode(self):
        text = "Threat: \u00e9l\u00e8ve"
        assert _decode_text(text.encode("utf-8"), "test.txt") == text

    def test_latin1_fallback(self):
        latin1_bytes = "caf\xe9".encode("latin-1")
        result = _decode_text(latin1_bytes, "test.txt")
        assert "caf" in result

    def test_raises_on_undecodable(self):
        # Latin-1 covers all 0-255 byte values, so we simulate failure by making
        # the mock bytes object raise UnicodeDecodeError for both encodings.
        mock_data = MagicMock()
        mock_data.decode.side_effect = [
            UnicodeDecodeError("utf-8", b"", 0, 1, "invalid start byte"),
            UnicodeDecodeError("latin-1", b"", 0, 1, "cannot decode"),
        ]
        with pytest.raises(ValueError, match="Cannot decode"):
            _decode_text(mock_data, "test.txt")


# ── _extract_pdf ───────────────────────────────────────────────────────────────

class TestExtractPdf:
    def test_pypdf_unavailable_raises_valueerror(self):
        import sys
        # Setting the module to None in sys.modules makes import raise ImportError
        with patch.dict(sys.modules, {"pypdf": None}):
            with pytest.raises(ValueError, match="pypdf not installed"):
                _extract_pdf(b"fake pdf", "test.pdf")

    def test_successful_extraction(self):
        mock_page = MagicMock()
        mock_page.extract_text.return_value = "Page 1 content"
        mock_reader = MagicMock()
        mock_reader.pages = [mock_page]

        mock_pypdf = MagicMock()
        mock_pypdf.PdfReader.return_value = mock_reader

        import sys
        with patch.dict(sys.modules, {"pypdf": mock_pypdf}):
            result = _extract_pdf(b"fake pdf bytes", "test.pdf")
        assert "Page 1 content" in result

    def test_parse_exception_raises_valueerror(self):
        mock_pypdf = MagicMock()
        mock_pypdf.PdfReader.side_effect = Exception("Corrupt PDF")

        import sys
        with patch.dict(sys.modules, {"pypdf": mock_pypdf}):
            with pytest.raises(ValueError, match="Error parsing PDF"):
                _extract_pdf(b"corrupt", "bad.pdf")

    def test_page_extraction_failure_skipped(self):
        mock_page_good = MagicMock()
        mock_page_good.extract_text.return_value = "Good page"
        mock_page_bad = MagicMock()
        mock_page_bad.extract_text.side_effect = Exception("Page error")
        mock_reader = MagicMock()
        mock_reader.pages = [mock_page_bad, mock_page_good]

        mock_pypdf = MagicMock()
        mock_pypdf.PdfReader.return_value = mock_reader

        import sys
        with patch.dict(sys.modules, {"pypdf": mock_pypdf}):
            result = _extract_pdf(b"pdf", "test.pdf")
        assert "Good page" in result
