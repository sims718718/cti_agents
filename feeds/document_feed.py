"""Document Feed — extract text from uploaded PDF, Markdown, and TXT files."""
from __future__ import annotations

import io

CHAR_LIMIT = 8_000  # Per-file character cap to stay within 55k raw_intel budget


def process_uploads(uploaded_files: list[dict]) -> tuple[list[dict], list[dict]]:
    """Extract text from uploaded documents.

    Args:
        uploaded_files: List of dicts with keys:
            - ``filename`` (str)
            - ``content_type`` (str)
            - ``bytes`` (bytes)

    Returns:
        ``(results, errors)`` where:
        - ``results`` is a list of document-intel dicts ready for
          ``raw_intel["document_intel"]``. Each dict has:
          type, source, doc_type, content, char_count.
        - ``errors`` is a list of ``{"source": filename, "error": message}``
          dicts for files that could not be processed. These are never mixed
          into ``results`` so error strings never reach LLM agents as content.
    """
    results: list[dict] = []
    errors: list[dict] = []

    for upload in uploaded_files:
        filename: str = upload.get("filename", "unknown")
        content_type: str = upload.get("content_type", "")
        data: bytes = upload.get("bytes", b"")

        if not data:
            continue

        try:
            if filename.lower().endswith(".pdf") or "pdf" in content_type:
                text = _extract_pdf(data, filename)
                doc_type = "pdf"
            else:
                text = _decode_text(data, filename)
                doc_type = "document"
        except ValueError as exc:
            errors.append({"source": filename, "error": str(exc)})
            continue

        text = text[:CHAR_LIMIT]
        results.append(
            {
                "type": "document_intel",
                "source": filename,
                "doc_type": doc_type,
                "content": text,
                "char_count": len(text),
            }
        )

    return results, errors


def _decode_text(data: bytes, filename: str) -> str:
    """Decode bytes to a string, trying UTF-8 then latin-1.

    Raises:
        ValueError: If neither encoding succeeds.
    """
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return data.decode("latin-1")
        except UnicodeDecodeError as exc:
            raise ValueError(f"Cannot decode {filename}: {exc}") from exc


def _extract_pdf(data: bytes, filename: str) -> str:
    """Extract text from a PDF using pypdf.

    Raises:
        ValueError: If pypdf is not installed or extraction fails.
    """
    try:
        import pypdf  # optional dependency
    except ImportError:
        raise ValueError(
            f"pypdf not installed — cannot parse {filename}. "
            "Install it with: pip install pypdf"
        )

    try:
        reader = pypdf.PdfReader(io.BytesIO(data))
        pages: list[str] = []
        for page in reader.pages:
            try:
                pages.append(page.extract_text() or "")
            except Exception:
                pass
        return "\n".join(pages)
    except Exception as exc:
        raise ValueError(f"Error parsing PDF {filename}: {exc}") from exc
