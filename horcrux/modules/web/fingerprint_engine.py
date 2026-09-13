from __future__ import annotations

import hashlib
import re
from typing import Any, Sequence
from urllib.parse import urlparse

from horcrux.models import (
    EvidenceClassification,
    ResponseFamily,
    ResponseFingerprint,
)


# Patterns for dynamic noise normalization
_UUID_PATTERN = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
_TIMESTAMP_ISO_PATTERN = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"
)
_TIMESTAMP_UNIX_PATTERN = re.compile(r"\b1[5-7]\d{8}(?:\d{3})?\b")
_REQUEST_ID_PATTERN = re.compile(
    r"(?:request[_-]?id|trace[_-]?id|correlation[_-]?id|x-amzn-trace-id)[\"':= ]+([a-zA-Z0-9_\-]+)",
    re.I,
)
_NONCE_CSRF_PATTERN = re.compile(
    r'(?:nonce|csrf[_-]?token|_token|xsrf[_-]?token|authenticity_token)(?:[\s=:\'"]+content)?[\s=:\'"]+([a-zA-Z0-9+/=_-]{8,})["\']?',
    re.I,
)
_NONCE_ATTR_PATTERN = re.compile(
    r'(?:name|id)=["\'](?:csrf[_-]?token|_token|nonce|xsrf[_-]?token)["\'][^>]*?(?:content|value)=["\']([^"\']+)["\']',
    re.I,
)
_NONCE_ATTR_REVERSE_PATTERN = re.compile(
    r'(?:content|value)=["\']([^"\']+)["\'][^>]*?(?:name|id)=["\'](?:csrf[_-]?token|_token|nonce|xsrf[_-]?token)["\']',
    re.I,
)
_WHITESPACE_PATTERN = re.compile(r"\s+")
_HTML_TAG_EXTRACTOR = re.compile(r"<([a-zA-Z0-9]+)[^>]*>")


def normalize_dynamic_content(text: str) -> str:
    """
    Normalizes volatile tokens (timestamps, UUIDs, nonces, request IDs)
    without destroying meaningful application content structure.
    """
    if not text:
        return ""
    # Normalize volatile dynamic values
    res = _UUID_PATTERN.sub("{UUID}", text)
    res = _TIMESTAMP_ISO_PATTERN.sub("{TIMESTAMP}", res)
    res = _TIMESTAMP_UNIX_PATTERN.sub("{TIMESTAMP}", res)
    res = _NONCE_ATTR_PATTERN.sub('name="nonce" value="{NONCE}"', res)
    res = _NONCE_ATTR_REVERSE_PATTERN.sub('name="nonce" value="{NONCE}"', res)
    res = _NONCE_CSRF_PATTERN.sub('nonce="{NONCE}"', res)
    res = _REQUEST_ID_PATTERN.sub(r"\1={REQ_ID}", res)
    # Collapse irregular whitespace
    res = _WHITESPACE_PATTERN.sub(" ", res).strip()
    return res


def extract_structural_signature(text: str, content_type: str = "") -> str:
    """
    Extracts structural skeleton (tag sequence for HTML, key structure for JSON).
    """
    if not text:
        return ""
    ct = content_type.lower()
    if "json" in ct or (text.startswith("{") and text.endswith("}")):
        # Extract top-level or key names
        keys = re.findall(r'"([a-zA-Z0-9_\-]+)"\s*:', text)
        return "json:" + ",".join(sorted(set(keys))[:30])
    if "html" in ct or "<html" in text.lower() or "<div" in text.lower():
        tags = _HTML_TAG_EXTRACTOR.findall(text)
        # Take sequence of first 60 structural tags
        return "html:" + ",".join(t.lower() for t in tags[:60])
    return f"plain:{len(text)}"


def compute_similarity_hash(text: str) -> str:
    """
    Computes a simplified SimHash / shingle token fingerprint for fast near-duplicate comparison.
    """
    if not text:
        return "0" * 16
    tokens = re.findall(r"\b[a-zA-Z0-9_]{3,}\b", text.lower())
    if not tokens:
        return hashlib.md5(text.encode("utf-8", errors="replace")).hexdigest()[:16]

    # 64-bit simhash
    v = [0] * 64
    for token in tokens:
        h = int(hashlib.md5(token.encode("utf-8")).hexdigest(), 16)
        for i in range(64):
            bit = (h >> i) & 1
            v[i] += 1 if bit else -1

    fingerprint = 0
    for i in range(64):
        if v[i] > 0:
            fingerprint |= 1 << i
    return f"{fingerprint:016x}"


def fingerprint_response(
    status_code: int,
    text: str,
    headers: dict[str, str] | Any = None,
    url: str = "",
    redirect_chain: Sequence[str] | None = None,
) -> ResponseFingerprint:
    """
    Constructs a robust, normalized ResponseFingerprint from an HTTP response.
    """
    headers = headers or {}
    # Case-insensitive header dictionary lookup
    h_dict = {k.lower(): str(v) for k, v in dict(headers).items()}
    ct = h_dict.get("content-type", "").lower()

    # Extract title
    title_match = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    title = (
        re.sub(r"\s+", " ", title_match.group(1)).strip() if title_match else ""
    )

    is_html = "html" in ct or bool(title_match) or "<html" in text.lower()
    is_json = "json" in ct or (text.strip().startswith("{") and text.strip().endswith("}"))

    # SPA detection markers
    is_spa = False
    if status_code == 200 and is_html:
        spa_indicators = [
            r'<div id=["\'](?:app|root|main)["\']',
            r'<noscript>.*?(?:enable javascript|requires javascript)',
            r'<script[^>]*src=["\'][^"\']*(?:main|app|bundle|chunk|runtime|vendor)[^"\']*\.js["\']',
            r"ng-app|data-reactroot|data-v-[a-f0-9]+",
            r"<app-root|<router-outlet",
        ]
        if any(re.search(pat, text, re.I | re.S) for pat in spa_indicators):
            is_spa = True

    normalized_text = normalize_dynamic_content(text)
    norm_body_hash = hashlib.sha256(
        normalized_text.encode("utf-8", errors="replace")
    ).hexdigest()
    sim_hash = compute_similarity_hash(normalized_text)
    struct_sig = extract_structural_signature(text, content_type=ct)

    return ResponseFingerprint(
        status_code=status_code,
        content_type=ct,
        normalized_body_length=len(normalized_text),
        title=title,
        normalized_body_hash=norm_body_hash,
        similarity_hash=sim_hash,
        structural_signature=struct_sig,
        redirect_chain=list(redirect_chain or []),
        final_url=url,
        is_html=is_html,
        is_json=is_json,
        is_spa_fallback=is_spa,
    )


def simhash_distance(h1: str, h2: str) -> int:
    """Hamming distance between two 64-bit hex strings."""
    try:
        val1 = int(h1, 16)
        val2 = int(h2, 16)
        return bin(val1 ^ val2).count("1")
    except Exception:
        return 64


def response_similarity(
    fp1: ResponseFingerprint, fp2: ResponseFingerprint
) -> float:
    """
    Computes a normalized similarity score (0.0 to 1.0) between two fingerprints.
    """
    # 1. Exact body hash match
    if fp1.normalized_body_hash and fp1.normalized_body_hash == fp2.normalized_body_hash:
        return 1.0

    # 2. If status code differs, base similarity is low unless both are redirects or client errors
    if fp1.status_code != fp2.status_code:
        return 0.1

    # 3. Structural signature exact match
    if fp1.structural_signature and fp1.structural_signature == fp2.structural_signature:
        # Check length ratio
        max_l = max(fp1.normalized_body_length, fp2.normalized_body_length, 1)
        min_l = min(fp1.normalized_body_length, fp2.normalized_body_length, 1)
        ratio = min_l / max_l
        if ratio >= 0.85:
            return 0.95
        return 0.80

    # 4. Title match for HTML pages
    if fp1.title and fp2.title and fp1.title.strip().lower() == fp2.title.strip().lower():
        max_l = max(fp1.normalized_body_length, fp2.normalized_body_length, 1)
        min_l = min(fp1.normalized_body_length, fp2.normalized_body_length, 1)
        if (min_l / max_l) >= 0.80:
            return 0.90

    # 5. SimHash bit distance
    dist = simhash_distance(fp1.similarity_hash, fp2.similarity_hash)
    sim = max(0.0, 1.0 - (dist / 64.0))

    # Factor in length similarity
    max_l = max(fp1.normalized_body_length, fp2.normalized_body_length, 1)
    min_l = min(fp1.normalized_body_length, fp2.normalized_body_length, 1)
    len_ratio = min_l / max_l

    return (sim * 0.7) + (len_ratio * 0.3)


def same_response_family(
    fp1: ResponseFingerprint,
    fp2: ResponseFingerprint,
    threshold: float = 0.85,
) -> bool:
    """
    Determines if two responses belong to the same response family
    (exact duplicate or near-duplicate fallback/template).
    """
    if fp1.status_code != fp2.status_code:
        return False

    # Exact body hash
    if fp1.normalized_body_hash == fp2.normalized_body_hash:
        return True

    # Same title and matching structure
    if fp1.title and fp2.title and fp1.title.strip().lower() == fp2.title.strip().lower():
        diff = abs(fp1.normalized_body_length - fp2.normalized_body_length)
        avg_l = max(fp1.normalized_body_length, 1)
        if (diff / avg_l) < 0.15:
            return True

    # SPA Catch-all matching
    if (fp1.is_spa_fallback or fp2.is_spa_fallback) and fp1.status_code == 200:
        if fp1.structural_signature == fp2.structural_signature:
            return True
        diff = abs(fp1.normalized_body_length - fp2.normalized_body_length)
        if (diff / max(fp1.normalized_body_length, 1)) < 0.08:
            return True

    return response_similarity(fp1, fp2) >= threshold


def cluster_response_families(
    fingerprints: Sequence[tuple[str, ResponseFingerprint] | ResponseFingerprint],
    baseline_fps: Sequence[ResponseFingerprint] = (),
    similarity_threshold: float = 0.85,
) -> tuple[list[ResponseFamily], dict[str, str]]:
    """
    Clusters a list of (path, fingerprint) tuples or ResponseFingerprint objects into unified ResponseFamily objects.
    Matches against baseline fallback fingerprints to mark SUPPRESSED_FALLBACK families.

    Returns:
        (list_of_families, path_to_family_id_map)
    """
    families: list[ResponseFamily] = []
    path_to_family: dict[str, str] = {}

    normalized_fps: list[tuple[str, ResponseFingerprint]] = []
    for item in fingerprints:
        if isinstance(item, tuple):
            normalized_fps.append(item)
        elif isinstance(item, ResponseFingerprint):
            normalized_fps.append((item.final_url or "/", item))

    for path, fp in normalized_fps:
        # 1. Check if matches any baseline fallback probe
        matches_baseline = any(same_response_family(fp, b_fp, threshold=similarity_threshold) for b_fp in baseline_fps)

        matched_fam: ResponseFamily | None = None
        for fam in families:
            if same_response_family(fp, fam.representative_fingerprint, threshold=similarity_threshold):
                matched_fam = fam
                break

        if matched_fam:
            matched_fam.member_count += 1
            if len(matched_fam.representative_paths) < 10:
                matched_fam.representative_paths.append(path)
            path_to_family[path] = matched_fam.family_id
            # If any member matches baseline or is SPA fallback, ensure classified as SUPPRESSED_FALLBACK
            if matches_baseline:
                matched_fam.classification = EvidenceClassification.SUPPRESSED_FALLBACK
        else:
            fam_id = f"fam_{fp.status_code}_{hashlib.md5((fp.structural_signature or fp.normalized_body_hash or path).encode()).hexdigest()[:8]}"
            classification = (
                EvidenceClassification.SUPPRESSED_FALLBACK
                if matches_baseline
                else EvidenceClassification.DISTINCT
            )
            new_fam = ResponseFamily(
                family_id=fam_id,
                representative_fingerprint=fp,
                member_count=1,
                representative_paths=[path],
                classification=classification,
                confidence=0.95 if matches_baseline else 0.85,
                evidence_references=[f"Status: {fp.status_code}, Length: {fp.normalized_body_length}, Title: {fp.title}"],
            )
            families.append(new_fam)
            path_to_family[path] = fam_id

    return families, path_to_family
