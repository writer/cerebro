"""Utility helpers for agent memory processing."""

from __future__ import annotations

import hashlib
import re
from typing import List


def cosine_similarity(
    query: List[float],
    query_norm: float,
    stored: List[float],
    stored_norm: float,
) -> float:
    if query_norm == 0 or stored_norm == 0:
        return 0.0
    length = min(len(query), len(stored))
    dot = sum(query[i] * stored[i] for i in range(length))
    return dot / (query_norm * stored_norm)


def hash_text(value: str) -> str:
    return hashlib.sha1(value.encode("utf-8")).hexdigest()


def estimate_token_count(value: str) -> int:
    approx_words = re.findall(r"\w+", value)
    return max(1, len(approx_words))


def summarize_text(text: str, max_chars: int) -> str:
    cleaned = re.sub(r"\s+", " ", text).strip()
    if not cleaned:
        return ""

    if len(cleaned) <= max_chars:
        return cleaned

    sentences = re.split(r"(?<=[.!?])\s+", cleaned)
    summary_parts: List[str] = []
    for sentence in sentences:
        if not sentence:
            continue
        candidate = f"{' '.join(summary_parts)} {sentence}".strip() if summary_parts else sentence
        if len(candidate) > max_chars:
            break
        summary_parts.append(sentence)

    summary = " ".join(summary_parts).strip()
    if not summary:
        summary = cleaned[:max_chars].rstrip()

    if len(summary) > max_chars:
        summary = summary[: max_chars - 3].rstrip() + "..."

    return summary
