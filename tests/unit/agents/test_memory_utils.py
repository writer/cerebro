"""Tests for agent memory utility functions."""

import math

import pytest

from cerebro.agents.memory_utils import (
    cosine_similarity,
    estimate_token_count,
    hash_text,
    summarize_text,
)


class TestCosineSimilarity:
    """Test cosine_similarity function."""

    def test_identical_vectors(self):
        """Test similarity of identical vectors is 1.0."""
        vec = [1.0, 2.0, 3.0]
        norm = math.sqrt(sum(x * x for x in vec))
        result = cosine_similarity(vec, norm, vec, norm)
        assert result == pytest.approx(1.0)

    def test_orthogonal_vectors(self):
        """Test similarity of orthogonal vectors is 0.0."""
        vec1 = [1.0, 0.0]
        vec2 = [0.0, 1.0]
        norm1 = 1.0
        norm2 = 1.0
        result = cosine_similarity(vec1, norm1, vec2, norm2)
        assert result == pytest.approx(0.0)

    def test_opposite_vectors(self):
        """Test similarity of opposite vectors is -1.0."""
        vec1 = [1.0, 0.0]
        vec2 = [-1.0, 0.0]
        norm1 = 1.0
        norm2 = 1.0
        result = cosine_similarity(vec1, norm1, vec2, norm2)
        assert result == pytest.approx(-1.0)

    def test_zero_norm_query(self):
        """Test zero norm query returns 0.0."""
        vec1 = [0.0, 0.0]
        vec2 = [1.0, 1.0]
        result = cosine_similarity(vec1, 0.0, vec2, math.sqrt(2))
        assert result == 0.0

    def test_zero_norm_stored(self):
        """Test zero norm stored returns 0.0."""
        vec1 = [1.0, 1.0]
        vec2 = [0.0, 0.0]
        result = cosine_similarity(vec1, math.sqrt(2), vec2, 0.0)
        assert result == 0.0

    def test_different_length_vectors(self):
        """Test vectors of different lengths uses minimum length."""
        vec1 = [1.0, 2.0, 3.0]
        vec2 = [1.0, 2.0]
        norm1 = math.sqrt(1 + 4 + 9)
        norm2 = math.sqrt(1 + 4)
        result = cosine_similarity(vec1, norm1, vec2, norm2)
        # Only first 2 elements are used for dot product
        expected_dot = 1.0 * 1.0 + 2.0 * 2.0  # = 5
        expected = expected_dot / (norm1 * norm2)
        assert result == pytest.approx(expected)


class TestHashText:
    """Test hash_text function."""

    def test_basic_hash(self):
        """Test basic text hashing."""
        result = hash_text("hello")
        assert isinstance(result, str)
        assert len(result) == 40  # SHA1 hex digest length

    def test_consistent_hash(self):
        """Test same input produces same hash."""
        text = "test string"
        assert hash_text(text) == hash_text(text)

    def test_different_inputs_different_hash(self):
        """Test different inputs produce different hashes."""
        assert hash_text("hello") != hash_text("world")

    def test_empty_string(self):
        """Test hashing empty string."""
        result = hash_text("")
        assert isinstance(result, str)
        assert len(result) == 40

    def test_unicode_text(self):
        """Test hashing unicode text."""
        result = hash_text("こんにちは")
        assert isinstance(result, str)
        assert len(result) == 40


class TestEstimateTokenCount:
    """Test estimate_token_count function."""

    def test_basic_sentence(self):
        """Test token count for basic sentence."""
        text = "This is a test sentence"
        result = estimate_token_count(text)
        assert result == 5

    def test_empty_string(self):
        """Test empty string returns 1."""
        result = estimate_token_count("")
        assert result == 1

    def test_punctuation_handling(self):
        """Test punctuation is handled correctly."""
        text = "Hello, world! How are you?"
        result = estimate_token_count(text)
        assert result == 5  # Hello, world, How, are, you

    def test_numbers(self):
        """Test numbers are counted as tokens."""
        text = "I have 42 apples"
        result = estimate_token_count(text)
        assert result == 4


class TestSummarizeText:
    """Test summarize_text function."""

    def test_short_text_unchanged(self):
        """Test short text is returned unchanged."""
        text = "Hello world"
        result = summarize_text(text, 100)
        assert result == "Hello world"

    def test_whitespace_normalization(self):
        """Test multiple whitespaces are normalized."""
        text = "Hello   world\n\ntest"
        result = summarize_text(text, 100)
        assert result == "Hello world test"

    def test_empty_string(self):
        """Test empty string returns empty."""
        result = summarize_text("", 100)
        assert result == ""

    def test_whitespace_only(self):
        """Test whitespace-only returns empty."""
        result = summarize_text("   \n\t  ", 100)
        assert result == ""

    def test_truncation_at_sentence_boundary(self):
        """Test truncation happens at sentence boundaries."""
        text = "First sentence. Second sentence. Third sentence."
        result = summarize_text(text, 35)
        assert result == "First sentence. Second sentence."

    def test_truncation_with_ellipsis(self):
        """Test very long text is truncated to max_chars."""
        text = "This is a very long single sentence without any breaks"
        result = summarize_text(text, 20)
        assert len(result) <= 20
        # Text is truncated at word boundary

    def test_exact_length_no_truncation(self):
        """Test text exactly at max_chars is not truncated."""
        text = "Exact."
        result = summarize_text(text, 6)
        assert result == "Exact."

    def test_single_long_sentence(self):
        """Test single sentence longer than max_chars."""
        text = "This is one very long sentence"
        result = summarize_text(text, 15)
        assert len(result) <= 15

    def test_multiple_sentence_boundaries(self):
        """Test handling of different sentence endings."""
        text = "Question? Exclamation! Statement."
        result = summarize_text(text, 25)
        assert "Question?" in result
