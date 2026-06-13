"""
Flow Attribution Engine — Component 4.

This is the core innovation of the system. It infers information movement
between tool invocations using three escalating phases:

  Phase A (Explicit): Exact reuse, token reuse, identifier reuse
  Phase B (Lexical):  Fuzzy matching via rapidfuzz
  Phase C (Semantic): Embedding similarity via sentence-transformers

Every detection must store evidence. Never emit a verdict without explanation.
"""

import re
import time
import logging
from typing import Dict, Any, List, Set, Optional, Tuple

from rapidfuzz import fuzz
from sentence_transformers import SentenceTransformer, util

from schema import FlowDetection, _extract_text
from metrics import GLOBAL_METRICS

logger = logging.getLogger(__name__)

# Common MCP boilerplate tokens that should not trigger flow detection.
# These appear in nearly every tool response and inflate false positives.
STOPWORDS: Set[str] = {
    "status", "ok", "success", "error", "true", "false", "null", "none",
    "saved", "sent", "done", "200", "201", "404", "500",
    "the", "a", "an", "is", "are", "was", "were", "be", "been",
    "have", "has", "had", "do", "does", "did", "will", "would",
    "could", "should", "may", "might", "shall", "can",
    "in", "on", "at", "to", "for", "of", "with", "by", "from",
    "and", "or", "but", "not", "no", "if", "then", "else",
    "it", "its", "this", "that", "these", "those",
}

# Patterns that suggest encoded data (base64, hex, URL-encoded)
ENCODING_PATTERNS = [
    (re.compile(r'[A-Za-z0-9+/]{20,}={0,2}'), "base64"),
    (re.compile(r'(?:0x)?[0-9a-fA-F]{16,}'), "hex"),
    (re.compile(r'(?:%[0-9a-fA-F]{2}){4,}'), "url_encoded"),
]


class FlowAttributionEngine:
    """
    Infers information flow between tool invocations.

    Uses a cascading detection strategy: explicit → lexical → semantic.
    The first phase to detect a flow wins (short-circuit evaluation),
    since higher phases have higher confidence.

    Args:
        model_name: Sentence transformer model for semantic phase.
        semantic_threshold: Minimum cosine similarity to trigger semantic detection.
        lexical_threshold: Minimum fuzzy ratio (0-1) for lexical detection.
        token_overlap_ratio: Minimum ratio of shared meaningful tokens.
        min_token_overlap: Minimum number of shared meaningful tokens.
    """

    def __init__(
        self,
        model_name: str = "all-MiniLM-L6-v2",
        semantic_threshold: float = 0.55,
        lexical_threshold: float = 0.75,
        token_overlap_ratio: float = 0.5,
        min_token_overlap: int = 3,
    ):
        import os
        import json
        
        self.active_tiers = {"explicit": True, "lexical": True, "semantic": True}
        
        # Load optimized thresholds if available
        thresh_file = "optimized_thresholds.json"
        if os.path.exists(thresh_file):
            try:
                with open(thresh_file, "r") as f:
                    opt = json.load(f)
                semantic_threshold = opt.get("semantic_threshold", semantic_threshold)
                lexical_threshold = opt.get("lexical_threshold", lexical_threshold)
                logger.info("Loaded optimized thresholds: Semantic=%.2f, Lexical=%.2f", semantic_threshold, lexical_threshold)
            except Exception as e:
                logger.error("Failed to load optimized thresholds: %s", e)

        self.semantic_threshold = semantic_threshold
        self.lexical_threshold = lexical_threshold
        self.token_overlap_ratio = token_overlap_ratio
        self.min_token_overlap = min_token_overlap

        local_model_path = os.path.join("models", model_name)
        if os.path.exists(local_model_path):
            logger.info("Loading local offline sentence transformer model: %s", local_model_path)
            self.model = SentenceTransformer(local_model_path)
        else:
            logger.info("Loading sentence transformer model from Hugging Face: %s", model_name)
            self.model = SentenceTransformer(model_name)
        
        logger.info("Model loaded successfully.")

    def check_flow(
        self,
        prev_output: Dict[str, Any],
        curr_input: Dict[str, Any],
    ) -> FlowDetection:
        """
        Check whether information flowed from prev_output to curr_input.

        Runs three phases in order and returns the first positive detection.
        Records attribution metrics for every call.
        """
        start_time = time.time()
        result = self._check_flow_internal(prev_output, curr_input)
        latency = time.time() - start_time
        GLOBAL_METRICS.record_attribution(result.method, result.confidence, latency)
        return result

    def _check_flow_internal(
        self,
        prev_output: Dict[str, Any],
        curr_input: Dict[str, Any],
    ) -> FlowDetection:
        """Internal flow check implementing the three-phase cascade."""
        prev_text = _extract_text(prev_output)
        curr_text = _extract_text(curr_input)

        if not prev_text.strip() or not curr_text.strip():
            return FlowDetection(
                flow_detected=False, confidence=0.0, evidence="", method="none"
            )

        # ── Phase A: Explicit Attribution ──────────────────────────────
        if self.active_tiers.get("explicit", True):
            explicit = self._check_explicit(prev_text, curr_text)
            if explicit and explicit.flow_detected:
                return explicit

        # ── Phase B: Lexical Attribution ───────────────────────────────
        if self.active_tiers.get("lexical", True):
            lexical = self._check_lexical(prev_text, curr_text)
            if lexical and lexical.flow_detected:
                return lexical

        # ── Phase C: Semantic Attribution ──────────────────────────────
        if self.active_tiers.get("semantic", True):
            semantic = self._check_semantic(prev_text, curr_text)
            if semantic and semantic.flow_detected:
                return semantic

        return FlowDetection(
            flow_detected=False, confidence=0.0, evidence="", method="none"
        )

    # ── Phase A: Explicit ──────────────────────────────────────────────

    def _check_explicit(self, prev_text: str, curr_text: str) -> FlowDetection:
        """
        Detect exact reuse, token reuse, identifier reuse, verbatim propagation,
        and encoded data propagation.
        """
        # A1: Exact substring match (skip trivial short strings)
        if len(prev_text) > 10 and (prev_text in curr_text or curr_text in prev_text):
            overlap = min(len(prev_text), len(curr_text))
            return FlowDetection(
                flow_detected=True,
                confidence=1.0,
                evidence=f"Exact substring match (overlap={overlap} chars)",
                method="explicit",
            )

        # A2: Identifier/token reuse (with stopword filtering)
        prev_tokens = self._meaningful_tokens(prev_text)
        curr_tokens = self._meaningful_tokens(curr_text)

        if prev_tokens and curr_tokens:
            intersection = prev_tokens & curr_tokens
            if len(intersection) >= self.min_token_overlap:
                ratio = len(intersection) / len(curr_tokens) if curr_tokens else 0
                if ratio >= self.token_overlap_ratio:
                    sample = sorted(list(intersection))[:5]
                    return FlowDetection(
                        flow_detected=True,
                        confidence=min(0.95, 0.7 + ratio * 0.3),
                        evidence=f"Token overlap: {ratio:.0%} ({len(intersection)} tokens). "
                                 f"Sample: {sample}",
                        method="explicit",
                    )

        # A3: N-gram matching (catch partial identifier reuse)
        ngram_result = self._check_ngram_overlap(prev_text, curr_text)
        if ngram_result is not None:
            return ngram_result

        # A4: Encoding detection (base64, hex, URL-encoded)
        encoding_result = self._check_encoded_propagation(prev_text, curr_text)
        if encoding_result is not None:
            return encoding_result

        return FlowDetection(
            flow_detected=False, confidence=0.0, evidence="", method="none"
        )

    def _meaningful_tokens(self, text: str) -> Set[str]:
        """Extract tokens after removing stopwords and short tokens."""
        tokens = set(text.lower().split())
        return {t for t in tokens if t not in STOPWORDS and len(t) > 2}

    def _check_ngram_overlap(
        self, prev_text: str, curr_text: str, n: int = 4
    ) -> Optional[FlowDetection]:
        """Check for shared n-grams (word-level) to catch partial reuse."""
        prev_words = prev_text.lower().split()
        curr_words = curr_text.lower().split()

        if len(prev_words) < n or len(curr_words) < n:
            return None

        prev_ngrams = {
            tuple(prev_words[i : i + n]) for i in range(len(prev_words) - n + 1)
        }
        curr_ngrams = {
            tuple(curr_words[i : i + n]) for i in range(len(curr_words) - n + 1)
        }

        shared = prev_ngrams & curr_ngrams
        if shared:
            sample = " ".join(list(shared)[0])
            return FlowDetection(
                flow_detected=True,
                confidence=0.85,
                evidence=f"Shared {n}-gram detected: '{sample}'",
                method="explicit",
            )
        return None

    def _check_encoded_propagation(
        self, prev_text: str, curr_text: str
    ) -> Optional[FlowDetection]:
        """Detect if encoded versions of data appear across tool boundaries."""
        import base64
        import urllib.parse

        # 1. Exact match of raw encoded substrings flowing (e.g. key.pem's base64 block)
        for pattern, encoding_name in ENCODING_PATTERNS:
            prev_matches = set(pattern.findall(prev_text))
            curr_matches = set(pattern.findall(curr_text))
            shared = prev_matches & curr_matches
            if shared and any(len(m) > 10 for m in shared):
                sample = list(shared)[0][:30]
                return FlowDetection(
                    flow_detected=True,
                    confidence=0.80,
                    evidence=f"{encoding_name} encoded data propagation: '{sample}...'",
                    method="explicit",
                )

        # 2. Decoding checks: is plain text in prev_text encoded in curr_text?
        # Check base64 decoding of substrings in curr_text
        b64_pattern = re.compile(r'[A-Za-z0-9+/]{8,}={0,2}')
        curr_b64_candidates = b64_pattern.findall(curr_text)
        for candidate in curr_b64_candidates:
            try:
                # Add missing padding if necessary
                missing_padding = len(candidate) % 4
                padded_candidate = candidate
                if missing_padding:
                    padded_candidate += '=' * (4 - missing_padding)
                decoded_bytes = base64.b64decode(padded_candidate, validate=True)
                decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
                # Check if decoded string is in prev_text (avoid trivial matches like short words)
                if len(decoded_str) >= 6 and decoded_str in prev_text and decoded_str.strip():
                    return FlowDetection(
                        flow_detected=True,
                        confidence=0.90,
                        evidence=f"Base64 decoded content '{decoded_str.strip()}' found in previous output",
                        method="explicit"
                    )
            except Exception:
                pass

        # Check URL decoding of substrings in curr_text
        if '%' in curr_text:
            try:
                decoded_str = urllib.parse.unquote(curr_text)
                if prev_text in decoded_str and len(prev_text) > 8:
                    return FlowDetection(
                        flow_detected=True,
                        confidence=0.90,
                        evidence="URL decoded content matches previous output",
                        method="explicit"
                    )
            except Exception:
                pass

        return None

    # ── Phase B: Lexical ───────────────────────────────────────────────

    def _check_lexical(self, prev_text: str, curr_text: str) -> FlowDetection:
        """Detect partial/fuzzy reuse via rapidfuzz."""
        score = fuzz.partial_ratio(prev_text, curr_text) / 100.0
        if score >= self.lexical_threshold:
            return FlowDetection(
                flow_detected=True,
                confidence=score,
                evidence=f"Lexical similarity (partial_ratio): {score:.2f}",
                method="lexical",
            )
        return FlowDetection(
            flow_detected=False, confidence=0.0, evidence="", method="none"
        )

    # ── Phase C: Semantic ──────────────────────────────────────────────

    def _check_semantic(self, prev_text: str, curr_text: str) -> FlowDetection:
        """Detect meaning-preserving paraphrasing via sentence embeddings."""
        emb_prev = self.model.encode(prev_text, convert_to_tensor=True)
        emb_curr = self.model.encode(curr_text, convert_to_tensor=True)
        score = float(util.cos_sim(emb_prev, emb_curr).item())

        if score >= self.semantic_threshold:
            return FlowDetection(
                flow_detected=True,
                confidence=score,
                evidence=f"Semantic similarity (cosine): {score:.2f} "
                         f"(threshold={self.semantic_threshold})",
                method="semantic",
            )
        return FlowDetection(
            flow_detected=False, confidence=0.0, evidence="", method="none"
        )
