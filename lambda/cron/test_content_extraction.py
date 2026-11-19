"""Tests for _extract_text_from_content_blocks in the Cron Lambda.

The cron Lambda keeps its own copy of the router's content-block extractor.
These cases mirror the #118 fixes in lambda/router/test_content_extraction.py
so a scheduled brief cannot leak raw '[{"type":"text",...' JSON into a
Telegram/Slack/Feishu message.
"""

import json
import os
import sys
import unittest
from unittest.mock import MagicMock

os.environ.setdefault("AGENTCORE_RUNTIME_ARN", "arn:aws:bedrock-agentcore:us-west-2:123456789012:runtime/test")
os.environ.setdefault("AGENTCORE_QUALIFIER", "test-endpoint")
os.environ.setdefault("IDENTITY_TABLE_NAME", "openclaw-identity")

sys.modules["boto3"] = MagicMock()
sys.modules["botocore"] = MagicMock()
sys.modules["botocore.config"] = MagicMock()
sys.modules["botocore.exceptions"] = MagicMock()

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import importlib  # noqa: E402

index = importlib.import_module("index")


class TestCronExtractTextFromContentBlocks(unittest.TestCase):
    """Content-block extraction in the cron Lambda matches the router (#118)."""

    def test_malformed_block_mid_reply_keeps_suffix(self):
        """A closed but malformed block (trailing comma) must not drop the text after it."""
        result = index._extract_text_from_content_blocks(
            'prefix [{"type":"text","text":"x"},] suffix'
        )
        self.assertNotIn("[{", result)
        self.assertTrue(result.startswith("prefix "), result)
        self.assertTrue(result.endswith(" suffix"), result)

    def test_trailing_partial_fragment_after_text_is_stripped(self):
        """A genuine unterminated fragment at the end is stripped; prefix kept."""
        result = index._extract_text_from_content_blocks(
            'Here is the answer.\n\n[{"type":"text","text":"partial'
        )
        self.assertEqual(result, "Here is the answer.\n\n")

    def test_prose_mentioning_block_syntax_is_unchanged(self):
        """Prose that quotes content-block syntax mid-reply keeps all its text."""
        raw = (
            'To send an image, the API expects content like '
            '[{"type": "image", ...}]. After that, call the second endpoint '
            'with the returned id.'
        )
        self.assertEqual(index._extract_text_from_content_blocks(raw), raw)

    def test_well_formed_blocks_still_unwrapped(self):
        """Regression guard: nested well-formed blocks are still fully unwrapped."""
        inner = json.dumps([{"type": "text", "text": "Daily brief."}])
        outer = json.dumps([{"type": "text", "text": inner}])
        self.assertEqual(index._extract_text_from_content_blocks(outer), "Daily brief.")

    def test_partial_content_block_json(self):
        """A reply that is only a partial content block does not leak '[{'."""
        result = index._extract_text_from_content_blocks('\n\n[{"type":"text","text":"hello')
        self.assertNotIn("[{", result)

    def test_pathological_quadratic_payload_is_bounded(self):
        """Many '[{' tokens must not trigger a quadratic rescan (CWE-407).

        A model (or injected tool/web result) can emit tens of thousands of
        '[{' candidates. Typed blocks without text are kept as they are, and
        the scan finishes well under the Lambda timeout.
        """
        import time as _time
        for text, limit in (('[{"type":0}' * 45454 + "]", 1.0), ('[{"type":0}' * 4000 + "]", 2.0)):
            start = _time.monotonic()
            result = index._extract_text_from_content_blocks(text)
            elapsed = _time.monotonic() - start
            self.assertEqual(result, text)
            self.assertLess(elapsed, limit, f"{len(text)} chars took {elapsed:.3f}s")

    def test_ten_thousand_blocks_finish_quickly_and_extract_fully(self):
        """A reply made of 10,000 blocks is unwrapped completely, in linear time."""
        import time as _time
        cases = (
            ('[{"type":"text","text":"x"}]' * 10000, "x" * 10000),
            ('[{"type":"text","text":"x"}] ' * 10000, "x " * 10000),
            ('[{"type":0}' * 10000 + "]", None),
            ('[{"type":"text","text":"\\q"}' * 10000 + "]", None),
        )
        for text, expected in cases:
            with self.subTest(text=text[:30]):
                start = _time.monotonic()
                result = index._extract_text_from_content_blocks(text)
                self.assertLess(_time.monotonic() - start, 2.0)
                self.assertEqual(result, text if expected is None else expected)

    def test_deeply_nested_json_is_kept_as_text(self):
        """JSON nested too deeply to decode is kept as text instead of raising."""
        deep = "[" * 20000 + '{"type":"text","text":"x"}' + "]" * 20000
        result = index._extract_text_from_content_blocks("before " + deep + " after")
        self.assertTrue(result.startswith("before "), result[:40])
        self.assertTrue(result.endswith(" after"), result[-40:])
        chain = '[{"a":' * 20000 + "1"
        self.assertEqual(index._extract_text_from_content_blocks(chain), chain)

    def test_decodes_that_unwrap_nothing_are_capped(self):
        """Text with many '[{' candidates that do not decode tries decoding a bounded number of times."""
        calls = []
        original = index.json.JSONDecoder

        class CountingDecoder(original):
            def raw_decode(self, s, idx=0):
                calls.append(idx)
                return super().raw_decode(s, idx)

        index.json.JSONDecoder = CountingDecoder
        try:
            text = '[{"type":0}' * 5000 + "]"
            self.assertEqual(index._extract_text_from_content_blocks(text), text)
        finally:
            index.json.JSONDecoder = original
        self.assertLessEqual(len(calls), index._MAX_UNUSED_DECODES)

    def test_many_candidates_finish_quickly(self):
        """Large replies full of '[{' do not take time quadratic in their length."""
        import time as _time
        for text in ("[{" * 250000, '[{"type":0}' * 45000 + "]",
                     '[{"type":"text","text":"\\q"}' * 16000 + "]", '[{"a":' * 80000):
            start = _time.monotonic()
            index._extract_text_from_content_blocks(text)
            self.assertLess(_time.monotonic() - start, 15.0)

    def test_whitespace_run_after_brace_finishes_quickly(self):
        """A long space or newline run after '}' does not make the block-close search quadratic."""
        import time as _time
        for run in (" " * 200000, "\n" * 200000):
            with self.subTest(run=repr(run[0])):
                start = _time.monotonic()
                index._extract_text_from_content_blocks('[{"type":}' + run + "x")
                self.assertLess(_time.monotonic() - start, 1.0)

    def test_block_close_still_allows_whitespace_and_one_comma(self):
        """'}]' with optional whitespace around at most one comma still closes a block."""
        for closer in ("}]", "},]", "} ]", "}, ]", "} ,]", "} , ]", "}\n,\n]", "}\n\n]"):
            with self.subTest(closer=closer):
                match = index._BLOCK_CLOSE_RE.search("x" + closer + "y")
                self.assertIsNotNone(match)
                self.assertEqual(match.group(), closer)
        for text in ("}", "} x]", "},,]", "}, ,]"):
            with self.subTest(text=text):
                self.assertIsNone(index._BLOCK_CLOSE_RE.search(text))

    def test_malformed_block_with_spaced_close_is_extracted(self):
        """Malformed blocks closed with whitespace, with or without a comma, still yield their text."""
        for raw in ('prefix [{"type":"text","text":"x"} ,\n ] suffix',
                    'prefix [{"type":"text","text","x"}\n] suffix'):
            with self.subTest(raw=raw):
                self.assertEqual(index._extract_text_from_content_blocks(raw), "prefix x suffix")

    def test_content_block_after_many_brackets_is_unwrapped(self):
        """'[{' that cannot start JSON does not use up the decode budget."""
        text = "[{" * 5000 + ' [{"type":"text","text":"kept"}]'
        result = index._extract_text_from_content_blocks(text)
        self.assertTrue(result.endswith(" kept"), result[-20:])


if __name__ == "__main__":
    unittest.main()
