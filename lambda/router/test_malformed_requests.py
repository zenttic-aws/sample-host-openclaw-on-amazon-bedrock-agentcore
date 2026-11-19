"""Unauthenticated malformed webhook requests get a 4xx instead of raising.

Covers each channel's HTTP entry point with non-ASCII, garbled, oversized and
missing signature or timestamp headers, and with bodies that are not JSON,
empty, or not decodable. The inner handler is called directly, so an
exception would fail the test instead of being absorbed by the last-resort
guard. All secrets and IDs below are synthetic placeholders.
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import sys
import time
import unittest
from unittest.mock import MagicMock, patch

os.environ.setdefault("AGENTCORE_RUNTIME_ARN",
    "arn:aws:bedrock-agentcore:us-west-2:123456789012:runtime/test")
os.environ.setdefault("AGENTCORE_QUALIFIER", "test-endpoint")
os.environ.setdefault("IDENTITY_TABLE_NAME", "openclaw-identity")
os.environ.setdefault("USER_FILES_BUCKET", "openclaw-user-files-123456789012-us-west-2")

sys.modules["boto3"] = MagicMock()
sys.modules["botocore"] = MagicMock()
sys.modules["botocore.config"] = MagicMock()
sys.modules["botocore.exceptions"] = MagicMock()

import importlib  # noqa: E402

index = importlib.import_module("index")
line_channel = importlib.import_module("line_channel")
whatsapp = importlib.import_module("whatsapp")

WEBHOOK_SECRET = "syntheticTelegramWebhookSecret0123456789"
SLACK_SIGNING = "synthetic-slack-signing-secret"
FEISHU_KEY = "synthetic-feishu-encrypt-key"
WA_CONFIG = {"accessToken": "synthetic-wa-token", "appSecret": "synthetic-wa-app-secret",
             "verifyToken": "synthetic-verify", "phoneNumberId": "100000000000001",
             "graphApiVersion": "v21.0"}
LINE_CONFIG = {"channelSecret": "0123456789abcdef0123456789abcdef",
               "channelAccessToken": "synthetic-line-token", "botUserId": ""}
DISCORD_CONFIG = {"applicationId": "400000000000000001", "publicKey": "ab" * 32,
                  "botToken": "synthetic.bot.token"}

ALL_CHANNELS = ("telegram", "slack", "feishu", "whatsapp", "line", "discord")
HUGE = "9" * 400  # int() accepts it; subtracting it from a float overflows


def _now():
    return str(int(time.time()))


def _event(channel, body="{}", headers=None, b64=False):
    path = f"/webhook/{channel}"
    return {"requestContext": {"http": {"method": "POST", "path": path, "sourceIp": "192.0.2.1"}},
            "rawPath": path, "headers": {} if headers is None else headers, "body": body,
            "isBase64Encoded": b64}


def _signed(channel, body):
    """Headers carrying a valid signature for body."""
    if channel == "telegram":
        return {"x-telegram-bot-api-secret-token": WEBHOOK_SECRET}
    if channel == "slack":
        ts = _now()
        sig = hmac.new(SLACK_SIGNING.encode(), f"v0:{ts}:{body}".encode(), hashlib.sha256).hexdigest()
        return {"x-slack-request-timestamp": ts, "x-slack-signature": "v0=" + sig}
    if channel == "feishu":
        ts, nonce = _now(), "synthetic-nonce"
        sig = hashlib.sha256(f"{ts}{nonce}{FEISHU_KEY}".encode() + body.encode()).hexdigest()
        return {"x-lark-request-timestamp": ts, "x-lark-request-nonce": nonce, "x-lark-signature": sig}
    if channel == "whatsapp":
        sig = hmac.new(WA_CONFIG["appSecret"].encode(), body.encode(), hashlib.sha256).hexdigest()
        return {"x-hub-signature-256": "sha256=" + sig}
    if channel == "line":
        sig = hmac.new(LINE_CONFIG["channelSecret"].encode(), body.encode(), hashlib.sha256).digest()
        return {"x-line-signature": base64.b64encode(sig).decode()}
    raise ValueError(channel)


def _with_signature(channel, value):
    """Signature header(s) for channel with the signature itself set to value; the rest valid."""
    if channel == "telegram":
        return {"x-telegram-bot-api-secret-token": value}
    if channel == "slack":
        return {"x-slack-request-timestamp": _now(), "x-slack-signature": value}
    if channel == "feishu":
        return {"x-lark-request-timestamp": _now(), "x-lark-request-nonce": "n", "x-lark-signature": value}
    if channel == "whatsapp":
        return {"x-hub-signature-256": value}
    if channel == "line":
        return {"x-line-signature": value}
    if channel == "discord":
        return {"x-signature-ed25519": value, "x-signature-timestamp": _now()}
    raise ValueError(channel)


GARBLED_SIGNATURES = {
    "non-ASCII": "\u00e9t\u00e9",
    "non-ASCII hex-length": "\u00e9" * 64,
    "lone surrogate": "\ud800",
    "prefixed non-ASCII": "sha256=\u00e9\u00e9",
    "slack prefix non-ASCII": "v0=\u00e9",
    "empty": "",
    "whitespace": "   ",
    "control characters": "\x00\x01\r\n",
    "oversized": "a" * 8192,
    "wrong": "0" * 64,
}


class _ChannelsConfigured(unittest.TestCase):
    def setUp(self):
        patches = [
            patch.object(index, "_get_webhook_secret", return_value=WEBHOOK_SECRET),
            patch.object(index, "_get_slack_tokens", return_value=("xoxb-synthetic", SLACK_SIGNING)),
            patch.object(index, "_get_feishu_credentials", return_value=("app", "secret", "vtoken", FEISHU_KEY)),
            patch.object(index, "_get_whatsapp_config", return_value=WA_CONFIG),
            patch.object(index, "_get_line_config", return_value=LINE_CONFIG),
            patch.object(index, "_get_discord_config", return_value=DISCORD_CONFIG),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        p = patch.object(index, "_self_invoke_async")
        self.mock_async = p.start()
        self.addCleanup(p.stop)

    def call(self, event):
        return index._handler_impl(event, None)

    def assert_status(self, event, status):
        self.assertEqual(self.call(event)["statusCode"], status)


class TestMalformedHeaders(_ChannelsConfigured):
    def test_garbled_signature_header_is_401(self):
        for ch in ALL_CHANNELS:
            for label, value in GARBLED_SIGNATURES.items():
                with self.subTest(channel=ch, signature=label):
                    self.assert_status(_event(ch, "{}", _with_signature(ch, value)), 401)
        self.mock_async.assert_not_called()

    def test_missing_headers_is_401(self):
        for ch in ALL_CHANNELS:
            with self.subTest(channel=ch):
                self.assert_status(_event(ch, "{}", {}), 401)
        self.mock_async.assert_not_called()

    def test_bad_timestamp_is_401(self):
        arabic_now = "".join(chr(0x0660 + int(d)) for d in _now())
        timestamps = [HUGE, "-" + HUGE, "abc", "1e10", "", "\u00e9", "\ud800", arabic_now, "9" * 5000]
        for ts in timestamps:
            cases = {
                "slack": {"x-slack-request-timestamp": ts, "x-slack-signature": "v0=" + "0" * 64},
                "feishu": {"x-lark-request-timestamp": ts, "x-lark-request-nonce": "n",
                           "x-lark-signature": "0" * 64},
                "discord": {"x-signature-ed25519": "0" * 128, "x-signature-timestamp": ts},
            }
            for ch, headers in cases.items():
                with self.subTest(channel=ch, timestamp=ts[:12]):
                    self.assert_status(_event(ch, "{}", headers), 401)
        self.mock_async.assert_not_called()

    def test_garbled_content_length_does_not_raise(self):
        for value in ("abc", "-1", "\u00e9", "9" * 5000):
            with self.subTest(content_length=value[:12]):
                self.assert_status(_event("telegram", "{}", {"content-length": value}), 401)
        self.assert_status(_event("telegram", "{}", {"content-length": str(10 ** 9)}), 413)


class TestMalformedBodies(_ChannelsConfigured):
    def test_unsigned_bodies_are_401(self):
        for ch in ALL_CHANNELS:
            for body in ("", "not json", "[]", "null", "\u00e9\u00e9", "{" * 1000, "\x00\xff"):
                with self.subTest(channel=ch, body=body[:12]):
                    self.assert_status(_event(ch, body, {}), 401)
        self.mock_async.assert_not_called()

    def test_undecodable_base64_body_is_400(self):
        invalid_utf8 = base64.b64encode(b"\xff\xfe\x80").decode("ascii")
        for ch in ALL_CHANNELS:
            for body in ("!!!not base64!!!", "abc", invalid_utf8):
                with self.subTest(channel=ch, body=body):
                    self.assert_status(_event(ch, body, {}, b64=True), 400)
        self.assert_status(_event("telegram", 12345, {}, b64=True), 400)
        self.mock_async.assert_not_called()

    def test_oversized_body_is_413(self):
        self.assert_status(_event("telegram", "x" * (index.MAX_BODY_BYTES + 1), {}), 413)

    def test_null_body_with_well_formed_headers_is_401(self):
        # A body of null with headers that pass every format and timestamp
        # check reaches the signature comparison on each channel.
        well_formed = {
            "telegram": _with_signature("telegram", "wrongButWellFormed"),
            "slack": _with_signature("slack", "v0=" + "0" * 64),
            "feishu": _with_signature("feishu", "0" * 64),
            "whatsapp": _with_signature("whatsapp", "sha256=" + "0" * 64),
            "line": _with_signature("line", "A" * 43 + "="),
            "discord": _with_signature("discord", "0" * 128),
        }
        for ch, headers in well_formed.items():
            with self.subTest(channel=ch):
                self.assert_status(_event(ch, None, headers), 401)
        self.mock_async.assert_not_called()


class TestValidRequestsUnchanged(_ChannelsConfigured):
    def test_signed_request_is_dispatched(self):
        body = json.dumps({"update_id": 1, "events": [], "entry": [], "type": "event_callback"})
        for ch in ("telegram", "slack", "feishu", "whatsapp", "line"):
            with self.subTest(channel=ch):
                self.mock_async.reset_mock()
                self.assertEqual(self.call(_event(ch, body, _signed(ch, body))), {"statusCode": 200, "body": "ok"})
                self.mock_async.assert_called_once()

    def test_signed_base64_request_is_dispatched(self):
        body = json.dumps({"update_id": 1})
        encoded = base64.b64encode(body.encode()).decode()
        headers = _signed("telegram", body)
        self.assertEqual(self.call(_event("telegram", encoded, headers, b64=True)), {"statusCode": 200, "body": "ok"})
        self.mock_async.assert_called_once_with("telegram", body, headers)

    def test_non_ascii_body_with_valid_signature_is_dispatched(self):
        body = json.dumps({"text": "\u00e9\u6f22\U0001f600"}, ensure_ascii=False)
        for ch in ("slack", "feishu", "whatsapp", "line"):
            with self.subTest(channel=ch):
                self.mock_async.reset_mock()
                self.assertEqual(self.call(_event(ch, body, _signed(ch, body)))["statusCode"], 200)
                self.mock_async.assert_called_once()

    def test_slack_url_verification_still_answered(self):
        body = json.dumps({"type": "url_verification", "challenge": "abc123"})
        resp = self.call(_event("slack", body, _signed("slack", body)))
        self.assertEqual((resp["statusCode"], json.loads(resp["body"])), (200, {"challenge": "abc123"}))


class TestHandlerGuard(unittest.TestCase):
    def test_unexpected_error_returns_500_and_logs_only_the_type(self):
        with patch.object(index, "validate_telegram_webhook", side_effect=RuntimeError("do-not-log")), \
                self.assertLogs(index.logger, level="ERROR") as logs:
            resp = index.handler(_event("telegram", '{"marker": "do-not-log"}', {}), None)
        self.assertEqual(resp, {"statusCode": 500, "body": "Internal Server Error"})
        self.assertIn("RuntimeError", "\n".join(logs.output))
        self.assertNotIn("do-not-log", "\n".join(logs.output))
        self.assertTrue(all(r.exc_info is None for r in logs.records))


class TestSharedVerifySignature(unittest.TestCase):
    def test_whatsapp(self):
        body = b"{}"
        good = "sha256=" + hmac.new(b"app", body, hashlib.sha256).hexdigest()
        self.assertTrue(whatsapp.verify_signature({"x-hub-signature-256": good}, body, "app"))
        for sig in ("sha256=\u00e9\u00e9", "sha256=\ud800", None, 123, ""):
            with self.subTest(sig=sig):
                self.assertFalse(whatsapp.verify_signature({"x-hub-signature-256": sig}, body, "app"))

    def test_line(self):
        body = b"{}"
        good = base64.b64encode(hmac.new(b"secret", body, hashlib.sha256).digest()).decode()
        self.assertTrue(line_channel.verify_signature({"x-line-signature": good}, body, "secret"))
        for sig in ("\u00e9" * 43 + "=", good + "\n", None, 123, ""):
            with self.subTest(sig=sig):
                self.assertFalse(line_channel.verify_signature({"x-line-signature": sig}, body, "secret"))


if __name__ == "__main__":
    unittest.main()
