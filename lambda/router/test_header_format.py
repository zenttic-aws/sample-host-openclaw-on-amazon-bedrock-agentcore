"""Telegram, Slack and Feishu signature headers are checked for format first.

A value that cannot be a signature (wrong length, uppercase hex, wrong
prefix, characters outside the Telegram token alphabet) gets 401 with an
"invalid format" warning and no HMAC computed; a well-formed wrong value
still gets 401 from the comparison. All secrets below are synthetic
placeholders.
"""

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

MALFORMED = {
    "telegram": ["has space", "a" * 257, "semi;colon", "\u00e9"],
    "slack": ["v0=" + "A" * 64, "v0=" + "0" * 63, "v1=" + "0" * 64, "0" * 64],
    "feishu": ["A" * 64, "0" * 63, "0" * 65, "v0=" + "0" * 64],
}
WELL_FORMED_WRONG = {"telegram": "wrong_but_well-formed", "slack": "v0=" + "0" * 64, "feishu": "0" * 64}


def _headers(channel, signature):
    now = str(int(time.time()))
    if channel == "telegram":
        return {"x-telegram-bot-api-secret-token": signature}
    if channel == "slack":
        return {"x-slack-request-timestamp": now, "x-slack-signature": signature}
    return {"x-lark-request-timestamp": now, "x-lark-request-nonce": "n", "x-lark-signature": signature}


def _event(channel, headers):
    path = f"/webhook/{channel}"
    return {"requestContext": {"http": {"method": "POST", "path": path, "sourceIp": "192.0.2.1"}},
            "rawPath": path, "headers": headers, "body": "{}", "isBase64Encoded": False}


class TestHeaderFormat(unittest.TestCase):
    def setUp(self):
        for p in (
            patch.object(index, "_get_webhook_secret", return_value="syntheticTelegramWebhookSecret0123"),
            patch.object(index, "_get_slack_tokens", return_value=("xoxb-synthetic", "synthetic-signing")),
            patch.object(index, "_get_feishu_credentials", return_value=("app", "secret", "vtoken", "fkey")),
        ):
            p.start()
            self.addCleanup(p.stop)
        p = patch.object(index, "_self_invoke_async")
        self.mock_async = p.start()
        self.addCleanup(p.stop)

    def test_malformed_value_is_401_by_format(self):
        for channel, values in MALFORMED.items():
            for value in values:
                with self.subTest(channel=channel, value=value[:12]), \
                        patch.object(index.hmac, "new", wraps=index.hmac.new) as mac, \
                        self.assertLogs(index.logger, level="WARNING") as logs:
                    resp = index.handler(_event(channel, _headers(channel, value)), None)
                self.assertEqual(resp["statusCode"], 401)
                self.assertTrue(any("invalid format" in line for line in logs.output), logs.output)
                mac.assert_not_called()
        self.mock_async.assert_not_called()

    def test_well_formed_wrong_value_is_401_by_comparison(self):
        for channel, value in WELL_FORMED_WRONG.items():
            with self.subTest(channel=channel), self.assertLogs(index.logger, level="WARNING") as logs:
                resp = index.handler(_event(channel, _headers(channel, value)), None)
            self.assertEqual(resp["statusCode"], 401)
            self.assertTrue(any("mismatch" in line for line in logs.output), logs.output)
        self.mock_async.assert_not_called()


if __name__ == "__main__":
    unittest.main()
