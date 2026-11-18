"""Agent reply text must not reach the Router or Cron logs.

Each channel's handler runs with the agent returning a reply that holds chat
text, a secret-looking value and a presigned URL. Delivery is stubbed three
ways: the platform accepts it, the platform answers HTTP 400, and the send
raises (for the Router this reaches the async dispatch guard, which logs a
traceback). No log record, tracebacks included, may contain any part of the
reply. Reply lengths may be logged.

The E2E log tailer reads the reply length from the length-only line.

All IDs, tokens and secrets below are synthetic placeholders.
"""

import email.message
import io
import json
import logging
import time
import urllib.error
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from tests.e2e import log_tailer
from tests.test_runtime_routing import FakeRuntime, cron_event, cron_table, load_lambda

SENTINELS = ("r1-sentinel-chat-text", "sk-r1sentinelsecret", "X-Amz-Signature=r1sentinelsig")
REPLY = (
    "Here is the summary r1-sentinel-chat-text. Your key is sk-r1sentinelsecret. "
    "Download: https://example-bucket.s3.amazonaws.com/report.pdf?X-Amz-Signature=r1sentinelsig"
)

WA_SECRET = json.dumps({"accessToken": "EAAtest-access-token", "appSecret": "test-app-secret",
                        "verifyToken": "test-verify-token", "phoneNumberId": "100000000000001"})
LINE_SECRET = json.dumps({"channelSecret": "0123456789abcdef0123456789abcdef",
                          "channelAccessToken": "synthetic-channel-access-token"})
LINE_USER = "U" + "0" * 31 + "1"
DISCORD_APP = "400000000000000001"


class FakeResponse(io.BytesIO):
    status = 200

    def __init__(self):
        super().__init__(b'{"ok":true,"code":0}')
        self.headers = email.message.Message()

    def getcode(self):
        return 200


def delivered(req, timeout=None):
    return FakeResponse()


def rejected(req, timeout=None):
    fp = io.BytesIO(b'{"ok":false,"error":"invalid_request"}')
    raise urllib.error.HTTPError(req.full_url, 400, "Bad Request", email.message.Message(), fp)


def _all_log_text(caplog):
    formatter = logging.Formatter("%(message)s")
    return "\n".join(formatter.format(record) for record in caplog.records)


def assert_reply_not_logged(caplog):
    text = _all_log_text(caplog)
    for sentinel in SENTINELS:
        assert sentinel not in text, f"reply text {sentinel!r} reached the logs"


# --- Router -----------------------------------------------------------------

def _router_cases(module):
    """Per channel: async body, extra patches, and the send function the 'raises' mode breaks."""
    wa = module.whatsapp
    line = module.line_channel
    discord = module.discord_channel
    now = int(time.time())
    return {
        "telegram": (
            {"message": {"text": "hi", "chat": {"id": 123}, "from": {"id": 123, "first_name": "Test"}}},
            [("_get_telegram_token", "123456:synthetic-token"), ("_periodic_typing", None),
             ("send_telegram_typing", None)],
            (module, "send_telegram_message"),
        ),
        "slack": (
            {"type": "event_callback", "event": {"type": "message", "user": "U12345USER",
                                                 "channel": "D12345CHAN", "text": "hi",
                                                 "ts": "1234567890.123456"}},
            [("_get_slack_tokens", ("xoxb-synthetic-token", "synthetic-signing-secret"))],
            (module, "send_slack_message"),
        ),
        "feishu": (
            {"schema": "2.0",
             "header": {"event_id": "evt_r1", "event_type": "im.message.receive_v1", "app_id": "cli_test"},
             "event": {"sender": {"sender_id": {"open_id": "ou_test123"}, "sender_type": "user"},
                       "message": {"message_id": "om_test", "chat_id": "oc_chat456", "chat_type": "p2p",
                                   "message_type": "text", "content": json.dumps({"text": "hi"})}}},
            [("_get_feishu_tenant_token", "t-synthetic-token"), ("_claim_feishu_event", True)],
            (module, "send_feishu_message"),
        ),
        "whatsapp": (
            {"object": "whatsapp_business_account", "entry": [{"id": "300000000000001", "changes": [{
                "field": "messages", "value": {
                    "messaging_product": "whatsapp",
                    "metadata": {"display_phone_number": "15550000000", "phone_number_id": "100000000000001"},
                    "contacts": [{"profile": {"name": "Test User"}, "wa_id": "15550000001"}],
                    "messages": [{"from": "15550000001", "id": "wamid.R1", "timestamp": str(now),
                                  "type": "text", "text": {"body": "hi"}}]}}]}]},
            [("_get_whatsapp_config", wa.parse_config(WA_SECRET)), ("_claim_whatsapp_message", True)],
            (wa, "send_text"),
        ),
        "line": (
            {"destination": "U" + "f" * 32, "events": [{
                "type": "message", "mode": "active", "timestamp": now * 1000,
                "source": {"type": "user", "userId": LINE_USER}, "webhookEventId": "01HSYNTHETICR1",
                "deliveryContext": {"isRedelivery": False}, "replyToken": "nHuyWiB7yP5Zw52FIkcQobQuGDXCTA",
                "message": {"id": "100000000000000001", "type": "text", "quoteToken": "q", "text": "hi"}}]},
            [("_get_line_config", line.parse_config(LINE_SECRET)), ("_claim_line_event", True)],
            (line, "send_text"),
        ),
        "discord": (
            {"type": 2, "id": "600000000000000001", "application_id": DISCORD_APP,
             "token": "aW50ZXJhY3Rpb246dGVzdA.synthetic-token",
             "data": {"id": "700000000000000001", "name": "ask", "type": 1,
                      "options": [{"name": "prompt", "type": 3, "value": "hi"}]},
             "user": {"id": "500000000000000001", "username": "synthetic", "global_name": "Synthetic User"}},
            [("_get_discord_config", {"applicationId": DISCORD_APP, "publicKey": "0" * 64,
                                      "botToken": "synthetic.bot.token"})],
            (discord, "send_reply"),
        ),
    }


def _run_router(channel, mode, caplog):
    module = load_lambda("router")
    body, extra, (send_owner, send_name) = _router_cases(module)[channel]
    route = SimpleNamespace(platform_version="V2", user_id="user_test", actor_id=f"{channel}:test",
                            session_id="ses_" + "1" * 40, generation=1)
    sent = []

    def record(req, timeout=None):
        sent.append(req.data or b"")
        return (delivered if mode == "delivered" else rejected)(req, timeout)

    with ExitStack() as stack:
        for name, value in extra:
            stack.enter_context(patch.object(module, name, return_value=value))
        for name, value in [("resolve_user", ("user_test", False)), ("get_or_create_session", route),
                            ("authorize_channel_actor", None), ("get_model_override", None),
                            ("invoke_agent_runtime", {"response": REPLY}),
                            ("_verify_async_dispatch", True)]:
            stack.enter_context(patch.object(module, name, return_value=value))
        stack.enter_context(patch.object(module.urllib_request, "urlopen", side_effect=record))
        if mode == "raises":
            stack.enter_context(patch.object(send_owner, send_name,
                                             side_effect=RuntimeError("synthetic send failure")))
        with caplog.at_level(logging.DEBUG):
            result = module.handler({"_async_dispatch": True, "_channel": channel,
                                     "_body": json.dumps(body), "_headers": {}}, None)
    assert result == {"statusCode": 200, "body": "ok"}
    return sent


@pytest.mark.parametrize("mode", ["delivered", "rejected", "raises"])
@pytest.mark.parametrize("channel", ["telegram", "slack", "feishu", "whatsapp", "line", "discord"])
def test_router_never_logs_the_reply(channel, mode, caplog):
    sent = _run_router(channel, mode, caplog)
    assert_reply_not_logged(caplog)
    if mode == "delivered":
        # The reply did reach the channel's send call (escaped forms included).
        assert any(b"r1-sentinel-chat-text" in data for data in sent), sent
    if mode == "raises":
        assert "Async dispatch failed" in caplog.text


def test_router_logs_the_telegram_reply_length(caplog):
    _run_router("telegram", "delivered", caplog)
    assert f"Telegram response ready (len={len(REPLY)}, streamed=False)" in caplog.text


def test_router_invocation_logs_no_reply(caplog):
    module = load_lambda("router")
    route = SimpleNamespace(actor_id="telegram:123", runtime_arn="arn:test", endpoint_name="DEFAULT",
                            session_id="ses_" + "1" * 40, generation=1,
                            payload_context=lambda: {}, invocation=lambda: {})
    module.agentcore_client = FakeRuntime([{"response": REPLY}])
    admission = SimpleNamespace(retain=lambda: None)

    class Admit:
        def __enter__(self):
            return admission

        def __exit__(self, *exc):
            return False

    with patch.object(module, "authorize_channel_actor"), \
            patch.object(module, "admit_route", return_value=Admit()), \
            caplog.at_level(logging.DEBUG):
        result = module.invoke_agent_runtime(route, "user_test", "telegram:123", "telegram", "hi")
    assert result["response"] == REPLY
    assert_reply_not_logged(caplog)


# --- Cron -------------------------------------------------------------------

def test_cron_run_logs_the_length_not_the_reply(caplog):
    module = load_lambda("cron")
    module.identity_table = cron_table()
    module.agentcore_client = FakeRuntime([{"status": "ready", "phase": "USER_READY"}, {"response": REPLY}])
    module._get_telegram_token = lambda: "123456:synthetic-token"
    sent = []

    def telegram(req, timeout=None):
        sent.append(req.data)
        return io.BytesIO(b'{"ok":true}')

    with patch.object(module.urllib_request, "urlopen", side_effect=telegram), caplog.at_level(logging.DEBUG):
        assert module.handler(cron_event(), None)["statusCode"] == 200
    assert any(b"r1-sentinel-chat-text" in data for data in sent)
    assert_reply_not_logged(caplog)
    assert f"Delivering response (len={len(REPLY)})" in caplog.text


@pytest.mark.parametrize("mode", ["delivered", "rejected", "raises"])
@pytest.mark.parametrize("channel,target", [
    ("telegram", "123"), ("slack", "D12345CHAN"), ("feishu", "oc_chat456"),
    ("whatsapp", "15550000001"), ("line", LINE_USER),
])
def test_cron_delivery_never_logs_the_reply(channel, target, mode, caplog):
    module = load_lambda("cron")
    module.WHATSAPP_TOKEN_SECRET_ID = "openclaw/channels/whatsapp"
    module.LINE_TOKEN_SECRET_ID = "openclaw/channels/line"
    secrets = {"openclaw/channels/whatsapp": WA_SECRET, "openclaw/channels/line": LINE_SECRET}
    if mode == "raises":
        def urlopen(req, timeout=None):
            raise OSError("synthetic network failure")
    else:
        urlopen = delivered if mode == "delivered" else rejected
    with patch.object(module, "_get_telegram_token", return_value="123456:synthetic-token"), \
            patch.object(module, "_get_slack_tokens", return_value=("xoxb-synthetic-token", "")), \
            patch.object(module, "_get_feishu_tenant_token", return_value="t-synthetic-token"), \
            patch.object(module, "_get_secret", side_effect=lambda sid: secrets.get(sid, "")), \
            patch.object(module.urllib_request, "urlopen", side_effect=urlopen), \
            caplog.at_level(logging.DEBUG):
        module.deliver_response(channel, target, REPLY)
    assert_reply_not_logged(caplog)


# --- E2E log tailer ---------------------------------------------------------

@pytest.mark.parametrize("line,length,text", [
    ("Telegram response ready (len=42, streamed=False)", 42, ""),
    ("Telegram response ready (len=7, streamed=True)", 7, ""),
    ("Response to send (len=5)", 5, ""),
    ("Response to send (len=5): hello", 5, "hello"),
])
def test_tailer_reads_the_reply_length(line, length, text):
    result = log_tailer.TailResult()
    log_tailer._parse_line(f"[INFO]\t2026-01-01T00:00:00Z\t{'0' * 8}-0000-0000-0000-{'0' * 12}\t{line}", result)
    assert (result.response_len, result.response_text) == (length, text)
