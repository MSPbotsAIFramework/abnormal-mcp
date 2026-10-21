# Copyright 2026 MSPbots.ai
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""API client and tool behaviour against a mocked Abnormal API (no network)."""

import json

import httpx
import pytest

from abnormal_mcp import api_client
from abnormal_mcp.api_client import AbnormalClient, AbnormalCredentials, AbnormalError
from abnormal_mcp.server import _credentials_var, create_mcp_server

THREAT = {
    "threatId": "184712ab-6d8b-47b3-89d3-a314efef79e2",
    "recipientCount": 2,
    "messages": [
        {
            "abxMessageId": 4551618356913732000,
            "abxMessageIdStr": "4551618356913732000",
            "subject": "Invoice overdue",
            "fromAddress": "billing@example.com",
            "recipientAddress": "user@example.com",
            "attackType": "Invoice/Payment Fraud (BEC)",
            "remediationStatus": "Auto-Remediated",
            "senderIpAddress": "192.0.2.10",
            "urls": ["https://example.com/pay"],
        }
    ],
}


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    async def instant(_seconds):
        return None

    monkeypatch.setattr(api_client.asyncio, "sleep", instant)


def _use_mock(monkeypatch, handler):
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    monkeypatch.setattr(api_client, "_get_shared_http_client", lambda: http)


async def _call(tool: str, args: dict, token: str = "YOUR_API_TOKEN"):
    mcp = create_mcp_server()
    ctx = _credentials_var.set(AbnormalCredentials(token))
    try:
        content, _ = await mcp.call_tool(tool, args)
    finally:
        _credentials_var.reset(ctx)
    return json.loads(content[0].text)


async def test_request_sends_bearer_token_to_us_host():
    seen = {}

    def handler(request):
        seen["url"], seen["auth"] = request.url, request.headers["authorization"]
        return httpx.Response(200, json={"threats": []})

    client = AbnormalClient(
        AbnormalCredentials("tok-1"), http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler))
    )
    await client.get("/threats", {"pageSize": 5, "sender": None})
    assert str(seen["url"]) == "https://api.abnormalplatform.com/v1/threats?pageSize=5"
    assert seen["auth"] == "Bearer tok-1"


async def test_retries_429_then_succeeds():
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(429) if len(calls) == 1 else httpx.Response(200, json={"cases": []})

    client = AbnormalClient(AbnormalCredentials("t"), http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    assert await client.get("/cases") == {"cases": []}
    assert len(calls) == 2


async def test_error_body_message_is_used_without_token():
    def handler(request):
        return httpx.Response(403, json={"message": "IP address not allowlisted"})

    client = AbnormalClient(
        AbnormalCredentials("secret-token"), http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler))
    )
    with pytest.raises(AbnormalError) as exc:
        await client.get("/threats")
    assert exc.value.status_code == 403
    assert "allowlisted" in exc.value.message
    assert "secret-token" not in exc.value.message


async def test_threats_list_pages_only_with_filter(monkeypatch):
    seen = []

    def handler(request):
        seen.append(dict(request.url.params))
        return httpx.Response(
            200, json={"threats": [{"threatId": "a"}], "pageNumber": 1, "nextPageNumber": 2}
        )

    _use_mock(monkeypatch, handler)
    no_filter = await _call("abnormal_threats_list", {"pageSize": 10})
    with_filter = await _call(
        "abnormal_threats_list",
        {"filter": "receivedTime gte 2026-01-01T00:00:00Z", "pageSize": 500, "pageNumber": 3},
    )
    assert "pageSize" not in seen[0]
    assert seen[1]["pageSize"] == "100" and seen[1]["pageNumber"] == "3"
    assert with_filter == {"items": [{"threatId": "a"}], "count": 1, "page": 1, "has_more": True, "next_page": 2}
    assert no_filter["count"] == 1


async def test_messages_list_returns_summaries(monkeypatch):
    _use_mock(monkeypatch, lambda r: httpx.Response(200, json=THREAT))
    result = await _call("abnormal_messages_list", {"threatId": THREAT["threatId"]})
    assert result["count"] == 1
    message = result["items"][0]
    assert message["subject"] == "Invoice overdue"
    assert "senderIpAddress" not in message and "urls" not in message


async def test_messages_get_falls_back_to_threat_messages(monkeypatch):
    paths = []

    def handler(request):
        paths.append(request.url.path)
        if request.url.path.startswith("/v1/threats/messages/"):
            return httpx.Response(404, json={"message": "not found"})
        return httpx.Response(200, json=THREAT)

    _use_mock(monkeypatch, handler)
    result = await _call(
        "abnormal_messages_get", {"threatId": THREAT["threatId"], "messageId": "4551618356913732000"}
    )
    assert paths == ["/v1/threats/messages/4551618356913732000", f"/v1/threats/{THREAT['threatId']}"]
    assert result["senderIpAddress"] == "192.0.2.10"


async def test_remediation_status_reads_history_and_remediate_posts(monkeypatch):
    seen = []

    def handler(request):
        seen.append((request.method, request.url.path, request.content))
        if request.method == "POST":
            return httpx.Response(202, json={"action_id": "act-1", "status_url": "https://example.com/s"})
        return httpx.Response(200, json={"remediation_history": {}, "folder_locations": ["Inbox"]})

    _use_mock(monkeypatch, handler)
    status = await _call("abnormal_remediation_manage", {"threatId": "t-1", "messageId": "42", "action": "status"})
    done = await _call("abnormal_remediation_manage", {"threatId": "t-1", "messageId": "42", "action": "remediate"})
    assert seen[0][:2] == ("GET", "/v1/messages/42/remediation_history")
    assert seen[1][:2] == ("POST", "/v1/threats/t-1")
    assert json.loads(seen[1][2]) == {"action": "remediate"}
    assert status["folder_locations"] == ["Inbox"]
    assert done["action_id"] == "act-1"


async def test_remediation_status_with_action_id(monkeypatch):
    seen = []

    def handler(request):
        seen.append(request.url.path)
        return httpx.Response(200, json={"status": "done", "description": "ok"})

    _use_mock(monkeypatch, handler)
    result = await _call(
        "abnormal_remediation_manage", {"threatId": "t-1", "messageId": "42", "action": "status", "actionId": "act-1"}
    )
    assert seen == ["/v1/threats/t-1/actions/act-1"]
    assert result["status"] == "done"


async def test_status_maps_401(monkeypatch):
    _use_mock(monkeypatch, lambda r: httpx.Response(401, json={"message": "Unauthorized"}))
    assert (await _call("abnormal_status", {}))["error"]["code"] == "unauthorized"


@pytest.mark.parametrize("case_id", [19377, "19377", " 19377 "])
async def test_cases_get_accepts_number_or_string(monkeypatch, case_id):
    paths = []

    def handler(request):
        paths.append(request.url.path)
        return httpx.Response(200, json={"caseId": "19377"})

    _use_mock(monkeypatch, handler)
    result = await _call("abnormal_cases_get", {"caseId": case_id})
    assert result == {"caseId": "19377"}
    assert paths == ["/v1/cases/19377"]


async def test_cases_get_rejects_blank_id(monkeypatch):
    _use_mock(monkeypatch, lambda r: pytest.fail("API must not be called"))
    result = await _call("abnormal_cases_get", {"caseId": "  "})
    assert result["error"]["code"] == "invalid_argument"
