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
"""Credential middleware: 401 on missing token, per-request isolation."""

import asyncio

import pytest
from starlette.testclient import TestClient

from abnormal_mcp.__main__ import build_http_app
from abnormal_mcp.server import (
    GatewayCredentialsMiddleware,
    _credentials_var,
    create_mcp_server,
    get_client_from_context,
)

MCP_HEADERS = {"Accept": "application/json, text/event-stream"}
LIST_TOOLS = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}


def _client() -> TestClient:
    return TestClient(build_http_app(create_mcp_server()))


def test_health_is_local():
    with _client() as client:
        resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


@pytest.mark.parametrize("value", [None, "", "Bearer ", "   "])
def test_missing_token_returns_401(value):
    headers = dict(MCP_HEADERS)
    if value is not None:
        headers["Authorization"] = value
    with _client() as client:
        resp = client.post("/mcp", json=LIST_TOOLS, headers=headers)
    assert resp.status_code == 401
    assert resp.json()["required_headers"] == ["Authorization"]


def test_case_manage_requires_authorization_header():
    call = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {"name": "abnormal_case_manage", "arguments": {"caseId": "1", "action": "acknowledge"}},
    }
    with _client() as client:
        resp = client.post("/mcp", json=call, headers=MCP_HEADERS)
    assert resp.status_code == 401
    assert resp.json()["required_headers"] == ["Authorization"]


def test_unknown_region_still_lists_tools():
    # The admin console refreshes the tool catalog with placeholder header values.
    headers = {"Authorization": "placeholder", "X-Abnormal-Region": "placeholder"}
    with _client() as client:
        resp = client.post("/mcp", json=LIST_TOOLS, headers=MCP_HEADERS | headers)
    assert resp.status_code == 200
    assert "abnormal_threats_list" in resp.text


def test_unknown_region_is_reported_by_tools():
    seen = _run_middleware([(b"authorization", b"tok"), (b"x-abnormal-region", b"apac")])
    assert seen["client"].header_error == "X-Abnormal-Region must be one of: us, eu"
    call = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "abnormal_status", "arguments": {}}}
    headers = MCP_HEADERS | {"Authorization": "Bearer YOUR_API_TOKEN", "X-Abnormal-Region": "apac"}
    with _client() as client:
        resp = client.post("/mcp", json=call, headers=headers)
    assert resp.status_code == 200
    assert '\\"invalid_argument\\"' in resp.text
    assert "X-Abnormal-Region must be one of: us, eu" in resp.text


def test_tools_list_over_http_with_token():
    with _client() as client:
        resp = client.post("/mcp", json=LIST_TOOLS, headers=MCP_HEADERS | {"Authorization": "YOUR_API_TOKEN"})
    assert resp.status_code == 200
    assert "abnormal_threats_list" in resp.text


def _run_middleware(headers: list[tuple[bytes, bytes]]) -> dict:
    seen: dict = {}

    async def app(scope, receive, send):
        seen["credentials"] = _credentials_var.get()
        seen["client"] = get_client_from_context()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(_message):
        return None

    asyncio.run(GatewayCredentialsMiddleware(app)({"type": "http", "path": "/mcp", "headers": headers}, receive, send))
    return seen


@pytest.mark.parametrize("value", [b"Bearer tok-123", b"bearer tok-123", b"tok-123", b"  Bearer   tok-123 "])
def test_token_accepted_with_or_without_bearer_prefix(value):
    seen = _run_middleware([(b"authorization", value)])
    assert seen["credentials"].token == "tok-123"
    assert seen["credentials"].region == "us"
    assert seen["client"].base_url == "https://api.abnormalplatform.com/v1"
    assert _credentials_var.get() is None


def test_eu_region_selects_eu_host():
    seen = _run_middleware([(b"authorization", b"tok"), (b"x-abnormal-region", b"EU")])
    assert seen["client"].base_url == "https://eu.rest.abnormalsecurity.com/v1"


def test_concurrent_requests_do_not_share_credentials():
    observed: list[tuple[str, str]] = []

    async def app(scope, receive, send):
        before = _credentials_var.get().token
        await asyncio.sleep(0.01)
        observed.append((before, _credentials_var.get().token))
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(_message):
        return None

    middleware = GatewayCredentialsMiddleware(app)

    def scope(token: bytes) -> dict:
        return {"type": "http", "path": "/mcp", "headers": [(b"authorization", token)]}

    async def both():
        await asyncio.gather(middleware(scope(b"tenant-a"), receive, send), middleware(scope(b"tenant-b"), receive, send))

    asyncio.run(both())
    assert sorted(observed) == [("tenant-a", "tenant-a"), ("tenant-b", "tenant-b")]


def test_credentials_repr_hides_token():
    seen = _run_middleware([(b"authorization", b"Bearer secret-token")])
    assert "secret-token" not in repr(seen["credentials"])
