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
"""FastMCP factory and the per-request credential middleware."""

import contextvars
import uuid
from collections.abc import Callable

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from ._arguments import EnvelopeFastMCP
from .api_client import AbnormalClient, AbnormalCredentials
from .config import DEFAULT_REGION, REGION_BASE_URLS, Settings

# The header name is kept as registered on the gateway; changing it would
# break existing tenant connections.
HEADER_TOKEN = "Authorization"
HEADER_REGION = "X-Abnormal-Region"
REQUIRED_HEADERS = [HEADER_TOKEN]
OPTIONAL_HEADERS = [HEADER_REGION]

# Per-request isolation: the middleware sets these for the duration of one
# HTTP request and resets them in `finally`. Nothing credential-related is
# ever stored at module level.
_credentials_var: contextvars.ContextVar[AbnormalCredentials | None] = contextvars.ContextVar(
    "abnormal_credentials", default=None
)
request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "abnormal_request_id", default="-"
)

INSTRUCTIONS = (
    "Abnormal Security is an AI email-security platform that detects phishing, "
    "business email compromise (BEC), account takeover and other email attacks "
    "in Microsoft 365 / Google Workspace. A threat is a campaign of one or more "
    "malicious messages; a case is an account-takeover investigation; the AI "
    "Security Mailbox (formerly Abuse Mailbox) holds campaigns reported by "
    "employees.\n"
    "Typical flows:\n"
    "- Recent attacks: abnormal_threats_list with filter "
    "'receivedTime gte 2026-01-01T00:00:00Z' -> abnormal_threats_get for details.\n"
    "- Messages of a threat: abnormal_messages_list(threatId) -> "
    "abnormal_messages_get(threatId, messageId).\n"
    "- Clean up: abnormal_remediation_manage(action='status') first; "
    "'remediate' or 'unremediate' only when the user asks (it acts on the "
    "whole threat campaign in users' mailboxes).\n"
    "- User-reported email: abnormal_abuse_list.\n"
    "- Account takeover: abnormal_cases_list -> abnormal_cases_get -> "
    "abnormal_case_manage to acknowledge a case or check an action's status "
    "(needs the Account Takeover license).\n"
    "Lists return {items, has_more, next_page}; pagination only works when a "
    "filter is given. abnormal_status checks the token; abnormal_navigate lists "
    "the tools of one area."
)


def get_client_from_context() -> AbnormalClient | None:
    """The Abnormal client for the current request, or None outside a request."""
    credentials = _credentials_var.get()
    if credentials is None:
        return None
    return AbnormalClient(credentials)


def _token_from_header(value: str | None) -> str:
    """Accept the token with or without a leading 'Bearer ' prefix."""
    parts = (value or "").split()
    if parts and parts[0].lower() == "bearer":
        parts = parts[1:]
    return " ".join(parts)


class GatewayCredentialsMiddleware:
    """Reads the Abnormal token from the Authorization header on /mcp requests.

    Missing token -> 401 listing the required header. An unknown region does not
    block the request (tools/list must work with any values); tools report it instead.
    """

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not scope.get("path", "").startswith("/mcp"):
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        token = _token_from_header(request.headers.get(HEADER_TOKEN))
        region = (request.headers.get(HEADER_REGION) or "").strip().lower() or DEFAULT_REGION

        if not token:
            await JSONResponse(
                {
                    "error": "Missing credentials",
                    "message": "Required header missing: Authorization (Abnormal API token)",
                    "required_headers": REQUIRED_HEADERS,
                    "optional_headers": OPTIONAL_HEADERS,
                },
                status_code=401,
            )(scope, receive, send)
            return

        header_error = None
        if region not in REGION_BASE_URLS:
            header_error = f"{HEADER_REGION} must be one of: {', '.join(REGION_BASE_URLS)}"
            region = DEFAULT_REGION

        request_id = (request.headers.get("x-request-id") or "").strip()[:64] or uuid.uuid4().hex[:12]
        creds_token = _credentials_var.set(AbnormalCredentials(token, region, header_error))
        rid_token = request_id_var.set(request_id)
        try:
            await self.app(scope, receive, send)
        finally:
            _credentials_var.reset(creds_token)
            request_id_var.reset(rid_token)


def create_mcp_server(settings: Settings | None = None) -> FastMCP:
    """Build the FastMCP server and register every Abnormal tool."""
    mcp = EnvelopeFastMCP(
        name="abnormal-mcp",
        instructions=INSTRUCTIONS,
        # The service sits behind the gateway, so Host is never localhost;
        # DNS-rebinding protection would reject those requests with 421.
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
        stateless_http=True,
    )

    client_factory: Callable[[], AbnormalClient | None] = get_client_from_context

    from .tools import abuse, cases, messages, navigation, remediation, threats

    for module in (navigation, threats, messages, remediation, abuse, cases):
        module.register(mcp, client_factory)

    return mcp
