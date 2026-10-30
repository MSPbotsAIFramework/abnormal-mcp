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
"""Token check and a per-area tool guide."""

from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..api_client import AbnormalClient
from ._common import READ_ONLY, ClientFactory, run_tool

DOMAIN_TOOLS: dict[str, dict[str, str]] = {
    "threats": {
        "abnormal_threats_list": "List threat IDs, filtered by time, sender, recipient, subject or attack type.",
        "abnormal_threats_get": "One threat with its messages.",
    },
    "messages": {
        "abnormal_messages_list": "Messages in one threat (summary view).",
        "abnormal_messages_get": "Full record of one message.",
    },
    "remediation": {
        "abnormal_remediation_manage": "Remediation status, or remediate/unremediate a threat (changes mailboxes).",
    },
    "abuse": {
        "abnormal_abuse_list": "Campaigns reported by employees to the AI Security Mailbox.",
    },
    "cases": {
        "abnormal_cases_list": "Account-takeover cases.",
        "abnormal_cases_get": "One case with analysis and related threats.",
        "abnormal_case_manage": "Acknowledge, or check the status of an action on, an account-takeover case.",
    },
}


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def abnormal_navigate(
        domain: Annotated[
            Literal["threats", "messages", "remediation", "abuse", "cases"],
            Field(description="Area to show tools for."),
        ],
    ) -> str:
        """Show which tools cover one area: threats, messages, remediation, abuse or cases.

        All tools are always available; this is only a guide. Makes no API call.
        """

        async def action(_client: AbnormalClient) -> dict:
            return {"domain": domain, "tools": DOMAIN_TOOLS[domain]}

        return await run_tool("abnormal_navigate", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def abnormal_status() -> str:
        """Check that the Abnormal API token is valid and the API is reachable.

        Use it to diagnose unauthorized errors from other tools. Note Abnormal
        also rejects calls from IP addresses not on the account's allowlist.
        """

        async def action(client: AbnormalClient) -> dict:
            since = (datetime.now(UTC) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
            await client.get("/threats", {"filter": f"receivedTime gte {since}", "pageSize": 1})
            return {"authenticated": True, "region": client.region, "api_base_url": client.base_url}

        return await run_tool("abnormal_status", client_factory, action)
