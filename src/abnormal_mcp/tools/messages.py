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
"""Messages that make up a threat."""

from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..api_client import AbnormalClient, AbnormalError
from ._common import READ_ONLY, ClientFactory, path_id, run_tool

ThreatId = Annotated[str, Field(description="Threat ID (UUID) the message belongs to.")]
MessageId = Annotated[
    str, Field(description="Abnormal message ID (abxMessageId) from abnormal_messages_list.")
]

# Fields kept in the list view; abnormal_messages_get returns everything.
_SUMMARY_FIELDS = (
    "abxMessageIdStr",
    "abxMessageId",
    "subject",
    "fromAddress",
    "fromName",
    "recipientAddress",
    "receivedTime",
    "attackType",
    "attackStrategy",
    "attackVector",
    "impersonatedParty",
    "remediationStatus",
    "autoRemediated",
    "isRead",
    "abxPortalUrl",
)


def summarize(message: Any) -> Any:
    if not isinstance(message, dict):
        return message
    return {k: message[k] for k in _SUMMARY_FIELDS if message.get(k) is not None}


def _message_id(message: dict) -> str:
    return str(message.get("abxMessageIdStr") or message.get("abxMessageId") or "")


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def abnormal_messages_list(threatId: ThreatId) -> str:
        """List the messages in one threat: sender, recipient, subject, attack type, remediation status.

        Abnormal returns at most 10 messages per threat here.
        """

        async def action(client: AbnormalClient) -> dict:
            threat = await client.get(f"/threats/{path_id(threatId)}") or {}
            messages = [summarize(m) for m in threat.get("messages") or []]
            return {
                "threatId": threat.get("threatId", threatId),
                "recipientCount": threat.get("recipientCount"),
                "items": messages,
                "count": len(messages),
            }

        return await run_tool("abnormal_messages_list", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def abnormal_messages_get(threatId: ThreatId, messageId: MessageId) -> str:
        """Get the full record of one message: headers, sender IP, URLs, attachments, insights, remediation."""

        async def action(client: AbnormalClient) -> Any:
            try:
                return await client.get(f"/threats/messages/{path_id(messageId)}")
            except AbnormalError as e:
                if e.status_code != 404:
                    raise
            # Fall back to the threat's own message list.
            threat = await client.get(f"/threats/{path_id(threatId)}") or {}
            for message in threat.get("messages") or []:
                if isinstance(message, dict) and _message_id(message) == str(messageId).strip():
                    return message
            raise AbnormalError(404, f"Message {messageId} not found in threat {threatId}")

        return await run_tool("abnormal_messages_get", client_factory, action)
