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
"""Remediation: remove or restore a threat's messages in users' mailboxes."""

from typing import Annotated, Any, Literal

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from ..api_client import AbnormalClient
from ._common import ClientFactory, path_id, run_tool


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(
        annotations=ToolAnnotations(
            readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True
        )
    )
    async def abnormal_remediation_manage(
        threatId: Annotated[str, Field(description="Threat ID (UUID).")],
        messageId: Annotated[str, Field(description="Abnormal message ID (abxMessageId) in that threat.")],
        action: Annotated[
            Literal["remediate", "unremediate", "status"],
            Field(description="status = read only; remediate / unremediate change mailboxes."),
        ],
        actionId: Annotated[
            str | None,
            Field(description="With action=status: an action ID returned by remediate/unremediate."),
        ] = None,
    ) -> str:
        """Check, or trigger, removal of a threat's messages from users' mailboxes.

        status: the message's remediation history (or an action's progress when
        actionId is given). remediate / unremediate act on the WHOLE threat
        campaign; only use them when the user explicitly asks.
        """

        async def run(client: AbnormalClient) -> Any:
            if action == "status":
                if actionId:
                    return await client.get(
                        f"/threats/{path_id(threatId)}/actions/{path_id(actionId)}"
                    )
                history = await client.get(f"/messages/{path_id(messageId)}/remediation_history")
                return {"threatId": threatId, "messageId": messageId, **(history or {})}
            result = await client.post(f"/threats/{path_id(threatId)}", body={"action": action})
            return {"threatId": threatId, "action": action, **(result or {})}

        return await run_tool("abnormal_remediation_manage", client_factory, run)
