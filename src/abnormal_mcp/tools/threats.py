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
"""Threats: campaigns of malicious messages detected by Abnormal."""

from typing import Annotated, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..api_client import AbnormalClient
from ._common import (
    READ_ONLY,
    ClientFactory,
    Offset,
    PageNumber,
    PageSize,
    filter_arg,
    locate,
    paged_result,
    path_id,
    run_tool,
)

ThreatId = Annotated[str, Field(description="Threat ID (UUID) from abnormal_threats_list.")]

AttackType = Literal[
    "Internal-to-Internal Attacks (Email Account Takeover)",
    "Spam",
    "Reconnaissance",
    "Scam",
    "Social Engineering (BEC)",
    "Phishing: Credential",
    "Invoice/Payment Fraud (BEC)",
    "Malware",
    "Extortion",
    "Phishing: Sensitive Data",
    "Other",
]


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def abnormal_threats_list(
        pageSize: PageSize = None,
        pageNumber: PageNumber = None,
        filter: filter_arg("receivedTime or latestTimeRemediated") = None,
        source: Annotated[
            Literal["all", "attacks", "borderline", "spam"] | None,
            Field(description="Detection source (default all)."),
        ] = None,
        sender: Annotated[str | None, Field(description="Sender name or e-mail address.")] = None,
        recipient: Annotated[str | None, Field(description="Recipient name or e-mail address.")] = None,
        subject: Annotated[str | None, Field(description="E-mail subject text.")] = None,
        attackType: AttackType | None = None,
        offset: Offset = None,
    ) -> str:
        """List threat IDs from the Threat Log, newest first.

        Without `filter` only the latest 100 threats are returned and paging is
        ignored (offset then skips into those 100). Use abnormal_threats_get for a threat's messages and details.
        """

        async def action(client: AbnormalClient) -> dict:
            params = {
                "filter": filter,
                "source": source,
                "sender": sender,
                "recipient": recipient,
                "subject": subject,
                "attackType": attackType,
            }
            if not filter:
                return paged_result(await client.get("/threats", params), "threats", 0, offset or 0, paged=False)
            number, size, start = locate(offset, pageNumber, pageSize)
            params |= {"pageSize": size, "pageNumber": number}
            return paged_result(await client.get("/threats", params), "threats", (number - 1) * size, start)

        return await run_tool("abnormal_threats_list", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def abnormal_threats_get(threatId: ThreatId) -> str:
        """Get one threat: recipient count, tenant and its messages (sender, subject, attack type, status).

        At most the first 10 messages are included.
        """

        async def action(client: AbnormalClient) -> dict:
            return await client.get(f"/threats/{path_id(threatId)}")

        return await run_tool("abnormal_threats_get", client_factory, action)
