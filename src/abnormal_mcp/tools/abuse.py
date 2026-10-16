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
"""AI Security Mailbox (formerly Abuse Mailbox): campaigns reported by employees."""

from typing import Annotated, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..api_client import AbnormalClient
from ._common import (
    READ_ONLY,
    ClientFactory,
    PageNumber,
    PageSize,
    filter_arg,
    page_params,
    paged_result,
    run_tool,
)


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def abnormal_abuse_list(
        pageSize: PageSize = None,
        pageNumber: PageNumber = None,
        filter: filter_arg("lastReportedTime (default: last 24h) or receivedTime") = None,
        threatType: Annotated[
            Literal["All", "Malicious", "Safe", "Spam"] | None, Field(description="Verdict filter.")
        ] = None,
        reporter: Annotated[str | None, Field(description="Reporter name or e-mail address.")] = None,
        sender: Annotated[str | None, Field(description="Sender name or e-mail address.")] = None,
        recipient: Annotated[str | None, Field(description="Recipient name or e-mail address.")] = None,
        subject: Annotated[str | None, Field(description="E-mail subject text.")] = None,
    ) -> str:
        """List campaigns employees reported to the AI Security Mailbox (formerly Abuse Mailbox).

        Defaults to the last 24 hours. Each item has the campaign ID and verdict.
        """

        async def action(client: AbnormalClient) -> dict:
            params = page_params(pageSize, pageNumber) | {
                "filter": filter,
                "threatType": threatType,
                "reporter": reporter,
                "sender": sender,
                "recipient": recipient,
                "subject": subject,
            }
            return paged_result(await client.get("/abusecampaigns", params), "campaigns")

        return await run_tool("abnormal_abuse_list", client_factory, action)
