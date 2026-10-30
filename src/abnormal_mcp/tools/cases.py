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
"""Cases: account-takeover investigations (Account Takeover license)."""

from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
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


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def abnormal_cases_list(
        pageSize: PageSize = None,
        pageNumber: PageNumber = None,
        filter: filter_arg("lastModifiedTime") = None,
        offset: Offset = None,
    ) -> str:
        """List account-takeover cases (case ID, severity, affected employee).

        Needs the Account Takeover license. Without `filter` only the latest
        100 cases are returned.
        """

        async def action(client: AbnormalClient) -> dict:
            params = {"filter": filter}
            if not filter:
                return paged_result(await client.get("/cases", params), "cases", 0, offset or 0, paged=False)
            number, size, start = locate(offset, pageNumber, pageSize)
            params |= {"pageSize": size, "pageNumber": number}
            return paged_result(await client.get("/cases", params), "cases", (number - 1) * size, start)

        return await run_tool("abnormal_cases_list", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def abnormal_cases_get(
        caseId: Annotated[int | str, Field(description="Case ID from abnormal_cases_list (number or string).")],
    ) -> str:
        """Get one case: status, severity, affected employee, related threat IDs and analysis."""

        async def action(client: AbnormalClient) -> dict:
            case_id = str(caseId).strip()
            if not case_id:
                raise ValueError("caseId must not be blank")
            return await client.get(f"/cases/{path_id(case_id)}")

        return await run_tool("abnormal_cases_get", client_factory, action)

    @mcp.tool(
        annotations=ToolAnnotations(
            readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True
        )
    )
    async def abnormal_case_manage(
        caseId: Annotated[int | str, Field(description="Case ID from abnormal_cases_list (number or string).")],
        action: Annotated[
            str,
            Field(description="status = read only; any other value (e.g. 'acknowledge') submits that action."),
        ],
        actionId: Annotated[
            str | None,
            Field(description="With action=status: an action ID returned by a previous action."),
        ] = None,
    ) -> str:
        """Acknowledge, or check the status of, an action on an account-takeover case.

        status requires actionId and reads that action's progress. Any other
        action (e.g. acknowledge) submits it and returns its actionId.
        Submitting the same action twice is Abnormal's own concern, not this
        server's.
        """

        async def run(client: AbnormalClient) -> Any:
            case_id = path_id(caseId)
            if action == "status":
                if not actionId:
                    raise ValueError("actionId is required when action='status'")
                return await client.get(f"/cases/{case_id}/actions/{path_id(actionId)}")
            result = await client.post(f"/cases/{case_id}/actions", body={"action": action})
            return {"caseId": caseId, "action": action, **(result or {})}

        return await run_tool("abnormal_case_manage", client_factory, run)
