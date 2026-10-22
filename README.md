# Abnormal Security MCP Server

An [MCP](https://modelcontextprotocol.io) server for the [Abnormal Security](https://abnormalsecurity.com)
REST API. It lets an AI agent review e-mail threats detected by Abnormal (phishing, BEC, account
takeover), read the messages behind them, check or trigger remediation, and look at
employee-reported campaigns and account-takeover cases.

- Transport: MCP Streamable HTTP at `POST /mcp`, health probe at `GET /health`
- Stateless and multi-tenant: the API token arrives on every request as an HTTP header and is
  never stored
- Python 3.12, [uv](https://docs.astral.sh/uv/), FastMCP, httpx
- License: Apache-2.0, Copyright 2026 MSPbots.ai

## Authentication headers

| Header | Required | Type | Default | Allowed values | Description | Example |
|---|---|---|---|---|---|---|
| `Authorization` | Yes | string | none | - | Abnormal REST API token, with or without a leading `Bearer ` | `Bearer YOUR_API_TOKEN` |
| `X-Abnormal-Region` | No | string | `us` | `us`, `eu` | Data region: `us` uses `api.abnormalplatform.com`, `eu` uses `eu.rest.abnormalsecurity.com` | `eu` |

Where to get them:

- **API token**: in the Abnormal portal, open **Settings -> Integrations -> Abnormal REST API**
  and generate a token.
- **IP allowlist**: Abnormal only accepts API calls from allowlisted IP addresses. Add the
  public egress IP of the environment that runs this server on the same Integrations page;
  calls from other addresses fail with `unauthorized`.
- **Licenses**: the case tools need Abnormal's Account Takeover license.

A request to `/mcp` without a token gets HTTP 401 listing the required header. An unknown region
does not block `tools/list`; tools then return an `invalid_argument` error naming the allowed
regions.

## Tools

All tools return a JSON string. List tools return `{items, count, page, has_more, next_page}`
plus `offset` / `next_offset`.
Abnormal only pages when a time `filter` is given (`<key> gte <time> lte <time>`, times like
`2026-01-31T00:00:00Z`); without one the threat and case lists return the latest 100 IDs.
A page cut to fit the 20,000-character response limit has its rest on no other page number, so
the list tools also take `offset` (record position, overriding `pageNumber`); pass back
`next_offset`, which starts right after the last record returned, to read every record once.

| Tool | Purpose | Parameters (required in **bold**) |
|---|---|---|
| `abnormal_navigate` | Show the tools of one area | **domain** (`threats`, `messages`, `remediation`, `abuse`, `cases`) |
| `abnormal_status` | Check that the token works | - |
| `abnormal_threats_list` | List threat IDs from the Threat Log | pageSize, pageNumber, filter (`receivedTime` / `latestTimeRemediated`), source, sender, recipient, subject, attackType, offset |
| `abnormal_threats_get` | One threat with its messages | **threatId** |
| `abnormal_messages_list` | Messages of one threat (summary) | **threatId** |
| `abnormal_messages_get` | Full record of one message | **threatId**, **messageId** |
| `abnormal_remediation_manage` | Remediation status, or remediate / unremediate (**changes mailboxes**) | **threatId**, **messageId**, **action** (`status`, `remediate`, `unremediate`), actionId |
| `abnormal_abuse_list` | Campaigns reported to the AI Security Mailbox | pageSize, pageNumber, filter (`lastReportedTime` / `receivedTime`), threatType, reporter, sender, recipient, subject, offset |
| `abnormal_cases_list` | Account-takeover cases | pageSize, pageNumber, filter (`lastModifiedTime`), offset |
| `abnormal_cases_get` | One case | **caseId** |

`pageSize` defaults to 50 (Abnormal's maximum is 100).

Errors come back as a JSON envelope instead of an exception:

```json
{"error": {"code": "unauthorized", "message": "Abnormal returned HTTP 401: ...", "retryable": false}}
```

`code` is one of `not_configured`, `unauthorized`, `not_found`, `invalid_argument`,
`rate_limited`, `upstream_error`.

## Run locally

```bash
uv sync
uv run python -m abnormal_mcp          # listens on 0.0.0.0:8080
```

or with Docker:

```bash
docker build --platform linux/amd64 -t abnormal-mcp:dev .
docker run --rm -p 8080:8080 abnormal-mcp:dev
```

Configuration (environment variables, all optional): `MCP_HTTP_HOST` (default `0.0.0.0`),
`MCP_HTTP_PORT` (default `8080`), `LOG_LEVEL` (default `INFO`). The token is never read from the
environment.

## Testing example

```bash
# list tools
curl -s http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'

# threats received since a date
curl -s http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"abnormal_threats_list","arguments":{"filter":"receivedTime gte 2026-01-01T00:00:00Z","pageSize":10}}}'
```

Unit tests (no network access needed):

```bash
uv run pytest
```

## Delivery notes

- **Header name.** The token header is `Authorization` rather than an `X-Abnormal-*` name
  because existing gateway registrations and tenant connections already use it.
  `X-Abnormal-Region` is a new optional header; without it the US host is used, as before.
- **Write tool.** `abnormal_remediation_manage` with `remediate` / `unremediate` changes users'
  mailboxes. Abnormal applies these actions to the whole threat campaign, so the description
  tells the agent to use them only on explicit request; it is annotated `destructiveHint=true`.
  `messageId` is used for the `status` action (remediation history of that message).
- **Message limits.** Abnormal returns at most 10 messages per threat on the threat-detail
  endpoint, which `abnormal_threats_get` and `abnormal_messages_list` use.

## License

Apache License 2.0 - see [LICENSE](LICENSE) and [NOTICE](NOTICE).
