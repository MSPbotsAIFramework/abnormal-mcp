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

<div align="center">

## MSPbots Connector

**The MCP Gateway built for MSPs: visible, controlled, and your data stays where it belongs.**

[**Get started at connect.mspbots.ai →**](https://connect.mspbots.ai)

</div>

---

MSPbots Connector gives your AI clients one MCP URL to reach your entire MSP stack (RMM, PSA, documentation, security, finance), and gives you control over who can call which tool and a record of everything that was called.

**Hosted service: [connect.mspbots.ai](https://connect.mspbots.ai)** · Free to use.

### Why Connector

![MSPbots Connector](https://stgoss.mspbots.ai/files/mcp/mspbots-mcp.png)

| | |
|---|---|
| **Visible** | Every tool call is logged: who, which vendor, when. Usage dashboard, CSV export, SIEM streaming. |
| **Controlled** | Role-based, per-tool allowlist. Deny by default. |
| **Protected** | Credentials encrypted per record. AI clients never see your vendor passwords or tokens. |
| **MSP-native** | Built for the MSP stack only: RMM, PSA, documentation, security, finance. |

### Quick start

1. **Sign up** at [connect.mspbots.ai](https://connect.mspbots.ai).
2. **Connect your vendors.** Pick from 150+ connectors and authorize each one on the vendor's own page, or bring your own API keys. No extra vendor accounts needed.
3. **Set access.** Create roles and decide which tools each role may call. Nothing is allowed until you allow it.
4. **Add your MCP URL to your AI client.** Copy the URL from your Connector dashboard into Claude, ChatGPT, Cursor, VS Code, Gemini, Codex, or any MCP-capable client.
5. **Ask your AI to do real work**, and watch every call appear in the audit log.

### Features

**Unified gateway**
- One MCP URL for all your AI clients
- 150+ connectors across the MSP stack
- Custom MCP servers supported, free
- Authorization happens on each vendor's own page; the AI never sees passwords or tokens
- Bring your own credentials: use the vendor API keys you already have
- Multiple accounts per app; connect once, reuse across AI clients
- Tool search: finds the right action for the task
- One sign-in; vendor credentials are injected behind the scenes and OAuth tokens refresh automatically

**Visibility**
- Audit log for every tool call (who, which vendor, when)
- Usage dashboard: call volume, top vendors, error rate, per-user activity
- Export audit logs to CSV, or stream to Loki, Graylog, or LogScale (SIEM)
- Optional recording of tool arguments and result summaries (off by default, enabled per organization)

**Control**
- Per-role, per-tool allowlist, deny by default
- owner / admin / member roles
- SCIM provisioning with Entra ID, Okta, JumpCloud, and Google Workspace

**Security**
- Credentials encrypted one record at a time (AES-256-GCM, per-record key)
- AI clients authenticate with OAuth 2.1 + PKCE
- Vendor responses are scanned for prompt-injection patterns and returned as structured data. This is one layer of defense, not a guarantee against every attack.
- Static egress IP for customer firewall and API allowlisting

### Pricing

**Free.**

Links: [connect.mspbots.ai](https://connect.mspbots.ai) · [mspbots.ai](https://mspbots.ai)

---

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
| `abnormal_case_manage` | Acknowledge a case, or check the status of a previous action | **caseId**, **action** (`status`, or any action name, e.g. `acknowledge`), actionId |

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
- **Case actions.** `abnormal_case_manage` mirrors `abnormal_remediation_manage`'s shape
  (an `action` string plus a `status` branch), but it is **not** `destructiveHint=true`:
  acknowledging a case does not change mailbox content, unlike threat remediation. The set
  of legal `action` values is not a documented closed enum, so the tool accepts any string
  and lets Abnormal's own API reject an unsupported one (surfaced as `invalid_argument`).

## License

Apache License 2.0 - see [LICENSE](LICENSE) and [NOTICE](NOTICE).
