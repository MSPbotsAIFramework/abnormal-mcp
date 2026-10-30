# PRD-21219 · Code review

## Round 1 · 2026-10-30 · reviewed dev/PRD-21219 @ d8111a1 (base main @ c636ead)

Status: frozen @ d8111a1

Verdict: approved

### Findings

1. [suggestion] src/abnormal_mcp/tools/cases.py:100 — `abnormal_case_manage` does not reject a blank `caseId` the way its sibling `abnormal_cases_get` does (cases.py:68-70, `raise ValueError("caseId must not be blank")`). A blank `caseId` here falls through to `path_id("")` → `GET/POST /cases//actions...`, which Abnormal will presumably 404 and `run_tool` turns into a structured `not_found` envelope either way (api_client.py:72, `classify_status`), so no exception escapes and no AC regresses — just an inconsistent validation path between the two tools in the same file. Not blocking; would be a one-line follow-up if touched again.
2. [suggestion] src/abnormal_mcp/tools/cases.py:80-89 — same observation for a blank `action` string: there is no equivalent guard, and it is submitted to Abnormal verbatim (`client.post(..., body={"action": action})`). This is consistent with the tech design's explicit choice (`docs/tickets/PRD-21219.md` § Tech design / Open questions: accept a free-form `action` and let Abnormal's own API reject an unsupported value), so it is intentional, not an oversight — listing it only because an empty string is a slightly different case than "unsupported value" and nothing currently tests it.

### Verification performed

- `uv run pytest` on `d8111a1` (synced with `main @ c636ead`, no further sync needed — `git merge-base --is-ancestor c636ead d8111a1` holds and `origin/main` is still at `c636ead`): 149 passed, 0 failed — matches the `[DEV]` stub's reported baseline 140 + 9 new, 0 regressions.
- `grep -rnP '[\x{4e00}-\x{9fff}]' --exclude-dir=.git --exclude-dir=.venv src/ tests/ README.md`: no hits.
- `README.md` "MSPbots Connector" section (lines 14-84) diffed byte-for-byte against `~/.claude/skills/vendor-mcp-development/reference/readme-connector-section.md`: identical (this diff doesn't touch that section anyway).
- Diff scope confirmed as additive-only: `src/abnormal_mcp/tools/threats.py`, `messages.py`, `remediation.py`, `abuse.py`, `_common.py`, `api_client.py` are untouched by `git diff c636ead...d8111a1` — AC6 (no regression to the other domains) holds by inspection, not just by the regression test count.
- New tool reuses `run_tool`, `path_id`, `ClientFactory`, `AbnormalClient.get`/`.post` exactly as the tech design specified — no new HTTP, retry, or auth code; no new dependency (`pyproject.toml` untouched).
- Credentials: `abnormal_case_manage` reads no header directly and takes no new credential — same per-request `AbnormalClient` built from the caller's own token as every other tool (server.py `GatewayCredentialsMiddleware`, unchanged by this diff).
- Error mapping: `AbnormalError.to_envelope()` + `classify_status()` (api_client.py:65-95) already map HTTP 404 → `not_found`; verified against `tests/test_api_client.py::test_case_manage_unknown_case_returns_not_found_envelope`.
- `abnormal_navigate(domain="cases")` coverage: `tests/test_tools.py::test_navigate_covers_every_tool` is a pre-existing parametrized test that now also exercises the new tool via `navigation.py`'s `DOMAIN_TOOLS["cases"]` entry (navigation.py:43) — confirmed it isn't a stub by reading the test body, not just the stub's claim.
- TC7 (manual, needs a real Abnormal tenant with Account Takeover license): correctly left `blocked`/non-blocking per `mcp-track.md` §2.5/§3 — no test was weakened or marked `pass` without evidence to work around the missing account.

No must-fix. The implementation mirrors `abnormal_remediation_manage` exactly as the tech design specified, reuses all shared infrastructure, introduces no new dependency, touches no file outside the `cases` domain + its own registration/docs/tests, and the test suite covers every AC except the one explicitly and correctly marked as a non-blocking manual gap.
