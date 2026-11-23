"""Claim ``secrets-stay-out-of-transcripts``: secrets used by an agent do not appear in its transcript.

Statement: ``irondome run`` places secrets in the child process's environment,
masks them (and their base64, hex and percent-encoded forms) in everything the
child prints, and never passes a session or grant token to the child. The MCP
server returns names, exit codes and masked output, not secret values.

"The transcript" is everything the agent sees: the command's stdout and
stderr, and every line the MCP server writes.
"""

from __future__ import annotations

import base64
import json
import sys
from urllib.parse import quote

from conftest import PASSWORD
from support.claimkit import add, document, fails, grant, init, ok, session

SECRET = "s3cr3t/value+with=symbols"
FORMS = {
    "plain": SECRET,
    "base64": base64.b64encode(SECRET.encode()).decode(),
    "hex": SECRET.encode().hex(),
    "percent": quote(SECRET, safe=""),
}
CHILD = (
    "import base64, json, os, sys, urllib.parse\n"
    "v = os.environ['TOKEN']\n"
    "print(v); print(base64.b64encode(v.encode()).decode()); print(v.encode().hex())\n"
    "print(urllib.parse.quote(v, safe='')); print(json.dumps({'token': v}))\n"
    "print(v, file=sys.stderr)\n"
    "names = ('IRONDOME_GRANT', 'IRONDOME_SESSION', 'IRONDOME_PASSWORD_FILE')\n"
    "print('bearer tokens:', sorted(n for n in names if n in os.environ))\n"
)


def setup(cli):
    init(cli)
    add(cli, "github", SECRET, "--alias", "GITHUB_TOKEN")


def assert_masked(text: str) -> None:
    leaked = [name for name, form in FORMS.items() if form in text]
    assert leaked == [], f"unmasked forms: {leaked}"
    assert "[irondome:TOKEN]" in text


def test_run_masks_the_secret_and_its_encodings_in_everything_the_child_prints(cli):
    setup(cli)
    token = grant(cli, "GITHUB_TOKEN")["token"]
    ran = ok(cli("run", "--env", "TOKEN=GITHUB_TOKEN", "--", sys.executable, "-c", CHILD,
                 env={"IRONDOME_GRANT": token}))
    assert_masked(ran.stdout)
    assert_masked(ran.stderr)
    assert "bearer tokens: []" in ran.stdout


def test_the_child_never_inherits_a_session_or_grant_token(cli):
    setup(cli)
    session_token = session(cli)
    grant_token = grant(cli, "GITHUB_TOKEN")["token"]
    ran = ok(cli("run", "--env", "TOKEN=GITHUB_TOKEN", "--", sys.executable, "-c", CHILD,
                 env={"IRONDOME_SESSION": session_token, "IRONDOME_GRANT": grant_token,
                      "IRONDOME_PASSWORD_FILE": "/nonexistent"}))
    assert "bearer tokens: []" in ran.stdout
    assert session_token not in ran.stdout + ran.stderr and grant_token not in ran.stdout + ran.stderr


def test_captured_output_in_json_is_masked_too(cli):
    setup(cli)
    token = grant(cli, "GITHUB_TOKEN")["token"]
    report = document(cli("run", "--json", "--env", "TOKEN=GITHUB_TOKEN", "--", sys.executable, "-c", CHILD,
                          env={"IRONDOME_GRANT": token}))
    assert report["exit_code"] == 0
    assert_masked(report["stdout"])
    assert_masked(report["stderr"])


#: Two spaces after it, as a field of an imported file or a pasted value can have; the vault keeps them.
KEPT_WITH_SPACES = "tok3n/kept+with=two-spaces-after  "
TRIMMING_CHILD = (
    "import base64, json, os\n"
    "v = os.environ['TOKEN']\n"
    "t = v.strip()\n"
    "assert t != v, 'the value arrived without its spaces'\n"
    "print('reading the token:', t, 'done'); print(base64.b64encode(t.encode()).decode())\n"
    "print(json.dumps({'token': t}))\n"
)


def test_a_secret_kept_with_white_space_around_it_is_masked_when_it_is_printed_without(cli):
    """Most programs trim what they read, and `$(...)` drops line breaks: what is printed is the value without."""
    init(cli)
    add(cli, "service", KEPT_WITH_SPACES, "--alias", "SERVICE_TOKEN")
    token = grant(cli, "SERVICE_TOKEN")["token"]
    ran = ok(cli("run", "--env", "TOKEN=SERVICE_TOKEN", "--", sys.executable, "-c", TRIMMING_CHILD,
                 env={"IRONDOME_GRANT": token}))
    trimmed = KEPT_WITH_SPACES.strip()
    assert trimmed not in ran.stdout and base64.b64encode(trimmed.encode()).decode() not in ran.stdout
    assert ran.stdout.splitlines() == [
        "reading the token: [irondome:TOKEN] done",
        "[irondome:TOKEN]",
        '{"token": "[irondome:TOKEN]"}',
    ]


def test_the_mcp_server_returns_names_and_masked_output_never_values(cli):
    setup(cli)
    token = grant(cli, "GITHUB_TOKEN", args=("--uses", "5"))["token"]
    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "list_secrets", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "run_with_secrets", "arguments": {
            "command": [sys.executable, "-c", CHILD], "env": {"TOKEN": "GITHUB_TOKEN"}}}},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
         "params": {"name": "reveal_secret", "arguments": {"reference": "GITHUB_TOKEN"}}},
    ]
    served = cli("mcp", stdin="".join(json.dumps(message) + "\n" for message in messages),
                 env={"IRONDOME_GRANT": token})
    assert served.returncode == 0, served.stderr
    lines = [json.loads(line) for line in served.stdout.splitlines()]
    answers = {line["id"]: line for line in lines}
    assert set(answers) == {1, 2, 3, 4}
    everything = served.stdout + served.stderr
    assert [name for name, form in FORMS.items() if form in everything] == []
    listed = answers[2]["result"]["structuredContent"]
    assert [item["name"] for item in listed["secrets"]] == ["GITHUB_TOKEN"]
    ran = answers[3]["result"]["structuredContent"]
    assert ran["exit_code"] == 0 and "[irondome:TOKEN]" in ran["stdout"]
    assert answers[4]["result"].get("isError") is True


# -- the boundary ------------------------------------------------------------------


def test_boundary_a_command_that_transforms_the_secret_on_purpose_defeats_masking(cli):
    setup(cli)
    token = grant(cli, "GITHUB_TOKEN")["token"]
    reverse = "import os; print(os.environ['TOKEN'][::-1])"
    ran = ok(cli("run", "--env", "TOKEN=GITHUB_TOKEN", "--", sys.executable, "-c", reverse,
                 env={"IRONDOME_GRANT": token}))
    assert ran.stdout.strip() == SECRET[::-1]


def test_boundary_a_reveal_grant_or_an_entry_marked_reveal_allows_showing_the_value(cli):
    setup(cli)
    use_only = grant(cli, "GITHUB_TOKEN")["token"]
    fails(cli("get", "GITHUB_TOKEN", env={"IRONDOME_GRANT": use_only}), 5)
    reveal = grant(cli, "GITHUB_TOKEN", args=("--reveal",))["token"]
    assert ok(cli("get", "GITHUB_TOKEN", env={"IRONDOME_GRANT": reveal})).stdout == SECRET
    ok(cli("edit", "github", "--agent", "reveal", "--password-stdin", stdin=PASSWORD + "\n"))
    assert ok(cli("get", "github", "--password-stdin", stdin=PASSWORD + "\n")).stdout == SECRET
