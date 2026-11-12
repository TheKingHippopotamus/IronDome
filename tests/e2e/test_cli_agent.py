"""The agent story, end to end, through the real command line.

Every test runs ``python -m irondome`` in a subprocess (the ``cli`` fixture, or the Touch ID runner
below) inside the isolated directories of tests/conftest.py and without a terminal: exactly the
position of an AI agent or a script. The owner's side gives the master password with
``--password-stdin``. The vault itself is filled in this process through the library, so what is
under test is the agent commands and not the commands that fill a vault.

Touch ID: the approval tests run the command line on a stand-in chip with a fingerprint sensor
(``FileTouch`` below). It keeps its keys and a log of every prompt in a JSON file, so the test and
the command share one chip; the test decides whether the finger is presented and reads back each
prompt that was shown.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import re
import select
import shlex
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from conftest import PASSWORD, secret
from irondome import caps, keys, otp, paths
from irondome.agent.runner import secret_patterns
from irondome.cli import context
from irondome.cli.main import main
from irondome.device.base import POLICY_BIOMETRY
from irondome.unlock import open_vault
from irondome.vault import Secret, Vault

GITHUB_PASSWORD = "ghp_Example0123456789TokenValue"
STRIPE_KEY = "sk_test_51HypotheticalKey0042"
BANK_PASSWORD = "Bank-Password-42!"
DB_URL = "postgres://app:s3cret-Pass@db.internal:5432/prod"
SEED = "JBSWY3DPEHPK3PXP"
ALL_SECRETS = (GITHUB_PASSWORD, STRIPE_KEY, BANK_PASSWORD, DB_URL, SEED)
TOKEN = re.compile(caps.TOKEN_PATTERN)
SUPPORT = Path(__file__).resolve().parent.parent / "support"

Done = subprocess.CompletedProcess
Cli = Callable[..., Done]


# ---------------------------------------------------------------------------
# The vault, and how each side talks to it
# ---------------------------------------------------------------------------


@pytest.fixture
def vault_ready(make_vault: Callable[..., Any]) -> None:
    """A vault with an entry of each kind an agent meets: allowed, revealable, forbidden, a field, too short."""
    vault, _ = make_vault()
    github = vault.add(
        "github", Secret(password=GITHUB_PASSWORD, totp=otp.make_totp(SEED)), username="king", agent="use"
    )
    stripe = vault.add("stripe", Secret(password=STRIPE_KEY), kind="secret", agent="reveal")
    vault.add("bank", Secret(password=BANK_PASSWORD, fields={"pin": "4321"}))
    database = vault.add("prod-db", Secret(password="db-owner-password", fields={"dsn": DB_URL}), agent="use")
    vault.add("tiny", Secret(password="abc"))
    vault.set_alias("GITHUB_TOKEN", github, "password")
    vault.set_alias("STRIPE_KEY", stripe, "password")
    vault.set_alias("DB_URL", database, "dsn")
    vault.commit()
    vault.close()


@contextlib.contextmanager
def opened() -> Iterator[Vault]:
    """The vault, unlocked in this process with the master password."""
    password = secret()
    try:
        vault = open_vault(password=password)
    finally:
        password.wipe()
    with vault:
        yield vault


def as_owner(cli: Cli, *arguments: str, env: Optional[Dict[str, str]] = None) -> Done:
    """The owner: the master password on the first line of stdin, flag given before the command."""
    return cli("--password-stdin", *arguments, stdin=PASSWORD + "\n", env=env)


def as_agent(cli: Cli, token: str, *arguments: str, env: Optional[Dict[str, str]] = None) -> Done:
    """An agent: no terminal, no password, a grant token in its environment and nothing else."""
    merged = {"IRONDOME_GRANT": token}
    merged.update(env or {})
    return cli(*arguments, env=merged)


def grant(cli: Cli, *arguments: str) -> str:
    done = as_owner(cli, "grant", "create", *arguments)
    assert done.returncode == 0, done.stderr
    assert TOKEN.fullmatch(done.stdout), done.stdout
    return done.stdout


def grant_id(token: str) -> str:
    return token.split("_")[2]


def grant_file(token: str) -> Path:
    return paths.caps_dir() / f"{grant_id(token)}.json"


def python(code: str, *arguments: str) -> List[str]:
    """A child program: this interpreter, isolated, quick to start."""
    return [sys.executable, "-I", "-S", "-c", textwrap.dedent(code), *arguments]


REPORT = """
    import base64, hashlib, json, os, sys
    value = os.environ.get(sys.argv[1], "")
    print("plain:", value)
    print("base64:", base64.b64encode(value.encode()).decode())
    print("hex:", value.encode().hex())
    print("stderr:", value, file=sys.stderr)
    control = [name for name in ("IRONDOME_GRANT", "IRONDOME_SESSION", "IRONDOME_PASSWORD_FILE") if name in os.environ]
    print("report:", json.dumps({"sha256": hashlib.sha256(value.encode()).hexdigest(), "control": control}))
"""


def report(done: Done) -> Dict[str, Any]:
    line = next(line for line in done.stdout.splitlines() if line.startswith("report: "))
    return json.loads(line[len("report: ") :])


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def leaked(value: str, *texts: str) -> List[str]:
    """The encodings of *value* that appear anywhere in *texts*."""
    joined = "".join(texts).encode("utf-8")
    return [label for label, pattern in secret_patterns(value) if pattern in joined]


def nothing_leaked(*texts: str) -> None:
    for value in ALL_SECRETS:
        assert leaked(value, *texts) == [], value


def audit_events(cli: Cli) -> List[Dict[str, Any]]:
    done = as_owner(cli, "--json", "audit", "-n", "0")
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)["events"]


def child_environment(*overrides: Optional[Dict[str, str]]) -> Dict[str, str]:
    """What the ``cli`` fixture gives its subprocess, for the runners that cannot use it."""
    merged = dict(os.environ)
    if SUPPORT.is_dir():
        merged["PYTHONPATH"] = os.pathsep.join(filter(None, [str(SUPPORT), merged.get("PYTHONPATH", "")]))
        merged["IRONDOME_TEST_BLOCK_SOCKETS"] = "1"
    for extra in overrides:
        merged.update(extra or {})
    return merged


def grant_plaintext(token: str) -> bytes:
    """Decrypt a grant file with `cryptography` alone, from the format irondome.caps documents."""
    _, _, cap_id, encoded = token.split("_")
    document = json.loads(grant_file(token).read_bytes())
    vault_id = base64.b64decode(document["vault_id"])
    descriptor = document["device"]
    assert descriptor["backend"] == "software"
    device_secret = (paths.device_dir() / f"{descriptor['ref']}.key").read_bytes()
    device_key = HKDF(hashes.SHA256(), 32, vault_id, b"irondome/v4/cap/device").derive(device_secret)
    key = HKDF(hashes.SHA256(), 32, base64.b64decode(document["salt"]), b"irondome/v4/cap/grant/token+device").derive(
        base64.b32decode(encoded + "====") + device_key
    )
    uses = document["uses_left"]
    device = json.dumps(descriptor, sort_keys=True, separators=(",", ":")).encode("ascii")
    aad = b"".join(
        [
            b"irondome/v4/cap\x00\x02grant\x00",
            bytes.fromhex(cap_id),
            vault_id,
            document["created"].to_bytes(8, "big"),
            document["expires"].to_bytes(8, "big"),
            b"\x00" if uses is None else b"\x01" + uses.to_bytes(8, "big"),
            len(device).to_bytes(2, "big"),
            device,
            document["label"].encode("utf-8"),
        ]
    )
    wrap = base64.b64decode(document["wrap"])
    padded = AESGCM(key).decrypt(wrap[:12], wrap[12:], aad)
    return padded[4 : 4 + int.from_bytes(padded[:4], "big")]


# ---------------------------------------------------------------------------
# A grant, used by a process that has nothing else
# ---------------------------------------------------------------------------


def test_a_grant_lets_a_process_with_only_the_token_run_a_child_that_gets_the_secret_masked(
    cli: Cli, vault_ready: None
) -> None:
    token = grant(cli, "GITHUB_TOKEN")
    session = as_owner(cli, "unlock", "--print-token").stdout
    environment = {"IRONDOME_GRANT": token, "IRONDOME_SESSION": session}

    done = cli("run", "--env", "GITHUB_TOKEN", "--", *python(REPORT, "GITHUB_TOKEN"), env=environment)

    assert done.returncode == 0, done.stderr
    assert report(done) == {"sha256": digest(GITHUB_PASSWORD), "control": []}
    for line in ("plain: [irondome:GITHUB_TOKEN]", "base64: [irondome:GITHUB_TOKEN]", "hex: [irondome:GITHUB_TOKEN]"):
        assert line in done.stdout.splitlines()
    assert "stderr: [irondome:GITHUB_TOKEN]" in done.stderr.splitlines()
    nothing_leaked(done.stdout, done.stderr)

    again = cli("run", "--env", "GITHUB_TOKEN", "--", *python(REPORT, "GITHUB_TOKEN"), env={"IRONDOME_GRANT": token})

    assert again.returncode == 4
    assert "used up" in again.stderr
    assert "report:" not in again.stdout
    assert not grant_file(token).exists()


def test_a_use_grant_cannot_print_its_value_and_a_reveal_grant_can(cli: Cli, vault_ready: None) -> None:
    use_only = grant(cli, "GITHUB_TOKEN", "--uses", "2")
    reveal = grant(cli, "GITHUB_TOKEN", "--reveal")

    refused = as_agent(cli, use_only, "get", "GITHUB_TOKEN")
    shown = as_agent(cli, reveal, "get", "GITHUB_TOKEN")

    assert refused.returncode == 5
    nothing_leaked(refused.stdout, refused.stderr)
    assert shown.returncode == 0, shown.stderr
    assert shown.stdout == GITHUB_PASSWORD


def test_a_grant_reaches_nothing_it_does_not_name_and_spends_nothing_trying(cli: Cli, vault_ready: None) -> None:
    token = grant(cli, "GITHUB_TOKEN")
    another = grant(cli, "GITHUB_TOKEN")

    by_run = as_agent(cli, token, "run", "--env", "BANK=bank", "--", *python(REPORT, "BANK"))
    by_get = as_agent(cli, another, "get", "bank")
    inside = as_agent(cli, token, "run", "--env", "GITHUB_TOKEN", "--", *python(REPORT, "GITHUB_TOKEN"))

    assert by_run.returncode == 5
    assert "does not cover 'bank'" in by_run.stderr and "Nothing was used" in by_run.stderr
    assert "report:" not in by_run.stdout
    assert by_get.returncode == 5
    nothing_leaked(by_run.stdout, by_run.stderr, by_get.stdout, by_get.stderr)
    assert inside.returncode == 0, inside.stderr  # the refused request did not use up the single-use grant
    assert report(inside)["sha256"] == digest(GITHUB_PASSWORD)
    refusals = [event for event in audit_events(cli) if event["kid"] == grant_id(token) and not event["ok"]]
    assert [(event["action"], event["actor"], event["target"]) for event in refusals] == [("use", "grant", "bank")]


def test_an_expired_grant_is_dead_and_its_file_is_destroyed(
    cli: Cli, vault_ready: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    with opened() as vault, monkeypatch.context() as clock:
        clock.setattr(caps, "_now", lambda: int(time.time()) - 3600)
        token, _ = caps.create_grant(vault, ["GITHUB_TOKEN"], ttl=60)
    assert grant_file(token).exists()

    done = as_agent(cli, token, "run", "--env", "GITHUB_TOKEN", "--", *python(REPORT, "GITHUB_TOKEN"))

    assert done.returncode == 4
    assert "expired" in done.stderr
    assert "report:" not in done.stdout
    assert not grant_file(token).exists()


def test_a_grant_for_a_totp_field_gives_working_codes_and_never_holds_the_seed(cli: Cli, vault_ready: None) -> None:
    token = grant(cli, "github/totp", "--uses", "3", "--ttl", "10m")
    settings = otp.make_totp(SEED)

    plain = grant_plaintext(token)
    item = json.loads(plain)["items"]["github/totp"]
    raw_seed = base64.b32decode(SEED)
    for form in (SEED.encode(), SEED.lower().encode(), raw_seed, raw_seed.hex().encode(), base64.b64encode(raw_seed)):
        assert form not in plain
    assert set(item) == {"entry", "field", "period", "digits", "codes"}
    assert all(code == otp.code_at(settings, int(counter) * 30) for counter, code in item["codes"].items())

    before = time.time()
    code = as_agent(cli, token, "otp", "github")
    injected = as_agent(cli, token, "run", "--no-mask", "--env", "CODE=github/totp", "--", *python(
        'import os; print(os.environ["CODE"])'
    ))
    after = time.time()

    valid = {otp.code_at(settings, moment) for moment in (before - 30, before, after, after + 30)}
    assert code.returncode == 0, code.stderr
    assert code.stdout.strip() in valid
    assert injected.returncode == 0, injected.stderr
    assert injected.stdout.strip() in valid


@pytest.mark.parametrize(
    "arguments",
    [
        ["grant", "create", "GITHUB_TOKEN"],
        ["grant", "create", "bank", "--reveal"],
        ["grant", "revoke", "--all"],
        ["unlock"],
        ["lock", "--all"],
        ["alias", "set", "MINE", "bank"],
        ["alias", "rm", "GITHUB_TOKEN"],
        ["add", "planted"],
        ["audit"],
        ["scan", "."],
    ],
)
def test_an_agent_cannot_widen_its_access_even_with_a_valid_grant(
    cli: Cli, vault_ready: None, arguments: List[str]
) -> None:
    token = grant(cli, "GITHUB_TOKEN", "--uses", "3")

    done = as_agent(cli, token, *arguments)

    assert done.returncode == 5, done.stderr
    assert "owner" in done.stderr
    assert [listed["uses_left"] for listed in json.loads(cli("--json", "grant", "ls").stdout)["grants"]] == [3]
    with opened() as vault:
        assert sorted(entry.name for entry in vault.list()) == ["bank", "github", "prod-db", "stripe", "tiny"]
        assert sorted(vault.aliases) == ["DB_URL", "GITHUB_TOKEN", "STRIPE_KEY"]
    assert [info.kind for info in caps.list_caps()] == ["grant"]


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------


def test_run_resolves_an_env_file_and_passes_its_literals_through_unmasked(
    cli: Cli, vault_ready: None, tmp_path: Path
) -> None:
    env_file = tmp_path / "app.env"
    env_file.write_text(
        "# names, not secrets\n"
        "export GITHUB_TOKEN=irondome://GITHUB_TOKEN\n"
        "DATABASE_URL = irondome://prod-db/dsn\n"
        'GREETING="hello world"\n'
    )
    code = """
        import hashlib, json, os
        names = ("GITHUB_TOKEN", "DATABASE_URL")
        print(json.dumps({name: hashlib.sha256(os.environ[name].encode()).hexdigest() for name in names}))
        print("greeting:", os.environ["GREETING"])
        print("raw:", os.environ["DATABASE_URL"])
    """

    done = as_owner(cli, "run", "--env-file", str(env_file), "--", *python(code))

    assert done.returncode == 0, done.stderr
    lines = done.stdout.splitlines()
    assert json.loads(lines[0]) == {"GITHUB_TOKEN": digest(GITHUB_PASSWORD), "DATABASE_URL": digest(DB_URL)}
    assert lines[1:] == ["greeting: hello world", "raw: [irondome:DATABASE_URL]"]
    assert f"using {env_file}" in done.stderr
    nothing_leaked(done.stdout, done.stderr)


def test_run_finds_env_irondome_in_the_directory_the_command_runs_in(
    cli: Cli, vault_ready: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / ".env.irondome").write_text("STRIPE_KEY=irondome://STRIPE_KEY\n")
    (tmp_path / "other.env").write_text("STRIPE_KEY=irondome://DB_URL\n")
    code = 'import os; print("cwd:", os.getcwd()); print("key:", os.environ.get("STRIPE_KEY"))'

    by_option = as_owner(cli, "run", "--cwd", str(project), "--", *python(code))
    monkeypatch.chdir(project)
    by_directory = as_owner(cli, "run", "--", *python(code))
    named = as_owner(cli, "run", "--env-file", str(tmp_path / "other.env"), "--", *python(code))

    for done in (by_option, by_directory):
        assert done.returncode == 0, done.stderr
        assert done.stdout.splitlines() == [f"cwd: {os.path.realpath(project)}", "key: [irondome:STRIPE_KEY]"]
        assert ".env.irondome" in done.stderr
    assert named.returncode == 0, named.stderr
    assert named.stdout.splitlines()[1] == "key: [irondome:STRIPE_KEY]"  # masked under the variable's name
    assert "other.env" in named.stderr and ".env.irondome" not in named.stderr
    nothing_leaked(by_option.stdout, by_directory.stdout, named.stdout)


@pytest.mark.skipif(not hasattr(os, "geteuid"), reason="POSIX ownership and permissions")
def test_an_env_irondome_others_can_change_is_not_used(cli: Cli, vault_ready: None, tmp_path: Path) -> None:
    project = tmp_path / "shared"
    project.mkdir()
    planted = project / ".env.irondome"
    planted.write_text("LOOT=irondome://bank\n")
    planted.chmod(0o666)

    done = as_owner(cli, "run", "--cwd", str(project), "--env", "GITHUB_TOKEN", "--", *python(REPORT, "LOOT"))

    assert done.returncode == 2
    assert "was not used" in done.stderr and "--env-file" in done.stderr
    assert "report:" not in done.stdout


def test_run_takes_var_equals_ref_a_bare_alias_and_percent_encoded_references(cli: Cli, vault_ready: None) -> None:
    code = """
        import hashlib, json, os
        names = ("GITHUB_TOKEN", "DB", "KEY")
        print(json.dumps({name: hashlib.sha256(os.environ[name].encode()).hexdigest() for name in names}))
    """

    done = as_owner(
        cli, "run", "--env", "GITHUB_TOKEN", "--env", "DB=irondome://prod-db%2Fdsn", "--env", "KEY=stripe", "--",
        *python(code),
    )

    assert done.returncode == 0, done.stderr
    expected = {"GITHUB_TOKEN": digest(GITHUB_PASSWORD), "DB": digest(DB_URL), "KEY": digest(STRIPE_KEY)}
    assert json.loads(done.stdout) == expected


def test_run_takes_a_reference_from_its_own_environment(cli: Cli, vault_ready: None) -> None:
    done = as_owner(cli, "run", "--", *python(REPORT, "STRIPE"), env={"STRIPE": "irondome://STRIPE_KEY"})

    assert done.returncode == 0, done.stderr
    assert report(done)["sha256"] == digest(STRIPE_KEY)


def test_run_passes_on_the_exit_status_and_a_missing_command_is_127_and_spends_nothing(
    cli: Cli, vault_ready: None
) -> None:
    status = as_owner(cli, "run", "--env", "GITHUB_TOKEN", "--", *python("import sys; sys.exit(7)"))
    token = grant(cli, "GITHUB_TOKEN")
    missing = as_agent(cli, token, "run", "--env", "GITHUB_TOKEN", "--", "no-such-command-for-irondome-tests")
    after = as_agent(cli, token, "run", "--env", "GITHUB_TOKEN", "--", *python(REPORT, "GITHUB_TOKEN"))

    assert status.returncode == 7
    assert missing.returncode == 127
    assert "command not found" in missing.stderr
    assert after.returncode == 0, after.stderr  # the command that could not start cost no use


@pytest.mark.skipif(sys.platform == "win32", reason="a POSIX shell")
def test_run_starts_the_program_it_found_under_the_name_it_was_given(cli: Cli, vault_ready: None) -> None:
    """Looked up once and started by that path, but the program sees the name it was called by (argv[0])."""
    for how in ((), ("--json",)):
        done = as_owner(cli, *how, "run", "--env", "GITHUB_TOKEN", "--", "sh", "-c", 'echo "$0"')
        assert done.returncode == 0, done.stderr
        shown = json.loads(done.stdout)["stdout"] if how else done.stdout
        assert shown == "sh\n"


def test_no_mask_shows_values_to_the_owner_but_never_through_a_use_only_grant(cli: Cli, vault_ready: None) -> None:
    printer = python('import os; print(os.environ["STRIPE_KEY"])')
    single = grant(cli, "STRIPE_KEY")
    reveal = grant(cli, "STRIPE_KEY", "--reveal")

    owner = as_owner(cli, "run", "--no-mask", "--env", "STRIPE_KEY", "--", *printer)
    refused = as_agent(cli, single, "run", "--no-mask", "--env", "STRIPE_KEY", "--", *printer)
    masked = as_agent(cli, single, "run", "--env", "STRIPE_KEY", "--", *printer)
    revealed = as_agent(cli, reveal, "run", "--no-mask", "--env", "STRIPE_KEY", "--", *printer)

    assert owner.returncode == 0 and owner.stdout.strip() == STRIPE_KEY
    assert refused.returncode == 5
    assert "--no-mask" in refused.stderr and "Nothing was used" in refused.stderr
    nothing_leaked(refused.stdout, refused.stderr)
    assert masked.returncode == 0 and masked.stdout.strip() == "[irondome:STRIPE_KEY]"
    assert revealed.returncode == 0 and revealed.stdout.strip() == STRIPE_KEY


def test_run_json_captures_masked_output_and_the_exit_status(cli: Cli, vault_ready: None) -> None:
    code = textwrap.dedent(REPORT) + "raise SystemExit(3)\n"

    done = as_owner(cli, "--json", "run", "--env", "GITHUB_TOKEN", "--", *python(code, "GITHUB_TOKEN"))

    document = json.loads(done.stdout)
    assert done.returncode == 3
    assert set(document) == {"exit_code", "stdout", "stderr", "truncated"}
    assert document["exit_code"] == 3 and document["truncated"] is False
    assert "plain: [irondome:GITHUB_TOKEN]" in document["stdout"]
    assert document["stderr"] == "stderr: [irondome:GITHUB_TOKEN]\n"
    nothing_leaked(done.stdout, done.stderr)


def test_run_stops_a_command_that_outlives_its_time_limit(cli: Cli, vault_ready: None) -> None:
    started = time.monotonic()

    done = as_owner(cli, "run", "--timeout", "1", "--env", "GITHUB_TOKEN", "--", *python("import time; time.sleep(60)"))

    assert done.returncode == 124
    assert "stopped" in done.stderr
    assert time.monotonic() - started < 40


def test_run_warns_when_a_value_is_too_short_to_mask(cli: Cli, vault_ready: None) -> None:
    done = as_owner(cli, "run", "--env", "PIN=tiny", "--", *python("pass"))

    assert done.returncode == 0, done.stderr
    assert "PIN is shorter than 4 bytes and is not masked" in done.stderr


def test_run_without_a_grant_a_password_or_a_terminal_is_refused(cli: Cli, vault_ready: None) -> None:
    done = cli("run", "--env", "GITHUB_TOKEN", "--", *python(REPORT, "GITHUB_TOKEN"))

    assert done.returncode == 4
    assert "IRONDOME_GRANT" in done.stderr
    assert "report:" not in done.stdout


@pytest.mark.parametrize(
    "arguments, message",
    [
        (["run", "--", "true"], "nothing to inject"),
        (["run", "--env", "GITHUB_TOKEN"], "give the command to run"),
        (["run", "--env", "1BAD=github", "--", "true"], "VAR must be made of letters"),
        (["run", "--env", "IRONDOME_GRANT=github", "--", "true"], "reserved by IronDome"),
        (["run", "--env", "X=irondome://bad%zz", "--", "true"], "two hexadecimal digits"),
        (["--json", "run", "--no-mask", "--env", "GITHUB_TOKEN", "--", "true"], "--no-mask cannot be combined"),
        (["run", "--cwd", "/no/such/directory", "--env", "GITHUB_TOKEN", "--", "true"], "does not exist"),
        (["run", "--timeout", "soon", "--env", "GITHUB_TOKEN", "--", "true"], "not a duration"),
        (["run", "--timeout", "0", "--env", "GITHUB_TOKEN", "--", "true"], "positive number of seconds"),
        (["run", "--env-file", "/no/such/file.env", "--env", "GITHUB_TOKEN", "--", "true"], "does not exist"),
    ],
)
def test_run_refuses_bad_input_before_anything_is_unlocked(
    cli: Cli, vault_ready: None, arguments: List[str], message: str
) -> None:
    done = cli(*arguments)  # no password, no grant: a refusal here cannot have come from unlocking

    assert done.returncode == 2, done.stderr
    assert message in done.stderr


def test_an_env_file_that_is_not_text_is_refused_without_quoting_it(
    cli: Cli, vault_ready: None, tmp_path: Path
) -> None:
    binary = tmp_path / "binary.env"
    binary.write_bytes(b"KEY=\xff\xfe secret-material\n")
    broken = tmp_path / "broken.env"
    broken.write_text('KEY="never closed secret-material\n')

    for path in (binary, broken):
        done = cli("run", "--env-file", str(path), "--", "true")
        assert done.returncode == 2
        assert "secret-material" not in done.stderr


# ---------------------------------------------------------------------------
# grant create, ls, revoke
# ---------------------------------------------------------------------------


def test_grant_create_prints_only_the_token_and_describes_the_grant_on_stderr(cli: Cli, vault_ready: None) -> None:
    done = as_owner(
        cli, "grant", "create", "GITHUB_TOKEN", "github/totp", "--ttl", "20m", "--uses", "3", "--label", "ci job"
    )

    assert done.returncode == 0, done.stderr
    assert TOKEN.fullmatch(done.stdout)
    identifier = grant_id(done.stdout)
    for text in (
        f"grant {identifier[:12]} created in bunker alpha",
        "covers   GITHUB_TOKEN (github/password), github/totp",
        "mode     use",
        "in 20m",
        "uses     3",
        f"id       {identifier}",
        "bearer secret",
    ):
        assert text in done.stderr
    assert done.stdout not in done.stderr
    nothing_leaked(done.stdout, done.stderr)


def test_grant_create_json(cli: Cli, vault_ready: None) -> None:
    before = int(time.time())

    done = as_owner(cli, "--json", "grant", "create", "STRIPE_KEY", "prod-db/dsn", "--unlimited", "--reveal")

    document = json.loads(done.stdout)
    assert set(document) == {"token", "id", "references", "mode", "expires", "uses"}
    assert TOKEN.fullmatch(document["token"]) and grant_id(document["token"]) == document["id"]
    assert document["references"] == ["STRIPE_KEY", "prod-db/dsn"]
    assert (document["mode"], document["uses"]) == ("reveal", None)
    assert before + 900 <= document["expires"] <= int(time.time()) + 900


@pytest.mark.parametrize(
    "arguments, status, message",
    [
        (["nosuchentry"], 3, "no entry or alias"),
        (["bank/nosuchfield"], 3, "no field named"),
        (["GITHUB_TOKEN", "--ttl", "10s"], 2, "a grant lasts from 1 minute to 30 days"),
        (["GITHUB_TOKEN", "--ttl", "31d"], 2, "a grant lasts from 1 minute to 30 days"),
        (["github/totp", "--ttl", "2d"], 2, "at most 86400 seconds"),
        (["GITHUB_TOKEN", "--uses", "0"], 2, "from 1 to"),
        (["GITHUB_TOKEN", "--uses", "2", "--unlimited"], 2, "not allowed with"),
        (["GITHUB_TOKEN", "irondome://GITHUB_TOKEN"], 2, "more than once"),
        (["GITHUB_TOKEN", "--label", "bad\tlabel"], 2, "printable"),
    ],
)
def test_grant_create_refuses_what_it_cannot_honour(
    cli: Cli, vault_ready: None, arguments: List[str], status: int, message: str
) -> None:
    done = as_owner(cli, "grant", "create", *arguments)

    assert done.returncode == status, done.stderr
    assert message in done.stderr
    assert done.stdout == ""
    assert caps.list_caps() == []


def test_grant_create_with_the_wrong_password_makes_nothing(cli: Cli, vault_ready: None) -> None:
    done = cli("--password-stdin", "grant", "create", "GITHUB_TOKEN", stdin="not the password\n")

    assert done.returncode == 4
    assert done.stdout == ""
    assert caps.list_caps() == []


def test_grant_ls_needs_no_unlock_and_shows_id_label_time_and_uses(cli: Cli, vault_ready: None) -> None:
    first = grant(cli, "GITHUB_TOKEN", "--label", "deploy bot")
    second = grant(cli, "STRIPE_KEY", "--unlimited", "--ttl", "2h")

    table = cli("grant", "ls")
    listed = json.loads(cli("--json", "grant", "ls").stdout)["grants"]

    assert table.returncode == 0, table.stderr
    rows = [line.split() for line in table.stdout.splitlines()]
    assert rows[0] == ["ID", "LABEL", "EXPIRES", "IN", "USES", "LEFT"]
    by_id = {row[0]: row[1:] for row in rows[1:]}  # oldest first; two made in the same second, by id
    assert sorted(by_id) == sorted([grant_id(first)[:12], grant_id(second)[:12]])
    labelled = by_id[grant_id(first)[:12]]
    assert labelled[:2] == ["deploy", "bot"] and labelled[2] in ("15m", "14m") and labelled[3:] == ["1"]
    assert by_id[grant_id(second)[:12]] == ["-", "2h", "unlimited"]
    described = {item["id"]: (item["label"], item["uses_left"], item["expired"]) for item in listed}
    assert described == {grant_id(first): ("deploy bot", 1, False), grant_id(second): ("", None, False)}
    assert first not in table.stdout and second not in table.stdout


def test_grant_revoke_kills_a_token_at_once_and_is_recorded(cli: Cli, vault_ready: None) -> None:
    token = grant(cli, "GITHUB_TOKEN", "--uses", "5")
    identifier = grant_id(token)

    revoked = as_owner(cli, "grant", "revoke", identifier[:8])
    used = as_agent(cli, token, "run", "--env", "GITHUB_TOKEN", "--", *python(REPORT, "GITHUB_TOKEN"))
    twice = as_owner(cli, "grant", "revoke", identifier[:8])

    assert revoked.returncode == 0, revoked.stderr
    assert f"revoked grant {identifier[:12]} in bunker alpha" in revoked.stderr
    assert used.returncode == 4 and "report:" not in used.stdout
    assert twice.returncode == 3
    assert ("grant.revoke", "owner", identifier) in [
        (event["action"], event["actor"], event["target"]) for event in audit_events(cli)
    ]


@pytest.mark.parametrize("piped", ["", "not the password\n"], ids=["no-line", "wrong"])
def test_an_agent_that_passes_password_stdin_revokes_and_ends_nothing(
    cli: Cli, vault_ready: None, piped: str
) -> None:
    """Revoking and ending sessions unlock nothing they need, so the password itself is checked: no revoke-anyway."""
    token = grant(cli, "GITHUB_TOKEN", "--uses", "3")
    session = as_owner(cli, "unlock", "--print-token").stdout
    for arguments in (["grant", "revoke", grant_id(token)[:8]], ["grant", "revoke", "--all"], ["lock", "--all"]):
        done = cli("--password-stdin", *arguments, stdin=piped)
        assert done.returncode == (2 if piped == "" else 4), done.stderr  # nothing entered, or a wrong password
        assert done.stdout == "" and "revoked" not in done.stderr and "ended" not in done.stderr
    assert sorted(info.kind for info in caps.list_caps()) == ["grant", "session"]
    used = as_agent(cli, token, "run", "--env", "GITHUB_TOKEN", "--", *python(REPORT, "GITHUB_TOKEN"))
    assert used.returncode == 0, used.stderr  # the grant still works
    assert cli("get", "GITHUB_TOKEN", env={"IRONDOME_SESSION": session}).returncode == 0  # and so does the session


def test_lock_all_with_the_password_records_every_session_it_ends(cli: Cli, vault_ready: None) -> None:
    for _ in range(2):
        as_owner(cli, "unlock", "--print-token")
    assert json.loads(as_owner(cli, "--json", "lock", "--all").stdout) == {"ended": 2}
    ends = [event for event in audit_events(cli) if event["action"] == "session.end"]
    assert [(event["actor"], event["ok"]) for event in ends] == [("owner", True), ("owner", True)]


def test_grant_revoke_all_and_what_it_refuses(cli: Cli, vault_ready: None) -> None:
    tokens = [grant(cli, "GITHUB_TOKEN"), grant(cli, "STRIPE_KEY")]

    done = as_owner(cli, "--json", "grant", "revoke", "--all")
    empty = as_owner(cli, "grant", "revoke", "--all")
    malformed = as_owner(cli, "grant", "revoke", "xyz")
    neither = as_owner(cli, "grant", "revoke")

    assert done.returncode == 0, done.stderr
    revoked = sorted(item["id"] for item in json.loads(done.stdout)["revoked"])
    assert revoked == sorted(grant_id(token) for token in tokens)
    assert caps.list_caps() == []
    assert empty.returncode == 0 and "no grants to revoke" in empty.stderr
    assert malformed.returncode == 2
    assert neither.returncode == 2


# ---------------------------------------------------------------------------
# approve, with a stand-in Touch ID sensor
# ---------------------------------------------------------------------------

FAKE_TOUCH = '''
import json
import os
import types

from irondome.device.base import POLICY_BIOMETRY, POLICY_DEVICE, DeviceBackend, Probe, check_descriptor, new_ref
from irondome.errors import AuthError, HardwareError
from irondome.secmem import SecureBuffer


class FileTouch(DeviceBackend):
    """A chip with a fingerprint sensor whose keys and prompt log live in one JSON file.

    IRONDOME_TEST_FINGER is what the person at the sensor does: "present" touches it, anything else
    cancels the prompt. Every prompt is appended to the file before it is answered.
    """

    name = "fake-touch"
    hardware = True
    policies = (POLICY_DEVICE, POLICY_BIOMETRY)

    def __init__(self, state):
        self.state = state

    def _load(self):
        with open(self.state) as handle:
            return json.load(handle)

    def _save(self, data):
        with open(self.state, "w") as handle:
            json.dump(data, handle)

    def probe(self):
        return Probe(self.name, True, True, True, "stand-in chip with a fingerprint sensor")

    def enroll(self, *, policy, auth, reason):
        data = self._load()
        ref = new_ref()
        raw = os.urandom(32)
        data["secrets"][ref] = raw.hex()
        self._save(data)
        return {"backend": self.name, "policy": policy, "ref": ref}, SecureBuffer.from_buffer(raw)

    def unseal(self, descriptor, *, auth, interactive, reason):
        check_descriptor(descriptor, self.name)
        data = self._load()
        stored = data["secrets"].get(descriptor.get("ref"))
        if stored is None:
            raise HardwareError("the stand-in chip does not hold this key")
        if descriptor["policy"] != POLICY_DEVICE:
            if not interactive:
                raise AuthError("a fingerprint is required, and it cannot be asked for here")
            data["prompts"].append(reason)
            self._save(data)
            if os.environ.get("IRONDOME_TEST_FINGER", "present") != "present":
                raise AuthError("the fingerprint prompt was cancelled")
        return SecureBuffer.from_buffer(bytes.fromhex(stored))

    def destroy(self, descriptor):
        data = self._load()
        data["secrets"].pop(descriptor.get("ref"), None)
        self._save(data)

    def exists(self, descriptor):
        return descriptor.get("ref") in self._load()["secrets"]

    def destroy_all(self):
        data = self._load()
        count = len(data["secrets"])
        data["secrets"] = {}
        self._save(data)
        return count


def install(state):
    """Make this process use the stand-in: registered as a backend, on a Mac, with prompts allowed."""
    from irondome import device, unlock

    backend = FileTouch(state)
    device._REGISTRY = device._REGISTRY + (("fake-touch", "irondome.no_such_module", "FileTouch"),)
    device._instances["fake-touch"] = backend
    unlock.sys = types.SimpleNamespace(platform="darwin")
    return backend
'''

TOUCH_MAIN = """
import os, sys
namespace = {"__name__": "fake_touch"}
with open(os.environ["IRONDOME_TEST_TOUCH_CODE"]) as handle:
    exec(compile(handle.read(), "fake_touch.py", "exec"), namespace)
namespace["install"](os.environ["IRONDOME_TEST_TOUCH_STATE"])
from irondome.cli.main import main
raise SystemExit(main(sys.argv[1:]))
"""


class Sensor:
    """The stand-in chip as the test sees it: run a command on it, read the prompts it showed."""

    def __init__(self, state: Path, code: Path) -> None:
        self.state = state
        self.code = code

    def prompts(self) -> List[str]:
        return json.loads(self.state.read_text())["prompts"]

    def run(self, *arguments: str, finger: str = "present", env: Optional[Dict[str, str]] = None) -> Done:
        merged = child_environment(
            {
                "IRONDOME_NO_TOUCH": "0",
                "IRONDOME_TEST_FINGER": finger,
                "IRONDOME_TEST_TOUCH_STATE": str(self.state),
                "IRONDOME_TEST_TOUCH_CODE": str(self.code),
            },
            env,
        )
        return subprocess.run(
            [sys.executable, "-c", TOUCH_MAIN, *arguments],
            input="",
            capture_output=True,
            text=True,
            env=merged,
            timeout=120,
        )


@pytest.fixture
def touch(vault_ready: None, tmp_path: Path) -> Sensor:
    """The vault of ``vault_ready`` with a Touch ID keyslot on the stand-in chip, and the chip."""
    code = tmp_path / "fake_touch.py"
    code.write_text(FAKE_TOUCH)
    state = tmp_path / "touch-state.json"
    state.write_text(json.dumps({"secrets": {}, "prompts": []}))
    namespace: Dict[str, Any] = {"__name__": "fake_touch"}
    exec(compile(FAKE_TOUCH, str(code), "exec"), namespace)  # noqa: S102 - the stand-in chip defined above
    with opened() as vault:
        slot = keys.create_device_slot(
            vault.vault_key, vault.vault_id, backend=namespace["FileTouch"](str(state)), policy=POLICY_BIOMETRY,
            label="Touch ID",
        )
        vault.add_slot(slot)
        vault.commit()
    return Sensor(state, code)


@pytest.fixture
def short_dir() -> Iterator[Path]:
    """A new, empty directory with a short path (its real path), removed afterwards.

    A Touch ID prompt names a program by its whole path, and refuses one too long to show; programs that
    must fit are put here, so that the tests do not depend on how long the path of ``tmp_path`` is.
    """
    made = tempfile.mkdtemp(prefix="irondome-", dir="/tmp" if os.path.isdir("/tmp") else None)
    try:
        yield Path(os.path.realpath(made))
    finally:
        shutil.rmtree(made, ignore_errors=True)


def shell_program(path: Path, body: str) -> Path:
    """A program at *path*: a POSIX shell script that runs *body*."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n" + body + "\n")
    path.chmod(0o755)
    return path


def test_approve_gives_an_agent_a_use_only_grant_after_one_touch(cli: Cli, touch: Sensor) -> None:
    done = touch.run("approve", "GITHUB_TOKEN", "--ttl", "10m")

    assert done.returncode == 0, done.stderr
    assert TOKEN.fullmatch(done.stdout)
    assert touch.prompts() == ["let an agent use GITHUB_TOKEN for 10 minutes (bunker alpha)"]
    (listed,) = json.loads(cli("--json", "grant", "ls").stdout)["grants"]
    assert (listed["id"], listed["label"]) == (grant_id(done.stdout), "approved with Touch ID")
    assert listed["uses_left"] is None
    assert listed["expires"] - listed["created"] == 600
    token = done.stdout
    for _ in range(2):
        used = as_agent(cli, token, "run", "--env", "GITHUB_TOKEN", "--", *python(REPORT, "GITHUB_TOKEN"))
        assert used.returncode == 0, used.stderr
        assert report(used)["sha256"] == digest(GITHUB_PASSWORD)
    shown = as_agent(cli, token, "get", "GITHUB_TOKEN")
    assert shown.returncode == 5
    nothing_leaked(done.stderr, used.stdout, used.stderr, shown.stdout, shown.stderr)
    assert touch.prompts() == ["let an agent use GITHUB_TOKEN for 10 minutes (bunker alpha)"]  # nothing more asked
    approvals = [event for event in audit_events(cli) if event["action"] == "approve"]
    assert [(event["actor"], event["target"], event["ok"]) for event in approvals] == [("agent", "GITHUB_TOKEN", True)]
    assert "600s" in approvals[0]["detail"]


def test_approve_names_every_reference_and_the_grant_covers_exactly_those(cli: Cli, touch: Sensor) -> None:
    done = touch.run("approve", "GITHUB_TOKEN", "DB_URL", "--ttl", "1h")

    assert done.returncode == 0, done.stderr
    assert touch.prompts() == ["let an agent use GITHUB_TOKEN and DB_URL for 1 hour (bunker alpha)"]
    outside = as_agent(cli, done.stdout, "run", "--env", "STRIPE_KEY", "--", *python(REPORT, "STRIPE_KEY"))
    assert outside.returncode == 5
    assert "report:" not in outside.stdout


def test_a_refused_touch_gives_the_agent_nothing(cli: Cli, touch: Sensor) -> None:
    done = touch.run("approve", "GITHUB_TOKEN", finger="refuse")

    assert done.returncode == 4
    assert done.stdout == ""
    assert touch.prompts() == ["let an agent use GITHUB_TOKEN for 10 minutes (bunker alpha)"]
    assert caps.list_caps() == []


def test_an_entry_marked_deny_is_never_approved(cli: Cli, touch: Sensor) -> None:
    """Refused before anything is made, and recorded.

    The policy is kept in the encrypted index, so it can be read only once the vault is open: the
    one prompt that opens it is shown, and nothing comes of it.
    """
    done = touch.run("approve", "GITHUB_TOKEN", "bank")

    assert done.returncode == 5
    assert done.stdout == ""
    assert "'bank' is not available to agents" in done.stderr
    assert len(touch.prompts()) == 1
    assert caps.list_caps() == []
    refused = [event for event in audit_events(cli) if event["action"] == "approve"]
    assert [(event["actor"], event["ok"]) for event in refused] == [("agent", False)]
    nothing_leaked(done.stdout, done.stderr)


def shown_program(prompt: str, secret_name: str, bunker: str = paths.FIRST_BUNKER) -> str:
    """The program a `run` prompt names, after checking the prompt is that and nothing else."""
    ending = f"' use {secret_name} (bunker {bunker})"
    assert prompt.startswith("let '") and prompt.endswith(ending), prompt
    return prompt[len("let '") : -len(ending)]


def started_as(program: str) -> str:
    """The path `irondome run` starts *program* by, and names in full: every directory resolved, its name kept."""
    directory, name = os.path.split(os.path.abspath(program))
    return os.path.join(os.path.realpath(directory), name)


def names_the_program(shown: str, program: str) -> bool:
    """True if *shown* is the whole path *program* is started by: never a shortened one."""
    return "\u2026" not in shown and shown == started_as(program)


def test_run_with_touch_asks_the_owner_once_and_the_entry_policy_decides(
    cli: Cli, touch: Sensor, tmp_path: Path
) -> None:
    """Touch ID for one command: the prompt names the program that runs and the secret; deny and use still hold."""
    used = touch.run("run", "--touch", "--env", "GITHUB_TOKEN", "--", *python(REPORT, "GITHUB_TOKEN"))
    denied = touch.run("run", "--touch", "--env", "BANK=bank", "--", *python(REPORT, "BANK"))
    unmasked = touch.run("run", "--touch", "--no-mask", "--env", "GITHUB_TOKEN", "--", *python(REPORT, "GITHUB_TOKEN"))
    revealed = touch.run("run", "--touch", "--no-mask", "--env", "STRIPE_KEY", "--", *python(REPORT, "STRIPE_KEY"))

    assert used.returncode == 0, used.stderr
    assert report(used) == {"sha256": digest(GITHUB_PASSWORD), "control": []}
    assert "plain: [irondome:GITHUB_TOKEN]" in used.stdout.splitlines()
    assert denied.returncode == 5 and "'bank' is not available to agents" in denied.stderr
    assert unmasked.returncode == 5 and "not shown to them" in unmasked.stderr
    assert revealed.returncode == 0 and f"plain: {STRIPE_KEY}" in revealed.stdout.splitlines()
    for done in (denied, unmasked):
        assert "report:" not in done.stdout
    nothing_leaked(used.stdout, used.stderr, denied.stdout, denied.stderr, unmasked.stdout, unmasked.stderr)
    prompts = touch.prompts()
    expected = ["GITHUB_TOKEN", "bank", "GITHUB_TOKEN", "STRIPE_KEY"]
    assert len(prompts) == len(expected)
    for prompt, name in zip(prompts, expected):
        assert names_the_program(shown_program(prompt, name), sys.executable), prompt
    agent_uses = [
        (event["action"], event["target"]) for event in audit_events(cli) if event["actor"] == "agent"
    ]
    assert agent_uses == [("use", "github/password"), ("reveal", "stripe/password")]


@pytest.mark.skipif(sys.platform == "win32", reason="a POSIX shell script")
def test_a_program_an_agent_planted_is_shown_by_its_real_path(touch: Sensor, short_dir: Path) -> None:
    """``./gh`` written into the agent's working directory does not pass for the real gh in the prompt."""
    work = short_dir / "agent-workdir"
    planted = shell_program(work / "gh", "echo planted")

    done = touch.run("run", "--touch", "--cwd", str(work), "--env", "GITHUB_TOKEN", "--", "./gh", finger="refuse")

    assert done.returncode == 4
    (prompt,) = touch.prompts()
    assert names_the_program(shown_program(prompt, "GITHUB_TOKEN"), str(planted)), prompt


BUNKER_TOKENS = {"work": "ghp_WorkToken0123456789Example", "personal": "ghp_PersonalToken0123456789Example"}


@pytest.fixture
def two_bunkers(touch: Sensor, make_vault: Callable[..., Any], monkeypatch: pytest.MonkeyPatch) -> Sensor:
    """Bunkers work and personal beside alpha, on the same chip: each has its own GITHUB_TOKEN, marked for agents."""
    namespace: Dict[str, Any] = {"__name__": "fake_touch"}
    exec(compile(FAKE_TOUCH, str(touch.code), "exec"), namespace)  # noqa: S102 - the stand-in chip defined above
    for bunker, value in BUNKER_TOKENS.items():
        monkeypatch.setenv(paths.ENV_BUNKER, bunker)
        vault, _ = make_vault()
        github = vault.add("github", Secret(password=value), agent="use")
        vault.set_alias("GITHUB_TOKEN", github, "password")
        vault.add_slot(
            keys.create_device_slot(
                vault.vault_key, vault.vault_id, backend=namespace["FileTouch"](str(touch.state)),
                policy=POLICY_BIOMETRY, label="Touch ID",
            )
        )
        vault.commit()
    monkeypatch.delenv(paths.ENV_BUNKER)
    return touch


@pytest.mark.skipif(sys.platform == "win32", reason="a POSIX shell script")
def test_the_touch_id_prompts_of_approve_and_run_name_the_bunker(two_bunkers: Sensor, short_dir: Path) -> None:
    """The same request made in two bunkers reads differently, so the owner can tell whose secret goes out."""
    keeper = shell_program(short_dir / "keep", 'printf %s "$GITHUB_TOKEN" > "$1"')

    for bunker in BUNKER_TOKENS:
        approved = two_bunkers.run("--bunker", bunker, "approve", "GITHUB_TOKEN")
        ran = two_bunkers.run(
            "--bunker", bunker, "run", "--touch", "--env", "GITHUB_TOKEN", "--", str(keeper), str(short_dir / bunker)
        )
        assert approved.returncode == 0, approved.stderr
        assert ran.returncode == 0, ran.stderr

    assert {bunker: (short_dir / bunker).read_text() for bunker in BUNKER_TOKENS} == BUNKER_TOKENS
    program = started_as(str(keeper))
    assert two_bunkers.prompts() == [
        "let an agent use GITHUB_TOKEN for 10 minutes (bunker work)",
        f"let '{program}' use GITHUB_TOKEN (bunker work)",
        "let an agent use GITHUB_TOKEN for 10 minutes (bunker personal)",
        f"let '{program}' use GITHUB_TOKEN (bunker personal)",
    ]


@pytest.mark.skipif(sys.platform == "win32", reason="a POSIX shell script")
def test_run_touch_names_a_long_program_path_in_full(touch: Sensor, short_dir: Path) -> None:
    """Nothing is cut out of a path, so the part an agent chose cannot be hidden behind a familiar ending."""
    program = shell_program(short_dir / ("x" * 60) / "opt" / "homebrew" / "bin" / "gh", "echo agent-made gh")
    assert len(str(program)) > 80

    done = touch.run("run", "--touch", "--env", "GITHUB_TOKEN", "--", str(program), finger="refuse")

    assert done.returncode == 4
    (prompt,) = touch.prompts()
    assert names_the_program(shown_program(prompt, "GITHUB_TOKEN"), str(program)), prompt


@pytest.mark.skipif(sys.platform == "win32", reason="a POSIX shell script")
def test_run_touch_refuses_a_program_whose_path_cannot_be_shown_in_full(touch: Sensor, short_dir: Path) -> None:
    """Too long to be named in full in the prompt: refused before any prompt, and the program never runs."""
    program = shell_program(short_dir / ("x" * 100) / ("y" * 80) / "gh", ': > "$0.ran"')

    done = touch.run("run", "--touch", "--env", "GITHUB_TOKEN", "--", str(program))

    assert done.returncode == 2, done.stderr
    assert "cannot be named in full in a Touch ID prompt" in done.stderr and "grant create" in done.stderr
    assert touch.prompts() == []
    assert not Path(f"{program}.ran").exists()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX links and shell scripts")
def test_a_link_and_dotdot_cannot_make_an_agent_program_look_like_a_system_one(touch: Sensor, short_dir: Path) -> None:
    """``L/../..`` is read the way the kernel reads it: through the link, not as text that cancels out."""
    link = short_dir / "L"
    depth = len(link.parts) - 1
    target = short_dir.joinpath("deep", *(["d"] * depth))
    target.mkdir(parents=True)
    link.symlink_to(target)
    planted = shell_program(short_dir / "deep" / "usr" / "bin" / "irondome-test-tool", "echo agent-made tool")
    spoof = str(link) + "/.." * depth + "/usr/bin/irondome-test-tool"
    assert os.path.normpath(spoof) == "/usr/bin/irondome-test-tool"  # what the path says as text
    assert os.path.realpath(spoof) == str(planted)  # what the kernel starts

    done = touch.run("run", "--touch", "--env", "GITHUB_TOKEN", "--", spoof, finger="refuse")

    assert done.returncode == 4
    (prompt,) = touch.prompts()
    assert shown_program(prompt, "GITHUB_TOKEN") == str(planted), prompt


PLANTING = FAKE_TOUCH + '''

_answer = FileTouch.unseal


def _answer_and_plant(self, descriptor, *, auth, interactive, reason):
    """While the prompt is on the owner's screen, the agent writes a program of its own: IRONDOME_TEST_PLANT."""
    planted = os.environ.get("IRONDOME_TEST_PLANT")
    if planted and interactive and descriptor["policy"] != POLICY_DEVICE:
        with open(planted, "w") as handle:
            handle.write("#!/bin/sh\\necho planted ran\\n")
        os.chmod(planted, 0o755)
    return _answer(self, descriptor, auth=auth, interactive=interactive, reason=reason)


FileTouch.unseal = _answer_and_plant
'''


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell scripts")
def test_a_program_put_earlier_on_path_while_the_prompt_is_shown_is_not_the_one_started(
    touch: Sensor, short_dir: Path
) -> None:
    """The program is looked up once, for the prompt, and started by that path: not looked up again after the touch."""
    touch.code.write_text(PLANTING)
    shown = shell_program(short_dir / "real" / "irondome-test-tool", "echo shown ran")
    late = short_dir / "late"
    late.mkdir()
    search = os.pathsep.join([str(late), str(shown.parent), os.environ.get("PATH", os.defpath)])

    done = touch.run(
        "run", "--touch", "--env", "GITHUB_TOKEN", "--", "irondome-test-tool",
        env={"PATH": search, "IRONDOME_TEST_PLANT": str(late / "irondome-test-tool")},
    )

    assert (late / "irondome-test-tool").exists()  # planted while the prompt was on screen
    assert done.returncode == 0, done.stderr
    assert done.stdout.splitlines() == ["shown ran"]
    (prompt,) = touch.prompts()
    assert names_the_program(shown_program(prompt, "GITHUB_TOKEN"), str(shown)), prompt


@pytest.mark.skipif(sys.platform == "win32", reason="a POSIX shell script")
def test_a_path_too_long_for_a_prompt_still_runs_where_no_prompt_is_shown(
    cli: Cli, touch: Sensor, short_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A grant, a session or the master password shows no prompt, so the program's path may be any length.

    A session that has expired does not bring up a prompt in its place: Touch ID stays off for the command.
    """
    program = shell_program(short_dir / ("x" * 100) / ("y" * 80) / "keep", 'printf %s "$GITHUB_TOKEN" > "$1"')
    token = grant(cli, "GITHUB_TOKEN")
    session = as_owner(cli, "unlock", "--print-token").stdout
    with opened() as vault, monkeypatch.context() as clock:
        clock.setattr(caps, "_now", lambda: int(time.time()) - 7200)
        expired = caps.create_session(vault, ttl=60)
    command = ["run", "--touch", "--env", "GITHUB_TOKEN", "--", str(program)]

    by_grant = touch.run(*command, str(short_dir / "grant"), env={"IRONDOME_GRANT": token})
    by_session = touch.run(*command, str(short_dir / "session"), env={"IRONDOME_SESSION": session})
    by_password = as_owner(cli, "run", "--env", "GITHUB_TOKEN", "--", str(program), str(short_dir / "password"))
    stale = touch.run(*command, str(short_dir / "stale"), env={"IRONDOME_SESSION": expired})

    for done in (by_grant, by_session, by_password):
        assert done.returncode == 0, done.stderr
    for name in ("grant", "session", "password"):
        assert (short_dir / name).read_text() == GITHUB_PASSWORD
    assert stale.returncode == 4 and not (short_dir / "stale").exists()
    assert touch.prompts() == []


@pytest.mark.parametrize(
    "arguments, message",
    [
        (["GITHUB_TOKEN", "--ttl", "2h"], "an approval lasts from 1 minute to 1 hour"),
        (["GITHUB_TOKEN", "--ttl", "30s"], "an approval lasts from 1 minute to 1 hour"),
        ([" GITHUB_TOKEN"], "whitespace"),
        (["GITHUB_TOKEN", "GITHUB_TOKEN"], "more than once"),
        ([f"secret-number-{index:03d}" for index in range(12)], "too long to be shown in full"),
    ],
)
def test_approve_refuses_what_it_can_before_any_prompt(touch: Sensor, arguments: List[str], message: str) -> None:
    done = touch.run("approve", *arguments)

    assert done.returncode == 2
    assert message in done.stderr
    assert touch.prompts() == []


def test_approve_without_a_touch_id_keyslot_tells_the_agent_to_ask_for_a_grant(cli: Cli, vault_ready: None) -> None:
    token = grant(cli, "GITHUB_TOKEN")
    session = as_owner(cli, "unlock", "--print-token").stdout

    plain = cli("approve", "GITHUB_TOKEN")
    with_password = as_owner(cli, "approve", "GITHUB_TOKEN")
    with_grant = as_agent(cli, token, "approve", "GITHUB_TOKEN")
    with_session = cli("approve", "GITHUB_TOKEN", env={"IRONDOME_SESSION": session})

    for done in (plain, with_password, with_grant, with_session):
        assert done.returncode == 4
        assert "Ask the vault's owner for a grant" in done.stderr
        assert done.stdout == ""
    assert sorted(info.kind for info in caps.list_caps()) == ["grant", "session"]  # nothing was added


# ---------------------------------------------------------------------------
# unlock and lock
# ---------------------------------------------------------------------------


def test_unlock_prints_a_line_to_eval_and_commands_then_work_with_only_the_session(cli: Cli, vault_ready: None) -> None:
    done = as_owner(cli, "unlock")

    assert done.returncode == 0, done.stderr
    match = re.fullmatch(r"export IRONDOME_SESSION='(irondome_s_[0-9a-f]{32}_[A-Z2-7]{52})'\n", done.stdout)
    assert match is not None, done.stdout
    session = match.group(1)
    assert 'eval "$(irondome unlock)"' in done.stderr and "irondome lock" in done.stderr
    assert "never export IRONDOME_SESSION into an agent's environment" in done.stderr
    evaluated = subprocess.run(
        ["/bin/sh", "-c", done.stdout + 'printf %s "$IRONDOME_SESSION"'], capture_output=True, text=True, timeout=30
    )
    assert evaluated.stdout == session

    shown = cli("get", "GITHUB_TOKEN", env={"IRONDOME_SESSION": session})
    used = cli("run", "--env", "DB_URL", "--", *python(REPORT, "DB_URL"), env={"IRONDOME_SESSION": session})
    locked = cli("lock", env={"IRONDOME_SESSION": session})
    after = cli("get", "GITHUB_TOKEN", env={"IRONDOME_SESSION": session})
    again = cli("lock", env={"IRONDOME_SESSION": session})

    assert shown.returncode == 0 and shown.stdout == GITHUB_PASSWORD
    assert used.returncode == 0, used.stderr
    assert report(used) == {"sha256": digest(DB_URL), "control": []}
    assert locked.returncode == 0 and locked.stdout == "unset IRONDOME_SESSION\n"
    assert "ended 1 session in bunker alpha" in locked.stderr
    assert after.returncode == 4 and after.stdout == ""
    assert again.returncode == 0 and again.stdout == "unset IRONDOME_SESSION\n" and again.stderr == ""


def test_unlock_print_token_prints_only_the_token(cli: Cli, vault_ready: None) -> None:
    done = as_owner(cli, "unlock", "--print-token", "--ttl", "5m")
    document = json.loads(as_owner(cli, "--json", "unlock", "--ttl", "1h").stdout)

    assert done.returncode == 0, done.stderr
    assert TOKEN.fullmatch(done.stdout) and done.stdout.startswith("irondome_s_")
    assert "5m" in done.stderr
    assert set(document) == {"token", "expires", "bunker"} and document["bunker"] == "alpha"
    assert TOKEN.fullmatch(document["token"])


def test_an_expired_session_falls_back_to_asking_and_without_a_terminal_fails(
    cli: Cli, vault_ready: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    with opened() as vault, monkeypatch.context() as clock:
        clock.setattr(caps, "_now", lambda: int(time.time()) - 7200)
        session = caps.create_session(vault, ttl=60)

    done = cli("get", "GITHUB_TOKEN", env={"IRONDOME_SESSION": session})

    assert done.returncode == 4
    assert "expired" in done.stderr
    assert done.stdout == ""


def drain(descriptor: int) -> bytes:
    """Everything a pseudo-terminal's other side wrote, without waiting for more."""
    chunks = []
    while select.select([descriptor], [], [], 0.5)[0]:
        try:
            chunk = os.read(descriptor, 65536)
        except OSError:
            break  # the other side is gone (Linux reports that as EIO)
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def on_a_terminal(*arguments: str) -> "subprocess.CompletedProcess[bytes]":
    """Run the command line with its stdout on a pseudo-terminal (stdin still carries the password)."""
    master, slave = os.openpty()
    try:
        done = subprocess.run(
            [sys.executable, "-m", "irondome", *arguments],
            input=(PASSWORD + "\n").encode(),
            stdout=slave,
            stderr=subprocess.PIPE,
            env=child_environment(),
            timeout=120,
            start_new_session=True,  # the pseudo-terminal is never this test run's own terminal
        )
        # Read while this side still holds the terminal open: macOS drops what is unread once it closes.
        done.stdout = drain(master)
    finally:
        os.close(slave)
        os.close(master)
    return done


@pytest.mark.skipif(not hasattr(os, "openpty"), reason="needs a POSIX pseudo-terminal")
def test_unlock_never_prints_a_session_token_to_a_terminal(vault_ready: None) -> None:
    refused = on_a_terminal("--password-stdin", "unlock")

    assert refused.returncode == 2
    assert b"irondome_s_" not in refused.stdout
    assert b'eval "$(irondome unlock)"' in refused.stderr
    assert caps.list_caps() == []

    asked = on_a_terminal("--password-stdin", "unlock", "--print-token")

    assert asked.returncode == 0, asked.stderr
    assert b"irondome_s_" in asked.stdout
    assert [info.kind for info in caps.list_caps()] == ["session"]


@pytest.mark.parametrize(
    "arguments, stdin, status",
    [
        (["unlock"], "", 5),
        (["--password-stdin", "unlock"], "wrong password\n", 4),
        (["--password-stdin", "unlock", "--ttl", "13h"], PASSWORD + "\n", 2),
        (["--password-stdin", "unlock", "--ttl", "30s"], PASSWORD + "\n", 2),
    ],
)
def test_unlock_is_for_the_owner_and_checks_its_lifetime(
    cli: Cli, vault_ready: None, arguments: List[str], stdin: str, status: int
) -> None:
    done = cli(*arguments, stdin=stdin)

    assert done.returncode == status, done.stderr
    assert done.stdout == ""
    assert caps.list_caps() == []


def test_lock_all_ends_every_session(cli: Cli, vault_ready: None) -> None:
    sessions = [as_owner(cli, "unlock", "--print-token").stdout for _ in range(2)]

    done = as_owner(cli, "--json", "lock", "--all")

    assert json.loads(done.stdout) == {"ended": 2}
    assert caps.list_caps() == []
    for session in sessions:
        assert cli("get", "GITHUB_TOKEN", env={"IRONDOME_SESSION": session}).returncode == 4


def test_lock_with_something_that_is_not_a_session_token_warns_and_still_unsets(cli: Cli, vault_ready: None) -> None:
    token = grant(cli, "GITHUB_TOKEN")

    done = cli("lock", env={"IRONDOME_SESSION": token})

    assert done.returncode == 0
    assert done.stdout == "unset IRONDOME_SESSION\n"
    assert "nothing was ended" in done.stderr
    assert grant_file(token).exists()


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------


def test_the_audit_log_shows_grant_uses_session_uses_and_changes_with_the_right_actor(
    cli: Cli, vault_ready: None
) -> None:
    assert as_owner(cli, "alias", "set", "BANK_PIN", "bank/pin").returncode == 0
    token = grant(cli, "GITHUB_TOKEN")
    command = python("pass")
    assert as_agent(cli, token, "run", "--env", "GITHUB_TOKEN", "--", *command).returncode == 0
    session = as_owner(cli, "unlock", "--print-token").stdout
    assert cli("run", "--env", "DB_URL", "--", *command, env={"IRONDOME_SESSION": session}).returncode == 0

    events = audit_events(cli)

    seen = [(event["kid"], event["actor"], event["action"], event["target"]) for event in events]
    identifier = grant_id(token)
    assert ("vault", "owner", "alias.set", "BANK_PIN") in seen
    assert ("vault", "owner", "grant.create", identifier) in seen
    assert (identifier, "grant", "grant.use", identifier) in seen
    assert (identifier, "grant", "use", "GITHUB_TOKEN") in seen
    assert ("vault", "owner", "session.start", grant_id(session)) in seen
    # A session token in a process with no terminal is exactly what an agent would hold.
    assert ("vault", "agent", "use", "prod-db/dsn") in seen
    line = shlex.join(command)
    shown = line if len(line) <= 200 else line[:199] + "\u2026"  # the command line, cut to 200 characters
    assert [event["detail"] for event in events if event["action"] == "use"] == [shown, shown]
    assert [event["seq"] for event in events] == sorted(event["seq"] for event in events)
    nothing_leaked(json.dumps(events))


def test_a_session_used_at_a_terminal_is_recorded_as_the_session(
    cli: Cli, vault_ready: None, monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture
) -> None:
    session = as_owner(cli, "unlock", "--print-token").stdout
    monkeypatch.setenv("IRONDOME_SESSION", session)
    monkeypatch.setenv(paths.ENV_BUNKER, paths.FIRST_BUNKER)

    def nobody_answers(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("nothing may be asked of the real terminal in a test")

    monkeypatch.setattr(context, "_has_terminal", lambda: True)
    monkeypatch.setattr(context, "read_secret", nobody_answers)
    monkeypatch.setattr(context.Context, "_read_line", nobody_answers)

    status = main(["run", "--env", "GITHUB_TOKEN", "--", *python('import os; print(os.environ["GITHUB_TOKEN"])')])

    captured = capfd.readouterr()
    assert status == 0, captured.err
    assert captured.out.strip() == "[irondome:GITHUB_TOKEN]"
    assert ("vault", "session", "use", "github/password") in [
        (event["kid"], event["actor"], event["action"], event["target"]) for event in audit_events(cli)
    ]


def test_audit_verify_passes_on_an_untouched_log_and_fails_after_one_line_is_edited(
    cli: Cli, vault_ready: None
) -> None:
    grant(cli, "GITHUB_TOKEN")
    grant(cli, "STRIPE_KEY")

    clean = as_owner(cli, "audit", "--verify")

    assert clean.returncode == 0, clean.stderr
    assert "verified: all" in clean.stdout and "authentic and in order" in clean.stdout

    log = paths.audit_file()
    lines = log.read_bytes().splitlines(keepends=True)
    record = json.loads(lines[0])
    record["ts"] += 1  # still well-formed: only the key that sealed it can tell
    lines[0] = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
    log.write_bytes(b"".join(lines))

    altered = as_owner(cli, "audit", "--verify")
    document = json.loads(as_owner(cli, "--json", "audit", "--verify").stdout)

    assert altered.returncode == 1
    assert "ALTERED" in altered.stdout and "line 1 failed authentication" in altered.stdout
    assert "was edited" in altered.stderr
    assert document["verify"]["ok"] is False and document["verify"]["problems"]
    assert as_owner(cli, "--json", "audit").returncode == 0  # reading without --verify still works


def test_audit_shows_the_newest_records_in_a_table(cli: Cli, vault_ready: None) -> None:
    for _ in range(3):
        grant(cli, "GITHUB_TOKEN")

    done = as_owner(cli, "audit", "-n", "2")
    document = json.loads(as_owner(cli, "--json", "audit", "-n", "2").stdout)
    negative = as_owner(cli, "audit", "-n", "-1")

    assert done.returncode == 0, done.stderr
    lines = done.stdout.splitlines()
    assert lines[0].split() == ["TIME", "WHO", "ACTION", "TARGET", "DETAIL"]
    assert len(lines) == 3 and all(" grant.create " in line for line in lines[1:])
    assert "showing the newest 2 records" in done.stderr
    assert [event["action"] for event in document["events"]] == ["grant.create", "grant.create"]
    assert document["verify"] is None
    assert document["events"][0]["seq"] < document["events"][1]["seq"]
    assert negative.returncode == 2


# ---------------------------------------------------------------------------
# alias
# ---------------------------------------------------------------------------


def test_alias_set_ls_and_rm(cli: Cli, vault_ready: None) -> None:
    created = as_owner(cli, "alias", "set", "BANK_PIN", "bank/pin")
    by_reference = as_owner(cli, "--json", "alias", "set", "DATABASE", "irondome://prod-db%2Fdsn")
    replaced = as_owner(cli, "alias", "set", "GITHUB_TOKEN", "stripe")
    listing = as_owner(cli, "alias", "ls")
    document = json.loads(as_owner(cli, "--json", "alias", "ls").stdout)
    removed = as_owner(cli, "alias", "rm", "BANK_PIN")

    assert created.returncode == 0, created.stderr
    assert created.stdout == "" and "BANK_PIN now points at bank/pin in bunker alpha" in created.stderr
    assert json.loads(by_reference.stdout) == {
        "alias": "DATABASE", "entry": "prod-db", "field": "dsn", "replaced": False
    }
    assert "(it pointed at github/password)" in replaced.stderr
    assert [line.split() for line in listing.stdout.splitlines()] == [
        ["ALIAS", "ENTRY", "FIELD"],
        ["BANK_PIN", "bank", "pin"],
        ["DATABASE", "prod-db", "dsn"],
        ["DB_URL", "prod-db", "dsn"],
        ["GITHUB_TOKEN", "stripe", "password"],
        ["STRIPE_KEY", "stripe", "password"],
    ]
    assert [item["alias"] for item in document["aliases"]] == [
        "BANK_PIN", "DATABASE", "DB_URL", "GITHUB_TOKEN", "STRIPE_KEY"
    ]
    assert removed.returncode == 0 and "it pointed at bank/pin" in removed.stderr
    with opened() as vault:
        assert sorted(vault.aliases) == ["DATABASE", "DB_URL", "GITHUB_TOKEN", "STRIPE_KEY"]
    nothing_leaked(created.stderr, listing.stdout, json.dumps(document), removed.stderr)
    assert "4321" not in listing.stdout + created.stderr
    assert ("vault", "owner", "alias.set", "BANK_PIN") in [
        (event["kid"], event["actor"], event["action"], event["target"]) for event in audit_events(cli)
    ]


@pytest.mark.parametrize(
    "arguments, status, message",
    [
        (["set", "NEW", "nosuchentry"], 3, "no entry or alias"),
        (["set", "NEW", "bank/nosuchfield"], 3, "no field named"),
        (["set", "NEW", "tiny/totp"], 3, "no one-time-password"),
        (["set", "1BAD", "bank"], 2, "an alias must start with"),
        (["set", "github", "stripe"], 2, "is the name of an entry"),
        (["set", "NEW", "bank/name"], 2, "not at the entry name"),
        (["rm", "NOSUCHALIAS"], 3, "no alias named 'NOSUCHALIAS' in bunker alpha"),
    ],
)
def test_alias_refuses_what_would_not_resolve_and_changes_nothing(
    cli: Cli, vault_ready: None, arguments: List[str], status: int, message: str
) -> None:
    done = as_owner(cli, "alias", *arguments)

    assert done.returncode == status, done.stderr
    assert message in done.stderr
    with opened() as vault:
        assert sorted(vault.aliases) == ["DB_URL", "GITHUB_TOKEN", "STRIPE_KEY"]


def test_alias_with_the_wrong_password_changes_nothing(cli: Cli, vault_ready: None) -> None:
    done = cli("--password-stdin", "alias", "set", "NEW", "bank", stdin="not it\n")

    assert done.returncode == 4
    with opened() as vault:
        assert "NEW" not in vault.aliases


def test_alias_ls_tells_a_grant_holder_that_a_grant_cannot_list_aliases(cli: Cli, vault_ready: None) -> None:
    token = grant(cli, "GITHUB_TOKEN")

    done = as_agent(cli, token, "alias", "ls")

    assert done.returncode == 5
    assert "irondome ls" in done.stderr
    assert [listed["uses_left"] for listed in json.loads(cli("--json", "grant", "ls").stdout)["grants"]] == [1]


def test_commands_that_need_a_vault_say_which_bunker_has_none(cli: Cli) -> None:
    alpha = as_owner(cli, "alias", "ls")
    bravo = as_owner(cli, "grant", "create", "GITHUB_TOKEN", env={"IRONDOME_BUNKER": "bravo"})
    scanned = as_owner(cli, "--bunker", "bravo", "scan", ".")

    assert alpha.returncode == 6 and "there is no vault in bunker alpha. Create it with: irondome init" in alpha.stderr
    assert bravo.returncode == 6 and "there is no vault in bunker bravo" in bravo.stderr
    assert "irondome bunker create bravo" in bravo.stderr
    assert scanned.returncode == 6 and "bunker bravo" in scanned.stderr


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------


def planted_tree(root: Path) -> Path:
    tree = root / "leaks"
    (tree / "agent" / "session").mkdir(parents=True)
    (tree / "agent" / "session" / "transcript.jsonl").write_text(
        '{"role": "tool", "content": "ok"}\n{"role": "tool", "content": "BANK=' + BANK_PASSWORD + '"}\n'
    )
    basic = base64.b64encode(("admin:" + BANK_PASSWORD).encode()).decode()
    (tree / "ci.log").write_text("step 1\nstep 2\nAuthorization: Basic " + basic + "\n")
    (tree / "dump.txt").write_text("\n\n\n" + BANK_PASSWORD.encode().hex() + "\n")
    (tree / "notes.md").write_text("nothing here\n")
    return tree


def test_scan_finds_a_planted_password_in_plain_base64_and_hex_and_never_prints_it(
    cli: Cli, vault_ready: None, tmp_path: Path
) -> None:
    tree = planted_tree(tmp_path)

    done = as_owner(cli, "scan", str(tree))
    document = json.loads(as_owner(cli, "--json", "scan", str(tree)).stdout)

    assert done.returncode == 1
    rows = [line.split() for line in done.stdout.splitlines()]
    assert rows[0] == ["PATH:LINE", "ENTRY", "FIELD", "ENCODING"]
    assert sorted(rows[1:]) == sorted(
        [
            [f"{tree}/agent/session/transcript.jsonl:2", "bank", "password", "plain"],
            [f"{tree}/ci.log:3", "bank", "password", "base64"],
            [f"{tree}/dump.txt:4", "bank", "password", "hex"],
        ]
    )
    assert "1 secret found in 3 files" in done.stderr
    assert set(document) == {"hits", "files_scanned", "files_skipped"}
    hits = document["hits"]
    found = [(Path(hit["path"]).name, hit["line"], hit["entry"], hit["field"], hit["encoding"]) for hit in hits]
    assert sorted(found) == [
        ("ci.log", 3, "bank", "password", "base64"),
        ("dump.txt", 4, "bank", "password", "hex"),
        ("transcript.jsonl", 2, "bank", "password", "plain"),
    ]
    assert (document["files_scanned"], document["files_skipped"]) == (4, 0)
    assert leaked(BANK_PASSWORD, done.stdout, done.stderr, json.dumps(document)) == []


def test_scan_of_a_clean_tree_exits_0(cli: Cli, vault_ready: None, tmp_path: Path) -> None:
    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "readme.md").write_text("no secrets here\n")

    done = as_owner(cli, "scan", str(clean))

    assert done.returncode == 0, done.stderr
    assert done.stdout == ""
    assert "no secret from the vault was found" in done.stderr


def test_scan_counts_what_it_skips(cli: Cli, vault_ready: None, tmp_path: Path) -> None:
    tree = planted_tree(tmp_path)
    os.symlink(tree / "ci.log", tree / "link.log")
    with open(tree / "huge.bin", "wb") as handle:
        handle.truncate(50 * 1024 * 1024 + 1)

    done = as_owner(cli, "scan", str(tree))
    document = json.loads(as_owner(cli, "--json", "scan", str(tree)).stdout)

    assert done.returncode == 1
    assert "skipped 2: 1 symbolic link, 1 larger than 50 MB" in done.stderr
    assert (document["files_scanned"], document["files_skipped"]) == (4, 2)


def test_scan_finds_totp_seeds_custom_fields_and_previous_passwords(
    cli: Cli, vault_ready: None, tmp_path: Path
) -> None:
    with opened() as vault:
        github = vault.find("github")
        vault.update(github, secret=Secret(password="ghp_RotatedToken9876543210", totp=otp.make_totp(SEED)))
        vault.commit()
    leaks = tmp_path / "leaks"
    leaks.mkdir()
    (leaks / "qr.txt").write_text(f"otpauth://totp/GitHub:king?secret={SEED}&issuer=GitHub\n")
    (leaks / "lower.txt").write_text(f"seed: {SEED.lower()}\n")
    (leaks / "old.txt").write_text(f"old token {GITHUB_PASSWORD}\n")
    (leaks / "env.txt").write_text(f"DATABASE_URL={DB_URL}\n")

    document = json.loads(as_owner(cli, "--json", "scan", str(leaks)).stdout)

    assert sorted((Path(hit["path"]).name, hit["entry"], hit["field"]) for hit in document["hits"]) == [
        ("env.txt", "prod-db", "dsn"),
        ("lower.txt", "github", "totp"),
        ("old.txt", "github", "previous password"),
        ("qr.txt", "github", "totp"),
    ]


def test_scan_is_for_the_owner_and_checks_its_paths_before_unlocking(
    cli: Cli, vault_ready: None, tmp_path: Path
) -> None:
    token = grant(cli, "GITHUB_TOKEN")

    by_agent = as_agent(cli, token, "scan", str(tmp_path))
    missing = cli("--password-stdin", "scan", str(tmp_path / "missing"), stdin="")
    wrong = cli("--password-stdin", "scan", str(tmp_path), stdin="not it\n")

    assert by_agent.returncode == 5
    assert missing.returncode == 2 and "does not exist" in missing.stderr
    assert wrong.returncode == 4


# ---------------------------------------------------------------------------
# mcp
# ---------------------------------------------------------------------------

CLAUDE_SERVERS = {
    "mcpServers": {"irondome": {"command": "irondome", "args": ["mcp"], "env": {"IRONDOME_GRANT": "${IRONDOME_GRANT}"}}}
}
SNIPPETS: Dict[str, Sequence[Any]] = {
    "claude-code": ["claude mcp add --transport stdio --scope user irondome -- irondome mcp", CLAUDE_SERVERS],
    "claude-desktop": [CLAUDE_SERVERS],
    "cursor": [
        {
            "mcpServers": {
                "irondome": {
                    "type": "stdio",
                    "command": "irondome",
                    "args": ["mcp"],
                    "env": {"IRONDOME_GRANT": "${env:IRONDOME_GRANT}"},
                }
            }
        }
    ],
    "codex": ['[mcp_servers.irondome]\ncommand = "irondome"\nargs = ["mcp"]\nenv_vars = ["IRONDOME_GRANT"]'],
    "vscode": [{"servers": {"irondome": {"type": "stdio", "command": "irondome", "args": ["mcp"]}}}],
    "zed": [{"context_servers": {"irondome": {"command": "irondome", "args": ["mcp"], "env": {}}}}],
}
WHERE = {
    "claude-desktop": "~/Library/Application Support/Claude/claude_desktop_config.json",
    "cursor": "~/.cursor/mcp.json",
    "codex": "~/.codex/config.toml",
    "vscode": ".vscode/mcp.json",
    "zed": "~/.config/zed/settings.json",
}


def files_under(root: Path) -> List[str]:
    return sorted(str(path.relative_to(root)) for path in root.rglob("*"))


@pytest.mark.parametrize("client", sorted(SNIPPETS))
def test_mcp_config_prints_the_verified_snippet_and_writes_nothing(cli: Cli, client: str, isolated: Path) -> None:
    home = isolated / "userhome"
    before = files_under(home)

    done = cli("mcp", "config", "--client", client)

    assert done.returncode == 0, done.stderr
    blocks = done.stdout.rstrip("\n").split("\n\n")
    expected = SNIPPETS[client]
    assert len(blocks) == len(expected)
    for block, snippet in zip(blocks, expected):
        assert (json.loads(block) if isinstance(snippet, dict) else block) == snippet
    if client in WHERE:
        assert WHERE[client] in done.stderr
    assert "never written into the file" in done.stderr
    assert files_under(home) == before
    assert not TOKEN.search(done.stdout + done.stderr)


def test_mcp_config_without_a_client_prints_them_all_and_json_names_where_each_goes(cli: Cli) -> None:
    every = cli("mcp", "config")
    document = json.loads(cli("--json", "mcp", "config").stdout)

    assert every.returncode == 0
    assert len(every.stdout.rstrip("\n").split("\n\n")) == sum(len(snippets) for snippets in SNIPPETS.values())
    assert [(item["client"], item["kind"]) for item in document["snippets"]] == [
        ("claude-code", "command"),
        ("claude-code", "file"),
        ("claude-desktop", "file"),
        ("cursor", "file"),
        ("codex", "file"),
        ("vscode", "file"),
        ("zed", "file"),
    ]
    assert all(set(item) == {"client", "kind", "file", "text"} for item in document["snippets"])


def test_mcp_serves_on_stdio_and_returns_its_status(cli: Cli, vault_ready: None) -> None:
    request = {"jsonrpc": "2.0", "id": 7, "method": "tools/list", "params": {}}

    done = cli("mcp", stdin=json.dumps(request) + "\n")

    assert done.returncode == 0, done.stderr
    replies = [json.loads(line) for line in done.stdout.splitlines() if line.strip()]
    assert [(reply["jsonrpc"], reply["id"]) for reply in replies] == [("2.0", 7)]


@pytest.mark.parametrize(
    "arguments, message",
    [
        (["--json", "mcp"], "--json does not apply"),
        (["mcp", "--touch-timeout", "soon"], "not a duration"),
        (["mcp", "--touch-timeout", "0"], "Touch ID timeout"),
        (["mcp", "config", "--client", "notepad"], "invalid choice"),
    ],
)
def test_mcp_refuses_bad_options(cli: Cli, arguments: List[str], message: str) -> None:
    done = cli(*arguments)

    assert done.returncode == 2
    assert message in done.stderr
