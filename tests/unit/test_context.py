"""The per-invocation context: who is asking, which token counts, and what a refusal tells them."""

from __future__ import annotations

import argparse
import io
from typing import List, Optional, Tuple

import pytest

from irondome import audit, caps, otp, paths
from irondome.cli import context as context_module
from irondome.cli.context import ENV_GRANT, ENV_SESSION, PURPOSE_REVEAL, Access, Context
from irondome.cli.output import Output
from irondome.errors import AuthError, HardwareError, PolicyError, UsageError, VaultError
from irondome.secmem import SecureBuffer
from irondome.vault import Secret

pytestmark = pytest.mark.usefixtures("isolated")

TOKEN = "irondome_g_" + "0" * 32 + "_" + "A" * 52


def make_context(**options) -> Tuple[Context, io.StringIO]:
    errors = io.StringIO()
    out = Output(stdout=io.StringIO(), stderr=errors, color=False)
    return Context(argparse.Namespace(**options.pop("args", {})), out, **options), errors


def test_a_caller_that_serves_an_agent_is_never_the_owner(monkeypatch: pytest.MonkeyPatch) -> None:
    """The MCP server can inherit its host's terminal; nobody at that terminal is asking."""
    monkeypatch.setattr(context_module, "_has_terminal", lambda: True)
    agent, _ = make_context(agent=True)
    assert agent.agent_mode is True and agent.has_terminal is False
    owner, _ = make_context()
    assert owner.agent_mode is False and owner.has_terminal is True


def test_without_a_terminal_and_a_password_it_is_an_agent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(context_module, "_has_terminal", lambda: False)
    assert make_context()[0].agent_mode is True
    assert make_context(args={"password_stdin": True})[0].agent_mode is False


@pytest.mark.parametrize("variable", [ENV_GRANT, ENV_SESSION])
def test_a_token_is_read_without_the_whitespace_around_it(monkeypatch: pytest.MonkeyPatch, variable: str) -> None:
    """`export IRONDOME_GRANT="$(...)"` and a pasted token can bring a newline or spaces with them."""
    for raw, expected in ((f"  {TOKEN}\n", TOKEN), (TOKEN, TOKEN), ("   \n", None), ("", None)):
        monkeypatch.setenv(variable, raw)
        assert context_module._token(variable) == expected
    monkeypatch.delenv(variable)
    assert context_module._token(variable) is None


def test_bunker_selection_and_access_agree_on_a_padded_token(monkeypatch: pytest.MonkeyPatch, bank_vault) -> None:
    token, _ = caps.create_grant(bank_vault, ["BANK"], uses=1)
    monkeypatch.setenv(ENV_GRANT, f"{token}\n")
    with make_context()[0].access() as access:
        assert access.via_grant and access.names() == ["BANK"]


def test_refusals_name_the_way_the_caller_injects_values(bank_vault) -> None:
    entry = bank_vault.find("bank")
    for ctx, expected in ((make_context()[0], "`irondome run`"),
                          (make_context(agent=True, inject_with="the run_with_secrets tool")[0],
                           "the run_with_secrets tool")):
        with pytest.raises(PolicyError, match="Inject it with " + expected.replace("`", ".")):
            Access(ctx, vault=bank_vault, restricted=True)._check_policy(entry, "password", PURPOSE_REVEAL)
    token, _ = caps.create_grant(bank_vault, ["BANK"], uses=2)
    for inject_with in ("`irondome run`", "the run_with_secrets tool"):
        ctx, _ = make_context(inject_with=inject_with)
        with caps.open_grant(token) as grant:
            with pytest.raises(PolicyError, match="into a command with " + inject_with.replace("`", ".")):
                Access(ctx, grant=grant).value("BANK", PURPOSE_REVEAL)


def test_a_session_that_cannot_be_used_right_now_falls_back_to_the_password(
    monkeypatch: pytest.MonkeyPatch, bank_vault, password: str
) -> None:
    """A locked Mac or a busy TPM makes the session unusable for a moment; the owner can still unlock."""
    monkeypatch.setenv(ENV_SESSION, TOKEN)

    def unusable(token, file):
        raise HardwareError("the Mac is locked; unlock it and try again")

    monkeypatch.setattr(caps, "open_session", unusable)
    ctx, errors = make_context(args={"password_stdin": True})

    def piped_password() -> SecureBuffer:  # what --password-stdin would read
        ctx._asked_password = True
        return SecureBuffer.from_buffer(password.encode())

    monkeypatch.setattr(ctx, "master_password", piped_password)
    vault = ctx.open_vault()
    try:
        assert ctx.unlocked_by == "password"
        assert vault.find("bank").name == "bank"
    finally:
        vault.close()
    assert "ignoring IRONDOME_SESSION: the Mac is locked" in errors.getvalue()


@pytest.fixture
def bank_vault(make_vault):
    vault, _ = make_vault(with_recovery=False)
    entry = vault.add("bank", Secret(password="correct-horse-pin-4711"), agent="use")
    vault.set_alias("BANK", entry)
    vault.commit()
    return vault


# -- prove_owner -------------------------------------------------------------


def piping(monkeypatch: pytest.MonkeyPatch, ctx: Context, text: str) -> List[str]:
    """Make *ctx* read *text* as the --password-stdin line; returns the list each read is noted in."""
    reads: List[str] = []

    def piped() -> SecureBuffer:
        reads.append(text)
        if not text:  # what reading an empty line from stdin says
            raise UsageError("nothing was entered")
        return SecureBuffer.from_buffer(text.encode())

    monkeypatch.setattr(ctx, "master_password", piped)
    return reads


def test_prove_owner_refuses_a_caller_that_serves_an_agent_whatever_it_holds(
    monkeypatch: pytest.MonkeyPatch, bank_vault, password: str
) -> None:
    monkeypatch.setattr(context_module, "_has_terminal", lambda: True)
    ctx, _ = make_context(agent=True, args={"password_stdin": True})
    reads = piping(monkeypatch, ctx, password)
    with pytest.raises(PolicyError, match="serves an agent"):
        ctx.prove_owner("removing a bunker")
    assert reads == []


def test_prove_owner_lets_a_person_at_a_terminal_through_without_asking(
    monkeypatch: pytest.MonkeyPatch, bank_vault
) -> None:
    monkeypatch.setattr(context_module, "_has_terminal", lambda: True)
    ctx, _ = make_context()
    reads = piping(monkeypatch, ctx, "never read")
    assert ctx.prove_owner("making bunker alpha the default") is None and reads == []


def test_prove_owner_without_a_terminal_or_a_password_says_what_would_work(
    monkeypatch: pytest.MonkeyPatch, bank_vault
) -> None:
    monkeypatch.setattr(context_module, "_has_terminal", lambda: False)
    with pytest.raises(PolicyError, match="at a terminal, or give the master password of bunker alpha with --pass"):
        make_context()[0].prove_owner("ending every session")


def test_prove_owner_with_a_password_checks_it_against_the_vault_and_never_a_session(
    monkeypatch: pytest.MonkeyPatch, bank_vault, password: str
) -> None:
    """The flag alone proves nothing: an agent can pass --password-stdin with any line, or none."""
    monkeypatch.setattr(context_module, "_has_terminal", lambda: False)
    monkeypatch.setenv(ENV_SESSION, caps.create_session(bank_vault, ttl=300))  # a session counts for nothing here
    for wrong, refusal in (("", UsageError), ("not the password", AuthError)):
        ctx, _ = make_context(args={"password_stdin": True})
        piping(monkeypatch, ctx, wrong)
        with pytest.raises(refusal):
            ctx.prove_owner("removing bunker alpha", bunker="alpha")
    ctx, _ = make_context(args={"password_stdin": True})
    reads = piping(monkeypatch, ctx, password)
    assert ctx.prove_owner("removing bunker alpha") is None and reads == [password]
    ctx, _ = make_context(args={"password_stdin": True})
    piping(monkeypatch, ctx, password)
    opened = ctx.prove_owner("revoking a grant", keep_open=True)
    assert opened is not None and ctx.unlocked_by == "password"
    with opened:
        assert opened.find("bank").name == "bank"


def test_prove_owner_refuses_before_reading_a_password_where_no_vault_can_check_it(
    monkeypatch: pytest.MonkeyPatch, bank_vault, password: str
) -> None:
    monkeypatch.setattr(context_module, "_has_terminal", lambda: False)
    ctx, _ = make_context(args={"password_stdin": True})
    reads = piping(monkeypatch, ctx, password)
    with pytest.raises(VaultError, match="no vault in bunker bravo"):
        ctx.prove_owner("removing bunker bravo", bunker="bravo")
    paths.vault_file().write_bytes(b"{ damaged")
    with pytest.raises(VaultError, match="cannot be read"):
        ctx.prove_owner("removing bunker alpha")
    assert reads == []


# -- looking at a grant before a use is spent ------------------------------------


def uses_left(token: str) -> Optional[int]:
    (info,) = [item for item in caps.list_caps() if token.split("_")[2] == item.id]
    return info.uses_left


def test_a_request_the_grant_refuses_spends_none_of_its_uses(monkeypatch: pytest.MonkeyPatch, bank_vault) -> None:
    entry = bank_vault.add("site", Secret(password="site-password-1", totp=otp.make_totp("JBSWY3DPEHPK3PXP")))
    bank_vault.commit()
    token, _ = caps.create_grant(bank_vault, ["BANK", "site/totp"], uses=1)
    monkeypatch.setenv(ENV_GRANT, token)
    ctx, _ = make_context()
    with pytest.raises(PolicyError, match="does not cover 'OTHER'.*Nothing was used"):
        ctx.access(references=["OTHER"], purpose=PURPOSE_REVEAL, detail="test")
    with pytest.raises(PolicyError, match=r"does not allow showing them \(say why\)\. Nothing was used"):
        ctx.access(references=["BANK"], purpose=PURPOSE_REVEAL, reveal_hint="say why")
    assert uses_left(token) == 1
    with ctx.access(references=["site/totp"], purpose=PURPOSE_REVEAL) as access:  # a code may be shown
        assert access.value("site/totp", PURPOSE_REVEAL).isdigit()
    assert caps.list_caps() == []  # that was its one use
    assert entry.name == "site"
    refusals = [event for event in audit.read(bank_vault, limit=None) if event.kid == token.split("_")[2]]
    assert [(event.action, event.target, event.ok) for event in refusals if not event.ok] == [
        ("reveal", "OTHER", False), ("reveal", "BANK", False),
    ]


# -- an agent with --touch -------------------------------------------------------


def test_an_agent_with_touch_on_a_vault_without_touch_id_is_pointed_at_grants(
    monkeypatch: pytest.MonkeyPatch, bank_vault
) -> None:
    monkeypatch.setattr(context_module, "_has_terminal", lambda: False)
    ctx, _ = make_context(args={"touch": True})
    with pytest.raises(AuthError) as refused:
        ctx.open_vault()
    message = str(refused.value)
    assert "no keyslot that opens with Touch ID alone" in message
    assert "irondome grant create" in message and "irondome approve" in message
    assert "the master password is required" not in message
