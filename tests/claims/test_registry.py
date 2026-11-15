"""The meta-test: the claims registry, its tests, its document and what the README says hold together.

``src/irondome/claims.json`` is the one list of what IronDome promises. This
file fails the build if a claim has no test, if a listed test does not exist,
if a claim's own test file has a test the registry does not list, if a
``selfcheck`` names a check ``irondome verify`` does not have, if
``docs/CLAIMS.md`` is not exactly what ``scripts/claims.py`` renders, if one of
the 3.x limits L1-L4 is closed by no claim, if the README, the threat model,
the architecture or SECURITY.md refers to a claim the registry does not have,
if the README's sample session shows a line the program does not print, or if
the README's exit codes are not exactly the program's.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Set

import pytest

from conftest import PASSWORD
from irondome import selftest

REPOSITORY = Path(__file__).resolve().parents[2]
REGISTRY = REPOSITORY / "src" / "irondome" / "claims.json"
CLAIMS_DIR = REPOSITORY / "tests" / "claims"
ID = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*")
CLAIM_KEYS = {"id", "title", "statement", "boundary", "platforms", "closes", "tests", "selfcheck"}


def registry() -> Dict[str, Any]:
    return json.loads(REGISTRY.read_text(encoding="utf-8"))


def claims() -> List[Dict[str, Any]]:
    return registry()["claims"]


def ids() -> Set[str]:
    return {claim["id"] for claim in claims()}


def script(name: str):
    spec = importlib.util.spec_from_file_location(f"irondome_script_{name}", REPOSITORY / "scripts" / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def own_file(claim_id: str) -> Path:
    return CLAIMS_DIR / f"test_{claim_id.replace('-', '_')}.py"


def functions_in(path: Path) -> List[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return [node.name for node in tree.body if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")]


@pytest.fixture(scope="module")
def collected() -> Set[str]:
    """Node ids pytest itself collects for every file the registry names (run in a subprocess)."""
    files = sorted({node.split("::")[0] for claim in claims() for node in claim["tests"]})
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider", *files],
        cwd=str(REPOSITORY), capture_output=True, text=True, timeout=600,
    )
    assert result.returncode == 0, result.stdout[-2000:] + result.stderr[-2000:]
    return {line.strip() for line in result.stdout.splitlines() if "::" in line}


def test_the_registry_is_well_formed():
    document = registry()
    assert document["version"] == 1 and document["about"].strip()
    limits = document["closed_limits"]
    assert all(re.fullmatch(r"L\d+", key) and text.strip() for key, text in limits.items())
    seen = set()
    for claim in document["claims"]:
        assert set(claim) == CLAIM_KEYS, claim["id"]
        assert ID.fullmatch(claim["id"]) and claim["id"] not in seen
        seen.add(claim["id"])
        assert claim["title"].strip() and claim["statement"].strip() and claim["boundary"].strip()
        assert claim["platforms"] and set(claim["platforms"]) <= {"macos", "linux", "windows"}
        assert set(claim["closes"]) <= set(limits), claim["id"]
        assert claim["selfcheck"] is None or re.fullmatch(r"[a-z_]+", claim["selfcheck"])
        assert len(claim["tests"]) == len(set(claim["tests"])), f"{claim['id']} lists a test twice"


def test_every_claim_has_at_least_one_test():
    assert [claim["id"] for claim in claims() if not claim["tests"]] == []


def test_every_claim_has_a_test_file_of_its_own_and_lists_it():
    for claim in claims():
        path = own_file(claim["id"])
        assert path.is_file(), f"{claim['id']} has no {path.relative_to(REPOSITORY)}"
        prefix = f"{path.relative_to(REPOSITORY).as_posix()}::"
        assert any(node.startswith(prefix) for node in claim["tests"]), claim["id"]


def test_every_test_in_a_claims_own_file_is_listed_under_that_claim():
    for claim in claims():
        path = own_file(claim["id"])
        listed = {node.split("::", 1)[1].split("[")[0] for node in claim["tests"]
                  if node.startswith(f"{path.relative_to(REPOSITORY).as_posix()}::")}
        assert set(functions_in(path)) == listed, claim["id"]


def test_there_is_no_claim_file_without_a_claim():
    expected = {own_file(claim_id).name for claim_id in ids()} | {"test_registry.py"}
    assert {path.name for path in CLAIMS_DIR.glob("test_*.py")} == expected


def test_every_listed_test_exists(collected):
    missing = []
    for claim in claims():
        for node in claim["tests"]:
            if node not in collected and not any(found.startswith(node + "[") for found in collected):
                missing.append(f"{claim['id']}: {node}")
    assert missing == []


def test_every_listed_test_is_defined_where_it_says():
    """The same, without pytest: each node id names a file and a function in it."""
    for claim in claims():
        for node in claim["tests"]:
            path, _, name = node.partition("::")
            assert (REPOSITORY / path).is_file(), node
            assert name.split("[")[0] in functions_in(REPOSITORY / path), node


def test_every_selfcheck_names_a_check_that_irondome_verify_runs():
    named = {claim["selfcheck"] for claim in claims() if claim["selfcheck"] is not None}
    assert named - set(selftest.CHECKS) == set()
    assert set(selftest.CHECKS) - named == set(), "a check that no claim names"
    assert all(callable(check) for check in selftest.CHECKS.values())


def test_the_limits_of_3x_l1_to_l4_are_each_closed_by_a_claim():
    document = registry()
    for limit in ("L1", "L2", "L3", "L4"):
        assert limit in document["closed_limits"]
        assert [claim["id"] for claim in document["claims"] if limit in claim["closes"]], limit


def test_claims_md_is_exactly_what_the_script_renders():
    rendered = script("claims").render(registry())
    assert (REPOSITORY / "docs" / "CLAIMS.md").read_text(encoding="utf-8") == rendered


def test_the_claims_script_check_passes_now_and_fails_on_a_stale_document(tmp_path, monkeypatch):
    checked = subprocess.run([sys.executable, str(REPOSITORY / "scripts" / "claims.py"), "--check"],
                             capture_output=True, text=True, timeout=60)
    assert checked.returncode == 0, checked.stderr
    module = script("claims")
    stale = tmp_path / "CLAIMS.md"
    stale.write_text(module.render(registry()).replace("Key material", "Keys"), encoding="utf-8")
    monkeypatch.setattr(module, "DOCUMENT", stale)
    assert module.main(["--check"]) == 1
    assert module.main(["render"]) == 0 and module.main(["--check"]) == 0


def test_the_document_names_every_claim_its_tests_and_its_check():
    text = (REPOSITORY / "docs" / "CLAIMS.md").read_text(encoding="utf-8")
    for claim in claims():
        assert f"## {claim['id']}\n" in text and claim["statement"] in text and claim["boundary"] in text
        for node in claim["tests"]:
            assert f"[`{node}`](../{node.split('::')[0]})" in text
        if claim["selfcheck"]:
            assert f"`irondome verify --claim {claim['id']}` (check `{claim['selfcheck']}`)" in text


def referenced_claims(text: str) -> Set[str]:
    """Claim ids a document refers to: CLAIMS.md anchors, ``--claim ID`` and "claim `ID`"."""
    found = set(re.findall(r"CLAIMS\.md#([a-z0-9-]+)", text))
    found |= set(re.findall(r"--claim[ =]([a-z0-9-]+)", text))
    found |= set(re.findall(r"\bclaims?\s+`([a-z0-9-]+)`", text, flags=re.IGNORECASE))
    return found


@pytest.mark.parametrize("document", ["README.md", "docs/THREAT_MODEL.md", "docs/ARCHITECTURE.md", "SECURITY.md"])
def test_the_documents_refer_to_no_claim_that_is_not_in_the_registry(document):
    path = REPOSITORY / document
    assert referenced_claims(path.read_text(encoding="utf-8")) - ids() == set()


def test_security_md_refers_to_claims_and_each_one_exists():
    """SECURITY.md sends reporters to the claims; the claims it names by anchor must be real ones."""
    named = referenced_claims((REPOSITORY / "SECURITY.md").read_text(encoding="utf-8"))
    assert named and named <= ids()


# -- what the README quotes of the program ---------------------------------------------


def _readme_hero() -> List[str]:
    """The README's first console block, line by line."""
    text = (REPOSITORY / "README.md").read_text(encoding="utf-8")
    block = re.search(r"```console\n(.*?)```", text, flags=re.DOTALL)
    assert block is not None
    return block.group(1).splitlines()


#: What differs from one run to the next in the README's sample output (a shortened token, ids, a time), and
#: what each stands for in what the program prints.
_VARIABLE = re.compile(
    r"(irondome_g_[0-9a-f]{4}…)|((?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f]))|((?<![0-9a-f])[0-9a-f]{12}(?![0-9a-f]))"
    r"|(\d{4}-\d\d-\d\d \d\d:\d\d)"
)
_REAL = (r"irondome_g_[0-9a-f]{32}_[A-Z2-7]{52}", "[0-9a-f]{32}", "[0-9a-f]{12}", r"\d{4}-\d\d-\d\d \d\d:\d\d")
#: Prompts the program writes on the terminal, where the README's reader types; with --password-stdin it
#: writes none.
_PROMPTS = {"Master password:", "Value for github:"}


def _pattern(line: str) -> "re.Pattern[str]":
    """*line* as an expression: its literal text exactly, its variable parts as what they stand for."""
    parts, last = [], 0
    for match in _VARIABLE.finditer(line):
        parts += [re.escape(line[last : match.start()]), _REAL[(match.lastindex or 1) - 1]]
        last = match.end()
    return re.compile("".join(parts) + re.escape(line[last:]))


def test_the_readme_sample_session_prints_exactly_what_the_program_prints(cli):
    """Every command of the README's first block runs here, and every line it shows is a line the program printed."""
    blocks: List[List[str]] = []
    for line in _readme_hero():
        if line.startswith("$ "):
            blocks.append([line])
        elif line.strip():
            blocks[-1].append(line)
    commands = [block[0] for block in blocks]
    assert commands[0].startswith("$ irondome add github --kind secret --alias GITHUB_TOKEN")
    # The token is never shown or typed: the shell puts it straight into the agent's environment.
    assert commands[1].startswith('$ export IRONDOME_GRANT="$(irondome grant create GITHUB_TOKEN --ttl 15m)"')
    agent = "$ irondome run --env GITHUB_TOKEN -- sh -c 'echo \"got $GITHUB_TOKEN\"'"
    assert commands[2:] == [agent, agent]
    assert "irondome_g_" not in "\n".join(_readme_hero())
    init_done = cli("init", "--password-stdin", stdin=PASSWORD + "\n")
    assert init_done.returncode == 0, init_done.stderr
    # The same commands with what the reader types at the prompts on stdin instead.
    added = cli("add", "github", "--kind", "secret", "--alias", "GITHUB_TOKEN", "--password-stdin", "--value-stdin",
                stdin=f"{PASSWORD}\nghp_{'x' * 36}\n")
    created = cli("grant", "create", "GITHUB_TOKEN", "--ttl", "15m", "--password-stdin", stdin=PASSWORD + "\n")
    token = {"IRONDOME_GRANT": created.stdout.strip()}
    run = ["run", "--env", "GITHUB_TOKEN", "--", "sh", "-c", 'echo "got $GITHUB_TOKEN"']
    printed = [added, created, cli(*run, env=token), cli(*run, env=token)]
    assert [done.returncode for done in printed] == [0, 0, 0, 4]
    for block, done in zip(blocks, printed):
        real = done.stdout.splitlines() + done.stderr.splitlines()
        for shown in block[1:]:
            if shown.strip() in _PROMPTS:
                continue
            assert any(_pattern(shown).fullmatch(line) for line in real), (shown, real)


def test_the_readme_lists_every_exit_status_the_program_has():
    """The README's exit codes are errors.py's, run's own and 130, and nothing else."""
    from irondome import errors
    from irondome.agent import runner

    text = (REPOSITORY / "README.md").read_text(encoding="utf-8")
    paragraph = re.search(r"Exit codes: (.*?)\n\n", text, flags=re.DOTALL)
    assert paragraph is not None
    listed = {int(number) for number in re.findall(r"(?<![\w-])(\d{1,3})(?![\w-])", paragraph.group(1))}
    defined = {
        value.exit_code for module in (errors, runner) for value in vars(module).values()
        if isinstance(value, type) and issubclass(value, errors.IronDomeError)
    }
    assert defined | {errors.EXIT_OK, errors.EXIT_INTERRUPTED} == listed - {128}


def test_the_readme_points_at_the_claims_and_at_irondome_verify():
    readme = (REPOSITORY / "README.md").read_text(encoding="utf-8")
    assert "docs/CLAIMS.md" in readme and "irondome verify" in readme


def test_the_reference_finder_finds_what_it_should():
    text = "see [x](docs/CLAIMS.md#crypto-erase), `irondome verify --claim no-such-claim` and the claim `fake-id`."
    assert referenced_claims(text) == {"crypto-erase", "no-such-claim", "fake-id"}


# -- the website's data ---------------------------------------------------------------


def test_site_data_writes_what_the_website_reads_and_checks_it(tmp_path):
    site = tmp_path / "site"
    (site / "src" / "data").mkdir(parents=True)
    (site / "src" / "data" / "transcript.txt").write_text("$ irondome verify\n", encoding="utf-8")
    run = [sys.executable, str(REPOSITORY / "scripts" / "site_data.py"), str(site)]
    written = subprocess.run(run, capture_output=True, text=True, timeout=600)
    assert written.returncode == 0, written.stderr
    counts = json.loads((site / "src" / "data" / "counts.json").read_text(encoding="utf-8"))
    assert set(counts) == {"version", "tests", "claims", "files", "python"}
    assert counts["claims"] == len(claims()) and counts["python"] == "3.9.2–3.14"
    assert sum(counts["files"].values()) == counts["tests"] and "tests/claims" in counts["files"]
    assert (site / "src" / "data" / "claims.json").read_bytes() == REGISTRY.read_bytes()
    assert subprocess.run(run + ["--check"], capture_output=True, timeout=600).returncode == 0
    (site / "src" / "data" / "transcript.txt").write_text("# PROVISIONAL\nwritten by hand\n", encoding="utf-8")
    provisional = subprocess.run(run + ["--check"], capture_output=True, text=True, timeout=600)
    assert provisional.returncode == 1 and "provisional" in provisional.stderr
    (site / "src" / "data" / "transcript.txt").write_text("$ irondome verify\n", encoding="utf-8")
    (site / "src" / "data" / "claims.json").write_text("{}", encoding="utf-8")
    assert subprocess.run(run + ["--check"], capture_output=True, timeout=600).returncode == 1


def test_both_scripts_use_the_standard_library_only():
    allowed = set(sys.builtin_module_names) | {"argparse", "json", "re", "subprocess", "sys", "pathlib", "typing",
                                               "__future__"}
    for name in ("claims", "site_data"):
        tree = ast.parse((REPOSITORY / "scripts" / f"{name}.py").read_text(encoding="utf-8"))
        imported = {alias.name.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.Import)
                    for alias in node.names}
        imported |= {node.module.split(".")[0] for node in ast.walk(tree)
                     if isinstance(node, ast.ImportFrom) and node.module}
        assert imported <= allowed, (name, imported - allowed)
