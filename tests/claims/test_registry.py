"""The meta-test: the claims registry, its tests, its document and what the README says hold together.

``src/irondome/claims.json`` is the one list of what IronDome promises. This
file fails the build if a claim has no test, if a listed test does not exist,
if a claim's own test file has a test the registry does not list, if a
``selfcheck`` names a check ``irondome verify`` does not have, if
``docs/CLAIMS.md`` is not exactly what ``scripts/claims.py`` renders, if one of
the 3.x limits L1-L4 is closed by no claim, or if the README or the threat
model refers to a claim the registry does not have.
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


@pytest.mark.parametrize("document", ["README.md", "docs/THREAT_MODEL.md", "docs/ARCHITECTURE.md"])
def test_the_documents_refer_to_no_claim_that_is_not_in_the_registry(document):
    path = REPOSITORY / document
    assert referenced_claims(path.read_text(encoding="utf-8")) - ids() == set()


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
    assert counts["claims"] == len(claims()) and counts["python"] == "3.9–3.14"
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
