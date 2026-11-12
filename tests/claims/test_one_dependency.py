"""Claim ``one-dependency``: one runtime dependency.

Statement: the package depends on the Python standard library and on
``cryptography``, and on nothing else. The only native code is a Secure
Enclave helper compiled on your machine from source shipped in the package.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

import irondome

if sys.version_info >= (3, 11):
    import tomllib
else:  # pytest itself depends on tomli before Python 3.11
    import tomli as tomllib

REPOSITORY = Path(__file__).resolve().parents[2]
PACKAGE = Path(irondome.__file__).resolve().parent

#: Standard-library top-level modules IronDome is allowed to use (Python 3.9 has no sys.stdlib_module_names).
STDLIB = frozenset(
    """
    __future__ abc argparse ast atexit base64 binascii codecs collections contextlib copy csv ctypes dataclasses
    datetime difflib errno fcntl fnmatch functools gc getpass grp hashlib heapq hmac importlib io itertools json math
    mmap msvcrt os pathlib platform pwd queue re resource secrets selectors shlex shutil signal stat string struct
    subprocess sys tempfile termios textwrap threading time traceback typing unicodedata urllib winreg
    """.split()
)


def project() -> dict:
    return tomllib.loads((REPOSITORY / "pyproject.toml").read_text(encoding="utf-8"))["project"]


def requirement_name(requirement: str) -> str:
    match = re.match(r"[A-Za-z0-9][A-Za-z0-9._-]*", requirement.strip())
    assert match, requirement
    return match.group(0).lower()


def imported_roots() -> dict:
    """``{top-level module: [where]}`` for every import, static or dynamic with a literal name."""
    found: dict = {}
    for path in sorted(PACKAGE.rglob("*.py")):
        where = path.relative_to(PACKAGE).as_posix()
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            names = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names = [node.module]
            elif isinstance(node, ast.Call):
                function = node.func
                called = function.attr if isinstance(function, ast.Attribute) else getattr(function, "id", None)
                if called in ("__import__", "import_module") and node.args and isinstance(node.args[0], ast.Constant):
                    names = [str(node.args[0].value)]
            for name in names:
                found.setdefault(name.split(".")[0], []).append(where)
    return found


def test_the_metadata_declares_exactly_one_runtime_requirement_and_it_is_cryptography():
    dependencies = project()["dependencies"]
    assert [requirement_name(item) for item in dependencies] == ["cryptography"]
    assert re.fullmatch(r"cryptography>=\d+(\.\d+)*", dependencies[0].replace(" ", ""))


def test_the_optional_extras_are_for_development_only():
    extras = project().get("optional-dependencies", {})
    assert set(extras) <= {"dev"}
    assert "cryptography" not in {requirement_name(item) for item in extras.get("dev", [])}


def test_no_module_imports_any_other_third_party_package():
    third_party = {root: where for root, where in imported_roots().items()
                   if root not in STDLIB and root not in ("irondome", "cryptography")}
    assert third_party == {}


def test_the_package_ships_no_compiled_code_and_the_helpers_source():
    compiled = [path.name for path in PACKAGE.rglob("*") if path.suffix in (".so", ".pyd", ".dylib", ".dll", ".exe")]
    assert compiled == []
    source = PACKAGE / "device" / "irondome_se.swift"
    assert source.is_file() and "SecureEnclave.P256.KeyAgreement.PrivateKey" in source.read_text(encoding="utf-8")
    data = project()
    assert data.get("scripts") == {"irondome": "irondome.cli.main:main"}
    package_data = tomllib.loads((REPOSITORY / "pyproject.toml").read_text())["tool"]["setuptools"]["package-data"]
    assert "device/*.swift" in package_data["irondome"]


def test_the_helper_is_compiled_here_from_that_source_and_named_after_its_hash(monkeypatch, tmp_path):
    import hashlib

    from irondome.device import macos_se

    monkeypatch.delenv("IRONDOME_SE_HELPER", raising=False)
    digest = hashlib.sha256(macos_se.helper_source().read_bytes()).hexdigest()[:16]
    assert macos_se._helper_path().name == f"irondome-se-{digest}"
    assert macos_se.helper_source().resolve() == (PACKAGE / "device" / "irondome_se.swift").resolve()


# -- the boundary ------------------------------------------------------------------


def test_boundary_cryptography_brings_its_own_openssl():
    from cryptography.hazmat.backends.openssl.backend import backend

    assert "OpenSSL" in backend.openssl_version_text()
