"""``irondome verify``: check, on this machine, that IronDome does what it claims.

Every claim IronDome makes is in ``claims.json`` with a check that proves it.
This command runs those checks here, with this machine's device backend, in a
private temporary directory. Your own vaults are never opened, changed or
deleted. See :mod:`irondome.selftest` for what each check does.
"""

from __future__ import annotations

import argparse
import sys
from typing import Any, Dict, List

from irondome import __version__, selftest
from irondome.cli.context import Context

__all__ = ["register", "verify"]

_DESCRIPTION = """\
Run, on this machine, the check behind every claim IronDome makes: device
binding, the security chip, Touch ID, nuke, wiping keys from memory,
encryption, tamper evidence, no network, file modes, grants, masking, the
audit log, bunkers and the recovery key. Everything happens in a private
temporary directory; your own vaults, keys, sessions and grants are never
touched, and nothing asks for a password. A claim that needs hardware this
machine does not have is reported as skipped, never as passed.
"""

_EPILOG = """\
results: pass (shown here), FAIL (does not hold here: exit status 1), skipped
(this machine cannot show it, or only the test suite can).
--touch adds the one check that needs you: a single Touch ID prompt proving
that a Touch ID key works after a touch (the automated check proves that it
refuses without one). The memory check searches this process's whole address
space and takes about a minute on a Mac.

examples:
  irondome verify                           every claim, here
  irondome verify --claim tamper-evident    one claim, by the id the results show
"""


def register(subparsers: Any, common: argparse.ArgumentParser) -> None:
    parser = subparsers.add_parser(
        "verify",
        parents=[common],
        help="check on this machine that IronDome does what it claims",
        description=_DESCRIPTION,
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--claim",
        metavar="ID",
        action="append",
        dest="claims",
        default=None,
        help="check only this claim (repeat for several); default: every claim",
    )
    parser.set_defaults(handler=verify)


def verify(ctx: Context, args: argparse.Namespace) -> int:
    """Run the checks; exit status 1 if any claim does not hold here."""
    touch = bool(getattr(args, "touch", False))
    claims: List[str] = list(args.claims or [])
    ctx.out.info(
        "Running IronDome's claim checks in a private temporary directory. Your own vaults are not opened."
    )
    if touch:
        ctx.out.info("One check will ask for Touch ID: touch the sensor when the prompt appears.")
    report = selftest.run(claims or None, touch=touch, progress=ctx.out.info)
    failed = report.count(selftest.FAIL)
    if ctx.out.json_mode:
        ctx.out.json(_document(report))
    else:
        rows = [(outcome.claim, outcome.result.status, outcome.result.detail) for outcome in report.outcomes]
        ctx.out.table(("claim", "result", "detail"), rows)
    for note in report.notes:
        ctx.out.warn(note)
    kind = "hardware" if report.hardware else "file-based, not hardware"
    summary = (
        f"{len(report.outcomes)} claims on {report.backend} ({kind}): {report.count(selftest.PASS)} pass, "
        f"{failed} FAIL, {report.count(selftest.SKIPPED)} skipped"
    )
    if failed:
        ctx.out.warn(f"{summary}. A FAIL means that claim does not hold on this machine; please report it.")
        return 1
    ctx.out.ok(summary)
    return 0


def _document(report: selftest.Report) -> Dict[str, Any]:
    return {
        "version": __version__,
        "python": sys.version.split()[0],
        "platform": sys.platform,
        "backend": {"name": report.backend, "hardware": report.hardware, "detail": report.backend_detail},
        "results": [
            {
                "claim": outcome.claim,
                "title": outcome.title,
                "check": outcome.check,
                "result": outcome.result.status,
                "detail": outcome.result.detail,
                "seconds": outcome.seconds,
            }
            for outcome in report.outcomes
        ],
        "passed": report.count(selftest.PASS),
        "failed": report.count(selftest.FAIL),
        "skipped": report.count(selftest.SKIPPED),
        "notes": list(report.notes),
    }
