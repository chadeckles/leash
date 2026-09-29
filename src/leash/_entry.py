"""Console entry point.  ``leash hook`` is called on every agent tool call,
so it skips the full CLI (argparse tree, httpx) and goes straight to the
runner."""

from __future__ import annotations

import sys


def main() -> None:
    argv = sys.argv[1:]
    if argv[:1] == ["hook"] and len(argv) <= 2 and not any(a.startswith("-") for a in argv):
        from leash.hooks.runner import run

        sys.exit(run(argv[1] if len(argv) == 2 else "auto"))
    from leash.cli import main as cli_main

    cli_main()
