"""Unified ``trace`` CLI entry point (Initiative H Phase 6 — TRACE 1.12.0).

Each subcommand is a thin click wrapper that delegates to the existing
``cmd/<name>.py`` module's ``main()``. The wrappers exist for two reasons:

* ``[project.scripts] trace = "trace_engine.cli:cli"`` becomes the
  single committed CLI surface (see ``docs/api-stability.md`` §3.8).
* The legacy ``python -m cmd.<name>`` invocations keep working for the
  1.x line so existing automation / runbooks do not break overnight;
  they print a ``DeprecationWarning`` and are scheduled for removal in
  TRACE 2.0.

Subcommands fall into two classes:

* **argparse-based wrappers** — most ``cmd/*.py`` modules use
  ``argparse`` inside ``main()``. The wrapper rewrites ``sys.argv`` and
  calls ``main()`` so ``trace <subcommand> --help`` reaches argparse and
  prints the real argument help.
* **click-based wrappers** — ``cmd/search_iocs.py`` already exposes a
  ``click.command``; the wrapper invokes it via ``main(args=...,
  standalone_mode=True)`` so ``--help`` is handled by click natively.

Both flavours use ``context_settings`` with ``help_option_names=[]`` so
the parent ``trace`` group does NOT intercept ``--help`` — it falls
through to the wrapped command's own help formatter.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import click

# ``cmd/*.py`` lives as a top-level directory at the repo root (sibling
# of ``src/``). It is intentionally NOT a package — historically each
# module is launched with ``python -m cmd.<name>`` from the repo root.
# Loading via ``importlib.import_module("cmd.<name>")`` collides with
# the stdlib ``cmd`` module, so we resolve each module by file path
# below; the loaded module is cached in ``sys.modules`` under a
# ``_trace_cmd_<name>`` key.
_PROJECT_ROOT = Path(__file__).resolve().parents[3]
_CMD_DIR = _PROJECT_ROOT / "cmd"


@click.group(
    context_settings={"help_option_names": ["-h", "--help"]},
    help=(
        "TRACE — Threat Report Analyzer & Crawling Engine.\n\n"
        "Unified entry point for the crawl / validate / enrich / submit "
        "workflows. Run 'trace <subcommand> --help' for the wrapped "
        "command's flag reference."
    ),
)
def cli() -> None:
    """TRACE top-level command group."""


def _load_cmd_module(name: str) -> ModuleType:
    """Load ``cmd/<name>.py`` by file path, bypassing the stdlib ``cmd`` shadow."""
    cache_key = f"_trace_cmd_{name}"
    cached = sys.modules.get(cache_key)
    if cached is not None:
        return cached
    cmd_path = _CMD_DIR / f"{name}.py"
    spec = importlib.util.spec_from_file_location(cache_key, cmd_path)
    if spec is None or spec.loader is None:
        raise ModuleNotFoundError(f"trace CLI: could not locate cmd/{name}.py at {cmd_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[cache_key] = module
    spec.loader.exec_module(module)
    return module


def _delegate_argparse(module: str, prog_name: str, args: list[str]) -> None:
    """Forward ``args`` to an argparse-based ``cmd/<module>.py:main()``."""
    mod = _load_cmd_module(module)
    saved_argv = sys.argv
    sys.argv = [prog_name, *args]
    try:
        result = mod.main()
    finally:
        sys.argv = saved_argv
    if isinstance(result, int) and result != 0:
        sys.exit(result)


def _delegate_click(module: str, prog_name: str, args: list[str]) -> None:
    """Forward ``args`` to a click-based ``cmd/<module>.py:main`` command."""
    mod = _load_cmd_module(module)
    mod.main(args=args, prog_name=prog_name, standalone_mode=True)


def _register_passthrough(
    cmd_name: str,
    module: str,
    short_help: str,
    *,
    kind: str = "argparse",
) -> None:
    """Register a click subcommand that forwards every flag to ``cmd/<module>.py``.

    ``ignore_unknown_options`` + ``allow_extra_args`` ensure click does
    not parse the wrapped command's flags; ``help_option_names=[]``
    delegates ``--help`` to the wrapped command so the operator sees the
    real argparse / click help output.
    """

    @cli.command(
        cmd_name,
        context_settings={
            "ignore_unknown_options": True,
            "allow_extra_args": True,
            "help_option_names": [],
        },
        short_help=short_help,
    )
    @click.pass_context
    def _wrapper(ctx: click.Context) -> None:  # noqa: D401
        prog = f"trace {cmd_name}"
        if kind == "click":
            _delegate_click(module, prog, list(ctx.args))
        else:
            _delegate_argparse(module, prog, list(ctx.args))

    _wrapper.__name__ = cmd_name.replace("-", "_")


# ---------------------------------------------------------------------------
# Subcommand table (docs/api-stability.md §3.8) — verb-noun naming.
# ---------------------------------------------------------------------------

_register_passthrough(
    "crawl-batch",
    "crawl_batch",
    "Batch crawl URLs from input/sources.yaml into STIX bundles.",
)
_register_passthrough(
    "crawl-single",
    "crawl_single",
    "Convert a single PDF / URL to a STIX 2.1 bundle.",
)
_register_passthrough(
    "search-iocs",
    "search_iocs",
    "Search the crawl_state IoC index for an indicator value.",
    kind="click",
)
_register_passthrough(
    "validate-pir",
    "validate_pir",
    "Validate BEACON pir_output.json (1.0.0 envelope).",
)
_register_passthrough(
    "validate-stix",
    "validate_stix",
    "Validate a STIX 2.1 bundle (OASIS validator + TRACE checks).",
)
_register_passthrough(
    "validate-assets",
    "validate_assets",
    "Validate assets.json before SAGE ingestion.",
)
_register_passthrough(
    "validate-identity",
    "validate_identity_assets",
    "Validate identity_assets.json (requires --it-assets).",
)
_register_passthrough(
    "validate-accounts",
    "validate_user_accounts",
    "Validate user_accounts.json (requires --it-assets).",
)
_register_passthrough(
    "validate-all",
    "validate_all",
    "Run every applicable TRACE validator and emit a Markdown report.",
)
_register_passthrough(
    "enrich-bundle",
    "enrich_bundle",
    "Enrich an external STIX bundle with PIR taxonomy tags.",
)
_register_passthrough(
    "submit-review",
    "submit_review",
    "Hand a TRACE validation report to a human reviewer.",
)
_register_passthrough(
    "taxonomy-refresh",
    "update_taxonomy_cache",
    "Refresh schema/threat_taxonomy.cached.json from BEACON.",
)


__all__ = ["cli"]
