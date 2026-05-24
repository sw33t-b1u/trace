"""Tests for the unified ``trace`` CLI entry point (Initiative H Phase 6).

Coverage:
  - ``trace --help`` lists every Phase 6 subcommand (12 entries from
    ``docs/api-stability.md`` §3.8).
  - ``trace <subcommand> --help`` resolves to the wrapped command's
    real help formatter (argparse text for the argparse-based wrappers,
    click text for ``search-iocs``).
  - End-to-end: ``trace validate-pir --pir <wrapped 1.0.0 fixture>``
    runs the underlying validator with exit code 0.
  - Each ``cmd/<name>.py`` direct invocation prints the
    ``DeprecationWarning`` line steering operators to ``trace
    <subcommand>``.

The legacy ``cmd/*.py --help`` checks shell out via subprocess so that
the ``__main__`` block — where the deprecation print lives — actually
executes. ``CliRunner`` cannot test that path because it imports the
module instead of running it as a script.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

from trace_engine.cli import cli

PROJECT_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).parent / "fixtures"

# (subcommand-name, cmd-module-basename, deprecation-substring-marker)
SUBCOMMANDS: list[tuple[str, str, str]] = [
    ("crawl-batch", "crawl_batch", "trace crawl-batch"),
    ("crawl-single", "crawl_single", "trace crawl-single"),
    ("search-iocs", "search_iocs", "trace search-iocs"),
    ("validate-pir", "validate_pir", "trace validate-pir"),
    ("validate-stix", "validate_stix", "trace validate-stix"),
    ("validate-assets", "validate_assets", "trace validate-assets"),
    ("validate-identity", "validate_identity_assets", "trace validate-identity"),
    ("validate-accounts", "validate_user_accounts", "trace validate-accounts"),
    ("validate-all", "validate_all", "trace validate-all"),
    ("enrich-bundle", "enrich_bundle", "trace enrich-bundle"),
    ("submit-review", "submit_review", "trace submit-review"),
    ("taxonomy-refresh", "update_taxonomy_cache", "trace taxonomy-refresh"),
]


# ---------------------------------------------------------------------------
# Group-level wiring
# ---------------------------------------------------------------------------


class TestTraceGroupHelp:
    def test_root_help_lists_every_phase_6_subcommand(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        for cmd_name, _, _ in SUBCOMMANDS:
            assert cmd_name in result.output, (
                f"{cmd_name!r} missing from 'trace --help' output:\n{result.output}"
            )

    def test_root_help_advertises_unified_entry(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert "trace <subcommand> --help" in result.output

    def test_all_12_subcommands_registered(self):
        registered = set(cli.commands.keys())
        expected = {cmd_name for cmd_name, _, _ in SUBCOMMANDS}
        assert registered == expected, (
            f"Subcommand drift — registered={sorted(registered)}, expected={sorted(expected)}"
        )


# ---------------------------------------------------------------------------
# Per-subcommand --help passthrough
# ---------------------------------------------------------------------------


class TestSubcommandHelpPassthrough:
    @pytest.mark.parametrize(
        "subcommand",
        [cmd_name for cmd_name, _, _ in SUBCOMMANDS],
    )
    def test_subcommand_help_resolves(self, subcommand: str):
        """``trace <subcommand> --help`` should exit 0 and emit help text.

        ``help_option_names=[]`` on the wrappers means ``--help`` is
        forwarded to the underlying argparse / click parser, which then
        prints usage and calls ``sys.exit(0)``.
        """
        runner = CliRunner()
        result = runner.invoke(cli, [subcommand, "--help"])
        # argparse / click both exit 0 on --help; CliRunner converts the
        # SystemExit into ``result.exit_code``.
        assert result.exit_code == 0, (
            f"trace {subcommand} --help exited {result.exit_code}:\n"
            f"out={result.output}\nexc={result.exception!r}"
        )
        # Some wrappers print to stdout (argparse default), search-iocs
        # uses click which also prints to stdout. Check combined output
        # contains the usage banner that argparse / click both produce.
        out = result.output.lower()
        assert "usage:" in out or "options:" in out, (
            f"no help banner found for trace {subcommand}:\n{result.output}"
        )


# ---------------------------------------------------------------------------
# End-to-end smoke: trace validate-pir on the canonical wrapped fixture
# ---------------------------------------------------------------------------


class TestTraceValidatePirEndToEnd:
    def test_validate_pir_on_wrapped_fixture_exits_zero(self, tmp_path: Path):
        """``trace validate-pir --pir <wrapped 1.0.0 fixture>`` should succeed."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "validate-pir",
                "--pir",
                str(FIXTURES / "valid_pir.json"),
            ],
        )
        assert result.exit_code == 0, (
            f"trace validate-pir failed: out={result.output}, "
            f"stderr={getattr(result, 'stderr', '')!r}, exc={result.exception!r}"
        )


# ---------------------------------------------------------------------------
# Deprecation warning when invoked via ``python cmd/<name>.py``
# ---------------------------------------------------------------------------


class TestCmdLegacyDeprecation:
    @pytest.mark.parametrize(
        ("subcommand", "cmd_module"),
        [(name, module) for name, module, _ in SUBCOMMANDS],
    )
    def test_cmd_help_emits_deprecation_to_stderr(
        self, subcommand: str, cmd_module: str, tmp_path: Path
    ):
        """``python cmd/<name>.py --help`` should print the deprecation
        line on stderr (in addition to its usage text on stdout).

        Subprocess invocation is required: the deprecation print lives
        in the ``if __name__ == "__main__":`` block which only fires
        when the module runs as a script.
        """
        env = os.environ.copy()
        # Mirror the runtime sandbox profile: drop proxies that interfere
        # with the no-network test run.
        for key in (
            "ALL_PROXY",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
        ):
            env.pop(key, None)
        env.setdefault("UV_CACHE_DIR", str(tmp_path / "uv-cache"))

        proc = subprocess.run(
            [sys.executable, f"cmd/{cmd_module}.py", "--help"],
            cwd=str(PROJECT_ROOT),
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )

        combined = proc.stdout + proc.stderr
        assert "DeprecationWarning" in proc.stderr, (
            f"cmd/{cmd_module}.py --help did not emit DeprecationWarning to "
            f"stderr.\nstdout={proc.stdout}\nstderr={proc.stderr}"
        )
        assert f"trace {subcommand}" in proc.stderr, (
            f"deprecation message missing 'trace {subcommand}' steer:\nstderr={proc.stderr}"
        )
        # --help should still succeed (argparse / click exit 0).
        assert proc.returncode == 0, (
            f"cmd/{cmd_module}.py --help returned {proc.returncode}:\n"
            f"stdout={proc.stdout}\nstderr={proc.stderr}"
        )
        # And the usage text must still appear (we did not break --help).
        assert "usage:" in combined.lower() or "options:" in combined.lower(), (
            f"no usage text from cmd/{cmd_module}.py --help:\n{combined}"
        )
