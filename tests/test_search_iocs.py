"""Tests for ``cmd/search_iocs.py`` (Initiative G Phase 5)."""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

# CLI mutates sys.path on import (matches sibling cmds).
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).parent.parent / "cmd"))

search_iocs = importlib.import_module("search_iocs")


FIXTURE = Path(__file__).parent / "fixtures" / "state_with_iocs.json"


def _make_runner() -> CliRunner:
    # click >= 8.2 dropped ``mix_stderr=False``; constructor with no args
    # already splits stderr (matches the test_register_incident_cli convention).
    return CliRunner()


# ---------------------------------------------------------------------------
# Fake TLP resolver — keyed by bundle filename so test fixtures don't need
# real STIX files on disk.
# ---------------------------------------------------------------------------


def _fake_tlp_resolver(bundle_path):
    if not bundle_path:
        return "clear"
    name = str(bundle_path)
    if "red" in name:
        return "red"
    if "amber" in name:
        return "amber"
    if "green" in name:
        return "green"
    return "clear"


def _invoke(args):
    runner = _make_runner()
    # Patch the bundle TLP resolver inside the CLI so we don't have to
    # write real STIX bundles. The CLI's ``search()`` helper accepts an
    # injectable ``tlp_resolver``; ``main`` doesn't expose it directly,
    # so we monkey-patch ``read_bundle_tlp`` at the module level.
    with patch.object(search_iocs, "read_bundle_tlp", side_effect=_fake_tlp_resolver):
        return runner.invoke(search_iocs.main, args)


# ---------------------------------------------------------------------------
# Happy path / table output
# ---------------------------------------------------------------------------


class TestSearchHappyPath:
    def test_match_found_prints_url_in_table(self):
        result = _invoke(["--ioc", "evil.example.com", "--state-path", str(FIXTURE)])
        assert result.exit_code == 0, result.output + result.stderr
        # The fqdn appears in clear/amber/red bundles → amber default
        # excludes red → 2 matches expected (clear + amber).
        assert "clear-article" in result.output
        assert "amber-article" in result.output
        assert "red-article" not in result.output
        assert "2 match" in result.output

    def test_match_count_message(self):
        result = _invoke(["--ioc", "192.0.2.10", "--state-path", str(FIXTURE)])
        assert result.exit_code == 0
        assert "1 match" in result.output

    def test_case_insensitive_value_match(self):
        result = _invoke(["--ioc", "EVIL.EXAMPLE.COM", "--state-path", str(FIXTURE)])
        assert result.exit_code == 0
        # Same 2 matches as the lower-case query.
        assert "clear-article" in result.output
        assert "amber-article" in result.output


# ---------------------------------------------------------------------------
# No-match path
# ---------------------------------------------------------------------------


class TestNoMatch:
    def test_no_match_exit_0_with_message(self):
        result = _invoke(["--ioc", "not-in-state.example.com", "--state-path", str(FIXTURE)])
        assert result.exit_code == 0
        assert "No matches" in result.output
        assert "0 match" in result.output


# ---------------------------------------------------------------------------
# --type narrows results
# ---------------------------------------------------------------------------


class TestTypeFilter:
    def test_type_filter_narrows_results(self):
        """Searching the SHA-256 hash with --type fqdn yields zero matches."""
        sha = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        result = _invoke(["--ioc", sha, "--type", "fqdn", "--state-path", str(FIXTURE)])
        assert result.exit_code == 0
        assert "0 match" in result.output

    def test_type_filter_matches_when_aligned(self):
        sha = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        result = _invoke(["--ioc", sha, "--type", "sha256", "--state-path", str(FIXTURE)])
        assert result.exit_code == 0
        assert "1 match" in result.output

    def test_type_filter_case_insensitive(self):
        result = _invoke(
            ["--ioc", "CVE-2026-12345", "--type", "CVE_ID", "--state-path", str(FIXTURE)]
        )
        assert result.exit_code == 0
        assert "1 match" in result.output

    def test_invalid_type_value_returns_usage_error(self):
        result = _invoke(
            ["--ioc", "evil.example.com", "--type", "registry_key", "--state-path", str(FIXTURE)]
        )
        assert result.exit_code == 2


# ---------------------------------------------------------------------------
# --tlp-max enforcement
# ---------------------------------------------------------------------------


class TestTlpFilter:
    def test_default_amber_hides_red(self):
        result = _invoke(["--ioc", "evil.example.com", "--state-path", str(FIXTURE)])
        assert "red-article" not in result.output
        assert "clear-article" in result.output

    def test_tlp_max_red_includes_red_bundles(self):
        result = _invoke(
            ["--ioc", "evil.example.com", "--tlp-max", "red", "--state-path", str(FIXTURE)]
        )
        assert "red-article" in result.output
        assert "3 match" in result.output  # clear + amber + red

    def test_tlp_max_clear_excludes_everything_above(self):
        result = _invoke(
            ["--ioc", "evil.example.com", "--tlp-max", "clear", "--state-path", str(FIXTURE)]
        )
        assert "clear-article" in result.output
        assert "amber-article" not in result.output
        assert "red-article" not in result.output
        assert "1 match" in result.output

    def test_tlp_max_green_includes_clear_and_green_only(self):
        # The green bundle holds the SHA — verify it surfaces under
        # --tlp-max=green while amber/red bundles for the same IoC
        # remain hidden.
        result = _invoke(
            ["--ioc", "evil.example.com", "--tlp-max", "green", "--state-path", str(FIXTURE)]
        )
        assert "clear-article" in result.output
        assert "amber-article" not in result.output
        assert "red-article" not in result.output


# ---------------------------------------------------------------------------
# --json output is valid JSON
# ---------------------------------------------------------------------------


class TestJsonOutput:
    def test_json_flag_emits_valid_json(self):
        result = _invoke(["--ioc", "evil.example.com", "--json", "--state-path", str(FIXTURE)])
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert isinstance(parsed, list)
        assert len(parsed) == 2
        urls = {p["matched_url"] for p in parsed}
        assert "https://example.com/articles/clear-article" in urls
        assert "https://example.com/articles/amber-article" in urls

    def test_json_match_record_carries_required_keys(self):
        result = _invoke(["--ioc", "evil.example.com", "--json", "--state-path", str(FIXTURE)])
        parsed = json.loads(result.output)
        entry = parsed[0]
        for key in (
            "type",
            "matched_url",
            "value",
            "confidence",
            "context_snippet",
            "first_seen",
            "last_seen",
            "bundle_path",
            "bundle_tlp",
        ):
            assert key in entry, f"missing key {key} in match record"

    def test_json_no_match_emits_empty_list(self):
        result = _invoke(
            [
                "--ioc",
                "not-in-state.example.com",
                "--json",
                "--state-path",
                str(FIXTURE),
            ]
        )
        assert result.exit_code == 0
        assert json.loads(result.output) == []


# ---------------------------------------------------------------------------
# --state-path override + error paths
# ---------------------------------------------------------------------------


class TestStatePathHandling:
    def test_missing_state_file_exits_2(self, tmp_path):
        bogus = tmp_path / "does-not-exist.json"
        result = _invoke(["--ioc", "evil.example.com", "--state-path", str(bogus)])
        assert result.exit_code == 2
        assert "not found" in result.stderr.lower() or "not found" in result.output.lower()

    def test_malformed_state_file_exits_2(self, tmp_path):
        path = tmp_path / "crawl_state.json"
        path.write_text("{not valid json")
        result = _invoke(["--ioc", "evil.example.com", "--state-path", str(path)])
        assert result.exit_code == 2

    def test_state_path_override_loads_custom_file(self, tmp_path):
        path = tmp_path / "custom_state.json"
        path.write_text(FIXTURE.read_text())
        result = _invoke(["--ioc", "evil.example.com", "--state-path", str(path)])
        assert result.exit_code == 0
        assert "clear-article" in result.output


# ---------------------------------------------------------------------------
# read_bundle_tlp helper — direct coverage so the real TLP resolver
# (which the rest of these tests mock) is at least exercised.
# ---------------------------------------------------------------------------


class TestReadBundleTlp:
    def test_missing_path_returns_clear(self):
        assert search_iocs.read_bundle_tlp(None) == "clear"
        assert search_iocs.read_bundle_tlp("") == "clear"

    def test_nonexistent_file_returns_clear(self, tmp_path):
        assert search_iocs.read_bundle_tlp(tmp_path / "missing.json") == "clear"

    def test_bundle_without_marking_returns_clear(self, tmp_path):
        path = tmp_path / "bundle.json"
        path.write_text(json.dumps({"type": "bundle", "objects": []}))
        assert search_iocs.read_bundle_tlp(path) == "clear"

    @pytest.mark.parametrize(
        "marking_ref,expected_level",
        [
            # TLP 2.0 canonical IDs
            ("marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487", "clear"),
            ("marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb", "green"),
            ("marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421", "amber"),
            ("marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1", "red"),
            # TLP 1.0 legacy
            ("marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed", "red"),
            ("marking-definition--f88d31f6-486f-44da-b317-01333bde0b82", "amber"),
        ],
    )
    def test_canonical_marking_refs_resolve(self, tmp_path, marking_ref, expected_level):
        path = tmp_path / "bundle.json"
        path.write_text(
            json.dumps(
                {
                    "type": "bundle",
                    "objects": [
                        {
                            "type": "indicator",
                            "id": "indicator--00000000-0000-0000-0000-000000000001",
                            "object_marking_refs": [marking_ref],
                        }
                    ],
                }
            )
        )
        assert search_iocs.read_bundle_tlp(path) == expected_level

    def test_most_restrictive_wins(self, tmp_path):
        """A bundle with both GREEN and RED markings should resolve to RED."""
        path = tmp_path / "bundle.json"
        path.write_text(
            json.dumps(
                {
                    "type": "bundle",
                    "objects": [
                        {
                            "type": "indicator",
                            "id": "indicator--00000000-0000-0000-0000-000000000001",
                            "object_marking_refs": [
                                "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb",
                            ],
                        },
                        {
                            "type": "indicator",
                            "id": "indicator--00000000-0000-0000-0000-000000000002",
                            "object_marking_refs": [
                                "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1",
                            ],
                        },
                    ],
                }
            )
        )
        assert search_iocs.read_bundle_tlp(path) == "red"
