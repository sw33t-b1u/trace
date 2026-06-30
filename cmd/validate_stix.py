"""Validate a STIX 2.1 bundle before SAGE ingests it.

Layers:
  1. OASIS ``stix2-validator`` — schema + value conformance.
  2. TRACE-local checks — id uniqueness, ``relationship.{source_ref,target_ref}``
     resolution, ``kill_chain_name == "mitre-attack"``, and
     ``bundle.spec_version == "2.1"``.

``--strict`` promotes OASIS warnings to errors. Without it, warnings are
recorded but do not block ingestion.

Usage:
    uv run python cmd/validate_stix.py --bundle output/stix_bundle_<...>.json
    uv run python cmd/validate_stix.py --bundle b.json --strict

.. deprecated:: TRACE 1.12.0

    Direct invocation as ``python -m cmd.validate_stix`` /
    ``python cmd/validate_stix.py`` is deprecated. Use the unified
    ``trace validate-stix`` entry (Initiative H Phase 6). Removal is
    scheduled for TRACE 2.0.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import structlog

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from trace_engine.cli._logging import configure as configure_logging  # noqa: E402
from trace_engine.config import load_config  # noqa: E402
from trace_engine.io.inputs import resolve_json_input  # noqa: E402
from trace_engine.review.markdown_report import render_report  # noqa: E402
from trace_engine.validate.semantic.findings import (  # noqa: E402
    ValidationFinding,
    has_errors,
)
from trace_engine.validate.semantic.relationships import (  # noqa: E402
    check_identity_ref_resolution,
    check_relationship_type_match,
)
from trace_engine.validate.stix import (  # noqa: E402
    check_stix_bundle,
    run_stix2_validator,
)

configure_logging()
logger = structlog.get_logger(__name__)


def validate_bundle_file(
    path: Path,
    *,
    strict: bool,
    identity_assets_path: Path | None = None,
) -> list[ValidationFinding]:
    with path.open() as f:
        bundle = json.load(f)
    ia_payload = None
    if identity_assets_path is not None:
        with identity_assets_path.open() as f:
            ia_payload = json.load(f)
    return validate_bundle_payload(bundle, strict=strict, identity_assets_payload=ia_payload)


def validate_bundle_payload(
    bundle: object,
    *,
    strict: bool,
    identity_assets_payload: object | None = None,
) -> list[ValidationFinding]:
    findings: list[ValidationFinding] = []
    findings.extend(run_stix2_validator(bundle, strict=strict))
    findings.extend(check_stix_bundle(bundle))
    findings.extend(check_relationship_type_match(bundle))
    if identity_assets_payload is not None:
        known_ids: set[str] = set()
        groups = (
            identity_assets_payload
            if isinstance(identity_assets_payload, list)
            else [identity_assets_payload]
        )
        for group in groups:
            for ident in group.get("identities") or []:
                if isinstance(ident, dict) and ident.get("id"):
                    known_ids.add(ident["id"])
        findings.extend(check_identity_ref_resolution(bundle, known_ids))
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate a STIX 2.1 bundle")
    parser.add_argument(
        "--bundle",
        "-b",
        required=True,
        help="Path, gs:// URI, or stix/ storage key for STIX bundle JSON",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Promote OASIS validator warnings to errors",
    )
    parser.add_argument("--report", type=Path, default=None, help="Markdown report output path")
    parser.add_argument(
        "--identity-assets",
        "--ida",
        default=None,
        dest="identity_assets",
        help=(
            "Path, gs:// URI, or assets/ storage key for identity_assets.json "
            "to check x-identity-internal identity_id cross-references"
        ),
    )
    args = parser.parse_args()
    cfg = load_config()

    try:
        bundle_payload, bundle_input = resolve_json_input(cfg, "stix", args.bundle)
    except FileNotFoundError:
        logger.error("file_not_found", path=str(args.bundle))
        sys.exit(1)
    except Exception as exc:  # noqa: BLE001
        logger.error("bundle_invalid", path=str(args.bundle), error=str(exc))
        sys.exit(1)
    identity_assets_payload = None
    if args.identity_assets is not None:
        try:
            identity_assets_payload, _ = resolve_json_input(cfg, "assets", args.identity_assets)
        except FileNotFoundError:
            logger.error("file_not_found", path=str(args.identity_assets))
            sys.exit(1)
        except Exception as exc:  # noqa: BLE001
            logger.error("identity_assets_invalid", path=str(args.identity_assets), error=str(exc))
            sys.exit(1)

    findings = validate_bundle_payload(
        bundle_payload,
        strict=args.strict,
        identity_assets_payload=identity_assets_payload,
    )

    for f in findings:
        log_method = logger.error if f.severity == "error" else logger.warning
        log_method(f.code, location=f.location, message=f.message)

    if args.report:
        text = render_report(
            [(f"STIX bundle: {bundle_input.display_name}", findings)],
            timestamp=datetime.now(tz=UTC),
        )
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(text, encoding="utf-8")
        print(f"Report written: {args.report}")

    errors = sum(1 for f in findings if f.severity == "error")
    warnings = sum(1 for f in findings if f.severity == "warning")
    print(f"stix validation: errors={errors} warnings={warnings}")
    sys.exit(1 if has_errors(findings) else 0)
