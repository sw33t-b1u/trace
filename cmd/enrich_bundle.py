"""Enrich an external STIX 2.1 bundle with PIR taxonomy labels.

Reads a bundle JSON, injects PIR vocabulary tags (``apt-china``,
``apt-russia``, …) onto every ``threat-actor`` and ``intrusion-set``
object whose name or aliases appear in the taxonomy index, then writes
the result atomically.

External bundles (OpenCTI feeds, hand-authored STIX, old TRACE output)
often lack these tags and are therefore silently dropped by SAGE's
``pir_filter.is_relevant_actor``.  Run this rescue step before
``run_etl --manual-bundle`` to ensure actors are retained.

Usage:
    uv run python cmd/enrich_bundle.py \\
        --input external.json \\
        --output enriched.json

    # Explicit taxonomy snapshot (default: schema/threat_taxonomy.cached.json)
    uv run python cmd/enrich_bundle.py \\
        --input external.json \\
        --output enriched.json \\
        --taxonomy schema/threat_taxonomy.cached.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

import structlog

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from trace_engine.cli._logging import configure as configure_logging  # noqa: E402
from trace_engine.stix.taxonomy_enrich import (  # noqa: E402
    enrich_bundle_objects,
    load_taxonomy_index,
)

configure_logging()
logger = structlog.get_logger(__name__)

_DEFAULT_TAXONOMY = (
    Path(__file__).resolve().parent.parent / "schema" / "threat_taxonomy.cached.json"
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Enrich a STIX 2.1 bundle with PIR taxonomy labels."
    )
    parser.add_argument(
        "--input",
        required=True,
        type=Path,
        metavar="BUNDLE_JSON",
        help="Path to the input STIX bundle JSON.",
    )
    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        metavar="OUTPUT_JSON",
        help="Path for the enriched bundle JSON (written atomically).",
    )
    parser.add_argument(
        "--taxonomy",
        type=Path,
        default=_DEFAULT_TAXONOMY,
        metavar="TAXONOMY_JSON",
        help=f"Taxonomy snapshot path (default: {_DEFAULT_TAXONOMY})",
    )
    args = parser.parse_args()

    if not args.input.exists():
        logger.error("input_not_found", path=str(args.input))
        sys.exit(1)

    try:
        bundle = json.loads(args.input.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        logger.error("input_invalid_json", path=str(args.input), error=str(exc))
        sys.exit(1)

    if not isinstance(bundle, dict):
        logger.error("input_not_a_bundle", path=str(args.input))
        sys.exit(1)

    if not args.taxonomy.exists():
        logger.error("taxonomy_not_found", path=str(args.taxonomy))
        sys.exit(1)

    try:
        index = load_taxonomy_index(args.taxonomy)
    except Exception as exc:
        logger.error("taxonomy_load_failed", path=str(args.taxonomy), error=str(exc))
        sys.exit(1)

    objects = bundle.get("objects", [])
    enriched_count = enrich_bundle_objects(objects, index)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=args.output.parent,
        delete=False,
        suffix=".tmp",
    ) as tmp:
        json.dump(bundle, tmp, indent=2, ensure_ascii=False)
        tmp.write("\n")
        tmp_path = Path(tmp.name)
    os.replace(tmp_path, args.output)

    logger.info(
        "bundle_enriched",
        input=str(args.input),
        output=str(args.output),
        objects_enriched=enriched_count,
        total_objects=len(objects),
    )
    print(f"Enriched {enriched_count}/{len(objects)} objects → {args.output}")


if __name__ == "__main__":
    main()
