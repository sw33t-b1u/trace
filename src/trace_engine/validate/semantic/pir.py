"""Semantic checks for ``pir_output.json``.

- ``pir_id`` uniqueness across the document
- every ``threat_actor_tags[*]`` matches the cached threat taxonomy (warning
  on miss — analyst-authored tags outside the canonical vocabulary are
  allowed but flagged for review)
- every ``asset_weight_rules[*].tag`` matches at least one tag on the supplied
  ``assets.json`` (only when assets are passed in — otherwise this check is
  silently skipped)

``valid_from < valid_until`` is already enforced at the schema layer.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from trace_engine.validate.schema.models import AssetsDocument, PIRDocument
from trace_engine.validate.semantic.findings import ValidationFinding
from trace_engine.validate.semantic.taxonomy import load_taxonomy_tags


def check_pir(
    doc: PIRDocument,
    *,
    assets: AssetsDocument | None = None,
    taxonomy_path: Path | None = None,
) -> list[ValidationFinding]:
    findings: list[ValidationFinding] = []

    findings.extend(_check_unique_pir_ids(doc))

    taxonomy_tags = load_taxonomy_tags(taxonomy_path)

    asset_tags: set[str] = set()
    if assets is not None:
        for a in assets.assets:
            asset_tags.update(a.tags)

    for i, pir in enumerate(doc.root):
        loc_base = f"pir[{i}] pir_id={pir.pir_id}"

        for j, tag in enumerate(pir.threat_actor_tags):
            if tag not in taxonomy_tags:
                findings.append(
                    ValidationFinding(
                        severity="warning",
                        code="PIR_TAG_NOT_IN_TAXONOMY",
                        location=f"{loc_base}.threat_actor_tags[{j}]",
                        message=(
                            f"tag {tag!r} is not present in the cached threat "
                            "taxonomy — analyst review recommended"
                        ),
                    )
                )

        if assets is not None:
            for j, rule in enumerate(pir.asset_weight_rules):
                if rule.tag not in asset_tags:
                    findings.append(
                        ValidationFinding(
                            severity="error",
                            code="PIR_RULE_TAG_UNUSED",
                            location=f"{loc_base}.asset_weight_rules[{j}]",
                            message=(
                                f"tag {rule.tag!r} matches no asset tag in the "
                                "supplied assets file — the rule has no effect"
                            ),
                        )
                    )

    return findings


def _check_unique_pir_ids(doc: PIRDocument) -> list[ValidationFinding]:
    ids = [p.pir_id for p in doc.root]
    out: list[ValidationFinding] = []
    for dup, n in Counter(ids).items():
        if n > 1:
            out.append(
                ValidationFinding(
                    severity="error",
                    code="PIR_ID_NOT_UNIQUE",
                    location="pir[*].pir_id",
                    message=f"pir_id {dup!r} appears {n} times",
                )
            )
    return out
