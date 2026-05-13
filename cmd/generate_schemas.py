"""Generate JSON Schema files from TRACE Pydantic contract models.

Run once to produce schema/*.schema.json:
  uv run python cmd/generate_schemas.py

These schemas are the consumer-canonical contract TRACE enforces on SAGE
input artifacts. They are committed to git (intentionally NOT gitignored)
and consulted by ``scripts/check_pir_schema_drift.py`` against BEACON's
producer-canonical exports.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

SCHEMA_DIR = Path(__file__).parent.parent / "schema"


def main() -> int:
    SCHEMA_DIR.mkdir(exist_ok=True)

    from trace_engine.validate.schema.models import AssetsDocument, PIRItem

    _write(SCHEMA_DIR / "pir.schema.json", PIRItem.model_json_schema())
    _write(SCHEMA_DIR / "assets.schema.json", AssetsDocument.model_json_schema())

    return 0


def _write(path: Path, schema: dict) -> None:
    path.write_text(json.dumps(schema, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Written: {path}")


if __name__ == "__main__":
    sys.exit(main())
