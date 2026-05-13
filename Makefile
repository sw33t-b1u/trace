.PHONY: check vet lint format test test-integration audit setup check-pir-schema-drift

# Full quality gate: vet → lint → test → audit → schema drift
check: vet lint test audit check-pir-schema-drift

vet:
	uv run ruff check src/ cmd/ tests/

lint:
	uv run ruff format --check src/ cmd/ tests/

format:
	uv run ruff format src/ cmd/ tests/
	uv run ruff check --fix src/ cmd/ tests/

test:
	uv run python -m pytest tests/ -v -m "not integration"

test-integration:
	uv run python -m pytest tests/ -v -m integration

audit:
	PIPAPI_PYTHON_LOCATION=.venv/bin/python3 uv run pip-audit

# Compare BEACON's producer-canonical PIR schema against TRACE's consumer
# canonical. Skips silently when the BEACON sibling repo is not checked out
# so TRACE-only contributors can still run `make check`.
check-pir-schema-drift:
	@if [ -f ../BEACON/schema/pir_output.schema.json ]; then \
		python3 scripts/check_pir_schema_drift.py \
			../BEACON/schema/pir_output.schema.json \
			schema/pir.schema.json; \
	else \
		echo "skip: ../BEACON/schema/pir_output.schema.json not found"; \
	fi

setup:
	git config core.hooksPath .githooks
	chmod +x .githooks/pre-commit .githooks/pre-push
	@echo "Git hooks installed (pre-commit: vet+lint, pre-push: full check)."
