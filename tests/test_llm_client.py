"""Tests for trace_engine/llm/client.py — Google Gen AI is fully mocked.

The client is a deliberate parallel copy of BEACON's ``llm/client.py``
(no cross-repo import per Rule 26); this file mirrors BEACON's
``tests/test_llm_client.py`` so drift between the two copies surfaces
in whichever repo diverges.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from trace_engine.config import Config


def _make_config(**kwargs) -> Config:
    defaults = dict(
        gcp_project_id="test-project",
        vertex_location="us-central1",
        llm_model_simple="gemini-2.5-flash",
        llm_model_medium="gemini-2.5-flash",
        llm_model_complex="gemini-2.5-pro",
    )
    defaults.update(kwargs)
    return Config(**defaults)


def _mock_response(text: str) -> MagicMock:
    resp = MagicMock()
    resp.text = text
    return resp


def _make_mock_genai(response_text: str) -> tuple[MagicMock, MagicMock]:
    """Return (mock_genai_module, mock_client_instance)."""
    mock_client = MagicMock()
    mock_client.models.generate_content.return_value = _mock_response(response_text)

    mock_genai = MagicMock()
    mock_genai.Client.return_value = mock_client

    return mock_genai, mock_client


def _reset_client():
    import trace_engine.llm.client as m

    m._client = None
    m._client_config = None


class TestCallLlm:
    def setup_method(self):
        _reset_client()

    def test_returns_model_text(self):
        config = _make_config()
        expected = '{"key": "value"}'
        mock_genai, _ = _make_mock_genai(expected)

        with patch("trace_engine.llm.client.genai", mock_genai):
            from trace_engine.llm.client import call_llm

            result = call_llm("simple", "test prompt", config=config)

        assert result == expected

    def test_selects_simple_model(self):
        config = _make_config()
        mock_genai, mock_client = _make_mock_genai("{}")

        with patch("trace_engine.llm.client.genai", mock_genai):
            from trace_engine.llm.client import call_llm

            call_llm("simple", "test", config=config)

        call_kwargs = mock_client.models.generate_content.call_args.kwargs
        assert call_kwargs["model"] == "gemini-2.5-flash"

    def test_selects_medium_model(self):
        config = _make_config()
        mock_genai, mock_client = _make_mock_genai("{}")

        with patch("trace_engine.llm.client.genai", mock_genai):
            from trace_engine.llm.client import call_llm

            call_llm("medium", "test", config=config)

        call_kwargs = mock_client.models.generate_content.call_args.kwargs
        assert call_kwargs["model"] == "gemini-2.5-flash"

    def test_selects_complex_model(self):
        config = _make_config()
        mock_genai, mock_client = _make_mock_genai("{}")

        with patch("trace_engine.llm.client.genai", mock_genai):
            from trace_engine.llm.client import call_llm

            call_llm("complex", "test", config=config)

        call_kwargs = mock_client.models.generate_content.call_args.kwargs
        assert call_kwargs["model"] == "gemini-2.5-pro"


class TestMaxOutputTokens:
    def setup_method(self):
        _reset_client()

    def test_default_budget_when_caller_omits(self):
        config = _make_config()
        mock_genai, mock_client = _make_mock_genai("{}")

        with patch("trace_engine.llm.client.genai", mock_genai):
            from trace_engine.llm.client import call_llm

            call_llm("simple", "test", config=config)

        actual = mock_client.models.generate_content.call_args.kwargs["config"]
        assert actual.max_output_tokens == 8192

    def test_explicit_override_wins(self):
        config = _make_config()
        mock_genai, mock_client = _make_mock_genai("{}")

        with patch("trace_engine.llm.client.genai", mock_genai):
            from trace_engine.llm.client import call_llm

            call_llm("simple", "test", config=config, max_output_tokens=99999)

        actual = mock_client.models.generate_content.call_args.kwargs["config"]
        assert actual.max_output_tokens == 99999


class TestCallLlmJson:
    def setup_method(self):
        _reset_client()

    def test_parses_json_response(self):
        config = _make_config()
        payload = {"score": 0.82, "matched_pir_ids": ["PIR-2025-001"]}
        mock_genai, _ = _make_mock_genai(json.dumps(payload))

        with patch("trace_engine.llm.client.genai", mock_genai):
            from trace_engine.llm.client import call_llm_json

            result = call_llm_json("simple", "test", config=config)

        assert result == payload

    def test_raises_on_invalid_json(self):
        config = _make_config()
        mock_genai, _ = _make_mock_genai("not json at all")

        with patch("trace_engine.llm.client.genai", mock_genai):
            from trace_engine.llm.client import call_llm_json

            with pytest.raises(ValueError, match="non-JSON"):
                call_llm_json("simple", "test", config=config)


class TestLoadPrompt:
    def test_stix_extraction_prompt_has_placeholders(self):
        from trace_engine.llm.client import load_prompt

        text = load_prompt("stix_extraction.md")
        assert "{{REPORT_TEXT}}" in text
        assert "{{PIR_CONTEXT_BLOCK}}" in text
        assert len(text) > 100

    def test_relevance_check_prompt_has_placeholders(self):
        from trace_engine.llm.client import load_prompt

        text = load_prompt("relevance_check.md")
        assert "{{ARTICLE_TEXT}}" in text
        assert "{{PIR_CONTEXT}}" in text

    def test_raises_for_missing_prompt(self):
        from trace_engine.llm.client import load_prompt

        with pytest.raises(FileNotFoundError):
            load_prompt("nonexistent_prompt.md")


class TestEnsureClient:
    def setup_method(self):
        _reset_client()

    def teardown_method(self):
        _reset_client()

    def test_creates_client_with_correct_args(self):
        config = _make_config(gcp_project_id="my-project", vertex_location="us-central1")
        mock_genai = MagicMock()

        with patch("trace_engine.llm.client.genai", mock_genai):
            from trace_engine.llm.client import _ensure_client

            _ensure_client(config)

        mock_genai.Client.assert_called_once_with(
            vertexai=True,
            project="my-project",
            location="us-central1",
        )

    def test_skips_reinit_same_config(self):
        config = _make_config()

        import trace_engine.llm.client as m

        existing_client = MagicMock()
        m._client = existing_client
        m._client_config = config

        mock_genai = MagicMock()
        with patch("trace_engine.llm.client.genai", mock_genai):
            from trace_engine.llm.client import _ensure_client

            result = _ensure_client(config)

        mock_genai.Client.assert_not_called()
        assert result is existing_client

    def test_raises_runtime_error_when_genai_missing(self):
        config = _make_config()

        with patch("trace_engine.llm.client.genai", None):
            from trace_engine.llm.client import _ensure_client

            with pytest.raises(RuntimeError, match="google-genai"):
                _ensure_client(config)


@pytest.mark.integration
class TestCallLlmIntegration:
    """Integration tests — require real Vertex AI. Run with: make test-integration.

    Smoke-level only: they verify the live model/prompt contract (model ids
    resolve, JSON mode honours the schema the L2/L3 pipeline expects), not
    output quality. Each test skips when GCP_PROJECT_ID is not set.
    """

    @staticmethod
    def _require_project() -> None:
        import os

        if not os.environ.get("GCP_PROJECT_ID"):
            pytest.skip("GCP_PROJECT_ID not set")

    def test_simple_call_returns_json(self):
        """Smoke: gemini flash-lite answers in JSON mode."""
        self._require_project()
        from trace_engine.llm.client import call_llm_json

        result = call_llm_json(
            "simple",
            'Return JSON: {"status": "ok", "message": "hello"}',
        )
        assert isinstance(result, dict)
        assert result.get("status") == "ok"

    def test_relevance_prompt_contract(self):
        """Smoke for the L2 gate: relevance_check.md yields score + matched_pir_ids."""
        self._require_project()
        from trace_engine.llm.client import call_llm_json, load_prompt

        prompt = (
            load_prompt("relevance_check.md")
            .replace(
                "{{PIR_CONTEXT}}",
                "- PIR-2025-001 (strategic): monitor ransomware campaigns "
                "targeting manufacturing ERP systems",
            )
            .replace(
                "{{ARTICLE_TEXT}}",
                "A ransomware group deployed new malware against a European "
                "car manufacturer's SAP environment last week.",
            )
        )
        result = call_llm_json("simple", prompt)
        assert isinstance(result, dict)
        assert "score" in result
        assert 0.0 <= float(result["score"]) <= 1.0
        assert isinstance(result.get("matched_pir_ids", []), list)

    def test_extraction_prompt_contract(self):
        """Smoke for the L3 extractor: stix_extraction.md yields entities/relationships."""
        self._require_project()
        from trace_engine.llm.client import call_llm_json, load_prompt

        prompt = (
            load_prompt("stix_extraction.md")
            .replace("{{PIR_CONTEXT_BLOCK}}", "")
            .replace(
                "{{REPORT_TEXT}}",
                "FIN7 used Cobalt Strike to exploit CVE-2023-3519 against "
                "internet-facing Citrix servers.",
            )
        )
        result = call_llm_json("medium", prompt)
        assert isinstance(result, dict)
        assert isinstance(result.get("entities"), list)
        assert isinstance(result.get("relationships"), list)
        names = {e.get("name", "").lower() for e in result["entities"]}
        assert any("fin7" in n for n in names)
