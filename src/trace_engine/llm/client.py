"""Google Gen AI (Vertex AI) LLM client for TRACE.

Exposes a single `call_llm(task, prompt)` function that is easy to mock in tests.
The Gen AI client is initialized lazily on first call.
"""

from __future__ import annotations

import json
from typing import Literal

import structlog

from trace_engine.config import Config, load_config

# Top-level import with fallback so tests can patch trace_engine.llm.client.genai
# without google-genai being installed.
try:
    from google import genai
    from google.genai import types as genai_types
except ImportError:  # pragma: no cover
    genai = None  # type: ignore[assignment]
    genai_types = None  # type: ignore[assignment]

logger = structlog.get_logger(__name__)

TaskType = Literal["simple", "medium", "complex"]

_client: genai.Client | None = None
_client_config: Config | None = None


def _ensure_client(config: Config) -> genai.Client:
    global _client, _client_config
    if _client is not None and _client_config is config:
        return _client
    if genai is None:
        raise RuntimeError("google-genai is required for LLM mode. Run: uv sync")
    _client = genai.Client(
        vertexai=True,
        project=config.gcp_project_id,
        location=config.vertex_location,
    )
    _client_config = config
    logger.info(
        "genai_client_initialized",
        project=config.gcp_project_id,
        location=config.vertex_location,
    )
    return _client


def call_llm(
    task: TaskType,
    prompt: str,
    *,
    config: Config | None = None,
    json_mode: bool = True,
    max_output_tokens: int = 8192,
) -> str:
    """Call Vertex AI Gemini via Google Gen AI SDK and return the text response.

    Args:
        task: Complexity level — selects the model ("simple", "medium", "complex").
        prompt: Full prompt text to send to the model.
        config: Config instance. Uses load_config() if None.
        json_mode: If True, sets response_mime_type="application/json".
        max_output_tokens: Maximum output tokens (default: 8192).

    Returns:
        The model's text response (JSON string if json_mode=True).
    """
    cfg = config or load_config()
    client = _ensure_client(cfg)

    model_name = _model_for_task(task, cfg)

    generation_config = genai_types.GenerateContentConfig(
        response_mime_type="application/json" if json_mode else "text/plain",
        temperature=0.2,
        max_output_tokens=max_output_tokens,
    )

    logger.info("llm_call_start", task=task, model=model_name)
    response = client.models.generate_content(
        model=model_name,
        contents=prompt,
        config=generation_config,
    )
    text = response.text
    logger.info("llm_call_done", task=task, model=model_name, chars=len(text))
    return text


def call_llm_json(
    task: TaskType,
    prompt: str,
    *,
    config: Config | None = None,
) -> dict | list:
    """Call Vertex AI Gemini and parse the JSON response.

    Raises:
        ValueError: If the response cannot be parsed as JSON.
    """
    raw = call_llm(task, prompt, config=config, json_mode=True)
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"LLM returned non-JSON response: {raw}") from exc


def _model_for_task(task: TaskType, config: Config) -> str:
    mapping = {
        "simple": config.llm_model_simple,
        "medium": config.llm_model_medium,
        "complex": config.llm_model_complex,
    }
    return mapping[task]


def load_prompt(name: str) -> str:
    """Load a prompt template from src/trace_engine/llm/prompts/<name>."""
    from pathlib import Path  # noqa: PLC0415

    path = Path(__file__).parent / "prompts" / name
    if not path.exists():
        raise FileNotFoundError(f"Prompt template not found: {path}")
    return path.read_text(encoding="utf-8")
