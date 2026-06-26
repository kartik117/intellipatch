"""Lazy LLM client construction -- same pattern as the sibling PNWater
project (which borrowed it from RepoMindMCP): constructing a Gemini
client eagerly validates the API key immediately, so a service with no
key configured would fail at import/startup time instead of falling
back gracefully exactly when it's needed. No API key is required for
this service to run correctly.
"""

from __future__ import annotations

from typing import Any

from intellipatch.config import settings

_client: Any = None
_attempted = False


def get_llm_client() -> Any | None:
    global _client, _attempted
    if _attempted:
        return _client

    _attempted = True
    if not settings.google_api_key:
        return None

    from langchain_google_genai import ChatGoogleGenerativeAI

    _client = ChatGoogleGenerativeAI(model="gemini-2.0-flash", api_key=settings.google_api_key)
    return _client


def reset_for_test() -> None:
    global _client, _attempted
    _client = None
    _attempted = False
