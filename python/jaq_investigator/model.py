"""Model boundary for the JAQ static investigator.

The rest of the investigator deliberately depends on the small ``ModelClient``
protocol in this module rather than on LiteLLM.  This keeps the evidence and
tool loop testable without installing a provider SDK or configuring a key.
Credentials are never read here.  LiteLLM is allowed to read the provider's
normal environment variables when it is called.
"""

from __future__ import annotations

import importlib
import json
import os
import re
from dataclasses import dataclass
from typing import Any, Mapping, Protocol, Sequence, runtime_checkable


class ModelError(RuntimeError):
    """Base class for errors crossing the model boundary."""

    category = "model"


class ModelConfigurationError(ModelError):
    category = "configuration"


class MissingModelError(ModelConfigurationError):
    """Raised when a logical role has no configured provider/model string."""


class ModelTimeoutError(ModelError):
    category = "timeout"


class ModelAuthenticationError(ModelError):
    category = "authentication"


class ModelProviderError(ModelError):
    category = "provider"


class ModelResponseError(ModelError):
    """Raised when a provider returns a response outside the contract."""

    category = "bad_response"


# Friendly aliases used by callers that prefer shorter names.
ModelAuthError = ModelAuthenticationError
ModelBadResponseError = ModelResponseError
ModelProviderTimeoutError = ModelTimeoutError
ModelClientError = ModelError


@dataclass(frozen=True)
class ToolCall:
    """A normalized function tool call returned by a model."""

    name: str
    arguments: Mapping[str, Any]
    id: str = ""


@dataclass(frozen=True)
class ModelResponse:
    """Provider-neutral structured generation result.

    ``structured`` is populated when a provider exposes parsed JSON.  It may
    be ``None`` even when ``content`` contains JSON; callers can parse the
    content using :func:`structured_payload`.
    """

    content: str | None = None
    structured: Any = None
    tool_calls: tuple[ToolCall, ...] = ()
    usage: Mapping[str, int] | None = None
    model: str | None = None
    provider: str | None = None
    finish_reason: str | None = None
    reasoning_content: str | None = None

    @property
    def data(self) -> Any:
        """Compatibility alias for code that calls parsed output ``data``."""

        return self.structured

    @property
    def parsed(self) -> Any:
        """Compatibility alias for LiteLLM/OpenAI's ``parsed`` field."""

        return self.structured


@runtime_checkable
class ModelClient(Protocol):
    """Project-owned interface for one structured model generation turn."""

    model: str

    def generate_structured(
        self,
        *,
        messages: Sequence[Mapping[str, Any]],
        schema: Mapping[str, Any],
        tools: Sequence[Mapping[str, Any]] | None = None,
        timeout: float | None = None,
        max_tokens: int | None = None,
        temperature: float | None = None,
        max_rounds: int | None = None,
    ) -> ModelResponse:
        """Generate a structured response and optional function tool calls."""


def _safe_error_message(error: BaseException) -> str:
    """Return a provider error without copying credentials into our output."""

    message = " ".join(str(error).split()) or error.__class__.__name__
    # Provider errors occasionally echo an Authorization header or an API key.
    # Redact common forms without reading any environment variable ourselves.
    message = re.sub(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [redacted]", message)
    message = re.sub(r"(?i)(api[_ -]?key|token|secret)\s*[:=]\s*[^,; ]+", r"\1=[redacted]", message)
    message = re.sub(r"\b(?:sk|sess|key)-[A-Za-z0-9_-]{12,}\b", "[redacted]", message)
    if len(message) > 500:
        message = message[:497] + "..."
    return message


def _looks_like_timeout(error: BaseException) -> bool:
    if isinstance(error, TimeoutError):
        return True
    text = f"{error.__class__.__name__} {error}".lower()
    return any(word in text for word in ("timeout", "timed out", "deadline exceeded"))


def _status_code(error: BaseException) -> int | None:
    for attr in ("status_code", "status", "http_status", "code"):
        value = getattr(error, attr, None)
        if isinstance(value, int):
            return value
    response = getattr(error, "response", None)
    value = getattr(response, "status_code", None)
    return value if isinstance(value, int) else None


def _looks_like_authentication(error: BaseException) -> bool:
    status = _status_code(error)
    if status in (401, 403):
        return True
    text = f"{error.__class__.__name__} {error}".lower()
    return any(
        word in text
        for word in (
            "authentication",
            "unauthorized",
            "invalid api key",
            "api key is invalid",
            "permission denied",
            "forbidden",
        )
    )


def normalize_provider_error(error: BaseException) -> ModelError:
    """Map common LiteLLM/provider failures to stable project exceptions."""

    if isinstance(error, ModelError):
        return error
    message = _safe_error_message(error)
    if _looks_like_timeout(error):
        return ModelTimeoutError(message)
    if _looks_like_authentication(error):
        return ModelAuthenticationError(message)
    return ModelProviderError(message)


def normalize_usage(value: Any) -> dict[str, int]:
    """Normalize LiteLLM/OpenAI usage objects to plain integer fields."""

    if value is None:
        return {}
    if isinstance(value, Mapping):
        source = value
    else:
        source = {
            name: getattr(value, name)
            for name in ("prompt_tokens", "completion_tokens", "total_tokens")
            if getattr(value, name, None) is not None
        }
    usage: dict[str, int] = {}
    aliases = {
        "prompt_tokens": "prompt_tokens",
        "input_tokens": "prompt_tokens",
        "completion_tokens": "completion_tokens",
        "output_tokens": "completion_tokens",
        "total_tokens": "total_tokens",
    }
    for key, output_key in aliases.items():
        raw = source.get(key) if isinstance(source, Mapping) else None
        if raw is None:
            continue
        try:
            number = int(raw)
        except (TypeError, ValueError):
            continue
        if number >= 0:
            usage[output_key] = number
    if "total_tokens" not in usage:
        if "prompt_tokens" in usage or "completion_tokens" in usage:
            usage["total_tokens"] = usage.get("prompt_tokens", 0) + usage.get("completion_tokens", 0)
    return usage


def _get(value: Any, key: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(key, default)
    return getattr(value, key, default)


def _content_text(content: Any) -> str | None:
    if content is None:
        return None
    if isinstance(content, str):
        return content
    if isinstance(content, (list, tuple)):
        pieces: list[str] = []
        for block in content:
            text = _get(block, "text")
            if text is None and isinstance(block, Mapping) and block.get("type") == "text":
                text = block.get("content")
            if text is not None:
                pieces.append(str(text))
        return "".join(pieces) or None
    return str(content)


def _json_object(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    text = value.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\s*```$", "", text)
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return None


def _normalize_tool_call(value: Any, index: int) -> ToolCall:
    call_id = _get(value, "id", "") or f"tool-call-{index + 1}"
    function = _get(value, "function")
    if function is None:
        function = value
    name = _get(function, "name")
    arguments = _get(function, "arguments", {})
    if not isinstance(name, str) or not name.strip():
        raise ModelResponseError("provider returned a tool call without a function name")
    if isinstance(arguments, str):
        parsed = _json_object(arguments)
        if not isinstance(parsed, Mapping):
            raise ModelResponseError("provider returned non-object tool arguments")
        arguments = parsed
    if not isinstance(arguments, Mapping):
        raise ModelResponseError("provider returned non-object tool arguments")
    return ToolCall(name=name, arguments=dict(arguments), id=str(call_id))


def normalize_model_response(
    raw: Any,
    *,
    default_model: str | None = None,
    default_provider: str | None = None,
) -> ModelResponse:
    """Convert a LiteLLM/OpenAI-shaped result into :class:`ModelResponse`."""

    if isinstance(raw, ModelResponse):
        return raw
    choices = _get(raw, "choices")
    if not isinstance(choices, (list, tuple)) or not choices:
        raise ModelResponseError("provider returned no choices")
    choice = choices[0]
    message = _get(choice, "message")
    if message is None:
        raise ModelResponseError("provider returned a choice without a message")
    raw_content = _get(message, "content")
    content = _content_text(raw_content)
    raw_calls = _get(message, "tool_calls", ()) or ()
    if isinstance(raw_calls, Mapping):
        raw_calls = [raw_calls]
    if not isinstance(raw_calls, (list, tuple)):
        raise ModelResponseError("provider returned malformed tool calls")
    calls = tuple(_normalize_tool_call(item, index) for index, item in enumerate(raw_calls))
    structured = _get(message, "parsed")
    if structured is None:
        structured = _get(message, "json")
    if structured is None and isinstance(raw_content, Mapping):
        structured = dict(raw_content)
    if structured is None:
        parsed_content = _json_object(content) if content else None
        if isinstance(parsed_content, (Mapping, list)):
            structured = parsed_content
    model = _get(raw, "model", default_model)
    provider = _get(raw, "provider", default_provider)
    if provider is not None and not isinstance(provider, str):
        provider = str(provider)
    finish_reason = _get(choice, "finish_reason")
    if finish_reason is not None:
        finish_reason = str(finish_reason)
    reasoning_content = _get(message, "reasoning_content")
    if reasoning_content is None:
        provider_fields = _get(message, "provider_specific_fields")
        if isinstance(provider_fields, Mapping):
            reasoning_content = provider_fields.get("reasoning_content")
    if reasoning_content is not None:
        reasoning_content = str(reasoning_content)
    return ModelResponse(
        content=content,
        structured=structured,
        tool_calls=calls,
        usage=normalize_usage(_get(raw, "usage")),
        model=str(model) if model is not None else None,
        provider=provider,
        finish_reason=finish_reason,
        reasoning_content=reasoning_content,
    )


class LiteLLMModelClient:
    """Synchronous LiteLLM adapter with a stable, credential-free surface."""

    def __init__(
        self,
        model: str | None = None,
        *,
        env_var: str = "JAQ_INVESTIGATOR_MODEL",
        default_timeout: float = 60.0,
        default_max_tokens: int = 4000,
    ) -> None:
        # Only the model selector is read here.  Provider credentials are left
        # to LiteLLM and are never copied into this object or its metadata.
        selected = model if model is not None else os.environ.get(env_var)
        if not isinstance(selected, str) or not selected.strip():
            raise MissingModelError(f"{env_var} is not configured")
        self.model = selected.strip()
        self.default_timeout = float(default_timeout)
        self.default_max_tokens = int(default_max_tokens)
        if self.default_timeout <= 0:
            raise ModelConfigurationError("default_timeout must be positive")
        if self.default_max_tokens <= 0:
            raise ModelConfigurationError("default_max_tokens must be positive")

    @classmethod
    def from_env(cls, *, env_var: str = "JAQ_INVESTIGATOR_MODEL", **kwargs: Any) -> "LiteLLMModelClient":
        """Construct from one role selector without accepting a model CLI arg."""

        return cls(None, env_var=env_var, **kwargs)

    @property
    def provider(self) -> str:
        """Best-effort provider label derived from a LiteLLM model string."""

        return self.model.split("/", 1)[0] if "/" in self.model else "unknown"

    def generate_structured(
        self,
        *,
        messages: Sequence[Mapping[str, Any]],
        schema: Mapping[str, Any],
        tools: Sequence[Mapping[str, Any]] | None = None,
        timeout: float | None = None,
        max_tokens: int | None = None,
        temperature: float | None = None,
        max_rounds: int | None = None,
    ) -> ModelResponse:
        if not isinstance(messages, (list, tuple)) or not messages:
            raise ModelConfigurationError("messages must be a non-empty sequence")
        if not isinstance(schema, Mapping):
            raise ModelConfigurationError("schema must be an object")
        if max_rounds is not None and (not isinstance(max_rounds, int) or max_rounds < 1):
            raise ModelConfigurationError("max_rounds must be positive when supplied")
        try:
            # This is intentionally the first and only LiteLLM import.  Tests
            # can inject a tiny fake module and environments need not install
            # LiteLLM for the investigator unit tests.
            litellm = importlib.import_module("litellm")
        except ModuleNotFoundError as error:
            raise ModelProviderError("LiteLLM is not installed; install the llm extra") from error
        except Exception as error:  # pragma: no cover - unusual import hooks
            raise normalize_provider_error(error) from error

        completion = getattr(litellm, "completion", None)
        if not callable(completion):
            raise ModelProviderError("LiteLLM does not expose completion()")
        response_format: dict[str, Any]
        if self.provider == "deepseek":
            # DeepSeek supports JSON object mode but currently rejects the
            # OpenAI-style strict json_schema response format. JAQ still
            # validates the returned object against its project-owned schema.
            response_format = {"type": "json_object"}
        else:
            response_format = {
                "type": "json_schema",
                "json_schema": {"name": "jaq_structured", "schema": dict(schema), "strict": True},
            }
        request: dict[str, Any] = {
            "model": self.model,
            "messages": [dict(message) for message in messages],
            "response_format": response_format,
            "timeout": self.default_timeout if timeout is None else float(timeout),
            "max_tokens": self.default_max_tokens if max_tokens is None else int(max_tokens),
        }
        if self.provider == "deepseek" and "deepseek-v4-" in self.model:
            # DeepSeek V4 thinking turns require provider-specific reasoning
            # state to be echoed through every tool round. JSON-mode responses
            # do not reliably expose that state through LiteLLM, so use the
            # provider's explicit non-thinking mode for this bounded tool loop.
            request["reasoning_effort"] = "none"
        if request["timeout"] <= 0:
            raise ModelConfigurationError("timeout must be positive")
        if request["max_tokens"] <= 0:
            raise ModelConfigurationError("max_tokens must be positive")
        if tools:
            request["tools"] = [dict(tool) for tool in tools]
            request["tool_choice"] = "auto"
        if temperature is not None:
            request["temperature"] = float(temperature)
        try:
            raw = completion(**request)
        except Exception as error:
            normalized = normalize_provider_error(error)
            raise normalized from error
        try:
            return normalize_model_response(
                raw,
                default_model=self.model,
                default_provider=self.provider,
            )
        except ModelError:
            raise
        except Exception as error:  # pragma: no cover - defensive boundary
            raise ModelResponseError(_safe_error_message(error)) from error

    # A short alias is useful to simple controller adapters. The project-owned
    # protocol remains ``generate_structured`` so the response contract is
    # explicit at call sites.
    generate = generate_structured
    complete = generate_structured


LiteLLMAdapter = LiteLLMModelClient


def structured_payload(response: ModelResponse | Mapping[str, Any] | Any) -> Any:
    """Extract parsed JSON from a normalized or test-double response."""

    if isinstance(response, ModelResponse):
        payload = response.structured
        if payload is None:
            payload = _json_object(response.content)
        return payload
    if isinstance(response, Mapping):
        if "claims" in response or "judgments" in response:
            return response
        for key in ("structured", "data", "parsed", "output"):
            if key in response and response[key] is not None:
                value = response[key]
                return _json_object(value) if isinstance(value, str) else value
        content = response.get("content")
        return _json_object(content) if isinstance(content, str) else content
    payload = getattr(response, "structured", None)
    if payload is None:
        payload = getattr(response, "data", None)
    if payload is None:
        payload = getattr(response, "parsed", None)
    if payload is None:
        payload = _json_object(getattr(response, "content", None))
    return payload


def response_tool_calls(response: ModelResponse | Mapping[str, Any] | Any) -> list[ToolCall]:
    """Extract tool calls from normalized responses and simple test doubles."""

    if isinstance(response, ModelResponse):
        return list(response.tool_calls)
    raw_calls = response.get("tool_calls", ()) if isinstance(response, Mapping) else getattr(response, "tool_calls", ())
    if raw_calls is None:
        return []
    if isinstance(raw_calls, Mapping):
        raw_calls = [raw_calls]
    if not isinstance(raw_calls, (list, tuple)):
        raise ModelResponseError("model response has malformed tool calls")
    return [_normalize_tool_call(call, index) for index, call in enumerate(raw_calls)]


def response_usage(response: ModelResponse | Mapping[str, Any] | Any) -> dict[str, int]:
    if isinstance(response, ModelResponse):
        return dict(response.usage or {})
    value = response.get("usage") if isinstance(response, Mapping) else getattr(response, "usage", None)
    return normalize_usage(value)


def response_model(response: ModelResponse | Mapping[str, Any] | Any, fallback: str | None = None) -> str | None:
    value = response.model if isinstance(response, ModelResponse) else (
        response.get("model") if isinstance(response, Mapping) else getattr(response, "model", None)
    )
    return str(value) if value is not None else fallback


def response_provider(
    response: ModelResponse | Mapping[str, Any] | Any,
    fallback: str | None = None,
) -> str | None:
    value = response.provider if isinstance(response, ModelResponse) else (
        response.get("provider") if isinstance(response, Mapping) else getattr(response, "provider", None)
    )
    return str(value) if value is not None else fallback


__all__ = [
    "LiteLLMModelClient",
    "LiteLLMAdapter",
    "MissingModelError",
    "ModelAuthError",
    "ModelAuthenticationError",
    "ModelBadResponseError",
    "ModelClient",
    "ModelClientError",
    "ModelConfigurationError",
    "ModelError",
    "ModelProviderError",
    "ModelProviderTimeoutError",
    "ModelResponse",
    "ModelResponseError",
    "ModelTimeoutError",
    "ToolCall",
    "normalize_model_response",
    "normalize_provider_error",
    "normalize_usage",
    "response_model",
    "response_provider",
    "response_tool_calls",
    "response_usage",
    "structured_payload",
]
