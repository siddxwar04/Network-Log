"""The OpenAI provider: one request to the Responses API, with Structured Outputs.

Structured Outputs makes the service return JSON that matches our schema, so a
well-behaved answer always has the agreed structure. The answer is still parsed and
checked by our own code afterwards; nothing here is trusted because the service said so.

`store=False` asks the service not to keep the request. The SDK's own retries are
switched off, because retrying is done once, in one place, for every provider.
"""

from __future__ import annotations

import openai

from netlog.llm.provider import (
    InvalidKeyError,
    LLMRequest,
    LLMResponse,
    MissingKeyError,
    ProviderError,
    ProviderTimeout,
    RateLimitError,
    RequestRejectedError,
    ServerError,
)


def strict_schema(schema: dict) -> dict:
    """Our schema in the form the service's strict mode accepts: every object closed to
    extra fields and with all its fields required."""

    def fix(node):
        if isinstance(node, list):
            return [fix(item) for item in node]
        if not isinstance(node, dict):
            return node
        node = {key: fix(value) for key, value in node.items() if key != "default"}
        if node.get("type") == "object" or "properties" in node:
            node["additionalProperties"] = False
            node["required"] = list(node.get("properties", {}))
        return node

    return fix(schema)


class _EffortRefused(Exception):
    """The model refused the reasoning-effort setting (HTTP 400)."""


class OpenAIProvider:
    name = "openai"

    def __init__(self, api_key: str, client=None) -> None:
        if not api_key and client is None:
            raise MissingKeyError("no OpenAI API key was given")
        self._key = api_key
        self._client = client or openai.OpenAI(api_key=api_key, max_retries=0)
        # Models that refused the reasoning-effort setting; it is not sent to them again.
        self._no_effort: set[str] = set()

    def _clean(self, error: Exception) -> str:
        """The error as text, with the key cut out should the service echo it back."""
        text = str(error) or type(error).__name__
        return text.replace(self._key, "[key]") if self._key else text

    def complete(self, request: LLMRequest) -> LLMResponse:
        try:
            return self._complete(request)
        except _EffortRefused:
            # A model that does not reason refuses the setting outright. The setting only
            # tunes cost, so the request is made once more without it.
            self._no_effort.add(request.model)
            return self._complete(request)

    def _complete(self, request: LLMRequest) -> LLMResponse:
        extra = {}
        if request.reasoning_effort and request.model not in self._no_effort:
            extra["reasoning"] = {"effort": request.reasoning_effort}
        try:
            response = self._client.responses.create(
                model=request.model,
                instructions=request.system,
                input=request.user,
                max_output_tokens=request.max_output_tokens,
                text={
                    "format": {
                        "type": "json_schema",
                        "name": request.schema_name,
                        "schema": strict_schema(request.schema),
                        "strict": True,
                    }
                },
                store=False,
                timeout=request.timeout_seconds,
                **extra,
            )
        except (openai.AuthenticationError, openai.PermissionDeniedError) as error:
            raise InvalidKeyError(
                f"OpenAI rejected the API key (HTTP {error.status_code}): {self._clean(error)}"
            ) from None
        except openai.RateLimitError as error:
            raise RateLimitError(
                f"OpenAI rate limit or quota reached: {self._clean(error)}",
                retry_after=_retry_after(error),
            ) from None
        except openai.APITimeoutError:
            raise ProviderTimeout(
                f"OpenAI did not answer within {request.timeout_seconds:g} seconds"
            ) from None
        except openai.APIConnectionError as error:
            raise ProviderTimeout(f"could not reach OpenAI: {self._clean(error)}") from None
        except openai.APIStatusError as error:
            if error.status_code >= 500:
                raise ServerError(
                    f"OpenAI server error (HTTP {error.status_code}): {self._clean(error)}"
                ) from None
            if extra and error.status_code == 400 and "reasoning" in str(error).lower():
                raise _EffortRefused from None
            raise RequestRejectedError(
                f"OpenAI rejected the request (HTTP {error.status_code}): {self._clean(error)}"
            ) from None
        except openai.OpenAIError as error:
            raise ProviderError(f"OpenAI request failed: {self._clean(error)}") from None

        if response.status == "incomplete":
            details = response.incomplete_details
            reason = getattr(details, "reason", None) or "unknown reason"
            raise ProviderError(
                f"OpenAI stopped before finishing the answer ({reason}); "
                "raise llm.max_output_tokens if this repeats"
            )
        for item in response.output or []:
            for part in getattr(item, "content", None) or []:
                if getattr(part, "type", "") == "refusal":
                    raise RequestRejectedError(f"OpenAI declined to answer: {part.refusal}")
        usage = response.usage
        return LLMResponse(
            text=response.output_text or "",
            input_tokens=getattr(usage, "input_tokens", 0) or 0,
            output_tokens=getattr(usage, "output_tokens", 0) or 0,
        )


def _retry_after(error: openai.APIStatusError) -> float | None:
    try:
        return float(error.response.headers.get("retry-after"))
    except (AttributeError, TypeError, ValueError):
        return None
