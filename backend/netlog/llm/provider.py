"""The provider interface: what the tool needs from an LLM service, and nothing more.

A provider takes one request (instructions, the user message, the structure the answer
must have) and returns the answer as text with its token counts. Everything that is the
same for every provider lives outside it: the prompt, the cache, the parsing, the retries.
Supporting another service means writing one class with one method.

`FakeProvider` returns answers given to it in advance. Every test uses it, so the test
suite never makes a real API call.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol


class ProviderError(Exception):
    """The provider could not give an answer. `retryable` says whether trying again may help."""

    retryable = False


class MissingKeyError(ProviderError):
    """A provider is configured but no API key was given."""


class InvalidKeyError(ProviderError):
    """The provider rejected the API key."""


class RequestRejectedError(ProviderError):
    """The provider refused the request itself: an unknown model, a bad parameter."""


class RateLimitError(ProviderError):
    """Too many requests, or the quota is used up for now."""

    retryable = True

    def __init__(self, message: str, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class ServerError(ProviderError):
    """The provider's side failed or is overloaded."""

    retryable = True


class ProviderTimeout(ProviderError):
    """No answer came within the time allowed, or the connection failed."""

    retryable = True


@dataclass(frozen=True)
class LLMRequest:
    system: str
    user: str
    # The JSON schema the answer must match, and a short name for it.
    schema: dict
    schema_name: str
    model: str
    max_output_tokens: int
    timeout_seconds: float
    # How hard a reasoning model should think: "low", "medium" ... Empty to not say.
    reasoning_effort: str = ""


@dataclass(frozen=True)
class LLMResponse:
    text: str
    input_tokens: int
    output_tokens: int


class Provider(Protocol):
    name: str

    def complete(self, request: LLMRequest) -> LLMResponse:
        """Send one request. Raises a `ProviderError` when no answer can be given."""
        ...


@dataclass
class FakeProvider:
    """Returns fixed answers, in order; the last one is repeated. For tests and demos.

    An answer may be text, a dictionary (sent back as JSON), an exception (raised), or a
    function that takes the request and returns any of those.
    """

    answers: list = field(default_factory=list)
    name: str = "fake"
    requests: list[LLMRequest] = field(default_factory=list)

    def complete(self, request: LLMRequest) -> LLMResponse:
        self.requests.append(request)
        if not self.answers:
            raise ServerError("the fake provider was given no answers")
        answer = self.answers[min(len(self.requests), len(self.answers)) - 1]
        if callable(answer) and not isinstance(answer, BaseException):
            answer = answer(request)
        if isinstance(answer, BaseException):
            raise answer
        if isinstance(answer, LLMResponse):
            return answer
        text = answer if isinstance(answer, str) else json.dumps(answer, ensure_ascii=False)
        return LLMResponse(
            text=text,
            input_tokens=(len(request.system) + len(request.user)) // 4,
            output_tokens=len(text) // 4,
        )


def complete_with_retries(
    provider: Provider,
    request: LLMRequest,
    *,
    max_retries: int,
    backoff_seconds: float,
    sleep: Callable[[float], None] = time.sleep,
) -> tuple[LLMResponse, int]:
    """Send a request, trying again after a rate limit, a server error or a timeout.

    The wait doubles each time: 2 s, 4 s, 8 s. A provider that says how long to wait is
    obeyed. Errors that trying again cannot fix (a bad key, a bad request) are raised at
    once. Returns the answer and how many attempts it took.
    """
    attempt = 1
    while True:
        try:
            return provider.complete(request), attempt
        except ProviderError as error:
            if not error.retryable or attempt > max_retries:
                error.attempts = attempt
                raise
            wait = backoff_seconds * 2 ** (attempt - 1)
            wait = max(wait, getattr(error, "retry_after", None) or 0)
            sleep(wait)
            attempt += 1
