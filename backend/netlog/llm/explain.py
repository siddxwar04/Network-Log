"""The explanation step: an evidence pack goes in, a structured explanation comes out.

    pack + audience mode
        -> cache lookup (hit: no request is made)
        -> request to the provider, retried on rate limits and server errors
        -> the answer is parsed against the agreed structure
        -> the validator checks it against the pack
        -> if it fails: one more request, telling the LLM what was wrong
        -> a valid answer is stored in the cache; every request is recorded

This step never fails the analysis. With no provider configured, a missing or rejected
key, a provider that is down, or two answers in a row that fail validation,
`explain_pack` returns a result with no explanation and the reason. `explain_incident`
then puts the built-in explanation in its place, so the caller always gets one, and the
result says which of the two it is.

Only an answer that passed validation is ever returned or cached. A cached answer is
checked again when it is read, because the checks may have been tightened since.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from netlog.config import load_config
from netlog.llm.evidence import EvidencePack
from netlog.llm.explanation import (
    MODES,
    Explanation,
    ExplanationError,
    explanation_schema,
    parse_explanation,
)
from netlog.llm.fallback import fallback_explanation
from netlog.llm.prompt import load_prompt
from netlog.llm.provider import (
    LLMRequest,
    MissingKeyError,
    Provider,
    ProviderError,
    complete_with_retries,
)
from netlog.llm.settings import ENV_KEY, LLMSettings, llm_settings
from netlog.llm.validate import (
    Problem,
    citation_counts,
    describe_problems,
    validate_explanation,
)
from netlog.redaction.redactor import Redactor
from netlog.storage.database import Database

SCHEMA_NAME = "incident_explanation"
NOT_CONFIGURED = "no LLM provider is configured"
SWITCHED_OFF = "the LLM was switched off"
# How many answers are asked for before giving up: the first, and one retry.
MAX_TRIES = 2


@dataclass
class Try:
    """One answer from the LLM and what the validator made of it."""

    # Empty when the answer passed. A malformed answer has one problem, check "structure".
    problems: list[Problem]
    # How many of the answer's citations name an id that exists, and how many it has.
    valid_citations: int = 0
    citations: int = 0

    @property
    def passed(self) -> bool:
        return not self.problems


@dataclass
class ExplanationResult:
    explanation: Explanation | None
    # Who wrote the explanation: "llm" for a fresh answer, "cache" for a stored one,
    # "fallback" for the built-in explanation, "none" when there is none.
    source: str
    mode: str
    # Why there is no explanation, when there is none.
    reason: str | None = None
    provider: str = ""
    model: str = ""
    cache_key: str | None = None
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: int = 0
    attempts: int = 0
    # The answers asked for in this call, in order: none on a cache hit or when no
    # request could be made, one when the first passed, two after a rejection.
    tries: list[Try] = field(default_factory=list)

    @property
    def cache_hit(self) -> bool:
        return self.source == "cache"

    @property
    def outcome(self) -> str:
        """`first_time`, `retry` (passed on the second answer), `cache`, or `fallback`."""
        if self.source == "llm":
            return "first_time" if len(self.tries) == 1 else "retry"
        return "cache" if self.source == "cache" else "fallback"


def restore_explanation(explanation: Explanation, redactor: Redactor) -> Explanation:
    """The explanation with the real addresses and names put back, for showing to the
    user. The evidence ids are left as they are."""

    def restore(value):
        if isinstance(value, str):
            return redactor.restore(value)
        if isinstance(value, list):
            return [restore(item) for item in value]
        if isinstance(value, dict):
            return {key: restore(item) for key, item in value.items()}
        return value

    return Explanation.model_validate(restore(explanation.model_dump()))


def make_provider(settings: LLMSettings) -> Provider | None:
    """The provider the settings name, or None when none is configured."""
    if not settings.configured:
        return None
    if settings.provider == "openai":
        if not settings.api_key:
            raise MissingKeyError(
                f"the LLM provider is set to openai but there is no API key; "
                f"put {ENV_KEY}=... in a file named .env"
            )
        from netlog.llm.openai_provider import OpenAIProvider

        return OpenAIProvider(settings.api_key)
    raise ProviderError(f"unknown LLM provider {settings.provider!r}; supported: openai")


def cache_key(pack_hash: str, prompt_version: str, provider: str, model: str, mode: str) -> str:
    """Change any of these and the question is a different one."""
    parts = "\x1f".join((pack_hash, prompt_version, provider, model, mode))
    return hashlib.sha256(parts.encode("utf-8")).hexdigest()


def explain_pack(
    cache: Database,
    pack: EvidencePack,
    mode: str = "senior",
    *,
    provider: Provider | None = None,
    settings: LLMSettings | None = None,
    config: dict | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> ExplanationResult:
    """Explain the incident in `pack` for a junior or a senior reader.

    `pack` must be the outgoing pack (`outgoing_pack`), which is redacted. `cache` is
    the database that holds stored explanations and the record of requests. `provider`
    replaces the configured one, which is how tests supply a fake.
    """
    if mode not in MODES:
        raise ValueError(f"unknown audience mode {mode!r}; choose from {', '.join(MODES)}")
    config = config or load_config()
    if config["redaction"]["enabled"] and not pack.redacted:
        raise ValueError(
            "refusing to send an evidence pack that was not redacted; build it with outgoing_pack"
        )
    settings = settings or llm_settings(config)
    incident_id = pack.data["incident"]["id"]
    result = ExplanationResult(explanation=None, source="none", mode=mode)

    def record(
        status: str,
        error: str | None = None,
        *,
        input_tokens: int = 0,
        output_tokens: int = 0,
        latency_ms: int = 0,
        attempts: int = 0,
        try_number: int = 1,
        rejected: str | None = None,
    ) -> ExplanationResult:
        cache.add_llm_call(
            incident_id=incident_id,
            cache_key=result.cache_key,
            provider=result.provider,
            model=result.model,
            mode=mode,
            status=status,
            cache_hit=result.cache_hit,
            error=error,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            latency_ms=latency_ms,
            attempts=attempts,
            try_number=try_number,
            rejected=rejected,
        )
        return result

    if provider is None:
        result.provider = settings.provider
        try:
            provider = make_provider(settings)
        except ProviderError as error:
            result.reason = str(error)
            return record("error", result.reason)
        if provider is None:
            result.reason = NOT_CONFIGURED
            return result
    result.provider = provider.name
    result.model = settings.model_for(provider.name)

    prompt = load_prompt(settings.prompt)
    key = cache_key(pack.hash, prompt.version, provider.name, result.model, mode)
    result.cache_key = key
    stored = cache.get_explanation(key)
    if stored is not None:
        try:
            explanation = parse_explanation(stored.content)
        except ExplanationError:
            explanation = None  # written by an older version of the structure: ask again
        # Checked again on the way out: the checks may be stricter than when it was stored.
        if explanation is not None and not validate_explanation(explanation, pack, config):
            result.explanation, result.source = explanation, "cache"
            result.input_tokens, result.output_tokens = stored.input_tokens, stored.output_tokens
            return record(
                "cached", input_tokens=stored.input_tokens, output_tokens=stored.output_tokens
            )

    feedback: str | None = None
    for try_number in range(1, MAX_TRIES + 1):
        system, user = prompt.render(pack, mode, feedback)
        request = LLMRequest(
            system=system,
            user=user,
            schema=explanation_schema(),
            schema_name=SCHEMA_NAME,
            model=result.model,
            max_output_tokens=settings.max_output_tokens,
            timeout_seconds=settings.timeout_seconds,
            reasoning_effort=settings.reasoning_effort,
        )
        started = time.perf_counter()
        try:
            response, attempts = complete_with_retries(
                provider,
                request,
                max_retries=settings.max_retries,
                backoff_seconds=settings.backoff_seconds,
                sleep=sleep,
            )
        except ProviderError as error:
            latency = round((time.perf_counter() - started) * 1000)
            attempts = getattr(error, "attempts", 1)
            result.latency_ms += latency
            result.attempts += attempts
            result.reason = str(error)
            return record(
                "error",
                result.reason,
                latency_ms=latency,
                attempts=attempts,
                try_number=try_number,
            )
        latency = round((time.perf_counter() - started) * 1000)
        result.latency_ms += latency
        result.attempts += attempts
        result.input_tokens += response.input_tokens
        result.output_tokens += response.output_tokens
        usage = dict(
            input_tokens=response.input_tokens,
            output_tokens=response.output_tokens,
            latency_ms=latency,
            attempts=attempts,
            try_number=try_number,
        )

        try:
            explanation = parse_explanation(response.text)
        except ExplanationError as error:
            status = "malformed"
            this = Try([Problem("structure", "answer", str(error))])
        else:
            status = "invalid"
            valid, cited = citation_counts(explanation, pack)
            this = Try(validate_explanation(explanation, pack, config), valid, cited)
        result.tries.append(this)

        if this.passed:
            cache.save_explanation(
                key,
                pack_hash=pack.hash,
                prompt_version=prompt.version,
                provider=provider.name,
                model=result.model,
                mode=mode,
                content=explanation.model_dump_json(),
                input_tokens=response.input_tokens,
                output_tokens=response.output_tokens,
            )
            result.explanation, result.source, result.reason = explanation, "llm", None
            return record("ok", **usage)

        feedback = describe_problems(this.problems)
        record(status, feedback, rejected=response.text, **usage)

    result.reason = f"{MAX_TRIES} answers in a row were rejected; the last one:\n{feedback}"
    return result


def explain_incident(
    cache: Database,
    pack: EvidencePack,
    mode: str = "senior",
    *,
    use_llm: bool = True,
    provider: Provider | None = None,
    settings: LLMSettings | None = None,
    config: dict | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> ExplanationResult:
    """Explain the incident in `pack`, whatever happens: by the LLM when one is configured
    and its answer passes validation, by the built-in explanation otherwise.

    The result's `source` says which. When it is "fallback", `reason` says why the LLM's
    explanation was not used. With `use_llm` false no request is made, whatever is
    configured.
    """
    if mode not in MODES:
        raise ValueError(f"unknown audience mode {mode!r}; choose from {', '.join(MODES)}")
    if use_llm:
        result = explain_pack(
            cache, pack, mode, provider=provider, settings=settings, config=config, sleep=sleep
        )
    else:
        result = ExplanationResult(None, "none", mode, reason=SWITCHED_OFF)
    if result.explanation is None:
        result.explanation = fallback_explanation(pack, mode, config)
        result.source = "fallback"
    return result
