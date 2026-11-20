"""Redaction: real addresses and names are swapped for stand-ins before an evidence pack
leaves this machine, and swapped back when the explanation is shown to the user.

    Failed password for jdoe from 203.0.113.9   ->   Failed password for USER_1 from IP_1

Three rules hold everything together:

  1. The same value always gets the same token within an upload, so the reader of the
     redacted text can still follow one address or one user through the story.
  2. The map from token to real value is kept in the local database and is never part
     of what is sent.
  3. Secrets (passwords, keys, community strings) are not given a token at all. They are
     removed, and nothing can bring them back.

A value is matched by its exact spelling. `R1` and `r1`, or one MAC address written in
two notations, get two tokens: that loses a little, but it is what lets `restore` give
back the original text character for character.

A username is replaced wherever it appears as a whole word, not only where the parser
found it, because the same name also shows up in paths and commands on other lines. The
price is that a username which is an ordinary word (someone trying to log in as `user`)
is replaced in ordinary sentences too.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable

from netlog.config import load_config

KINDS = ("IP", "USER", "HOST", "MAC", "TEXT")
REMOVED = "[REMOVED]"
NOTE = (
    "Addresses, device names, usernames and MAC addresses are replaced by tokens. "
    "The same token always stands for the same value."
)

_WORD = "A-Za-z0-9_"
_TOKEN = rf"(?<![{_WORD}])(?:{'|'.join(KINDS)})_\d+(?![{_WORD}])"
_TOKEN_RE = re.compile(_TOKEN)
_MAC = (
    rf"(?<![{_WORD}:.-])(?:[0-9A-Fa-f]{{2}}(?P<sep>[:-]))(?:[0-9A-Fa-f]{{2}}(?P=sep)){{4}}[0-9A-Fa-f]{{2}}"
    rf"(?![{_WORD}:-])"
    rf"|(?<![{_WORD}.])[0-9A-Fa-f]{{4}}\.[0-9A-Fa-f]{{4}}\.[0-9A-Fa-f]{{4}}(?![{_WORD}]|\.\w)"
)
_IP4 = rf"(?<![{_WORD}.])(?:\d{{1,3}}\.){{3}}\d{{1,3}}(?![{_WORD}]|\.\d)"
_IP6 = rf"(?<![{_WORD}:.])(?:[0-9A-Fa-f]{{0,4}}:){{2,7}}[0-9A-Fa-f]{{0,4}}(?![{_WORD}:]|\.\d)"
_HEX_ONLY = re.compile(r"[0-9A-Fa-f]+")

# Fields of an evidence pack that only ever hold the tool's own vocabulary (rule names,
# severity levels, item ids, times). They are left alone, so that a user who happens to
# be called `root` or `critical` cannot damage the structure of the pack. This applies
# to a field holding plain values only: a section of the pack that happens to share one
# of these names is still gone through. Everything under "details" is redacted whatever
# its name, because those values come from logs.
STRUCTURAL_KEYS = frozenset(
    {
        "version",
        "id",
        "types",
        "severity",
        "role",
        "certainty",
        "confidence",
        "kind",
        "rule",
        "flags",
        "event_key",
        "evidence",
        "examples",
        "cause",
        "effect",
        "findings",
        "finding",
        "time",
        "start",
        "end",
        "first_seen",
        "last_seen",
    }
)


class Redactor:
    """Holds one upload's token map and applies it.

    Create it with `Redactor.load(db, upload_id)` so tokens stay the same from one
    incident to the next, and call `save` afterwards.
    """

    def __init__(
        self, config: dict | None = None, entries: Iterable[tuple[str, str, str]] = ()
    ) -> None:
        settings = (config or load_config())["redaction"]
        self.enabled = bool(settings["enabled"])
        self.remove_secrets = bool(settings["remove_secrets"])
        try:
            self._private = [ipaddress.ip_network(n) for n in settings["private_networks"]]
        except ValueError as error:
            raise ValueError(f"redaction.private_networks: {error}") from None
        self._secrets: list[re.Pattern[str]] = []
        for secret in settings["secrets"]:
            try:
                pattern = re.compile(secret["pattern"])
            except re.error as error:
                raise ValueError(
                    f"redaction secret {secret['name']!r} is not a valid pattern: {error}"
                ) from None
            if "secret" not in pattern.groupindex:
                raise ValueError(
                    f"redaction secret {secret['name']!r} must name the part to remove "
                    "with (?P<secret>...)"
                )
            self._secrets.append(pattern)

        self._by_token: dict[str, tuple[str, str]] = {}  # token -> (kind, original)
        self._by_original: dict[str, str] = {}  # original -> token
        self._next = {kind: 1 for kind in KINDS}
        # Hostnames and usernames to look for: unlike an address, they cannot be
        # recognized by their shape, so they have to be told.
        self._known: dict[str, str] = {}
        self._saved: set[str] = set()
        for token, kind, original in entries:
            self._remember(token, kind, original)
            self._saved.add(token)

    # --- Setting up -----------------------------------------------------------------------

    @classmethod
    def load(cls, db, upload_id: int, config: dict | None = None) -> Redactor:
        return cls(config, db.redaction_map(upload_id))

    def save(self, db, upload_id: int) -> None:
        """Store the tokens handed out since the map was loaded."""
        new = [
            (token, kind, original)
            for token, (kind, original) in self._by_token.items()
            if token not in self._saved
        ]
        db.save_redaction_map(upload_id, new)
        self._saved.update(token for token, _, _ in new)

    def fork(self) -> Redactor:
        """A copy to try something on, without handing out tokens in this one."""
        copy = object.__new__(Redactor)
        copy.__dict__.update(self.__dict__)
        copy._by_token = dict(self._by_token)
        copy._by_original = dict(self._by_original)
        copy._next = dict(self._next)
        copy._known = dict(self._known)
        copy._saved = set(self._saved)
        return copy

    def add_known(self, kind: str, values: Iterable[str]) -> None:
        """Say that these values are hostnames (`HOST`) or usernames (`USER`)."""
        if kind not in KINDS:
            raise ValueError(f"not a kind of token: {kind!r}")
        for value in values:
            if isinstance(value, str) and value.strip():
                self._known.setdefault(value, kind)

    @property
    def mapping(self) -> dict[str, str]:
        """Token to original value. Never send this anywhere."""
        return {token: original for token, (_, original) in self._by_token.items()}

    def _remember(self, token: str, kind: str, original: str) -> None:
        self._by_token[token] = (kind, original)
        self._by_original[original] = token
        number = int(token.rsplit("_", 1)[1])
        self._next[kind] = max(self._next.get(kind, 1), number + 1)

    def _token(self, kind: str, original: str) -> str:
        token = self._by_original.get(original)
        if token is None:
            token = f"{kind}_{self._next[kind]}"
            self._remember(token, kind, original)
        return token

    # --- Redacting ------------------------------------------------------------------------

    def _pattern(self, within: str | None = None) -> tuple[re.Pattern[str], dict[str, str]]:
        """One pattern that finds everything to replace, and the kind of each known value.

        `within` is the text about to be searched; known values that do not occur in it
        are left out of the pattern, which keeps it small when thousands are known.
        """
        known = dict(self._known)
        for kind, original in self._by_token.values():
            if kind in ("USER", "HOST"):
                known.setdefault(original, kind)
        if within is not None:
            known = {value: kind for value, kind in known.items() if value in within}

        # Longest first, so a hostname that contains another is replaced as a whole. A
        # value made only of hex digits could be a piece of an address, and is matched
        # only where it is not one.
        ordered = sorted(known, key=lambda value: (-len(value), value))
        plain = [re.escape(v) for v in ordered if not _HEX_ONLY.fullmatch(v)]
        hexish = [re.escape(v) for v in ordered if _HEX_ONLY.fullmatch(v)]
        parts = [f"(?P<token>{_TOKEN})"]
        if plain:
            parts.append(f"(?P<known>(?<![{_WORD}])(?:{'|'.join(plain)})(?![{_WORD}]))")
        if hexish:
            parts.append(
                f"(?P<hexish>(?<![{_WORD}.:-])(?:{'|'.join(hexish)})(?![{_WORD}]|[.:-]\\w))"
            )
        parts += [f"(?P<mac>{_MAC})", f"(?P<ip4>{_IP4})", f"(?P<ip6>{_IP6})"]
        return re.compile("|".join(parts)), known

    def _strip_secrets(self, text: str) -> str:
        for pattern in self._secrets:

            def remove(match: re.Match[str]) -> str:
                whole, offset = match.group(0), match.start()
                start, end = match.span("secret")
                if start < 0 or match.group("secret") == REMOVED:
                    return whole
                return whole[: start - offset] + REMOVED + whole[end - offset :]

            text = pattern.sub(remove, text)
        return text

    def _tokenize(self, text: str, pattern: re.Pattern[str], known: dict[str, str]) -> str:
        def swap(match: re.Match[str]) -> str:
            found, group = match.group(0), match.lastgroup
            if group == "token":
                # Log text that already looks like one of our tokens. It gets a token of
                # its own, or `restore` would later mistake it for a real one.
                return self._token("TEXT", found)
            if group in ("known", "hexish"):
                return self._token(known[found], found)
            if group == "mac":
                return self._token("MAC", found)
            try:
                ipaddress.ip_address(found)
            except ValueError:
                return found  # shaped like an address without being one: 02:46:12
            return self._token("IP", found)

        return pattern.sub(swap, text)

    def redact_text(self, text: str) -> str:
        """Redact one piece of text."""
        if self.remove_secrets:
            text = self._strip_secrets(text)
        if self.enabled:
            text = self._tokenize(text, *self._pattern(text))
        return text

    def redact_data(self, data: dict) -> dict:
        """Redact every piece of text in an evidence pack's data, and add the legend that
        tells the reader which addresses are private and which public."""
        if self.remove_secrets:
            data = _walk(data, self._strip_secrets)
        if not self.enabled:
            return data
        pattern, known = self._pattern("\x00".join(_strings(data)))
        data = _walk(data, lambda text: self._tokenize(text, pattern, known))

        used = {token for text in _strings(data) for token in _TOKEN_RE.findall(text)}
        addresses = sorted(
            (token for token in used if token.startswith("IP_") and token in self._by_token),
            key=lambda token: int(token[3:]),
        )
        data["redaction"] = {
            "note": NOTE,
            "addresses": {token: self.describe(token) for token in addresses},
        }
        return data

    def describe(self, token: str) -> str:
        """The one thing told about an address: whether it is private or public."""
        kind, original = self._by_token[token]
        if kind != "IP":
            return ""
        address = ipaddress.ip_address(original)
        inside = any(address.version == net.version and address in net for net in self._private)
        return "private" if inside else "public"

    # --- Reversing ------------------------------------------------------------------------

    def restore(self, text: str) -> str:
        """Put the real values back into a piece of text, for showing it to the user.

        A token this upload never handed out is left as it is. Removed secrets stay
        removed.
        """
        return _TOKEN_RE.sub(
            lambda match: self._by_token.get(match.group(0), ("", match.group(0)))[1], text
        )


_VALUE_RE = re.compile(f"(?P<token>{_TOKEN})|(?P<mac>{_MAC})|(?P<ip4>{_IP4})|(?P<ip6>{_IP6})")


def find_values(text: str) -> list[tuple[str, str]]:
    """Every token, MAC address and IP address in a piece of text, as (kind, value).

    The kind is `token`, `mac` or `ip`. Used to check that an explanation mentions only
    values that are in the evidence pack it was written from.
    """
    found = []
    for match in _VALUE_RE.finditer(text):
        kind, value = match.lastgroup, match.group(0)
        if kind in ("ip4", "ip6"):
            try:
                ipaddress.ip_address(value)
            except ValueError:
                continue  # shaped like an address without being one: 02:46:12
            kind = "ip"
        found.append((kind, value))
    return found


def _walk(value, change, structural: bool = True):
    """A copy of `value` with `change` applied to every piece of text that is not in a
    structural field."""
    if isinstance(value, str):
        return change(value)
    if isinstance(value, list):
        return [_walk(item, change, structural) for item in value]
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if structural and key in STRUCTURAL_KEYS and _is_plain(item):
                out[key] = item
            else:
                out[key] = _walk(item, change, structural and key != "details")
        return out
    return value


def _is_plain(value) -> bool:
    """Text, a number, nothing, or a list of those."""
    items = value if isinstance(value, list) else [value]
    return not any(isinstance(item, dict | list) for item in items)


def _strings(value, structural: bool = True) -> list[str]:
    """Every piece of text `_walk` would change."""
    found: list[str] = []
    _walk(value, lambda text: found.append(text) or text, structural)
    return found
