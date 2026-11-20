"""The held-out and noise test sets: freshly generated logs the rules were never tuned on.

    python -m eval.heldout              write them to data/eval/ (about 170 files)

For each kind of scenario there are 20 seeds, and each seed is a different variant: how
strong the incident is (some just above a rule's threshold, some far above, some just
below, which must give nothing), how much normal traffic surrounds it, and for the
cascade how many routers it reaches. The noise set is 10 files of normal traffic only, of
different sizes.

What a variant should give is written here, from the rule thresholds documented in
docs/RULES.md, not read from the rules themselves: if a rule is changed, these
expectations do not quietly follow it.

The seeds start at 1001 so they never meet the seed of the tuned set (1). If a rule is
changed after looking at held-out results, change SEED_BASE too, so the held-out set is
new again.
"""

from __future__ import annotations

import argparse
import json
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from generator.cli import DEFAULT_START, generate, write

SEED_BASE = 1001
SEEDS_PER_TYPE = 20
OUT = Path("data/eval")
# Normal traffic around the incident: lines and the hours they cover, by seed.
VOLUMES = ((2000, 4.0), (5000, 6.0), (10000, 12.0), (3000, 6.0), (8000, 8.0))


@dataclass
class Variant:
    scenario: str
    seed: int
    lines: int
    hours: float
    settings: dict = field(default_factory=dict)
    expect: dict = field(default_factory=dict)
    why: str = ""  # what this variant tests, in a few words

    @property
    def name(self) -> str:
        return f"{self.scenario}-{self.seed}"


def _link_flap(i: int) -> tuple[dict, dict, str]:
    # The rule: 5 downs on one interface in 5 minutes is Medium, 10 or more High.
    cycles = (3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 10, 11, 12, 13, 14, 15, 16, 18, 20, 4)[i]
    if cycles < 5:
        return {"cycles": cycles}, {"nothing": f"{cycles} downs, below 5"}, "just below"
    severity = "medium" if cycles < 10 else "high"
    near = "just above" if cycles in (5, 6, 10, 11) else "far above"
    return {"cycles": cycles}, {"severity": severity}, f"{cycles} downs, {near}"


def _cascade(i: int) -> tuple[dict, dict, str]:
    peers = (1, 2, 3)[i % 3]
    return {"peers": peers}, {}, f"{peers + 1} devices"


def _brute_force(i: int) -> tuple[dict, dict, str]:
    # The rule: 20 failed logins from one address in 10 minutes is Medium, Critical when a
    # login from it then succeeds.
    attempts, minutes, succeed = (
        (12, 8, False),
        (15, 8, False),
        (19, 8, False),
        (40, 60, False),
        (30, 60, False),
        (20, 8, False),
        (22, 8, False),
        (25, 8, False),
        (40, 8, False),
        (60, 9, False),
        (100, 10, False),
        (300, 12, False),
        (25, 8, True),
        (40, 8, True),
        (60, 9, True),
        (100, 10, True),
        (200, 12, True),
        (400, 12, True),
        (400, 20, True),
        (800, 30, False),
    )[i]
    settings = {"attempts": attempts, "minutes": minutes, "succeed": succeed}
    if attempts < 20 or attempts / minutes < 2:  # spread thin: under 20 in any 10 minutes
        how = "too few" if attempts < 20 else f"spread over {minutes} minutes"
        return settings, {"nothing": f"{attempts} failures, {how}"}, "just below"
    severity = "critical" if succeed else "medium"
    near = "just above" if attempts <= 25 else "far above"
    return (
        settings,
        {"severity": severity},
        f"{attempts} failures, {near}" + (", then a success" if succeed else ""),
    )


def _dhcp(i: int) -> tuple[dict, dict, str]:
    # The rule: 10 refusals in 5 minutes. One client retrying is refused at most 5 times.
    devices = (1, 15, 20, 30, 45)[i % 5]
    if devices == 1:
        return {"refused_devices": 1}, {"nothing": "one client, at most 5 refusals"}, "just below"
    return {"refused_devices": devices}, {}, f"{devices} clients refused"


def _overlap(i: int) -> tuple[dict, dict, str]:
    cycles, attempts = 10 + i % 5, (40, 100, 200, 300)[i % 4]
    return {"cycles": cycles, "attempts": attempts}, {}, f"{cycles} downs and {attempts} failures"


def _plain(_i: int) -> tuple[dict, dict, str]:
    return {}, {}, "another seed"


KINDS = {
    "link_flap": _link_flap,
    "cascade": _cascade,
    "config_bgp": _plain,
    "brute_force": _brute_force,
    "dhcp_exhaustion": _dhcp,
    "device_reload": _plain,
    "prompt_injection": _plain,
    "overlap": _overlap,
}
NOISE_SIZES = (
    (1000, 2.0),
    (2000, 4.0),
    (3000, 6.0),
    (5000, 6.0),
    (7000, 12.0),
    (10000, 12.0),
    (15000, 24.0),
    (20000, 24.0),
    (30000, 24.0),
    (50000, 24.0),
)


def heldout_variants(seeds: int = SEEDS_PER_TYPE) -> list[Variant]:
    variants = []
    for scenario, make in KINDS.items():
        for i in range(seeds):
            settings, expect, why = make(i % SEEDS_PER_TYPE)
            lines, hours = VOLUMES[i % len(VOLUMES)]
            variants.append(Variant(scenario, SEED_BASE + i, lines, hours, settings, expect, why))
    return variants


def noise_variants(count: int = len(NOISE_SIZES)) -> list[Variant]:
    return [
        Variant("noise", SEED_BASE + i, lines, hours, why=f"{lines} lines of normal traffic")
        for i, (lines, hours) in enumerate(NOISE_SIZES[:count])
    ]


def write_set(variants: list[Variant], folder: Path) -> list[Path]:
    """Generate each variant into `folder`, emptied first. Returns the log files."""
    if folder.exists():
        shutil.rmtree(folder)
    start = datetime.fromisoformat(DEFAULT_START)
    paths = []
    for variant in variants:
        text, labels = generate(
            variant.scenario,
            variant.seed,
            variant.lines,
            start,
            variant.hours,
            settings=variant.settings,
            expect=variant.expect,
        )
        labels["variant"] = variant.why
        paths.append(write(folder, variant.name, text, labels))
    return paths


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m eval.heldout", description=__doc__)
    parser.add_argument("--out", type=Path, default=OUT, help="folder to write to")
    args = parser.parse_args(argv)
    held = write_set(heldout_variants(), args.out / "heldout")
    noise = write_set(noise_variants(), args.out / "noise")
    negatives = sum(
        1
        for p in held
        if json.loads(p.with_suffix(".labels.json").read_text(encoding="utf-8")).get("negative")
    )
    print(
        f"{len(held)} held-out files ({negatives} built to give nothing) in {args.out / 'heldout'}"
    )
    print(f"{len(noise)} noise files in {args.out / 'noise'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
