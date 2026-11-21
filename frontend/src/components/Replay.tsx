// The replay of an incident: a bar at the bottom of the screen that walks through the
// explanation one sentence at a time. On top it draws the steps as a track, numbered circles
// joined by arrows like a small diagram: the current one is larger, the ones passed are
// filled, and any of them can be clicked. Under it, the current step in words, and the
// controls. The page highlights the step's box in the chain, its markers on the timeline
// and its log lines. Left and right arrows step, space plays and pauses, Escape leaves.

import { ArrowRight, ChevronLeft, ChevronRight, Pause, Play, X } from "lucide-react";
import { useEffect, useRef } from "react";
import { utcTime } from "../lib/format";
import { announce, prefersReducedMotion, type ReplayStep } from "../lib/replay";
import { Button } from "./ui";

/** The track draws one circle per step up to this many; a longer replay gets a plain
 * progress line instead, as that many circles could not be read. */
const TRACK_MAX = 24;

export function ReplayBar({
  steps,
  index,
  playing,
  stepSeconds,
  onStep,
  onPlaying,
  onExit,
}: {
  steps: ReplayStep[];
  index: number;
  playing: boolean;
  /** How long Play stays on a step. It comes from the API's settings. */
  stepSeconds: number;
  onStep: (index: number) => void;
  onPlaying: (playing: boolean) => void;
  onExit: () => void;
}) {
  const step = steps[index];
  const last = index >= steps.length - 1;
  const controls = useRef<HTMLDivElement>(null);
  const still = prefersReducedMotion();

  // Focus lands on Play and Pause, so the keyboard works from the first moment.
  useEffect(() => {
    controls.current?.querySelector<HTMLButtonElement>("[data-toggle]")?.focus({ preventScroll: true });
  }, []);

  // Play: move on after the delay, and stop on the last step.
  useEffect(() => {
    if (!playing) return;
    // On the last step, or with an API too old to say how long a step lasts, Play stops.
    if (last || !(stepSeconds > 0)) {
      onPlaying(false);
      return;
    }
    const timer = window.setTimeout(() => onStep(index + 1), stepSeconds * 1000);
    return () => window.clearTimeout(timer);
  }, [playing, last, index, stepSeconds, onStep, onPlaying]);

  // From the last step, Play starts over.
  const play = () => {
    if (playing) return onPlaying(false);
    if (last && steps.length > 1) onStep(0);
    onPlaying(true);
  };
  const back = () => {
    onPlaying(false);
    if (index > 0) onStep(index - 1);
  };
  const next = () => {
    onPlaying(false);
    if (!last) onStep(index + 1);
  };

  const pick = (to: number) => {
    onPlaying(false);
    onStep(to);
  };

  const keys = useRef({ play, back, next, onExit });
  keys.current = { play, back, next, onExit };
  useEffect(() => {
    const press = (event: KeyboardEvent) => {
      if (event.altKey || event.ctrlKey || event.metaKey) return;
      const target = event.target as HTMLElement | null;
      if (target?.closest?.("input, textarea, select, [role=dialog]")) return;
      if (event.key === "Escape") keys.current.onExit();
      else if (event.key === "ArrowLeft") keys.current.back();
      else if (event.key === "ArrowRight") keys.current.next();
      else if (event.key === " ") {
        // Space on a button or a link presses it; anywhere else it plays and pauses.
        if (target?.closest?.("button, a, [role=button], summary")) return;
        keys.current.play();
      } else return;
      event.preventDefault();
    };
    window.addEventListener("keydown", press);
    return () => window.removeEventListener("keydown", press);
  }, []);

  if (!step) return null;
  return (
    <section
      aria-label="Replay"
      className="fixed inset-x-0 bottom-0 z-40 border-t border-line-strong bg-raised shadow-panel"
    >
      {steps.length > 1 && steps.length <= TRACK_MAX && (
        <ol aria-label="Steps" className="mx-auto flex max-w-6xl items-center gap-1 overflow-x-auto px-4 pt-3 pb-0.5">
          {steps.map((item, i) => (
            <li key={i} className="flex shrink-0 items-center gap-1">
              {i > 0 && (
                <ArrowRight aria-hidden="true" className={`size-3.5 transition-colors ${i <= index ? "text-accent" : "text-faint"}`} />
              )}
              <button
                type="button"
                onClick={() => pick(i)}
                aria-label={`Go to step ${i + 1}: ${item.title}`}
                aria-current={i === index ? "step" : undefined}
                title={item.sentence}
                className={`inline-flex items-center justify-center rounded-full border text-2xs font-semibold tabular-nums transition-all ${
                  i === index
                    ? "size-7 border-accent bg-accent text-accent-ink ring-2 ring-accent/30"
                    : i < index
                      ? "size-6 border-accent bg-accent/15 text-ink hover:bg-accent/25"
                      : "size-6 border-line-strong bg-panel text-muted hover:border-faint hover:text-ink"
                }`}
              >
                {i + 1}
              </button>
            </li>
          ))}
        </ol>
      )}
      <div className="mx-auto flex max-w-6xl flex-wrap items-center gap-x-4 gap-y-2 px-4 py-3">
        <div className="min-w-0 flex-1 basis-80">
          <p className="flex flex-wrap items-center gap-x-2 text-2xs text-muted">
            <span className="rounded-sm bg-accent px-1.5 py-0.5 font-semibold text-accent-ink">
              Step {index + 1} of {steps.length}
            </span>
            <span className={`font-semibold tracking-wide uppercase ${step.node.suspect ? "text-warn" : step.node.root ? "text-root" : "text-faint"}`}>
              {step.title}
            </span>
            {step.devices.length > 0 && <span className="font-mono text-ink">{step.devices.join(", ")}</span>}
            {step.time && <span className="font-mono tabular-nums">{utcTime(step.time)} UTC</span>}
            {step.offset && step.offset !== "start" && <span className="font-mono">{step.offset}</span>}
          </p>
          {/* Keyed by step, so each new step fades in; plain text, as log content is untrusted. */}
          <p
            key={index}
            data-motion={still ? "off" : "on"}
            className={`mt-1 text-base leading-snug text-ink ${still ? "" : "replay-step"}`}
          >
            {step.sentence}
          </p>
          <p role="status" aria-live="polite" className="sr-only">
            {announce(step, index, steps.length)}
          </p>
        </div>
        <div ref={controls} role="group" aria-label="Replay controls" className="flex items-center gap-1.5">
          <Button onClick={back} disabled={index === 0} aria-label="Back" title="Back (left arrow)" className="px-2">
            <ChevronLeft aria-hidden="true" className="size-4" />
          </Button>
          <Button data-toggle variant="primary" onClick={play} title="Play or pause (space)" className="min-w-24">
            {playing ? <Pause aria-hidden="true" className="size-4" /> : <Play aria-hidden="true" className="size-4" />}
            {playing ? "Pause" : "Play"}
          </Button>
          <Button onClick={next} disabled={last} aria-label="Next" title="Next (right arrow)" className="px-2">
            <ChevronRight aria-hidden="true" className="size-4" />
          </Button>
          <Button variant="ghost" onClick={onExit} title="Leave the replay (Escape)">
            <X aria-hidden="true" className="size-4" />
            Exit
          </Button>
        </div>
      </div>
      {steps.length > TRACK_MAX && (
        <div aria-hidden="true" className="h-1 bg-line">
          <div className="h-full bg-accent transition-all" style={{ width: `${((index + 1) / steps.length) * 100}%` }} />
        </div>
      )}
    </section>
  );
}
