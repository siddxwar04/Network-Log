// The pipeline as a row of steps: Parse, Templates, Detect, Correlate, Explain.

import { Check, LoaderCircle, X } from "lucide-react";
import type { Stage } from "../api/types";

export const STEPS: { stage: Stage; label: string; doing: string }[] = [
  { stage: "parsing", label: "Parse", doing: "Reading and parsing the lines" },
  { stage: "templates", label: "Templates", doing: "Finding message patterns" },
  { stage: "detection", label: "Detect", doing: "Running the detection rules" },
  { stage: "correlation", label: "Correlate", doing: "Grouping findings into incidents" },
  { stage: "explanation", label: "Explain", doing: "Writing the explanations" },
];

export type StepState = "done" | "active" | "pending" | "failed";

/** Where each step stands, given the pipeline's stage. */
export function stepStates(stage: Stage, failedStage: Stage | null = null): StepState[] {
  if (stage === "done") return STEPS.map(() => "done");
  const order = STEPS.map((step) => step.stage);
  if (stage === "failed") {
    const at = failedStage ? order.indexOf(failedStage) : -1;
    // Failed before any step began (or the stage is not known): mark the first.
    const failedAt = at < 0 ? 0 : at;
    return STEPS.map((_, i) => (i < failedAt ? "done" : i === failedAt ? "failed" : "pending"));
  }
  const at = order.indexOf(stage);
  return STEPS.map((_, i) => (at < 0 ? "pending" : i < at ? "done" : i === at ? "active" : "pending"));
}

const WORDS: Record<StepState, string> = {
  done: "done",
  active: "in progress",
  pending: "not started",
  failed: "failed",
};

const CIRCLE: Record<StepState, string> = {
  done: "border-ok bg-ok text-canvas",
  active: "border-accent text-accent",
  pending: "border-line text-muted",
  failed: "border-danger bg-danger text-canvas",
};

export function Stepper({ stage, failedStage }: { stage: Stage; failedStage?: Stage | null }) {
  const states = stepStates(stage, failedStage ?? null);
  return (
    <ol className="grid grid-cols-5 gap-1 sm:gap-2" aria-label="Pipeline stages">
      {STEPS.map((step, i) => {
        const state = states[i];
        return (
          <li
            key={step.stage}
            className="flex min-w-0 flex-col items-center gap-1.5 text-center"
            aria-current={state === "active" ? "step" : undefined}
            data-state={state}
          >
            <div className="flex w-full items-center">
              <span
                aria-hidden="true"
                className={`h-0.5 flex-1 ${i === 0 ? "invisible" : states[i - 1] === "done" ? "bg-ok" : "bg-line"}`}
              />
              <span
                className={`flex size-8 shrink-0 items-center justify-center rounded-full border-2 text-xs font-semibold ${CIRCLE[state]}`}
                aria-hidden="true"
              >
                {state === "done" ? (
                  <Check className="size-4" strokeWidth={3} />
                ) : state === "failed" ? (
                  <X className="size-4" strokeWidth={3} />
                ) : state === "active" ? (
                  <LoaderCircle className="size-4 animate-spin" />
                ) : (
                  i + 1
                )}
              </span>
              <span
                aria-hidden="true"
                className={`h-0.5 flex-1 ${i === STEPS.length - 1 ? "invisible" : state === "done" ? "bg-ok" : "bg-line"}`}
              />
            </div>
            <span
              className={`truncate text-xs font-medium sm:text-sm ${state === "pending" ? "text-muted" : "text-ink"}`}
            >
              {step.label}
              <span className="sr-only">: {WORDS[state]}</span>
            </span>
          </li>
        );
      })}
    </ol>
  );
}
