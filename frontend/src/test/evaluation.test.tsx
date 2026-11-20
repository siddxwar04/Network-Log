import { screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { Evaluation, EvaluationSet } from "../api/types";
import { HEALTH, mockApi } from "./mockApi";
import { renderApp } from "./render";

function set(overrides: Partial<EvaluationSet> = {}): EvaluationSet {
  return {
    files: 160,
    lines: 894486,
    overall: { expected: 167, found: 165, false_alarms: 1, precision: 0.994, recall: 0.988, f1: 0.991 },
    by_type: {
      link_flap: { expected: 36, found: 35, false_alarms: 0, precision: 1, recall: 0.972, f1: 0.986 },
    },
    root_cause: { correct: 160, of: 165, rate: 0.97 },
    severity: { correct: 165, of: 165, rate: 1 },
    devices: { correct: 150, of: 165, rate: 0.909 },
    correlation: { split: 0, merged: 1, expected: 167 },
    false_alarms_per_10k_lines: 0.01,
    lines_per_second: 5000,
    ...overrides,
  };
}

const RESULTS: Evaluation = {
  generated_at: "2026-11-21T12:00:00+00:00",
  limits: "These are synthetic logs from this project's own generator.",
  matching_rule: "A found incident matches an expected one when it is of the same type.",
  topology: false,
  sets: { heldout: set(), tuned: set({ files: 10 }), noise: set({ files: 10, lines: 143014 }) },
  efficiency: {
    compression_ratio: 317.4,
    lines: 94918,
    templates: 299,
    evidence_pack_tokens: { incidents: 9, median: 849, largest: 2931, limit: 3000 },
  },
  explanations: { measured: false, why: "needs a real LLM provider" },
  problems: [
    {
      set: "heldout", file: "link_flap-1009", scenario: "link_flap", seed: 1009,
      variant: "8 downs, far above", kind: "miss", reason: "expected link_flap on R1; found: nothing near it",
    },
  ],
};

describe("the accuracy page", () => {
  it("shows the limits first, then each set, the types and every miss", async () => {
    mockApi({ "GET /api/health": HEALTH, "GET /api/evaluation": RESULTS });
    renderApp("/evaluation");

    expect(await screen.findByRole("note")).toHaveTextContent("These are synthetic logs");
    const heldout = screen.getByRole("rowheader", { name: /Held-out/ }).closest("tr")!;
    expect(within(heldout).getByText("99.4%")).toBeInTheDocument(); // precision
    expect(within(heldout).getByText("98.8%")).toBeInTheDocument(); // recall
    expect(within(heldout).getByText("90.9%")).toBeInTheDocument(); // devices
    expect(within(heldout).getByText("0 / 1")).toBeInTheDocument(); // split / merged
    expect(screen.getByText("link_flap")).toBeInTheDocument();
    expect(screen.getByText(/317 to 1/)).toBeInTheDocument();
    expect(screen.getByText("Misses and false alarms (1)")).toBeInTheDocument();
    expect(screen.getByText("expected link_flap on R1; found: nothing near it")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Accuracy" })).toBeInTheDocument();
  });

  it("says how to make results when there are none", async () => {
    mockApi({
      "GET /api/health": HEALTH,
      "GET /api/evaluation": { status: 404, body: { error: { code: "no_results", message: "No results." } } },
    });
    renderApp("/evaluation");

    expect(await screen.findByText("No results yet")).toBeInTheDocument();
    expect(screen.getByText(/python -m eval.harness/)).toBeInTheDocument();
  });
});
