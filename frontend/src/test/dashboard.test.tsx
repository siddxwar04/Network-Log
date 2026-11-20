import { screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { describeEvents, eventsSeries } from "../lib/eventsChart";
import { formatDuration, utcSpan } from "../lib/format";
import { dashboard, HEALTH, incident, mockApi, page, status, summary, uploadDetail } from "./mockApi";
import { renderApp } from "./render";

function tile(label: string): HTMLElement {
  const term = screen.getAllByText(label).find((el) => el.tagName === "DT");
  if (!term?.parentElement) throw new Error(`no tile ${label}`);
  return term.parentElement;
}

const BRUTE = incident({
  id: "inc-a727726dd8",
  headline: "300 failed logins from 192.0.2.77 in 7m 58s",
  severity: "medium",
  start: "2026-03-03T03:30:00Z",
  end: "2026-03-03T03:37:58Z",
  duration_seconds: 478,
  devices: ["srv1"],
  root_cause: {
    kind: "brute_force_login",
    summary: "300 failed logins from 192.0.2.77 in 7m 58s",
    devices: ["srv1"],
    entity: "192.0.2.77",
    findings: [9],
    explains: 1,
  },
  confidence: "medium",
  findings: 1,
});
const FLAP = incident({
  id: "inc-724b694524",
  headline: "Interface GigabitEthernet0/5 on SW2 went down 10 times in 3m 2s",
  severity: "high",
  devices: ["SW2"],
  root_cause: null,
  findings: 1,
});
const CONFIG = incident({
  id: "inc-b3dfb3ee42",
  headline: "BGP session from R2 to 203.0.113.1 went down",
  root_cause: {
    kind: "config_change",
    summary: "The configuration of R2 was changed by jdoe from 10.10.10.53 shortly before the failure",
    devices: ["R2"],
    entity: "jdoe",
    findings: [3],
    explains: 1,
  },
});

describe("the dashboard", () => {
  it("shows the stats, the chart, the incidents most severe first and the side lists", async () => {
    mockApi({ "GET /api/health": HEALTH, ...dashboard(1, { incidents: [CONFIG, FLAP, BRUTE] }) });
    const { user } = renderApp("/uploads/1");

    expect(await screen.findByRole("heading", { level: 1, name: "02_cascade.log" })).toBeInTheDocument();
    // 1. Stat tiles, with large numbers written for reading. They appear once the summary is in.
    await screen.findByText("147 lines per pattern");
    expect(within(tile("Lines")).getByText("5,000")).toBeInTheDocument();
    expect(within(tile("Devices")).getByText("4")).toBeInTheDocument();
    expect(within(tile("Time span")).getByText(formatDuration(21597))).toBeInTheDocument();
    expect(within(tile("Time span")).getByText(/3 Mar 2026, 00:00:01 to 05:59:58 UTC/)).toBeInTheDocument();
    expect(within(tile("Parsed")).getByText("100.0%")).toBeInTheDocument();
    expect(within(tile("Parsed")).getByText("Every line understood")).toBeInTheDocument();
    expect(within(tile("Message patterns")).getByText("34")).toBeInTheDocument();
    expect(within(tile("Message patterns")).getByText("147 lines per pattern")).toBeInTheDocument();
    expect(within(tile("Incidents")).getByText("Critical")).toBeInTheDocument();

    // 2. The chart, with its description for screen readers.
    const chart = await screen.findByTestId("events-chart");
    expect(chart).toHaveAttribute("data-bars", "4"); // the empty 02:50 bucket is filled in
    const figure = screen.getByRole("img", { name: /Events over time from 3 Mar 2026, 02:40:00/ });
    expect(figure).toHaveAccessibleName(/critical incident from 02:46:11 UTC: Interface GigabitEthernet0\/1 on R1/);

    // 3. Incident cards: most severe first, as the API sent them, each opening its page.
    const cards = within(screen.getByRole("region", { name: /Incidents/ })).getAllByRole("link");
    expect(cards.map((card) => card.getAttribute("href"))).toEqual([
      "/uploads/1/incidents/inc-b3dfb3ee42",
      "/uploads/1/incidents/inc-724b694524",
      "/uploads/1/incidents/inc-a727726dd8",
    ]);
    // A configuration change is a suspect, never a proven cause.
    expect(within(cards[0]).getByText(/Suspect:/)).toBeInTheDocument();
    expect(within(cards[2]).getByText(/Likely cause:/)).toBeInTheDocument();
    expect(within(cards[2]).getByText("srv1")).toBeInTheDocument();
    expect(within(cards[2]).getByText("for 7m 58s")).toBeInTheDocument();
    expect(within(cards[2]).getByText("Medium confidence")).toBeInTheDocument();

    // 4. The noisiest patterns and the busiest devices, busiest first.
    const patterns = within(screen.getByRole("region", { name: "Noisiest message patterns" })).getAllByRole("listitem");
    expect(patterns[0]).toHaveTextContent("DHCPACK on <IP> to <MAC> (<HOST>) via <IF>761");
    const devices = within(screen.getByRole("region", { name: "Busiest devices" })).getAllByRole("listitem");
    expect(devices.map((row) => row.textContent)).toEqual(["dhcp11,810", "srv11,450", "R1640", "SW1300"]);

    // Assumptions are said plainly.
    expect(screen.getByText("The log lines carry no year; 2026 was used, as given.")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();

    // Clicking an incident band in the chart opens that incident.
    await user.click(screen.getByRole("button", { name: /Band: Interface GigabitEthernet0\/1/ }));
    expect(await screen.findByText(/has no incident with the id/)).toBeInTheDocument();
  });

  it("says clearly when nothing is wrong, and still shows the stats", async () => {
    const quiet = summary({
      summary: { ...summary().summary, incidents: 0, incidents_by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } },
      incident_periods: [],
    });
    mockApi({ "GET /api/health": HEALTH, ...dashboard(1, { summary: quiet, incidents: [] }) });
    renderApp("/uploads/1");

    expect(await screen.findByText("No incidents found in this log.")).toBeInTheDocument();
    expect(screen.getByText(/Routine events, such as configuration changes/)).toBeInTheDocument();
    expect(within(tile("Lines")).getByText("5,000")).toBeInTheDocument();
    expect(within(tile("Incidents")).getByText("0")).toBeInTheDocument();
    expect(within(tile("Incidents")).getByText("None")).toBeInTheDocument();
    expect(screen.getByRole("img", { name: /No incident periods\./ })).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("warns when too few lines were understood, and lists them on request", async () => {
    const poor = summary({
      file: { ...summary().file, lines: 8, parsed: 6, unparsed: 2, percent_parsed: 75 },
      warnings: [
        'Only 75.0% of lines were understood, so problems may have been missed. Most common lines not understood: "unknown record N" (2)',
      ],
    });
    const api = mockApi({
      "GET /api/health": HEALTH,
      ...dashboard(1, { summary: poor }),
      "GET /api/uploads/1/events": page([
        { id: 7, line_no: 7, raw: "unknown record 17", timestamp: null, host: null, event_key: null, message: "unknown record 17", parse_status: "unparsed" },
        { id: 8, line_no: 8, raw: "<script>alert(1)</script>", timestamp: null, host: null, event_key: null, message: "x", parse_status: "unparsed" },
      ]),
    });
    const { user } = renderApp("/uploads/1");

    const warning = await screen.findByRole("alert");
    expect(warning).toHaveTextContent("Only 75.0% of lines were understood");
    expect(within(tile("Parsed")).getByText("75.0%")).toBeInTheDocument();
    expect(within(tile("Parsed")).getByText("2 lines not understood")).toBeInTheDocument();
    expect(api.calls.some((c) => c.path === "/api/uploads/1/events")).toBe(false); // only on request

    await user.click(within(warning).getByRole("button", { name: "Show the lines not understood" }));
    expect(await within(warning).findByText("unknown record 17")).toBeInTheDocument();
    // A log line is text, never markup.
    expect(within(warning).getByText("<script>alert(1)</script>")).toBeInTheDocument();
    expect(document.querySelector("script")).toBeNull();
    expect(within(warning).getByText("7")).toBeInTheDocument();
    expect(within(warning).getByText(/The first 2 of 2 lines not understood/)).toBeInTheDocument();
  });

  it("sends an upload still being processed to the processing screen", async () => {
    mockApi({
      "GET /api/health": HEALTH,
      "GET /api/uploads/2": uploadDetail({ id: 2, status: "processing", stage: "templates" }),
      "GET /api/uploads/2/status": status("templates", { id: 2 }),
    });
    renderApp("/uploads/2");
    expect(await screen.findByText("Finding message patterns")).toBeInTheDocument();
  });

  it("shows a missing upload as a readable error", async () => {
    mockApi({
      "GET /api/health": HEALTH,
      "GET /api/uploads/9": { status: 404, body: { error: { code: "upload_not_found", message: "There is no upload with id 9." } } },
    });
    renderApp("/uploads/9");
    expect(await screen.findByText("There is no upload with id 9.")).toBeInTheDocument();
  });
});

describe("the incidents list and an incident", () => {
  it("sorts by severity or by time", async () => {
    mockApi({ "GET /api/health": HEALTH, ...dashboard(1, { incidents: [CONFIG, FLAP, BRUTE] }) });
    const { user } = renderApp("/uploads/1/incidents");

    const headlines = async () =>
      (await screen.findAllByRole("heading", { level: 3 })).map((h) => h.textContent?.slice(0, 12));
    expect(await headlines()).toEqual(["BGP session ", "Interface Gi", "300 failed l"]);
    await user.click(screen.getByRole("button", { name: "Earliest" }));
    expect(screen.getByRole("button", { name: "Earliest" })).toHaveAttribute("aria-pressed", "true");
    expect(await headlines()).toEqual(["BGP session ", "Interface Gi", "300 failed l"].sort((a, b) =>
      a === "300 failed l" ? 1 : b === "300 failed l" ? -1 : 0,
    ));
    const crumbs = screen.getByRole("navigation", { name: "Breadcrumb" });
    expect(within(crumbs).getByRole("link", { name: "02_cascade.log" })).toHaveAttribute("href", "/uploads/1");
  });

  it("opens an incident with the facts the rules decided", async () => {
    mockApi({ "GET /api/health": HEALTH, ...dashboard(1, { incidents: [CONFIG] }) });
    renderApp("/uploads/1/incidents/inc-b3dfb3ee42");

    expect(await screen.findByRole("heading", { name: "BGP session from R2 to 203.0.113.1 went down" })).toBeInTheDocument();
    expect(screen.getByText("Suspect")).toBeInTheDocument();
    expect(screen.getByText(/changed by jdoe from 10\.10\.10\.53/)).toBeInTheDocument();
    expect(screen.getByText(utcSpan(CONFIG.start, CONFIG.end))).toBeInTheDocument();
    expect(screen.getByText("Critical")).toBeInTheDocument();
  });
});

describe("the events-over-time data", () => {
  const over = summary().events_over_time;

  it("fills in empty buckets so time runs evenly", () => {
    const series = eventsSeries(over, summary().incident_periods);
    expect(series.bars.map((bar) => new Date(bar.start).toISOString().slice(11, 16))).toEqual([
      "02:40", "02:45", "02:50", "02:55",
    ]);
    expect(series.bars.map((bar) => bar.count)).toEqual([60, 95, 0, 50]);
    expect(series.total).toBe(205);
    expect(series.busiest?.count).toBe(95);
  });

  it("makes every incident band at least one bar wide", () => {
    const series = eventsSeries(over, summary().incident_periods);
    const [band] = series.bands;
    expect(band.end - band.start).toBe(300_000); // 41 seconds, widened to one 5-minute bar
    const long = eventsSeries(over, [{ ...summary().incident_periods[0], end: "2026-03-03T03:00:00Z" }]);
    expect(long.bands[0].end).toBe(Date.parse("2026-03-03T03:00:00Z"));
  });

  it("describes itself in words", () => {
    const text = describeEvents(eventsSeries(over, summary().incident_periods));
    expect(text).toBe(
      "Events over time from 3 Mar 2026, 02:40:00 to 03:00:00 UTC, 205 events in bars of 5 min. " +
        "Busiest: 95 events at 02:45:00 UTC. " +
        "critical incident from 02:46:11 UTC: Interface GigabitEthernet0/1 on R1 was down for 8m 36s.",
    );
    expect(describeEvents(eventsSeries({ bucket_seconds: null, buckets: [] }, []))).toBe("No events with a time to chart.");
  });
});

describe("upload progress and confirmations", () => {
  it("shows how much of the file has gone while it uploads", async () => {
    mockApi({
      "GET /api/health": HEALTH,
      "GET /api/demo/scenarios": page([]),
      "GET /api/uploads": page([]),
      // The server never answers, so the progress stays on screen.
      "POST /api/uploads": () => new Promise(() => {}),
    });
    // Replace the fake XHR with one that reports half the file sent and then waits.
    const { vi } = await import("vitest");
    class HalfSent {
      upload: { onprogress: ((event: ProgressEvent) => void) | null } = { onprogress: null };
      onload = null;
      onerror = null;
      open() {}
      send() {
        setTimeout(() => this.upload.onprogress?.({ lengthComputable: true, loaded: 50, total: 100 } as ProgressEvent), 0);
      }
    }
    vi.stubGlobal("XMLHttpRequest", HalfSent);
    const { user } = renderApp("/");

    await user.upload(screen.getByTestId("file-input"), new File(["x".repeat(2048)], "big.log"));
    const bar = await screen.findByRole("progressbar", { name: "Uploading big.log" });
    await waitFor(() => expect(bar).toHaveAttribute("aria-valuenow", "50"));
    expect(screen.getByText("50% of 2 KB")).toBeInTheDocument();
  });

  it("confirms a delete with a short message", async () => {
    let rows = [uploadDetail({ id: 3, filename: "overlap.log" })];
    mockApi({
      "GET /api/health": HEALTH,
      "GET /api/demo/scenarios": page([]),
      "GET /api/uploads": () => page(rows),
      "DELETE /api/uploads/3": () => {
        rows = [];
        return { status: 204 };
      },
    });
    const { user } = renderApp("/");

    await user.click(await screen.findByRole("button", { name: "Delete overlap.log" }));
    await user.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Delete" }));
    expect(await screen.findByText("Deleted overlap.log")).toBeInTheDocument();
    expect(await screen.findByText("No uploads yet.")).toBeInTheDocument();
  });
});
