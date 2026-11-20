import { screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { LiveIncident, LiveStatus } from "../api/types";
import { HEALTH, incident, mockApi } from "./mockApi";
import { renderApp } from "./render";

function liveIncident(overrides: Partial<LiveIncident> = {}): LiveIncident {
  return {
    ...incident({ id: "live-6f49884585", headline: "Interface GigabitEthernet0/1 on R1 was down for 8m 36s" }),
    state: "open",
    opened_at: "2026-11-21T10:00:29Z",
    changed_at: "2026-11-21T10:00:57Z",
    closed_at: null,
    ...overrides,
  };
}

function status(overrides: Partial<LiveStatus> = {}): LiveStatus {
  return {
    enabled: true,
    listening: { udp: "127.0.0.1:5514", tcp: "127.0.0.1:5514" },
    upload_id: 7,
    counters: {
      received: 1204, accepted: 1200, stored: 1196, refused: 0, rate_limited: 0,
      oversized: 1, not_text: 3, malformed: 4, dropped: 0,
    },
    per_minute: 312,
    queued: 0,
    senders: [
      { address: "198.51.100.1", messages: 900, discarded: 0, last_seen: "2026-11-21T10:01:00Z" },
      { address: "198.51.100.2", messages: 300, discarded: 8, last_seen: "2026-11-21T10:01:00Z" },
    ],
    warnings: [],
    last_detection: "2026-11-21T10:01:00Z",
    lines: 1196,
    open_incidents: [liveIncident()],
    closed_incidents: [],
    ...overrides,
  };
}

describe("the live page", () => {
  it("says how to switch the listener on when it is off", async () => {
    mockApi({ "GET /api/health": HEALTH, "GET /api/live": { enabled: false } });
    renderApp("/live");

    expect(await screen.findByText("The live listener is off")).toBeInTheDocument();
    expect(screen.getByText('$env:NETLOG_LIVE = "1"')).toBeInTheDocument();
    expect(screen.getByText(/netlog replay data\\scenarios\\02_cascade.log --speed 60/)).toBeInTheDocument();
  });

  it("shows the rate, the senders, what was not stored and the open incidents", async () => {
    mockApi({ "GET /api/health": HEALTH, "GET /api/live": status() });
    renderApp("/live");

    expect(await screen.findByText("Listening")).toBeInTheDocument();
    expect(screen.getByText("UDP 127.0.0.1:5514")).toBeInTheDocument();
    const rate = screen.getByText("Messages per minute").parentElement!;
    expect(rate).toHaveTextContent("312");
    expect(screen.getByText("Stored").parentElement).toHaveTextContent("1,196of 1,204 messages received");

    const dropped = screen.getByRole("region", { name: "Not stored" });
    expect(dropped).toHaveTextContent("4 not syslog");
    expect(dropped).toHaveTextContent("3 not text");
    expect(dropped).toHaveTextContent("1 too long");
    expect(dropped).not.toHaveTextContent("dropped in a burst");

    const open = screen.getByRole("region", { name: "Open incidents" });
    const card = within(open).getByRole("link", { name: /Interface GigabitEthernet0\/1 on R1 was down for 8m 36s/ });
    // A live incident opens on the ordinary incident page.
    expect(card).toHaveAttribute("href", "/uploads/7/incidents/live-6f49884585");

    const senders = screen.getByRole("table", { name: "Devices that sent messages" });
    expect(within(senders).getAllByRole("row")).toHaveLength(3);
    const second = within(senders).getAllByRole("row")[2];
    expect(within(second).getAllByRole("cell").map((cell) => cell.textContent)).toEqual(["198.51.100.2", "300", "8"]);
  });

  it("updates by itself as incidents open and close, without a reload", async () => {
    let calls = 0;
    mockApi({
      "GET /api/health": HEALTH,
      "GET /api/live": () => {
        calls += 1;
        if (calls === 1) return status({ open_incidents: [] });
        return status({ open_incidents: [], closed_incidents: [liveIncident({ state: "closed", closed_at: "2026-11-21T10:06:00Z" })] });
      },
    });
    renderApp("/live");

    expect(await screen.findByText(/Nothing open/)).toBeInTheDocument();
    const closed = screen.getByRole("region", { name: "Recently closed" });
    expect(within(closed).getByText("None yet.")).toBeInTheDocument();
    await waitFor(() => expect(within(closed).getByRole("link")).toBeInTheDocument(), { timeout: 4000 });
    expect(calls).toBeGreaterThanOrEqual(2);
  });

  it("shows a warning about an overflowing queue", async () => {
    mockApi({
      "GET /api/health": HEALTH,
      "GET /api/live": status({
        counters: { ...status().counters, dropped: 150 },
        warnings: ["2026-11-21T10:00:00+00:00: the queue of 10000 messages overflowed; the oldest are being dropped"],
      }),
    });
    renderApp("/live");
    const dropped = await screen.findByRole("region", { name: "Not stored" });
    expect(dropped).toHaveTextContent("150 dropped in a burst");
    expect(dropped).toHaveTextContent("the oldest are being dropped");
  });
});
