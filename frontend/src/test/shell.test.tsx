import { screen, within } from "@testing-library/react";
import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { formatBytes, formatNumber, scenarioTitle } from "../lib/format";
import { SEVERITY, SeverityBadge, SeverityCounts } from "../lib/severity";
import { LEVELS } from "../api/types";
import { dashboard, DEMOS, HEALTH, mockApi, page, summary, uploadDetail } from "./mockApi";
import { renderApp } from "./render";

const HOME = {
  "GET /api/health": HEALTH,
  "GET /api/demo/scenarios": page(DEMOS),
  "GET /api/uploads": page([]),
};

describe("navigation", () => {
  it("has the dashboard and incidents unavailable until an upload is open", async () => {
    mockApi(HOME);
    renderApp("/");
    const nav = screen.getByRole("navigation", { name: "Main" });

    expect(within(nav).getByRole("link", { name: "Upload" })).toHaveAttribute("aria-current", "page");
    expect(within(nav).getByText("Dashboard")).toHaveAttribute("aria-disabled", "true");
    expect(within(nav).getByText("Incidents")).toHaveAttribute("aria-disabled", "true");
    await screen.findByText("No uploads yet.");
  });

  it("points at the open upload, and remembers it", async () => {
    mockApi({ ...HOME, ...dashboard(4), "GET /api/uploads/4": uploadDetail({ id: 4, filename: "flap.log" }) });
    const first = renderApp("/uploads/4");
    expect(await screen.findByRole("heading", { name: "flap.log" })).toBeInTheDocument();
    const nav = screen.getByRole("navigation", { name: "Main" });
    expect(within(nav).getByRole("link", { name: "Dashboard" })).toHaveAttribute("href", "/uploads/4");
    expect(within(nav).getByRole("link", { name: "Incidents" })).toHaveAttribute("href", "/uploads/4/incidents");
    first.unmount();

    // Back on the home screen later, the links still lead to it.
    renderApp("/");
    const again = screen.getByRole("navigation", { name: "Main" });
    expect(within(again).getByRole("link", { name: "Dashboard" })).toHaveAttribute("href", "/uploads/4");
    await screen.findByText("No uploads yet.");
  });

  it("sends a dashboard that is still processing to the processing screen", async () => {
    mockApi({
      ...HOME,
      "GET /api/uploads/2": uploadDetail({ id: 2, status: "processing", stage: "templates" }),
      "GET /api/uploads/2/status": { ...uploadDetail(), stage: "templates", status: "processing", finished: false, stages: HEALTH.stages, failed_stage: null, counts: { lines: 10, templates: 0, findings: 0, incidents: 0 } },
    });
    renderApp("/uploads/2");
    expect(await screen.findByText("Finding message patterns")).toBeInTheDocument();
  });

  it("has a page for an address that does not exist", async () => {
    mockApi(HOME);
    const { user } = renderApp("/no/such/page");
    expect(screen.getByText("There is no page at this address.")).toBeInTheDocument();
    await user.click(screen.getByRole("link", { name: "Back to uploads" }));
    expect(await screen.findByRole("heading", { name: "Analyze a log file" })).toBeInTheDocument();
  });

  it("offers a way to skip straight to the content", () => {
    mockApi(HOME);
    renderApp("/");
    expect(screen.getByRole("link", { name: "Skip to content" })).toHaveAttribute("href", "#main");
    expect(screen.getByRole("main")).toHaveAttribute("id", "main");
  });
});

describe("the theme", () => {
  it("is dark by default, switches to light, and is remembered", async () => {
    mockApi(HOME);
    const { user, unmount } = renderApp("/");
    expect(document.documentElement).toHaveClass("dark");

    await user.click(screen.getByRole("button", { name: "Switch to light theme" }));
    expect(document.documentElement).not.toHaveClass("dark");
    expect(localStorage.getItem("netlog-theme")).toBe("light");
    expect(screen.getByRole("button", { name: "Switch to dark theme" })).toBeInTheDocument();
    unmount();

    renderApp("/");
    expect(document.documentElement).not.toHaveClass("dark");
    await screen.findByText("No uploads yet.");
  });
});

describe("severity", () => {
  it("is never color alone: every level has its own icon and its name", () => {
    const icons = new Set(LEVELS.map((level) => SEVERITY[level].icon));
    expect(icons.size).toBe(5);
    render(<SeverityBadge level="critical" count={2} />);
    const badge = screen.getByText("Critical").parentElement!;
    expect(badge).toHaveTextContent("2Critical");
    expect(badge.querySelector("svg")).toHaveAttribute("aria-hidden", "true");
  });

  it("lists only the levels that have incidents, most severe first", () => {
    render(<SeverityCounts counts={{ critical: 0, high: 2, medium: 0, low: 1, info: 0 }} />);
    expect(screen.getAllByText(/High|Low/).map((el) => el.textContent)).toEqual(["High", "Low"]);
  });
});

describe("formatting", () => {
  it("writes numbers, sizes and scenario names for reading", () => {
    expect(formatNumber(48210)).toBe("48,210");
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(530682)).toBe("518 KB");
    expect(formatBytes(50 * 1024 * 1024)).toBe("50 MB");
    expect(formatBytes(1536)).toBe("1.5 KB");
    expect(scenarioTitle("02_cascade")).toBe("Cascade");
    expect(scenarioTitle("05_dhcp_exhaustion")).toBe("DHCP exhaustion");
    expect(scenarioTitle("03_config_bgp")).toBe("Config BGP");
    expect(scenarioTitle("08_noise_50k")).toBe("Noise 50k");
  });
});

describe("a screen that crashes", () => {
  it("shows the problem inside the frame, with the navigation still usable", async () => {
    const { vi } = await import("vitest");
    const quiet = vi.spyOn(console, "error").mockImplementation(() => {});
    // An answer in a shape the screen does not expect makes it fail while drawing.
    mockApi({ ...HOME, ...dashboard(4), "GET /api/uploads/4/summary": { ...summary(), file: null } });
    const { user } = renderApp("/uploads/4");

    expect(await screen.findByText("This screen ran into a problem and could not be shown.")).toBeInTheDocument();
    const nav = screen.getByRole("navigation", { name: "Main" });
    await user.click(within(nav).getByRole("link", { name: "Upload" }));
    expect(await screen.findByRole("heading", { name: "Analyze a log file" })).toBeInTheDocument();
    quiet.mockRestore();
  });
});
