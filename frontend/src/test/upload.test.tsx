import { screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { apiError, dashboard, DEMOS, HEALTH, mockApi, page, status, uploadDetail, uploadItem } from "./mockApi";
import { renderApp } from "./render";

function logFile(name = "router.log", text = "Mar  3 02:00:00 R1 %LINK-3-UPDOWN: x\n") {
  return new File([text], name, { type: "text/plain" });
}

const HOME = {
  "GET /api/health": HEALTH,
  "GET /api/demo/scenarios": page(DEMOS),
  "GET /api/uploads": page([]),
};

describe("the upload screen", () => {
  it("shows the size limit, the demo scenarios and an empty list", async () => {
    mockApi(HOME);
    renderApp("/");

    expect(screen.getByRole("heading", { name: "Analyze a log file" })).toBeInTheDocument();
    expect(await screen.findByText(/up to 50 MB/)).toBeInTheDocument();
    expect(await screen.findByRole("button", { name: /Cascade/ })).toBeInTheDocument();
    expect(screen.getByText("No uploads yet.")).toBeInTheDocument();
    // A scenario with an incident shows its expected severity; one without says so.
    const cascade = screen.getByRole("button", { name: /Cascade/ });
    expect(within(cascade).getByText("Critical")).toBeInTheDocument();
    expect(within(screen.getByRole("button", { name: /Noise/ })).getByText("No incident")).toBeInTheDocument();
  });

  it("uploads a chosen file and moves on to the processing screen", async () => {
    const api = mockApi({
      ...HOME,
      "POST /api/uploads": { status: 202, body: uploadItem({ id: 7, filename: "router.log", status: "processing", stage: "queued" }) },
      "GET /api/uploads/7": uploadDetail({ id: 7, filename: "router.log", status: "processing", stage: "parsing" }),
      "GET /api/uploads/7/status": status("parsing", { id: 7 }),
    });
    const { user } = renderApp("/");

    await user.upload(screen.getByTestId("file-input"), logFile());

    expect(await screen.findByRole("heading", { name: /Analyzing router\.log/ })).toBeInTheDocument();
    const sent = api.calls.find((call) => call.method === "POST");
    expect(sent?.path).toBe("/api/uploads");
    const form = sent?.body as FormData;
    expect((form.get("file") as File).name).toBe("router.log");
    expect(form.get("year")).toBeNull();
  });

  it("accepts a file dropped on the zone, with a year and timezone", async () => {
    const api = mockApi({
      ...HOME,
      "POST /api/uploads": { status: 202, body: uploadItem({ id: 8, status: "processing" }) },
      "GET /api/uploads/8": uploadDetail({ id: 8 }),
      "GET /api/uploads/8/status": status("queued", { id: 8 }),
    });
    const { user } = renderApp("/");

    await user.click(screen.getByText(/Options for logs/));
    await user.type(screen.getByLabelText("Year of the first line"), "2025");
    await user.type(screen.getByLabelText("Devices' timezone"), "+05:30");
    const zone = screen.getByTestId("drop-zone");
    const dataTransfer = { files: [logFile("switch.log")], types: ["Files"] };
    const { fireEvent } = await import("@testing-library/react");
    fireEvent.drop(zone, { dataTransfer });

    await screen.findByRole("heading", { name: /Analyzing/ });
    const form = api.calls.find((call) => call.method === "POST")?.body as FormData;
    expect((form.get("file") as File).name).toBe("switch.log");
    expect(form.get("year")).toBe("2025");
    expect(form.get("timezone")).toBe("+05:30");
  });

  it("shows the server's reason when an upload is refused, and stays put", async () => {
    mockApi({
      ...HOME,
      "POST /api/uploads": apiError(400, "not_text", "The file is not a text file, so it cannot be a log."),
    });
    const { user } = renderApp("/");

    await user.upload(screen.getByTestId("file-input"), logFile("photo.png"));

    expect(await screen.findByRole("alert")).toHaveTextContent("The file is not a text file");
    expect(screen.getByRole("heading", { name: "Analyze a log file" })).toBeInTheDocument();
  });

  it("refuses an empty or oversized file without sending it", async () => {
    const api = mockApi({ ...HOME, "GET /api/health": { ...HEALTH, max_upload_bytes: 10 } });
    const { user } = renderApp("/");
    await screen.findByText(/up to 10 B/);

    await user.upload(screen.getByTestId("file-input"), logFile("empty.log", ""));
    expect(await screen.findByRole("alert")).toHaveTextContent("empty.log is empty.");

    await user.upload(screen.getByTestId("file-input"), logFile("big.log", "x".repeat(50)));
    expect(await screen.findByRole("alert")).toHaveTextContent("big.log is 50 B, larger than the 10 B limit.");
    expect(api.calls.some((call) => call.method === "POST")).toBe(false);
  });

  it("refuses a year that is not one", async () => {
    const api = mockApi(HOME);
    const { user } = renderApp("/");
    await user.click(screen.getByText(/Options for logs/));
    await user.type(screen.getByLabelText("Year of the first line"), "12");

    await user.upload(screen.getByTestId("file-input"), logFile());
    expect(await screen.findByRole("alert")).toHaveTextContent("between 1970 and 2100");
    expect(api.calls.some((call) => call.method === "POST")).toBe(false);
  });

  it("loads a demo scenario with one click", async () => {
    const api = mockApi({
      ...HOME,
      "POST /api/demo/scenarios/02_cascade": { status: 202, body: uploadItem({ id: 3, status: "processing" }) },
      "GET /api/uploads/3": uploadDetail({ id: 3, filename: "02_cascade.log" }),
      "GET /api/uploads/3/status": status("detection", { id: 3 }),
    });
    const { user } = renderApp("/");

    await user.click(await screen.findByRole("button", { name: /Cascade/ }));

    expect(await screen.findByRole("heading", { name: /Analyzing 02_cascade\.log/ })).toBeInTheDocument();
    expect(api.calls.some((c) => c.method === "POST" && c.path === "/api/demo/scenarios/02_cascade")).toBe(true);
  });
});

describe("the recent uploads table", () => {
  const ROWS = [
    uploadItem({ id: 3, filename: "overlap.log", incidents_by_severity: { critical: 0, high: 1, medium: 1, low: 0, info: 0 } }),
    uploadItem({ id: 2, filename: "busy.log", status: "processing", stage: "detection", lines: 4000 }),
    uploadItem({ id: 1, filename: "notes.txt", status: "failed", stage: "failed", failed_stage: "parsing", error: "No recognizable log lines in the file." }),
    uploadItem({ id: 4, filename: "quiet.log", incidents_by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } }),
  ];

  it("lists each upload with its incidents by severity and its status", async () => {
    mockApi({ ...HOME, "GET /api/uploads": page(ROWS) });
    renderApp("/");

    const table = await screen.findByRole("table");
    const rows = within(table).getAllByRole("row").slice(1);
    expect(rows).toHaveLength(4);
    expect(within(rows[0]).getByText("High")).toBeInTheDocument();
    expect(within(rows[0]).getByText("Medium")).toBeInTheDocument();
    expect(within(rows[0]).getByText("Done")).toBeInTheDocument();
    expect(within(rows[1]).getByText("Detect")).toBeInTheDocument();
    expect(within(rows[2]).getByText("Failed")).toBeInTheDocument();
    expect(within(rows[3]).getByText("None")).toBeInTheDocument();
    // Each row leads where it makes sense: the dashboard, or the processing screen.
    expect(within(rows[0]).getByRole("link", { name: "overlap.log" })).toHaveAttribute("href", "/uploads/3");
    expect(within(rows[1]).getByRole("link", { name: "busy.log" })).toHaveAttribute("href", "/uploads/2/processing");
    expect(within(rows[2]).getByRole("link", { name: "notes.txt" })).toHaveAttribute("href", "/uploads/1/processing");
    // An upload still being processed cannot be deleted.
    expect(within(rows[1]).getByRole("button", { name: "Delete busy.log" })).toBeDisabled();
  });

  it("opens an upload when its row is clicked", async () => {
    mockApi({
      ...HOME,
      ...dashboard(3),
      "GET /api/uploads": page(ROWS),
      "GET /api/uploads/3": uploadDetail({ id: 3, filename: "overlap.log" }),
    });
    const { user } = renderApp("/");

    await user.click(await screen.findByText("overlap.log"));
    expect(await screen.findByRole("heading", { name: "overlap.log" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "All incidents" })).toHaveAttribute("href", "/uploads/3/incidents");
  });

  it("deletes an upload only after it is confirmed", async () => {
    let rows = [...ROWS];
    const api = mockApi({
      ...HOME,
      "GET /api/uploads": () => page(rows),
      "DELETE /api/uploads/3": () => {
        rows = rows.filter((row) => row.id !== 3);
        return { status: 204 };
      },
    });
    const { user } = renderApp("/");

    await user.click(await screen.findByRole("button", { name: "Delete overlap.log" }));
    const dialog = await screen.findByRole("alertdialog", { name: "Delete this upload?" });
    expect(dialog).toHaveTextContent("overlap.log and everything found in it will be deleted");
    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(api.calls.some((c) => c.method === "DELETE")).toBe(false);
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Delete overlap.log" }));
    await user.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Delete" }));

    await waitFor(() => expect(screen.queryByText("overlap.log")).not.toBeInTheDocument());
    expect(api.calls.filter((c) => c.method === "DELETE").map((c) => c.path)).toEqual(["/api/uploads/3"]);
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
  });

  it("keeps the dialog open with the reason when a delete is refused", async () => {
    mockApi({
      ...HOME,
      "GET /api/uploads": page(ROWS),
      "DELETE /api/uploads/3": apiError(409, "still_processing", "This upload is still being processed."),
    });
    const { user } = renderApp("/");

    await user.click(await screen.findByRole("button", { name: "Delete overlap.log" }));
    const dialog = await screen.findByRole("alertdialog");
    await user.click(within(dialog).getByRole("button", { name: "Delete" }));

    expect(await within(dialog).findByRole("alert")).toHaveTextContent("still being processed");
    expect(screen.getByText("overlap.log", { selector: "a" })).toBeInTheDocument();
  });
});

describe("when the server cannot be reached", () => {
  it("says so plainly, tells how to start it, and is not a blank page", async () => {
    mockApi({
      "GET /api/health": "unreachable",
      "GET /api/demo/scenarios": "unreachable",
      "GET /api/uploads": "unreachable",
    });
    renderApp("/");

    const banner = await screen.findByText(/The netlog server is not reachable\. Start it with/);
    expect(banner).toBeInTheDocument();
    const alerts = await screen.findAllByRole("alert");
    expect(alerts.length).toBeGreaterThanOrEqual(3); // the banner, the demos, the uploads
    expect(screen.getAllByText("python -m uvicorn netlog.api.app:app").length).toBeGreaterThan(1);
    expect(screen.getAllByRole("button", { name: "Try again" })).toHaveLength(2);
    // The drop zone is still there to use once the server is back.
    expect(screen.getByText("Drop a log file here")).toBeInTheDocument();
  });

  it("treats a development proxy with nothing behind it as unreachable", async () => {
    mockApi({
      "GET /api/health": { status: 500, body: null },
      "GET /api/demo/scenarios": { status: 502, body: null },
      "GET /api/uploads": page([]),
    });
    renderApp("/");

    expect(await screen.findByText(/The netlog server is not reachable\. Start it/)).toBeInTheDocument();
  });

  it("recovers by itself once the server answers", async () => {
    let up = false;
    mockApi({
      ...HOME,
      "GET /api/health": () => (up ? HEALTH : "unreachable"),
      "GET /api/uploads": () => (up ? page([uploadItem()]) : "unreachable"),
    });
    const { user } = renderApp("/");
    await screen.findByText(/The netlog server is not reachable\. Start it/);

    up = true;
    const retry = screen.getAllByRole("button", { name: "Try again" });
    await user.click(retry[retry.length - 1]);
    expect(await screen.findByText("02_cascade.log", { selector: "a" })).toBeInTheDocument();
  });
});
