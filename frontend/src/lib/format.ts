// Numbers, sizes and times written the same way on every screen.

const NUMBER = new Intl.NumberFormat("en-US");

export function formatNumber(value: number): string {
  return NUMBER.format(value);
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  const digits = value >= 10 || Number.isInteger(value) ? 0 : 1;
  return `${value.toFixed(digits)} ${units[unit]}`;
}

const DATE_TIME = new Intl.DateTimeFormat("en-GB", {
  day: "numeric",
  month: "short",
  year: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  timeZoneName: "short",
});

/** When something happened on this computer, in the reader's own timezone, which is named. */
export function formatLocalTime(iso: string): string {
  const moment = new Date(iso);
  return Number.isNaN(moment.getTime()) ? iso : DATE_TIME.format(moment);
}

/** `02_cascade` -> `Cascade`, `05_dhcp_exhaustion` -> `DHCP exhaustion`. */
export function scenarioTitle(name: string): string {
  const words = name.replace(/^\d+_/, "").split("_");
  const upper = new Set(["bgp", "dhcp", "ospf", "dns"]);
  const title = words.map((word) => (upper.has(word) ? word.toUpperCase() : word)).join(" ");
  return title.charAt(0).toUpperCase() + title.slice(1);
}

export function plural(count: number, word: string): string {
  return `${formatNumber(count)} ${word}${count === 1 ? "" : "s"}`;
}

// --- Times from the logs, which are always UTC -------------------------------------------

const UTC_TIME = new Intl.DateTimeFormat("en-GB", {
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
  timeZone: "UTC",
});
const UTC_DATE = new Intl.DateTimeFormat("en-GB", {
  day: "numeric",
  month: "short",
  year: "numeric",
  timeZone: "UTC",
});

/** `02:46:11` from a log time. The caller says "UTC" once nearby. */
export function utcTime(iso: string): string {
  return UTC_TIME.format(new Date(iso));
}

/** `3 Mar 2026` from a log time. */
export function utcDate(iso: string): string {
  return UTC_DATE.format(new Date(iso));
}

/** `41s`, `8m 36s`, `5h 59m`, `2d 3h`: a length of time for reading. */
export function formatDuration(seconds: number): string {
  if (seconds < 1) return "under a second";
  const s = Math.round(seconds);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return s % 60 ? `${m}m ${s % 60}s` : `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 48) return m % 60 ? `${h}h ${m % 60}m` : `${h}h`;
  const d = Math.floor(h / 24);
  return h % 24 ? `${d}d ${h % 24}h` : `${d}d`;
}

/** `3 Mar 2026, 02:46:11 to 02:46:52 UTC`, naming the second date only when it differs. */
export function utcSpan(start: string, end: string): string {
  const sameDay = utcDate(start) === utcDate(end);
  const until = sameDay ? utcTime(end) : `${utcDate(end)}, ${utcTime(end)}`;
  return start === end
    ? `${utcDate(start)}, ${utcTime(start)} UTC`
    : `${utcDate(start)}, ${utcTime(start)} to ${until} UTC`;
}
