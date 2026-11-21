// The frame around every screen: the navigation, the server's status, the theme switch,
// and a warning when the server cannot be reached.

import { EyeOff, FlaskConical, Moon, ServerOff, Sun, TriangleAlert } from "lucide-react";
import { useEffect } from "react";
import { NavLink, Outlet, useLocation, useMatch } from "react-router";
import { START_SERVER } from "../api/client";
import { useHealth } from "../api/queries";
import { useApp } from "../lib/app-state";
import { ErrorBoundary } from "./ErrorBoundary";

function NavItem({ to, label, end }: { to: string | null; label: string; end?: boolean }) {
  const base = "relative rounded-md px-2.5 py-1.5 text-sm font-medium";
  if (to === null) {
    return (
      <span
        className={`${base} cursor-not-allowed text-faint opacity-60`}
        aria-disabled="true"
        title="Open an upload first"
      >
        {label}
      </span>
    );
  }
  return (
    <NavLink
      to={to}
      end={end}
      className={({ isActive }) =>
        `${base} ${isActive ? "bg-raised text-ink" : "text-muted hover:bg-raised hover:text-ink"}`
      }
    >
      {label}
    </NavLink>
  );
}

/** The product's mark: the root cause in violet, with the three devices it affected. */
function Logo() {
  const tile = "32,8 52.78,20 52.78,44 32,56 11.22,44 11.22,20";
  return (
    <svg viewBox="0 0 64 64" aria-hidden="true" className="size-7">
      <polygon points={tile} fill="none" stroke="#3d4466" strokeWidth="10" strokeLinejoin="round" />
      <polygon points={tile} fill="#191c2b" stroke="#191c2b" strokeWidth="8" strokeLinejoin="round" />
      <path
        d="M32 35V19M32 35L18.1 43M32 35l13.9 8"
        stroke="#9aa0b8"
        strokeWidth="3.5"
        strokeLinecap="round"
      />
      <g fill="#eef0f7">
        <circle cx="32" cy="19" r="4.5" />
        <circle cx="18.1" cy="43" r="4.5" />
        <circle cx="45.9" cy="43" r="4.5" />
      </g>
      <circle cx="32" cy="35" r="6.5" fill="#785ef0" />
    </svg>
  );
}

/** A small notice that the app runs without an LLM, and what that means. */
function DemoBanner({ stored }: { stored: number }) {
  return (
    <div role="status" className="border-t border-line bg-sunken text-muted">
      <div className="mx-auto flex max-w-7xl items-start gap-2 px-4 py-1.5 text-xs">
        <FlaskConical aria-hidden="true" className="mt-0.5 size-3.5 shrink-0 text-accent" />
        <span>
          <span className="font-medium text-ink">Demo mode.</span> No LLM is set up, so nothing is
          sent anywhere.{" "}
          {stored > 0
            ? "The demo scenarios show explanations an LLM wrote earlier, stored with the app; your own files get the built-in explanations."
            : "Every explanation comes from the built-in templates."}
        </span>
      </div>
    </div>
  );
}

function ServerStatus() {
  const health = useHealth();
  if (health.isPending) return null;
  const up = !health.error;
  const llm = health.data?.llm;
  return (
    <span className="hidden items-center gap-3 text-xs text-muted sm:flex">
      <span className="inline-flex items-center gap-1.5" title={up ? "The API answers" : "The API does not answer"}>
        <span aria-hidden="true" className={`size-2 rounded-full ${up ? "bg-ok" : "bg-danger"}`} />
        {up ? "Connected" : "Offline"}
      </span>
      {up && llm && (
        <span
          className="hidden md:inline"
          title={
            llm.configured
              ? "Explanations are written by an LLM and checked against the evidence"
              : "Explanations come from the built-in templates; no LLM is set up"
          }
        >
          {llm.configured ? `LLM: ${llm.provider || "on"}` : "LLM: off"}
        </span>
      )}
      {up && llm?.configured && health.data?.redaction && (
        // What leaves this machine, said where it can always be seen.
        <span
          className={`hidden items-center gap-1 lg:inline-flex ${health.data.redaction.enabled ? "" : "font-medium text-warn"}`}
          title={
            health.data.redaction.enabled
              ? "Addresses, device names and usernames are replaced by stand-ins before anything is sent to the LLM. Change it with redaction.enabled in the settings."
              : "Addresses, device names and usernames are sent to the LLM as they are. Passwords and keys are still removed. Change it with redaction.enabled in the settings."
          }
        >
          {health.data.redaction.enabled ? (
            <EyeOff aria-hidden="true" className="size-3.5" />
          ) : (
            <TriangleAlert aria-hidden="true" className="size-3.5" />
          )}
          {health.data.redaction.enabled ? "Names hidden from the LLM" : "Names sent to the LLM"}
        </span>
      )}
    </span>
  );
}

export function Layout() {
  const { theme, toggleTheme, currentUpload, setCurrentUpload } = useApp();
  const health = useHealth();
  // The upload in the address, when there is one, becomes the current upload.
  const match = useMatch("/uploads/:id/*");
  const { pathname } = useLocation();
  const inAddress = Number(match?.params.id);
  useEffect(() => {
    if (Number.isInteger(inAddress) && inAddress > 0) setCurrentUpload(inAddress);
  }, [inAddress, setCurrentUpload]);

  const upload = currentUpload;
  return (
    <div className="flex min-h-screen flex-col">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50 focus:rounded focus:bg-panel focus:px-3 focus:py-2"
      >
        Skip to content
      </a>
      <header className="no-print sticky top-0 z-30 border-b border-line bg-panel/90 backdrop-blur">
        <div className="mx-auto flex h-12 max-w-7xl items-center gap-3 px-4">
          <NavLink to="/" className="flex items-center gap-2 font-semibold tracking-tight text-ink">
            <Logo />
            <span>CauseLine</span>
          </NavLink>
          <span aria-hidden="true" className="h-5 w-px bg-line" />
          <nav aria-label="Main" className="flex min-w-0 flex-1 items-center gap-0.5 overflow-x-auto">
            <NavItem to="/" label="Upload" end />
            <NavItem to={upload ? `/uploads/${upload}` : null} label="Dashboard" end />
            <NavItem to={upload ? `/uploads/${upload}/incidents` : null} label="Incidents" />
            <NavItem to="/live" label="Live" />
            <NavItem to="/evaluation" label="Accuracy" />
          </nav>
          <ServerStatus />
          <button
            type="button"
            onClick={toggleTheme}
            className="rounded-md p-1.5 text-muted hover:bg-raised hover:text-ink"
            aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
            title={theme === "dark" ? "Light theme" : "Dark theme"}
          >
            {theme === "dark" ? (
              <Sun aria-hidden="true" className="size-4" />
            ) : (
              <Moon aria-hidden="true" className="size-4" />
            )}
          </button>
        </div>
        {health.error?.unreachable && (
          <div role="alert" className="border-t border-danger/40 bg-danger/10 text-ink">
            <div className="mx-auto flex max-w-7xl items-center gap-2 px-4 py-2 text-sm">
              <ServerOff aria-hidden="true" className="size-4 shrink-0 text-danger" />
              <span>
                The CauseLine server is not reachable. Start it with{" "}
                <code className="font-mono text-xs">{START_SERVER}</code>. This page checks again
                every few seconds.
              </span>
            </div>
          </div>
        )}
        {health.data?.demo?.active && <DemoBanner stored={health.data.demo.stored_explanations} />}
      </header>
      <main id="main" className="mx-auto w-full max-w-7xl flex-1 px-4 py-6">
        <ErrorBoundary resetKey={pathname}>
          <Outlet />
        </ErrorBoundary>
      </main>
    </div>
  );
}
