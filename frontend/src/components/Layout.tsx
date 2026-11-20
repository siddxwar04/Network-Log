// The frame around every screen: the navigation, the server's status, the theme switch,
// and a warning when the server cannot be reached.

import { Moon, ServerOff, Sun } from "lucide-react";
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

/** A mark for the product: three log lines, the middle one flagged. */
function Logo() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true" className="size-6">
      <rect x="1" y="1" width="22" height="22" rx="5" className="fill-accent" />
      <rect x="5.5" y="6.5" width="13" height="2" rx="1" className="fill-accent-ink" opacity="0.55" />
      <rect x="5.5" y="11" width="8" height="2" rx="1" className="fill-accent-ink" />
      <circle cx="17" cy="12" r="1.6" className="fill-accent-ink" />
      <rect x="5.5" y="15.5" width="10" height="2" rx="1" className="fill-accent-ink" opacity="0.55" />
    </svg>
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
            <span>netlog</span>
          </NavLink>
          <span aria-hidden="true" className="h-5 w-px bg-line" />
          <nav aria-label="Main" className="flex min-w-0 flex-1 items-center gap-0.5 overflow-x-auto">
            <NavItem to="/" label="Upload" end />
            <NavItem to={upload ? `/uploads/${upload}` : null} label="Dashboard" end />
            <NavItem to={upload ? `/uploads/${upload}/incidents` : null} label="Incidents" />
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
                The netlog server is not reachable. Start it with{" "}
                <code className="font-mono text-xs">{START_SERVER}</code>. This page checks again
                every few seconds.
              </span>
            </div>
          </div>
        )}
      </header>
      <main id="main" className="mx-auto w-full max-w-7xl flex-1 px-4 py-6">
        <ErrorBoundary resetKey={pathname}>
          <Outlet />
        </ErrorBoundary>
      </main>
    </div>
  );
}
