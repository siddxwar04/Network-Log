// Small building blocks shared by every screen: panels, buttons, page headers, and the
// loading, empty and error states.

import { ChevronRight, LoaderCircle, ServerOff, TriangleAlert } from "lucide-react";
import { useId, type ButtonHTMLAttributes, type ReactNode } from "react";
import { Link } from "react-router";
import { ApiError, START_SERVER } from "../api/client";

export function Panel({
  title,
  action,
  children,
  className = "",
  bodyClassName = "",
}: {
  title?: ReactNode;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
}) {
  // A titled panel is a region named by its title, so screen readers can jump between them.
  const heading = useId();
  return (
    <section
      aria-labelledby={title ? heading : undefined}
      className={`rounded-lg border border-line bg-panel shadow-panel ${className}`}
    >
      {title && (
        <header className="flex items-center justify-between gap-3 border-b border-line px-4 py-2.5">
          <h2 id={heading} className="text-sm font-semibold text-ink">
            {title}
          </h2>
          {action}
        </header>
      )}
      <div className={bodyClassName}>{children}</div>
    </section>
  );
}

type Variant = "primary" | "secondary" | "danger" | "ghost";

const VARIANTS: Record<Variant, string> = {
  primary: "bg-accent text-accent-ink hover:brightness-110",
  secondary: "border border-line-strong bg-raised text-ink hover:border-faint",
  danger: "bg-danger text-white hover:brightness-110 dark:text-canvas",
  ghost: "text-muted hover:bg-raised hover:text-ink",
};

export function Button({
  variant = "secondary",
  className = "",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant }) {
  return (
    <button
      type="button"
      className={`inline-flex items-center justify-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium transition disabled:cursor-not-allowed disabled:opacity-50 ${VARIANTS[variant]} ${className}`}
      {...props}
    />
  );
}

export function Spinner({ label, className = "" }: { label?: string; className?: string }) {
  return (
    <span className={`inline-flex items-center gap-2 text-sm text-muted ${className}`} role="status">
      <LoaderCircle aria-hidden="true" className="size-4 animate-spin" />
      {label ?? <span className="sr-only">Loading</span>}
    </span>
  );
}

/** Grey bars in the shape of what is about to appear. */
export function SkeletonRows({ rows = 3 }: { rows?: number }) {
  return (
    <div className="space-y-2.5 p-4" aria-hidden="true">
      {Array.from({ length: rows }, (_, i) => (
        <div
          key={i}
          className="h-4 animate-pulse rounded bg-raised"
          style={{ width: `${100 - ((i * 17) % 35)}%` }}
        />
      ))}
    </div>
  );
}

export function EmptyState({
  title,
  icon,
  children,
}: {
  title: string;
  icon?: ReactNode;
  children?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center px-4 py-8 text-center">
      {icon}
      <p className="text-sm font-medium text-ink">{title}</p>
      {children && <div className="mt-1 max-w-md text-sm text-muted">{children}</div>}
    </div>
  );
}

/** A problem, said plainly, with a way to try again. */
export function ErrorState({ error, onRetry }: { error: ApiError; onRetry?: () => void }) {
  const Icon = error.unreachable ? ServerOff : TriangleAlert;
  return (
    <div role="alert" className="flex items-start gap-3 px-4 py-4">
      <Icon aria-hidden="true" className="mt-0.5 size-5 shrink-0 text-danger" />
      <div className="min-w-0 flex-1">
        <p className="text-sm font-medium text-ink">
          {error.unreachable ? "The netlog server is not reachable." : error.message}
        </p>
        {error.unreachable && (
          <p className="mt-1 text-sm text-muted">
            Start it from the project folder with <Code>{START_SERVER}</Code>
          </p>
        )}
      </div>
      {onRetry && (
        <Button onClick={onRetry} className="shrink-0">
          Try again
        </Button>
      )}
    </div>
  );
}

export function Code({ children }: { children: ReactNode }) {
  return (
    <code className="rounded-sm bg-raised px-1 py-0.5 font-mono text-[0.8em] text-ink">{children}</code>
  );
}

export interface Crumb {
  label: string;
  to?: string;
}

/** Where this screen sits ("Uploads > router.log > Incidents"), its title and its actions. */
export function PageHeader({
  crumbs,
  title,
  meta,
  actions,
}: {
  crumbs: Crumb[];
  title: ReactNode;
  meta?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div className="min-w-0">
        <nav aria-label="Breadcrumb">
          <ol className="flex flex-wrap items-center gap-1 text-xs text-faint">
            {crumbs.map((crumb, i) => (
              <li key={i} className="flex min-w-0 items-center gap-1">
                {i > 0 && <ChevronRight aria-hidden="true" className="size-3" />}
                {crumb.to ? (
                  <Link to={crumb.to} className="truncate hover:text-ink hover:underline">
                    {crumb.label}
                  </Link>
                ) : (
                  <span aria-current="page" className="truncate">
                    {crumb.label}
                  </span>
                )}
              </li>
            ))}
          </ol>
        </nav>
        <h1 className="mt-1 truncate text-xl font-semibold tracking-tight text-ink">{title}</h1>
        {meta && <div className="mt-1 text-sm text-muted">{meta}</div>}
      </div>
      {actions && <div className="flex shrink-0 gap-2">{actions}</div>}
    </div>
  );
}
