// If a screen crashes while drawing, show what happened and a way out, never a blank page.
// The navigation stays usable, because only the screen inside the frame is replaced.

import { Component, type ErrorInfo, type ReactNode } from "react";
import { Button, Panel } from "./ui";

interface State {
  error: Error | null;
}

export class ErrorBoundary extends Component<{ children: ReactNode; resetKey?: string }, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error("A screen failed to draw", error, info.componentStack);
  }

  componentDidUpdate(previous: { resetKey?: string }): void {
    // Moving to another address gives that screen a fresh start.
    if (this.state.error && previous.resetKey !== this.props.resetKey) {
      this.setState({ error: null });
    }
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <Panel>
        <div role="alert" className="space-y-3 p-5">
          <p className="font-medium text-ink">This screen ran into a problem and could not be shown.</p>
          <p className="font-mono text-xs break-words text-muted">{this.state.error.message}</p>
          <div className="flex gap-2">
            <Button onClick={() => this.setState({ error: null })}>Try again</Button>
            <a
              href="/"
              className="inline-flex items-center rounded-md px-3 py-1.5 text-sm font-medium text-accent hover:underline"
            >
              Back to uploads
            </a>
          </div>
        </div>
      </Panel>
    );
  }
}
