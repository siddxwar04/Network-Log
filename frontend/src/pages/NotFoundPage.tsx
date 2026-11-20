import { ArrowLeft } from "lucide-react";
import { Link } from "react-router";
import { Panel } from "../components/ui";

export function NotFoundPage() {
  return (
    <Panel>
      <div className="space-y-3 p-6 text-center">
        <p className="text-sm text-ink">There is no page at this address.</p>
        <Link to="/" className="inline-flex items-center gap-1 text-sm text-accent hover:underline">
          <ArrowLeft aria-hidden="true" className="size-4" /> Back to uploads
        </Link>
      </div>
    </Panel>
  );
}
