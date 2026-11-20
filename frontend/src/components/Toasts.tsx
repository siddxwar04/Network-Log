// Short messages that confirm an action ("Deleted router.log") and fade away. Radix places
// them in a live region, so screen readers announce them too.

import * as Toast from "@radix-ui/react-toast";
import { CircleCheck, CircleX, X } from "lucide-react";
import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";

type Tone = "success" | "error";

interface Note {
  id: number;
  title: string;
  description?: string;
  tone: Tone;
}

type Notify = (note: { title: string; description?: string; tone?: Tone }) => void;

const ToastContext = createContext<Notify | null>(null);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [notes, setNotes] = useState<Note[]>([]);
  const notify = useCallback<Notify>(({ title, description, tone = "success" }) => {
    setNotes((current) => [...current.slice(-3), { id: Date.now() + Math.random(), title, description, tone }]);
  }, []);
  const remove = (id: number) => setNotes((current) => current.filter((note) => note.id !== id));

  const value = useMemo(() => notify, [notify]);
  return (
    <ToastContext.Provider value={value}>
      <Toast.Provider swipeDirection="right" duration={4000}>
        {children}
        {notes.map((note) => {
          const Icon = note.tone === "success" ? CircleCheck : CircleX;
          return (
            <Toast.Root
              key={note.id}
              type={note.tone === "error" ? "foreground" : "background"}
              onOpenChange={(open) => !open && remove(note.id)}
              className="flex items-start gap-3 rounded-lg border border-line-strong bg-raised p-3 shadow-pop data-[state=closed]:opacity-0"
            >
              <Icon
                aria-hidden="true"
                className={`mt-0.5 size-4 shrink-0 ${note.tone === "success" ? "text-ok" : "text-danger"}`}
              />
              <div className="min-w-0 flex-1">
                <Toast.Title className="text-sm font-medium text-ink">{note.title}</Toast.Title>
                {note.description && (
                  <Toast.Description className="mt-0.5 text-sm text-muted">
                    {note.description}
                  </Toast.Description>
                )}
              </div>
              <Toast.Close aria-label="Dismiss" className="rounded p-0.5 text-muted hover:text-ink">
                <X aria-hidden="true" className="size-4" />
              </Toast.Close>
            </Toast.Root>
          );
        })}
        <Toast.Viewport className="fixed right-0 bottom-0 z-50 flex w-full max-w-sm flex-col gap-2 p-4 outline-none" />
      </Toast.Provider>
    </ToastContext.Provider>
  );
}

export function useToast(): Notify {
  const notify = useContext(ToastContext);
  if (!notify) throw new Error("useToast must be used inside <ToastProvider>");
  return notify;
}
