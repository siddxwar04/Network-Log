// The little the screens share that is not data from the API: which upload is open, and
// the theme. (Data from the API is shared through TanStack Query, in api/queries.ts.)

import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";

const THEME_KEY = "netlog-theme";
const UPLOAD_KEY = "netlog-current-upload";

export type Theme = "dark" | "light";

function read(key: string): string | null {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

function write(key: string, value: string | null): void {
  try {
    if (value === null) localStorage.removeItem(key);
    else localStorage.setItem(key, value);
  } catch {
    // Storage may be blocked; the app still works, it only forgets on reload.
  }
}

interface AppState {
  currentUpload: number | null;
  setCurrentUpload: (id: number | null) => void;
  theme: Theme;
  toggleTheme: () => void;
}

const AppContext = createContext<AppState | null>(null);

export function AppProvider({ children }: { children: ReactNode }) {
  const [currentUpload, setCurrent] = useState<number | null>(() => {
    const saved = Number(read(UPLOAD_KEY));
    return Number.isInteger(saved) && saved > 0 ? saved : null;
  });
  const [theme, setTheme] = useState<Theme>(() => (read(THEME_KEY) === "light" ? "light" : "dark"));

  useEffect(() => {
    document.documentElement.classList.toggle("dark", theme === "dark");
    write(THEME_KEY, theme);
  }, [theme]);

  const setCurrentUpload = useCallback((id: number | null) => {
    setCurrent(id);
    write(UPLOAD_KEY, id === null ? null : String(id));
  }, []);

  const value = useMemo<AppState>(
    () => ({
      currentUpload,
      setCurrentUpload,
      theme,
      toggleTheme: () => setTheme((t) => (t === "dark" ? "light" : "dark")),
    }),
    [currentUpload, setCurrentUpload, theme],
  );
  return <AppContext.Provider value={value}>{children}</AppContext.Provider>;
}

export function useApp(): AppState {
  const state = useContext(AppContext);
  if (!state) throw new Error("useApp must be used inside <AppProvider>");
  return state;
}
