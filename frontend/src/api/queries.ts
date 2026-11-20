// What each screen reads from the API, through TanStack Query: answers are cached and
// shared between screens, repeated where something is still changing, and retried when the
// server could not be reached.

import { QueryClient, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "./client";
import type { Audience, Explanation, Page, UploadListItem } from "./types";

declare module "@tanstack/react-query" {
  interface Register {
    defaultError: ApiError;
  }
}

// How often the processing screen asks, and how long to wait after a failed attempt.
export const POLL_MS = 500;
export const RETRY_MS = 2000;

export function createQueryClient({ retry = true }: { retry?: boolean } = {}): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 10_000,
        refetchOnWindowFocus: false,
        // A wrong address or a missing upload will not change by asking again; a server
        // that is down or overloaded may.
        retry: retry
          ? (failures, error) =>
              error instanceof ApiError && (error.unreachable || error.status >= 500) && failures < 2
          : false,
        retryDelay: 1000,
      },
    },
  });
}

export const keys = {
  health: ["health"] as const,
  uploads: ["uploads"] as const,
  upload: (id: string | number) => ["upload", String(id)] as const,
  status: (id: string | number) => ["status", String(id)] as const,
  summary: (id: string | number) => ["summary", String(id)] as const,
  incidents: (id: string | number) => ["incidents", String(id)] as const,
  unparsed: (id: string | number) => ["unparsed", String(id)] as const,
  incident: (id: string | number, incidentId: string) =>
    ["incident", String(id), incidentId] as const,
  explanation: (id: string | number, incidentId: string, mode: Audience) =>
    ["explanation", String(id), incidentId, mode] as const,
  lines: (id: string | number, line: number) => ["lines", String(id), line] as const,
  timeline: (id: string | number, incidentId: string) =>
    ["timeline", String(id), incidentId] as const,
  demos: ["demos"] as const,
  live: ["live"] as const,
};

export function useHealth() {
  return useQuery({
    queryKey: keys.health,
    queryFn: api.health,
    retry: false,
    // While the server is down, look again now and then, so the page recovers by itself.
    refetchInterval: (query) => (query.state.error ? 5000 : false),
  });
}

export function useUploads() {
  return useQuery({
    queryKey: keys.uploads,
    queryFn: () => api.uploads(20),
    // Keep the status column live while anything is still being processed.
    refetchInterval: (query) =>
      query.state.data?.items.some((item) => item.status === "processing") ? 2000 : false,
  });
}

export function useUpload(id: string) {
  return useQuery({ queryKey: keys.upload(id), queryFn: () => api.upload(id) });
}

export function usePipelineStatus(id: string) {
  return useQuery({
    queryKey: keys.status(id),
    queryFn: () => api.status(id),
    staleTime: 0,
    retry: false,
    refetchInterval: (query) => {
      const { data, error } = query.state;
      if (error) return error.status === 404 ? false : RETRY_MS;
      return data?.finished ? false : POLL_MS;
    },
  });
}

export function useSummary(id: string, enabled = true) {
  return useQuery({ queryKey: keys.summary(id), queryFn: () => api.summary(id), enabled });
}

export function useIncidents(id: string, enabled = true) {
  return useQuery({ queryKey: keys.incidents(id), queryFn: () => api.incidents(id), enabled });
}

export function useUnparsedLines(id: string, enabled: boolean) {
  return useQuery({ queryKey: keys.unparsed(id), queryFn: () => api.unparsedLines(id), enabled });
}

export function useIncident(id: string, incidentId: string) {
  return useQuery({
    queryKey: keys.incident(id, incidentId),
    queryFn: () => api.incident(id, incidentId),
    staleTime: Infinity, // what the rules decided does not change
  });
}

/** The explanation for one audience. It may take a while when an LLM writes it, so the
 * page shows the facts first and fills this in when it arrives. */
export function useExplanation(id: string, incidentId: string, mode: Audience) {
  return useQuery({
    queryKey: keys.explanation(id, incidentId, mode),
    queryFn: () => api.explanation(id, incidentId, mode),
    staleTime: Infinity,
  });
}

/** Ask the LLM again. The new answer replaces the one shown. */
export function useRegenerate(id: string, incidentId: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (mode: Audience) => api.regenerate(id, incidentId, mode),
    onSuccess: (explanation: Explanation, mode) => {
      client.setQueryData(keys.explanation(id, incidentId, mode), explanation);
    },
  });
}

export function useTimeline(id: string, incidentId: string) {
  return useQuery({
    queryKey: keys.timeline(id, incidentId),
    queryFn: () => api.timeline(id, incidentId),
    staleTime: Infinity,
  });
}

export function useLinesAround(id: string, line: number, enabled: boolean) {
  return useQuery({
    queryKey: keys.lines(id, line),
    queryFn: () => api.linesAround(id, line),
    enabled,
    staleTime: Infinity,
  });
}

// How often the live page asks for news.
export const LIVE_MS = 2000;

/** The live listener's state, asked for again every two seconds while the page is open. */
export function useLive() {
  return useQuery({
    queryKey: keys.live,
    queryFn: api.live,
    staleTime: 0,
    refetchInterval: LIVE_MS,
  });
}

export function useDemos() {
  return useQuery({ queryKey: keys.demos, queryFn: api.demos, staleTime: Infinity });
}

/** Delete an upload. It disappears from the list at once and comes back if the server
 * refuses. */
export function useDeleteUpload() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (upload: UploadListItem) => api.deleteUpload(upload.id),
    onMutate: async (upload) => {
      await client.cancelQueries({ queryKey: keys.uploads });
      const before = client.getQueryData<Page<UploadListItem>>(keys.uploads);
      if (before) {
        client.setQueryData<Page<UploadListItem>>(keys.uploads, {
          ...before,
          items: before.items.filter((item) => item.id !== upload.id),
          total: before.total - 1,
        });
      }
      return { before };
    },
    onError: (_error, _upload, context) => {
      if (context?.before) client.setQueryData(keys.uploads, context.before);
    },
    onSettled: (_data, _error, upload) => {
      for (const key of [keys.upload, keys.status, keys.summary, keys.incidents, keys.unparsed]) {
        client.removeQueries({ queryKey: key(upload.id) });
      }
      for (const name of ["incident", "explanation", "lines", "timeline"]) {
        client.removeQueries({ queryKey: [name, String(upload.id)] });
      }
      return client.invalidateQueries({ queryKey: keys.uploads });
    },
  });
}
