// What each screen reads from the API, through TanStack Query: answers are cached and
// shared between screens, repeated where something is still changing, and retried when the
// server could not be reached.

import { QueryClient, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "./client";
import type { Page, UploadListItem } from "./types";

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
  demos: ["demos"] as const,
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
      return client.invalidateQueries({ queryKey: keys.uploads });
    },
  });
}
