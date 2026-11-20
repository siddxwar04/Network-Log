// Every screen has its own address, so a page can be bookmarked and the back button works.
// The dashboard and incident screens are loaded only when first opened, which keeps the
// chart library out of the first download.

import { QueryClientProvider, type QueryClient } from "@tanstack/react-query";
import { lazy, Suspense, useState } from "react";
import { Route, Routes } from "react-router";
import { createQueryClient } from "./api/queries";
import { Layout } from "./components/Layout";
import { ToastProvider } from "./components/Toasts";
import { Panel, SkeletonRows } from "./components/ui";
import { AppProvider } from "./lib/app-state";
import { HomePage } from "./pages/HomePage";
import { NotFoundPage } from "./pages/NotFoundPage";
import { ProcessingPage } from "./pages/ProcessingPage";

const DashboardPage = lazy(() => import("./pages/DashboardPage"));
const IncidentsPage = lazy(() => import("./pages/IncidentsPage"));
const IncidentPage = lazy(() => import("./pages/IncidentPage"));

function Loading() {
  return (
    <Panel>
      <SkeletonRows rows={4} />
    </Panel>
  );
}

export function AppRoutes({ queryClient }: { queryClient?: QueryClient }) {
  const [client] = useState(() => queryClient ?? createQueryClient());
  return (
    <QueryClientProvider client={client}>
      <AppProvider>
        <ToastProvider>
          <Suspense fallback={<Loading />}>
            <Routes>
              <Route element={<Layout />}>
                <Route index element={<HomePage />} />
                <Route path="uploads/:id" element={<DashboardPage />} />
                <Route path="uploads/:id/processing" element={<ProcessingPage />} />
                <Route path="uploads/:id/incidents" element={<IncidentsPage />} />
                <Route path="uploads/:id/incidents/:incidentId" element={<IncidentPage />} />
                <Route path="*" element={<NotFoundPage />} />
              </Route>
            </Routes>
          </Suspense>
        </ToastProvider>
      </AppProvider>
    </QueryClientProvider>
  );
}
