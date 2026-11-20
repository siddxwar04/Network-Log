import { render } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { AppRoutes } from "../App";
import { createQueryClient } from "../api/queries";

/** The whole app, opened at an address, with a user who can click and type. Each test gets
 * its own cache, and a failed request is not tried again, so tests stay fast. */
export function renderApp(path = "/") {
  const user = userEvent.setup();
  const result = render(
    <MemoryRouter initialEntries={[path]}>
      <AppRoutes queryClient={createQueryClient({ retry: false })} />
    </MemoryRouter>,
  );
  return { user, ...result };
}
