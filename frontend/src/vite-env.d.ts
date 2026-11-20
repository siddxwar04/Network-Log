/// <reference types="vite/client" />

interface ImportMetaEnv {
  // Where the API is, when it is not on the same address as the page.
  readonly VITE_API_BASE?: string;
}
