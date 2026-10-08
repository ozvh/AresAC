import "./sentry";
import * as Sentry from "@sentry/react";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./index.css";
import Landing from "./pages/Landing";

// Independent entry point: private pages and API clients never enter this module graph.
const root = document.getElementById("root");
if (root === null) throw new Error("Ares public page mount is missing");
createRoot(root).render(
  <StrictMode>
    <Sentry.ErrorBoundary fallback={<p role="alert">Please reload the Ares preview.</p>}>
      <Landing />
    </Sentry.ErrorBoundary>
  </StrictMode>,
);
