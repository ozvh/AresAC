import "./sentry";
import * as Sentry from "@sentry/react";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./index.css";
import App from "./App";
import Landing from "./pages/Landing";
import Admin from "./pages/Admin";
import Account from "./pages/Account";
import BuildRequest from "./pages/BuildRequest";
import Login from "./pages/Login";
import Privacy from "./pages/Privacy";
import Signup from "./pages/Signup";

/**
 * Eight surfaces, one bundle, no router library.
 *
 * The choice is made once, from the path, before anything mounts. That matters for two
 * reasons. The operator console boots a telemetry stream the moment it mounts, and a
 * stranger loading the policy page must not open an SSE subscription for a system they
 * have no business observing. And there is no client-side navigation to support: every
 * page here is a post-and-stay form or a read, and every link between them is a full page
 * load. A routing library would add a dependency and a re-render path in exchange for
 * decisions that a pathname comparison already makes.
 *
 * The landing page is at `/` and the console is at `/console`. The front of a site is the
 * page a stranger is meant to meet, and the console is an operator instrument whose read
 * surfaces are loopback-and-same-origin only — putting the instrument at the front would
 * have made the first impression of this system a diagnostic readout that a visitor has no
 * authority to see. No URL is lost by the move: the console keeps every one of its own
 * paths (`/request`, `/signup`, `/login`, `/account`, `/admin`, `/privacy`), and only the
 * console itself changed address.
 *
 * The admin page is included in this switch without any client-side gate. That is
 * deliberate: the page is a view, not an authority, and it renders a refusal the server
 * sent it. Nothing here decides whether someone is an administrator — the server decides
 * that per request, from a session record, and the page would be equally unable to act if
 * this switch let anyone reach it.
 */
const SURFACES: Readonly<Record<string, { readonly component: () => React.JSX.Element; readonly title: string }>> = {
  "/": { component: Landing, title: "Ares Anti Cheat — Evidence-led protection" },
  "/console": { component: App, title: "ARES // ARBITER CONSOLE" },
  "/request": { component: BuildRequest, title: "ARES // BUILD REQUEST" },
  "/signup": { component: Signup, title: "ARES // CREATE AN ACCOUNT" },
  "/login": { component: Login, title: "ARES // SIGN IN" },
  "/account": { component: Account, title: "ARES // YOUR ACCOUNT" },
  "/admin": { component: Admin, title: "ARES // ADMINISTRATION" },
  "/privacy": { component: Privacy, title: "ARES // PRIVACY POLICY" },
};

/**
 * Resolve the surface for the current path.
 *
 * Trailing slashes are stripped so `/admin/` cannot fall through, and an unrecognised path
 * resolves to the landing page rather than to a 404 page. That is the same reasoning it
 * used to apply to the console, with the front page in the role: an address nobody has
 * typed yet is a stranger arriving, and the marketing page tells that stranger what this
 * system is without showing them a telemetry readout they cannot act on.
 */
function surface(pathname: string): { readonly component: () => React.JSX.Element; readonly title: string } {
  const path = pathname.replace(/\/+$/, "") === "" ? "/" : pathname.replace(/\/+$/, "");
  const found = SURFACES[path];
  if (found !== undefined) return found;
  return { component: Landing, title: "Ares Anti Cheat — Evidence-led protection" };
}

const root = document.getElementById("root");
if (root === null) {
  // The shell in index.html always provides this node. Failing loudly beats mounting into
  // nothing and leaving a blank page with no explanation.
  throw new Error("ARES: #root is missing from the document");
}

const chosen = surface(window.location.pathname);
document.title = chosen.title;
const Component = chosen.component;

createRoot(root).render(
  <StrictMode>
    <Sentry.ErrorBoundary fallback={<p role="alert">Ares could not display this page. Please reload and try again.</p>}>
      <Component />
    </Sentry.ErrorBoundary>
  </StrictMode>,
);
