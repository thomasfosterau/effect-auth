// @ts-nocheck — TanStack Start typings can lag behind runtime API; this file works at runtime
import {
  createRootRouteWithContext,
  Link,
  Outlet,
  Scripts,
  HeadContent,
} from "@tanstack/react-router";
import { fetchCurrentUser } from "~/server/fns";
import type { ConduitProfile } from "~/server/types";

interface RouterContext {
  user: ConduitProfile | null;
}

export const Route = createRootRouteWithContext<RouterContext>()({
  head: () => ({
    meta: [
      { charSet: "utf-8" },
      { name: "viewport", content: "width=device-width, initial-scale=1" },
      { title: "Conduit — effect-auth × TanStack Start" },
    ],
    links: [
      { rel: "stylesheet", href: "//demo.productionready.io/main.css" },
      { rel: "stylesheet", href: "//code.ionicframework.com/ionicons/2.0.1/css/ionicons.min.css" },
    ],
  }),
  beforeLoad: async () => {
    const user = await fetchCurrentUser();
    return { user };
  },
  component: RootComponent,
});

function RootComponent() {
  const { user } = Route.useRouteContext();
  return (
    <html lang="en">
      <head>
        <HeadContent />
      </head>
      <body>
        <nav className="navbar navbar-light">
          <div className="container">
            <Link to="/" className="navbar-brand">
              conduit
            </Link>
            <ul className="nav navbar-nav pull-xs-right">
              <li className="nav-item">
                <Link to="/" className="nav-link">
                  Home
                </Link>
              </li>
              {user ? (
                <>
                  <li className="nav-item">
                    <Link to="/editor" className="nav-link">
                      <i className="ion-compose" />
                      &nbsp;New Article
                    </Link>
                  </li>
                  <li className="nav-item">
                    <Link to="/settings" className="nav-link">
                      <i className="ion-gear-a" />
                      &nbsp;Settings
                    </Link>
                  </li>
                  <li className="nav-item">
                    <Link
                      to="/profile/$username"
                      params={{ username: user.username }}
                      className="nav-link"
                    >
                      {user.username}
                    </Link>
                  </li>
                </>
              ) : (
                <>
                  <li className="nav-item">
                    <Link to="/login" className="nav-link">
                      Sign in
                    </Link>
                  </li>
                  <li className="nav-item">
                    <Link to="/register" className="nav-link">
                      Sign up
                    </Link>
                  </li>
                </>
              )}
            </ul>
          </div>
        </nav>
        <Outlet />
        <Scripts />
      </body>
    </html>
  );
}
