// @ts-nocheck — React 18/19 @types collision in monorepo; runtime works fine
import {
  Links,
  Meta,
  NavLink,
  Outlet,
  Scripts,
  ScrollRestoration,
  useRouteLoaderData,
} from "@remix-run/react";
import type { LinksFunction, LoaderFunctionArgs } from "@remix-run/node";
import { getCurrentUser } from "~/server/auth/session";
import type { ConduitProfile } from "~/server/types";

export const links: LinksFunction = () => [
  { rel: "stylesheet", href: "//demo.productionready.io/main.css" },
  { rel: "stylesheet", href: "//code.ionicframework.com/ionicons/2.0.1/css/ionicons.min.css" },
  {
    rel: "stylesheet",
    href: "//fonts.googleapis.com/css?family=Titillium+Web:700|Source+Serif+Pro:400,700|Merriweather+Sans:400,700|Source+Sans+Pro:400,300,600,700,300italic,400italic,600italic,700italic",
  },
];

export const loader = async ({ request }: LoaderFunctionArgs) => {
  const { user } = await getCurrentUser(request);
  return { user };
};

export function useOptionalUser(): ConduitProfile | null {
  const data = useRouteLoaderData<typeof loader>("root");
  return data?.user ?? null;
}

export default function App() {
  const data = useRouteLoaderData<typeof loader>("root");
  const user = data?.user ?? null;
  return (
    <html lang="en">
      <head>
        <meta charSet="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Conduit — effect-auth × Remix</title>
        <Meta />
        <Links />
      </head>
      <body>
        <nav className="navbar navbar-light">
          <div className="container">
            <NavLink className="navbar-brand" to="/">
              conduit
            </NavLink>
            <ul className="nav navbar-nav pull-xs-right">
              <li className="nav-item">
                <NavLink className="nav-link" to="/" end>
                  Home
                </NavLink>
              </li>
              {user ? (
                <>
                  <li className="nav-item">
                    <NavLink className="nav-link" to="/editor">
                      <i className="ion-compose" />
                      &nbsp;New Article
                    </NavLink>
                  </li>
                  <li className="nav-item">
                    <NavLink className="nav-link" to="/settings">
                      <i className="ion-gear-a" />
                      &nbsp;Settings
                    </NavLink>
                  </li>
                  <li className="nav-item">
                    <NavLink className="nav-link" to={`/profile/${user.username}`}>
                      {user.username}
                    </NavLink>
                  </li>
                </>
              ) : (
                <>
                  <li className="nav-item">
                    <NavLink className="nav-link" to="/login">
                      Sign in
                    </NavLink>
                  </li>
                  <li className="nav-item">
                    <NavLink className="nav-link" to="/register">
                      Sign up
                    </NavLink>
                  </li>
                </>
              )}
            </ul>
          </div>
        </nav>
        <Outlet />
        <footer>
          <div className="container">
            <NavLink to="/" className="logo-font">
              conduit
            </NavLink>
            <span className="attribution">effect-auth × Remix example.</span>
          </div>
        </footer>
        <ScrollRestoration />
        <Scripts />
      </body>
    </html>
  );
}
