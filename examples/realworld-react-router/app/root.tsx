import { Links, Meta, NavLink, Outlet, Scripts, ScrollRestoration } from "react-router";
import type { LinksFunction, LoaderFunctionArgs } from "react-router";
import { getCurrentUser } from "~/server/auth/session";

export const links: LinksFunction = () => [
  { rel: "stylesheet", href: "//demo.productionready.io/main.css" },
  { rel: "stylesheet", href: "//code.ionicframework.com/ionicons/2.0.1/css/ionicons.min.css" },
];

export const loader = async ({ request }: LoaderFunctionArgs) => {
  const { user } = await getCurrentUser(request);
  return { user };
};

export default function App({ loaderData }: { loaderData: Awaited<ReturnType<typeof loader>> }) {
  const user = loaderData?.user ?? null;
  return (
    <html lang="en">
      <head>
        <meta charSet="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Conduit — effect-auth × React Router</title>
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
            <span className="attribution">effect-auth × React Router example.</span>
          </div>
        </footer>
        <ScrollRestoration />
        <Scripts />
      </body>
    </html>
  );
}
