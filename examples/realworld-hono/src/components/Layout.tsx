import type { FC } from "hono/jsx";
import type { ConduitProfile } from "../types";

export const Layout: FC<{ user: ConduitProfile | null; active?: string; children?: unknown }> = ({
  user,
  active,
  children,
}) => (
  <html lang="en">
    <head>
      <meta charset="utf-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <title>Conduit — effect-auth × Hono</title>
      <link rel="stylesheet" href="//demo.productionready.io/main.css" />
      <link rel="stylesheet" href="//code.ionicframework.com/ionicons/2.0.1/css/ionicons.min.css" />
    </head>
    <body>
      <nav class="navbar navbar-light">
        <div class="container">
          <a class="navbar-brand" href="/">
            conduit
          </a>
          <ul class="nav navbar-nav pull-xs-right">
            <li class="nav-item">
              <a class={active === "/" ? "nav-link active" : "nav-link"} href="/">
                Home
              </a>
            </li>
            {user ? (
              <>
                <li class="nav-item">
                  <a class={active === "/editor" ? "nav-link active" : "nav-link"} href="/editor">
                    <i class="ion-compose" />
                    &nbsp;New Article
                  </a>
                </li>
                <li class="nav-item">
                  <a
                    class={active === "/settings" ? "nav-link active" : "nav-link"}
                    href="/settings"
                  >
                    <i class="ion-gear-a" />
                    &nbsp;Settings
                  </a>
                </li>
                <li class="nav-item">
                  <a
                    class={active === `/profile/${user.username}` ? "nav-link active" : "nav-link"}
                    href={`/profile/${user.username}`}
                  >
                    {user.username}
                  </a>
                </li>
              </>
            ) : (
              <>
                <li class="nav-item">
                  <a class="nav-link" href="/login">
                    Sign in
                  </a>
                </li>
                <li class="nav-item">
                  <a class="nav-link" href="/register">
                    Sign up
                  </a>
                </li>
              </>
            )}
          </ul>
        </div>
      </nav>
      {children}
      <footer>
        <div class="container">
          <a href="/" class="logo-font">
            conduit
          </a>
          <span class="attribution">
            effect-auth × Hono example. Conduit design from Thinkster.
          </span>
        </div>
      </footer>
    </body>
  </html>
);
