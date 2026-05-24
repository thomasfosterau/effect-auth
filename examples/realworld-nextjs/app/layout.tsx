import type { Metadata } from "next";
import Nav from "@/lib/components/Nav";
import { getCurrentUser } from "@/lib/server/auth/session";

export const metadata: Metadata = {
  title: "Conduit — effect-auth × Next.js",
};

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const { user } = await getCurrentUser();
  return (
    <html lang="en">
      <head>
        <link
          href="//code.ionicframework.com/ionicons/2.0.1/css/ionicons.min.css"
          rel="stylesheet"
          type="text/css"
        />
        <link
          href="//fonts.googleapis.com/css?family=Titillium+Web:700|Source+Serif+Pro:400,700|Merriweather+Sans:400,700|Source+Sans+Pro:400,300,600,700,300italic,400italic,600italic,700italic"
          rel="stylesheet"
          type="text/css"
        />
        <link rel="stylesheet" href="//demo.productionready.io/main.css" />
      </head>
      <body>
        <Nav user={user} />
        {children}
        <footer>
          <div className="container">
            <a href="/" className="logo-font">
              conduit
            </a>
            <span className="attribution">
              effect-auth × Next.js example. Conduit design from Thinkster.
            </span>
          </div>
        </footer>
      </body>
    </html>
  );
}
