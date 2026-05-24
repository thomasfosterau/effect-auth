/**
 * React 18 vs 19 shim.
 *
 * Remix 2's `@remix-run/react` is typed against React 18. The workspace
 * may resolve `@types/react` to v19 (because Next.js is in the
 * monorepo), and React 19 added `bigint` to `ReactNode`. That makes
 * Remix's `Form` / `Link` forwarded-ref components reject `React.ReactNode`
 * as a return type with a "bigint is not assignable" error.
 *
 * We narrow `ReactNode` for this app to the React 18-compatible union
 * so Remix's JSX components type-check. Runtime behaviour is unaffected.
 */
import "react";

declare module "react" {
  type ReactNode =
    | ReactElement
    | string
    | number
    | Iterable<ReactNode>
    | ReactPortal
    | boolean
    | null
    | undefined;
}
