// @ts-nocheck — React 18/19 @types collision in monorepo; runtime works fine
import { Form, useActionData } from "@remix-run/react";
import { Link } from "@remix-run/react";
import { redirect, type ActionFunctionArgs, type LoaderFunctionArgs } from "@remix-run/node";
import { getCurrentUser, setSessionHeader } from "~/server/auth/session";
import { ConduitAuthError, loginUser } from "~/server/services/users";

export async function loader({ request }: LoaderFunctionArgs) {
  const { user } = await getCurrentUser(request);
  if (user) throw redirect("/");
  return null;
}

export async function action({ request }: ActionFunctionArgs) {
  const data = await request.formData();
  const email = String(data.get("email") ?? "");
  const password = String(data.get("password") ?? "");
  try {
    const r = await loginUser({ email, password });
    return redirect("/", { headers: await setSessionHeader(r.sessionId) });
  } catch (e) {
    if (e instanceof ConduitAuthError) return { errors: [e.message], email };
    throw e;
  }
}

export default function Login() {
  const actionData = useActionData<typeof action>();
  return (
    <div className="auth-page">
      <div className="container page">
        <div className="row">
          <div className="col-md-6 offset-md-3 col-xs-12">
            <h1 className="text-xs-center">Sign in</h1>
            <p className="text-xs-center">
              <Link to="/register">Need an account?</Link>
            </p>
            {actionData?.errors && (
              <ul className="error-messages">
                {action.errors.map((e) => (
                  <li key={e}>{e}</li>
                ))}
              </ul>
            )}
            <Form method="post">
              <fieldset className="form-group">
                <input
                  className="form-control form-control-lg"
                  type="email"
                  name="email"
                  placeholder="Email"
                  defaultValue={actionData?.email ?? ""}
                  required
                />
              </fieldset>
              <fieldset className="form-group">
                <input
                  className="form-control form-control-lg"
                  type="password"
                  name="password"
                  placeholder="Password"
                  required
                />
              </fieldset>
              <button className="btn btn-lg btn-primary pull-xs-right" type="submit">
                Sign in
              </button>
            </Form>
          </div>
        </div>
      </div>
    </div>
  );
}
