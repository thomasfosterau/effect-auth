import { Form, Link, redirect, useActionData } from "react-router";
import type { ActionFunctionArgs, LoaderFunctionArgs } from "react-router";
import { getCurrentUser, setSessionHeader } from "~/server/auth/session";
import { ConduitAuthError, registerUser } from "~/server/services/users";

export async function loader({ request }: LoaderFunctionArgs) {
  const { user } = await getCurrentUser(request);
  if (user) throw redirect("/");
  return null;
}

export async function action({ request }: ActionFunctionArgs) {
  const data = await request.formData();
  const email = String(data.get("email") ?? "");
  const username = String(data.get("username") ?? "");
  const password = String(data.get("password") ?? "");
  try {
    const r = await registerUser({ email, username, password });
    return redirect("/", { headers: await setSessionHeader(r.sessionId) });
  } catch (e) {
    if (e instanceof ConduitAuthError) return { errors: [e.message], email, username };
    throw e;
  }
}

export default function Register() {
  const actionData = useActionData<typeof action>();
  return (
    <div className="auth-page">
      <div className="container page">
        <div className="row">
          <div className="col-md-6 offset-md-3 col-xs-12">
            <h1 className="text-xs-center">Sign up</h1>
            <p className="text-xs-center">
              <Link to="/login">Have an account?</Link>
            </p>
            {actionData?.errors && (
              <ul className="error-messages">
                {actionData.errors.map((e) => (
                  <li key={e}>{e}</li>
                ))}
              </ul>
            )}
            <Form method="post">
              <fieldset className="form-group">
                <input
                  className="form-control form-control-lg"
                  type="text"
                  name="username"
                  placeholder="Username"
                  defaultValue={actionData?.username ?? ""}
                  required
                />
              </fieldset>
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
                  placeholder="Password (8+ characters)"
                  minLength={8}
                  required
                />
              </fieldset>
              <button className="btn btn-lg btn-primary pull-xs-right" type="submit">
                Sign up
              </button>
            </Form>
          </div>
        </div>
      </div>
    </div>
  );
}
