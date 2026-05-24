import { Form, redirect, useActionData, useLoaderData } from "react-router";
import type { ActionFunctionArgs, LoaderFunctionArgs } from "react-router";
import { clearSessionHeader, getCurrentUser, requireUser } from "~/server/auth/session";
import { invalidateSession } from "~/server/auth/runtime";
import { ConduitAuthError, updateUser } from "~/server/services/users";

export async function loader({ request }: LoaderFunctionArgs) {
  const user = await requireUser(request);
  return { user };
}

export async function action({ request }: ActionFunctionArgs) {
  const data = await request.formData();
  if (data.get("_action") === "logout") {
    const { sessionId } = await getCurrentUser(request);
    if (sessionId) await invalidateSession(sessionId);
    return redirect("/", { headers: await clearSessionHeader() });
  }
  const user = await requireUser(request);
  try {
    await updateUser(user.id, {
      image: String(data.get("image") ?? "") || null,
      username: String(data.get("username") ?? "") || undefined,
      bio: String(data.get("bio") ?? "") || null,
      email: String(data.get("email") ?? "") || undefined,
      password: String(data.get("password") ?? "") || undefined,
    });
  } catch (e) {
    if (e instanceof ConduitAuthError) return { errors: [e.message] };
    throw e;
  }
  return redirect(`/profile/${data.get("username")}`);
}

export default function Settings() {
  const { user } = useLoaderData<typeof loader>();
  const actionData = useActionData<typeof action>();
  return (
    <div className="settings-page">
      <div className="container page">
        <div className="row">
          <div className="col-md-6 offset-md-3 col-xs-12">
            <h1 className="text-xs-center">Your Settings</h1>
            {actionData && "errors" in actionData && actionData.errors && (
              <ul className="error-messages">
                {actionData.errors.map((e) => (
                  <li key={e}>{e}</li>
                ))}
              </ul>
            )}
            <Form method="post">
              <fieldset>
                <fieldset className="form-group">
                  <input
                    className="form-control"
                    type="text"
                    name="image"
                    placeholder="URL of profile picture"
                    defaultValue={user.image ?? ""}
                  />
                </fieldset>
                <fieldset className="form-group">
                  <input
                    className="form-control form-control-lg"
                    type="text"
                    name="username"
                    placeholder="Your Name"
                    defaultValue={user.username}
                    required
                  />
                </fieldset>
                <fieldset className="form-group">
                  <textarea
                    className="form-control form-control-lg"
                    rows={8}
                    name="bio"
                    placeholder="Short bio about you"
                    defaultValue={user.bio ?? ""}
                  />
                </fieldset>
                <fieldset className="form-group">
                  <input
                    className="form-control form-control-lg"
                    type="email"
                    name="email"
                    placeholder="Email"
                    defaultValue={user.email}
                    required
                  />
                </fieldset>
                <fieldset className="form-group">
                  <input
                    className="form-control form-control-lg"
                    type="password"
                    name="password"
                    placeholder="New Password (leave blank to keep)"
                  />
                </fieldset>
                <button className="btn btn-lg btn-primary pull-xs-right" type="submit">
                  Update Settings
                </button>
              </fieldset>
            </Form>
            <hr />
            <Form method="post">
              <input type="hidden" name="_action" value="logout" />
              <button className="btn btn-outline-danger" type="submit">
                Or click here to logout.
              </button>
            </Form>
          </div>
        </div>
      </div>
    </div>
  );
}
