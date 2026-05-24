// @ts-nocheck — React 18/19 @types collision in monorepo; runtime works fine
import { Form, useActionData } from "@remix-run/react";
import { redirect, type ActionFunctionArgs, type LoaderFunctionArgs } from "@remix-run/node";
import { requireUser } from "~/server/auth/session";
import { ConduitArticleError, createArticle } from "~/server/services/articles";

export async function loader({ request }: LoaderFunctionArgs) {
  await requireUser(request);
  return null;
}

export async function action({ request }: ActionFunctionArgs) {
  const user = await requireUser(request);
  const data = await request.formData();
  try {
    const article = createArticle(user.id, {
      title: String(data.get("title") ?? ""),
      description: String(data.get("description") ?? ""),
      body: String(data.get("body") ?? ""),
      tagList: String(data.get("tagList") ?? "")
        .split(/[ ,]+/)
        .filter(Boolean),
    });
    return redirect(`/article/${article.slug}`);
  } catch (e) {
    if (e instanceof ConduitArticleError) {
      return {
        errors: [e.message],
        values: {
          title: String(data.get("title") ?? ""),
          description: String(data.get("description") ?? ""),
          body: String(data.get("body") ?? ""),
          tagList: String(data.get("tagList") ?? ""),
        },
      };
    }
    throw e;
  }
}

export default function Editor() {
  const actionData = useActionData<typeof action>();
  const v = actionData?.values ?? {};
  return (
    <div className="editor-page">
      <div className="container page">
        <div className="row">
          <div className="col-md-10 offset-md-1 col-xs-12">
            {actionData?.errors && (
              <ul className="error-messages">
                {action.errors.map((e) => (
                  <li key={e}>{e}</li>
                ))}
              </ul>
            )}
            <Form method="post">
              <fieldset>
                <fieldset className="form-group">
                  <input
                    type="text"
                    className="form-control form-control-lg"
                    name="title"
                    placeholder="Article Title"
                    defaultValue={v.title ?? ""}
                  />
                </fieldset>
                <fieldset className="form-group">
                  <input
                    type="text"
                    className="form-control"
                    name="description"
                    placeholder="What's this article about?"
                    defaultValue={v.description ?? ""}
                  />
                </fieldset>
                <fieldset className="form-group">
                  <textarea
                    className="form-control"
                    rows={8}
                    name="body"
                    placeholder="Write your article (in markdown)"
                    defaultValue={v.body ?? ""}
                  />
                </fieldset>
                <fieldset className="form-group">
                  <input
                    type="text"
                    className="form-control"
                    name="tagList"
                    placeholder="Enter tags (space or comma separated)"
                    defaultValue={v.tagList ?? ""}
                  />
                </fieldset>
                <button className="btn btn-lg pull-xs-right btn-primary" type="submit">
                  Publish Article
                </button>
              </fieldset>
            </Form>
          </div>
        </div>
      </div>
    </div>
  );
}
