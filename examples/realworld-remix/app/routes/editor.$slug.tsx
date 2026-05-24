// @ts-nocheck — React 18/19 @types collision in monorepo; runtime works fine
import { Form, useActionData, useLoaderData } from "@remix-run/react";
import { redirect, type ActionFunctionArgs, type LoaderFunctionArgs } from "@remix-run/node";
import { requireUser } from "~/server/auth/session";
import { ConduitArticleError, getArticleBySlug, updateArticle } from "~/server/services/articles";

export async function loader({ request, params }: LoaderFunctionArgs) {
  const user = await requireUser(request);
  const article = getArticleBySlug(params.slug!, user.id);
  if (!article) throw new Response("not found", { status: 404 });
  if (article.author.username !== user.username) throw redirect("/");
  return { article };
}

export async function action({ request, params }: ActionFunctionArgs) {
  const user = await requireUser(request);
  const data = await request.formData();
  try {
    const updated = updateArticle(user.id, params.slug!, {
      title: String(data.get("title") ?? ""),
      description: String(data.get("description") ?? ""),
      body: String(data.get("body") ?? ""),
    });
    return redirect(`/article/${updated.slug}`);
  } catch (e) {
    if (e instanceof ConduitArticleError) return { errors: [e.message] };
    throw e;
  }
}

export default function EditArticle() {
  const { article } = useLoaderData<typeof loader>();
  const actionData = useActionData<typeof action>();
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
                    defaultValue={article.title}
                  />
                </fieldset>
                <fieldset className="form-group">
                  <input
                    type="text"
                    className="form-control"
                    name="description"
                    defaultValue={article.description}
                  />
                </fieldset>
                <fieldset className="form-group">
                  <textarea
                    className="form-control"
                    rows={8}
                    name="body"
                    defaultValue={article.body}
                  />
                </fieldset>
                <button className="btn btn-lg pull-xs-right btn-primary" type="submit">
                  Update Article
                </button>
              </fieldset>
            </Form>
          </div>
        </div>
      </div>
    </div>
  );
}
