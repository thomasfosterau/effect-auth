// @ts-nocheck
import { createFileRoute, notFound, redirect, useRouter } from "@tanstack/react-router";
import { useState } from "react";
import { editArticle, fetchArticle } from "~/server/fns";

export const Route = createFileRoute("/editor/$slug")({
  beforeLoad: ({ context }) => {
    if (!context.user) throw redirect({ to: "/login" });
  },
  loader: async ({ params, context }) => {
    const article = await fetchArticle({ data: { slug: params.slug } });
    if (!article) throw notFound();
    if (article.author.username !== context.user!.username) throw redirect({ to: "/" });
    return { article };
  },
  component: EditArticlePage,
});

function EditArticlePage() {
  const { article } = Route.useLoaderData();
  const router = useRouter();
  const [form, setForm] = useState({
    title: article.title,
    description: article.description,
    body: article.body,
  });
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    try {
      const updated = await editArticle({ data: { slug: article.slug, ...form } });
      router.navigate({ to: "/article/$slug", params: { slug: updated.slug } });
    } catch (err) {
      setError((err as Error).message);
    }
  }

  return (
    <div className="editor-page">
      <div className="container page">
        <div className="row">
          <div className="col-md-10 offset-md-1 col-xs-12">
            {error && (
              <ul className="error-messages">
                <li>{error}</li>
              </ul>
            )}
            <form onSubmit={submit}>
              <fieldset>
                <fieldset className="form-group">
                  <input
                    type="text"
                    className="form-control form-control-lg"
                    value={form.title}
                    onChange={(e) => setForm({ ...form, title: e.target.value })}
                  />
                </fieldset>
                <fieldset className="form-group">
                  <input
                    type="text"
                    className="form-control"
                    value={form.description}
                    onChange={(e) => setForm({ ...form, description: e.target.value })}
                  />
                </fieldset>
                <fieldset className="form-group">
                  <textarea
                    className="form-control"
                    rows={8}
                    value={form.body}
                    onChange={(e) => setForm({ ...form, body: e.target.value })}
                  />
                </fieldset>
                <button className="btn btn-lg pull-xs-right btn-primary" type="submit">
                  Update Article
                </button>
              </fieldset>
            </form>
          </div>
        </div>
      </div>
    </div>
  );
}
