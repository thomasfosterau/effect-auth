<script setup lang="ts">
import type { ConduitArticle, ConduitProfile } from "../../server/types";

const user = useState<ConduitProfile | null>("user");
if (!user.value) navigateTo("/login");
const router = useRouter();

const form = reactive({ title: "", description: "", body: "", tagList: "" });
const errors = ref<string[]>([]);

async function submit() {
  errors.value = [];
  try {
    const res = await $fetch<{ article: ConduitArticle }>("/api/articles", {
      method: "POST",
      body: {
        article: {
          title: form.title,
          description: form.description,
          body: form.body,
          tagList: form.tagList.split(/[ ,]+/).filter(Boolean),
        },
      },
    });
    await router.push(`/article/${res.article.slug}`);
  } catch (e: unknown) {
    const err = e as { statusMessage?: string };
    errors.value = [err.statusMessage ?? "publish failed"];
  }
}
</script>

<template>
  <div class="editor-page">
    <div class="container page">
      <div class="row">
        <div class="col-md-10 offset-md-1 col-xs-12">
          <ul v-if="errors.length" class="error-messages">
            <li v-for="e in errors" :key="e">{{ e }}</li>
          </ul>
          <form @submit.prevent="submit">
            <fieldset>
              <fieldset class="form-group">
                <input
                  v-model="form.title"
                  class="form-control form-control-lg"
                  type="text"
                  placeholder="Article Title"
                />
              </fieldset>
              <fieldset class="form-group">
                <input
                  v-model="form.description"
                  class="form-control"
                  type="text"
                  placeholder="What's this article about?"
                />
              </fieldset>
              <fieldset class="form-group">
                <textarea
                  v-model="form.body"
                  class="form-control"
                  rows="8"
                  placeholder="Write your article (in markdown)"
                />
              </fieldset>
              <fieldset class="form-group">
                <input
                  v-model="form.tagList"
                  class="form-control"
                  type="text"
                  placeholder="Enter tags (space or comma separated)"
                />
              </fieldset>
              <button class="btn btn-lg pull-xs-right btn-primary" type="submit">
                Publish Article
              </button>
            </fieldset>
          </form>
        </div>
      </div>
    </div>
  </div>
</template>
