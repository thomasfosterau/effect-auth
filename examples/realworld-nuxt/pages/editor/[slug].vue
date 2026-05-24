<script setup lang="ts">
import type { ConduitArticle, ConduitProfile } from "../../server/types";

const route = useRoute();
const router = useRouter();
const slug = route.params.slug as string;
const user = useState<ConduitProfile | null>("user");
if (!user.value) navigateTo("/login");

const { data, error } = await useFetch<{ article: ConduitArticle }>(`/api/articles/${slug}`);
if (error.value) throw createError({ statusCode: 404 });

const form = reactive({
  title: data.value?.article.title ?? "",
  description: data.value?.article.description ?? "",
  body: data.value?.article.body ?? "",
});
const errors = ref<string[]>([]);

async function submit() {
  errors.value = [];
  try {
    const res = await $fetch<{ article: ConduitArticle }>(`/api/articles/${slug}`, {
      method: "PUT",
      body: { article: form },
    });
    await router.push(`/article/${res.article.slug}`);
  } catch (e: unknown) {
    const err = e as { statusMessage?: string };
    errors.value = [err.statusMessage ?? "update failed"];
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
                <input v-model="form.title" class="form-control form-control-lg" type="text" />
              </fieldset>
              <fieldset class="form-group">
                <input v-model="form.description" class="form-control" type="text" />
              </fieldset>
              <fieldset class="form-group">
                <textarea v-model="form.body" class="form-control" rows="8" />
              </fieldset>
              <button class="btn btn-lg pull-xs-right btn-primary" type="submit">
                Update Article
              </button>
            </fieldset>
          </form>
        </div>
      </div>
    </div>
  </div>
</template>
