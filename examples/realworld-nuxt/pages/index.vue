<script setup lang="ts">
import type { ConduitArticle, ConduitProfile } from "../server/types";

const route = useRoute();
const user = useState<ConduitProfile | null>("user");

const tab = computed(() =>
  route.query.tag ? "tag" : ((route.query.tab as string) ?? (user.value ? "your" : "global")),
);
const tag = computed(() => (route.query.tag as string | undefined) ?? undefined);
const offset = computed(() => Number(route.query.offset ?? 0));
const limit = 10;

const { data: articlesData } = await useFetch<{
  articles: ConduitArticle[];
  articlesCount: number;
}>(() => (tab.value === "your" && user.value ? "/api/articles/feed" : "/api/articles"), {
  query: computed(() => ({
    ...(tag.value ? { tag: tag.value } : {}),
    limit,
    offset: offset.value,
  })),
});
const { data: tagsData } = await useFetch<{ tags: string[] }>("/api/tags");

const baseHref = computed(() =>
  tag.value
    ? `/?tag=${encodeURIComponent(tag.value)}`
    : tab.value === "your"
      ? "/?tab=your"
      : "/?tab=global",
);
</script>

<template>
  <div class="home-page">
    <div class="banner">
      <div class="container">
        <h1 class="logo-font">conduit</h1>
        <p>A place to share your knowledge.</p>
      </div>
    </div>
    <div class="container page">
      <div class="row">
        <div class="col-md-9">
          <div class="feed-toggle">
            <ul class="nav nav-pills outline-active">
              <li v-if="user" class="nav-item">
                <NuxtLink :class="['nav-link', { active: tab === 'your' }]" to="/?tab=your"
                  >Your Feed</NuxtLink
                >
              </li>
              <li class="nav-item">
                <NuxtLink :class="['nav-link', { active: tab === 'global' }]" to="/?tab=global"
                  >Global Feed</NuxtLink
                >
              </li>
              <li v-if="tag" class="nav-item">
                <NuxtLink class="nav-link active" :to="`/?tag=${tag}`">#{{ tag }}</NuxtLink>
              </li>
            </ul>
          </div>
          <ArticleList
            v-if="articlesData"
            :articles="articlesData.articles"
            :articles-count="articlesData.articlesCount"
            :offset="offset"
            :limit="limit"
            :base-href="baseHref"
          />
        </div>
        <div class="col-md-3">
          <div class="sidebar">
            <p>Popular Tags</p>
            <div class="tag-list">
              <NuxtLink
                v-for="t in tagsData?.tags ?? []"
                :key="t"
                :to="`/?tag=${encodeURIComponent(t)}`"
                class="tag-pill tag-default"
              >
                {{ t }}
              </NuxtLink>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
