<script setup lang="ts">
import type { ConduitArticle } from "../server/types";

const props = defineProps<{
  articles: ConduitArticle[];
  articlesCount: number;
  offset: number;
  limit: number;
  baseHref: string;
}>();

const pages = computed(() => Math.max(1, Math.ceil(props.articlesCount / props.limit)));
const current = computed(() => Math.floor(props.offset / props.limit));
const pageHref = (i: number) => {
  const sep = props.baseHref.includes("?") ? "&" : "?";
  return `${props.baseHref}${sep}offset=${i * props.limit}`;
};
</script>

<template>
  <div v-if="articles.length === 0" class="article-preview">No articles are here... yet.</div>
  <div v-else>
    <div v-for="a in articles" :key="a.slug" class="article-preview">
      <div class="article-meta">
        <NuxtLink :to="`/profile/${a.author.username}`">
          <img v-if="a.author.image" :src="a.author.image" alt="" />
        </NuxtLink>
        <div class="info">
          <NuxtLink :to="`/profile/${a.author.username}`" class="author">{{
            a.author.username
          }}</NuxtLink>
          <span class="date">{{ new Date(a.createdAt).toDateString() }}</span>
        </div>
        <button
          :class="[
            'btn',
            'btn-sm',
            'pull-xs-right',
            a.favorited ? 'btn-primary' : 'btn-outline-primary',
          ]"
        >
          <i class="ion-heart" /> {{ a.favoritesCount }}
        </button>
      </div>
      <NuxtLink :to="`/article/${a.slug}`" class="preview-link">
        <h1>{{ a.title }}</h1>
        <p>{{ a.description }}</p>
        <span>Read more...</span>
        <ul v-if="a.tagList.length" class="tag-list">
          <li v-for="t in a.tagList" :key="t" class="tag-default tag-pill tag-outline">{{ t }}</li>
        </ul>
      </NuxtLink>
    </div>

    <ul v-if="pages > 1" class="pagination">
      <li v-for="i in pages" :key="i" :class="['page-item', { active: i - 1 === current }]">
        <NuxtLink class="page-link" :to="pageHref(i - 1)">{{ i }}</NuxtLink>
      </li>
    </ul>
  </div>
</template>
