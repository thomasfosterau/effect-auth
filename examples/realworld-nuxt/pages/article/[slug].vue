<script setup lang="ts">
import type { ConduitArticle, ConduitComment, ConduitProfile } from "../../server/types";

const route = useRoute();
const router = useRouter();
const slug = route.params.slug as string;
const user = useState<ConduitProfile | null>("user");

const { data: articleData, refresh: refreshArticle } = await useFetch<{ article: ConduitArticle }>(
  `/api/articles/${slug}`,
);
const { data: commentsData, refresh: refreshComments } = await useFetch<{
  comments: ConduitComment[];
}>(`/api/articles/${slug}/comments`);

if (!articleData.value) throw createError({ statusCode: 404, statusMessage: "article not found" });

const newComment = ref("");

const article = computed(() => articleData.value!.article);
const isAuthor = computed(() => user.value?.username === article.value.author.username);

async function toggleFavorite() {
  if (!user.value) return router.push("/login");
  await $fetch(`/api/articles/${slug}/favorite`, {
    method: article.value.favorited ? "DELETE" : "POST",
  });
  await refreshArticle();
}

async function toggleFollow() {
  if (!user.value) return router.push("/login");
  const u = article.value.author.username;
  await $fetch(`/api/profiles/${u}/follow`, {
    method: article.value.author.following ? "DELETE" : "POST",
  });
  await refreshArticle();
}

async function deleteArticle() {
  // Cast to string to bypass typed-route narrowing: a dynamic `/api/articles/${slug}`
  // also matches the static /api/articles/feed route, so Nuxt intersects the allowed
  // methods down to GET even though /api/articles/[slug] has a DELETE handler.
  await $fetch(`/api/articles/${slug}` as string, { method: "DELETE" });
  await router.push("/");
}

async function postComment() {
  if (!newComment.value.trim()) return;
  await $fetch(`/api/articles/${slug}/comments`, {
    method: "POST",
    body: { comment: { body: newComment.value } },
  });
  newComment.value = "";
  await refreshComments();
}

async function deleteComment(id: number) {
  await $fetch(`/api/articles/${slug}/comments/${id}`, { method: "DELETE" });
  await refreshComments();
}
</script>

<template>
  <div class="article-page">
    <div class="banner">
      <div class="container">
        <h1>{{ article.title }}</h1>
        <div class="article-meta">
          <NuxtLink :to="`/profile/${article.author.username}`">
            <img v-if="article.author.image" :src="article.author.image" alt="" />
          </NuxtLink>
          <div class="info">
            <NuxtLink :to="`/profile/${article.author.username}`" class="author">{{
              article.author.username
            }}</NuxtLink>
            <span class="date">{{ new Date(article.createdAt).toDateString() }}</span>
          </div>
          <template v-if="isAuthor">
            <NuxtLink :to="`/editor/${article.slug}`" class="btn btn-sm btn-outline-secondary">
              <i class="ion-edit" /> Edit Article
            </NuxtLink>
            &nbsp;
            <button class="btn btn-sm btn-outline-danger" @click="deleteArticle">
              <i class="ion-trash-a" /> Delete Article
            </button>
          </template>
          <template v-else-if="user">
            <button class="btn btn-sm btn-outline-secondary" @click="toggleFollow">
              <i class="ion-plus-round" /> {{ article.author.following ? "Unfollow" : "Follow" }}
              {{ article.author.username }}
            </button>
            &nbsp;
            <button
              :class="['btn', 'btn-sm', article.favorited ? 'btn-primary' : 'btn-outline-primary']"
              @click="toggleFavorite"
            >
              <i class="ion-heart" /> {{ article.favorited ? "Unfavorite" : "Favorite" }} Article
              ({{ article.favoritesCount }})
            </button>
          </template>
        </div>
      </div>
    </div>

    <div class="container page">
      <div class="row article-content">
        <div class="col-md-12">
          <p style="white-space: pre-wrap">{{ article.body }}</p>
          <ul v-if="article.tagList.length" class="tag-list">
            <li v-for="t in article.tagList" :key="t" class="tag-default tag-pill tag-outline">
              {{ t }}
            </li>
          </ul>
        </div>
      </div>
      <hr />
      <div class="row">
        <div class="col-xs-12 col-md-8 offset-md-2">
          <form v-if="user" class="card comment-form" @submit.prevent="postComment">
            <div class="card-block">
              <textarea
                v-model="newComment"
                class="form-control"
                placeholder="Write a comment..."
                rows="3"
              />
            </div>
            <div class="card-footer">
              <img v-if="user.image" :src="user.image" class="comment-author-img" alt="" />
              <button class="btn btn-sm btn-primary" type="submit">Post Comment</button>
            </div>
          </form>
          <p v-else>
            <NuxtLink to="/login">Sign in</NuxtLink> or
            <NuxtLink to="/register">sign up</NuxtLink> to add comments on this article.
          </p>

          <div v-for="c in commentsData?.comments ?? []" :key="c.id" class="card">
            <div class="card-block">
              <p class="card-text">{{ c.body }}</p>
            </div>
            <div class="card-footer">
              <NuxtLink :to="`/profile/${c.author.username}`" class="comment-author">
                <img
                  v-if="c.author.image"
                  :src="c.author.image"
                  class="comment-author-img"
                  alt=""
                />
              </NuxtLink>
              &nbsp;
              <NuxtLink :to="`/profile/${c.author.username}`" class="comment-author">{{
                c.author.username
              }}</NuxtLink>
              <span class="date-posted">{{ new Date(c.createdAt).toDateString() }}</span>
              <button
                v-if="user && user.username === c.author.username"
                class="mod-options"
                style="float: right"
                aria-label="Delete comment"
                @click="deleteComment(c.id)"
              >
                <i class="ion-trash-a" />
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
