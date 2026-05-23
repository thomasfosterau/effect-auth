<script setup lang="ts">
import type { ConduitArticle, ConduitProfile } from "../../server/types";

const route = useRoute();
const username = route.params.username as string;
const me = useState<ConduitProfile | null>("user");

const tab = computed(() => (route.query.tab === "favorites" ? "favorites" : "my"));
const isMe = computed(() => me.value?.username === username);

const { data: profileData, refresh: refreshProfile } = await useFetch<{ profile: ConduitProfile }>(
  `/api/profiles/${username}`,
);
if (!profileData.value) throw createError({ statusCode: 404 });

const articlesEndpoint = computed(() => "/api/articles");
const { data: articlesData } = await useFetch<{
  articles: ConduitArticle[];
  articlesCount: number;
}>(articlesEndpoint, {
  query: computed(() =>
    tab.value === "favorites"
      ? { favorited: username, limit: 10 }
      : { author: username, limit: 10 },
  ),
});

async function toggleFollow() {
  if (!me.value) return navigateTo("/login");
  const method = profileData.value!.profile.following ? "DELETE" : "POST";
  await $fetch(`/api/profiles/${username}/follow`, { method });
  await refreshProfile();
}
</script>

<template>
  <div class="profile-page">
    <div class="user-info">
      <div class="container">
        <div class="row">
          <div class="col-xs-12 col-md-10 offset-md-1">
            <img
              v-if="profileData?.profile.image"
              :src="profileData.profile.image"
              class="user-img"
              alt=""
            />
            <h4>{{ profileData?.profile.username }}</h4>
            <p v-if="profileData?.profile.bio">{{ profileData.profile.bio }}</p>
            <NuxtLink
              v-if="isMe"
              to="/settings"
              class="btn btn-sm btn-outline-secondary action-btn"
            >
              <i class="ion-gear-a" /> Edit Profile Settings
            </NuxtLink>
            <button
              v-else-if="me"
              class="btn btn-sm btn-outline-secondary action-btn"
              @click="toggleFollow"
            >
              <i class="ion-plus-round" />
              {{ profileData?.profile.following ? "Unfollow" : "Follow" }}
              {{ profileData?.profile.username }}
            </button>
          </div>
        </div>
      </div>
    </div>
    <div class="container">
      <div class="row">
        <div class="col-xs-12 col-md-10 offset-md-1">
          <div class="articles-toggle">
            <ul class="nav nav-pills outline-active">
              <li class="nav-item">
                <NuxtLink
                  :class="['nav-link', { active: tab === 'my' }]"
                  :to="`/profile/${username}`"
                  >My Articles</NuxtLink
                >
              </li>
              <li class="nav-item">
                <NuxtLink
                  :class="['nav-link', { active: tab === 'favorites' }]"
                  :to="`/profile/${username}?tab=favorites`"
                >
                  Favorited Articles
                </NuxtLink>
              </li>
            </ul>
          </div>
          <ArticleList
            v-if="articlesData"
            :articles="articlesData.articles"
            :articles-count="articlesData.articlesCount"
            :offset="0"
            :limit="10"
            :base-href="`/profile/${username}${tab === 'favorites' ? '?tab=favorites' : ''}`"
          />
        </div>
      </div>
    </div>
  </div>
</template>
