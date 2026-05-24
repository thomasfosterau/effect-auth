<script setup lang="ts">
import type { ConduitProfile } from "../server/types";
const user = useState<ConduitProfile | null>("user", () => null);
const route = useRoute();
const isActive = (path: string) => route.path === path;
</script>

<template>
  <nav class="navbar navbar-light">
    <div class="container">
      <NuxtLink to="/" class="navbar-brand">conduit</NuxtLink>
      <ul class="nav navbar-nav pull-xs-right">
        <li class="nav-item">
          <NuxtLink :class="['nav-link', { active: isActive('/') }]" to="/">Home</NuxtLink>
        </li>
        <template v-if="user">
          <li class="nav-item">
            <NuxtLink :class="['nav-link', { active: isActive('/editor') }]" to="/editor">
              <i class="ion-compose" />&nbsp;New Article
            </NuxtLink>
          </li>
          <li class="nav-item">
            <NuxtLink :class="['nav-link', { active: isActive('/settings') }]" to="/settings">
              <i class="ion-gear-a" />&nbsp;Settings
            </NuxtLink>
          </li>
          <li class="nav-item">
            <NuxtLink
              :class="['nav-link', { active: isActive(`/profile/${user.username}`) }]"
              :to="`/profile/${user.username}`"
            >
              {{ user.username }}
            </NuxtLink>
          </li>
        </template>
        <template v-else>
          <li class="nav-item">
            <NuxtLink :class="['nav-link', { active: isActive('/login') }]" to="/login"
              >Sign in</NuxtLink
            >
          </li>
          <li class="nav-item">
            <NuxtLink :class="['nav-link', { active: isActive('/register') }]" to="/register"
              >Sign up</NuxtLink
            >
          </li>
        </template>
      </ul>
    </div>
  </nav>

  <slot />

  <footer>
    <div class="container">
      <NuxtLink to="/" class="logo-font">conduit</NuxtLink>
      <span class="attribution">effect-auth × Nuxt example. Conduit design from Thinkster.</span>
    </div>
  </footer>
</template>
