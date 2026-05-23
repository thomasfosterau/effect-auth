<script setup lang="ts">
import type { ConduitProfile } from "../server/types";

const email = ref("");
const username = ref("");
const password = ref("");
const errors = ref<string[]>([]);
const user = useState<ConduitProfile | null>("user");
const router = useRouter();

async function submit() {
  errors.value = [];
  try {
    const res = await $fetch<{ user: ConduitProfile }>("/api/users", {
      method: "POST",
      body: { user: { email: email.value, username: username.value, password: password.value } },
    });
    user.value = res.user;
    await router.push("/");
  } catch (e: unknown) {
    const err = e as { statusMessage?: string };
    errors.value = [err.statusMessage ?? "registration failed"];
  }
}
</script>

<template>
  <div class="auth-page">
    <div class="container page">
      <div class="row">
        <div class="col-md-6 offset-md-3 col-xs-12">
          <h1 class="text-xs-center">Sign up</h1>
          <p class="text-xs-center"><NuxtLink to="/login">Have an account?</NuxtLink></p>
          <ul v-if="errors.length" class="error-messages">
            <li v-for="e in errors" :key="e">{{ e }}</li>
          </ul>
          <form @submit.prevent="submit">
            <fieldset class="form-group">
              <input
                v-model="username"
                class="form-control form-control-lg"
                type="text"
                placeholder="Username"
                required
              />
            </fieldset>
            <fieldset class="form-group">
              <input
                v-model="email"
                class="form-control form-control-lg"
                type="email"
                placeholder="Email"
                required
              />
            </fieldset>
            <fieldset class="form-group">
              <input
                v-model="password"
                class="form-control form-control-lg"
                type="password"
                placeholder="Password (8+ characters)"
                minlength="8"
                required
              />
            </fieldset>
            <button class="btn btn-lg btn-primary pull-xs-right" type="submit">Sign up</button>
          </form>
        </div>
      </div>
    </div>
  </div>
</template>
