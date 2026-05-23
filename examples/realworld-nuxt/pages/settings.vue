<script setup lang="ts">
import type { ConduitProfile } from "../server/types";

const user = useState<ConduitProfile | null>("user");
const router = useRouter();
if (!user.value) navigateTo("/login");

const form = reactive({
  image: user.value?.image ?? "",
  username: user.value?.username ?? "",
  bio: user.value?.bio ?? "",
  email: user.value?.email ?? "",
  password: "",
});
const errors = ref<string[]>([]);

async function submit() {
  errors.value = [];
  try {
    const res = await $fetch<{ user: ConduitProfile }>("/api/user", {
      method: "PUT",
      body: {
        user: {
          image: form.image || null,
          username: form.username,
          bio: form.bio || null,
          email: form.email,
          ...(form.password ? { password: form.password } : {}),
        },
      },
    });
    user.value = res.user;
    await router.push(`/profile/${res.user.username}`);
  } catch (e: unknown) {
    const err = e as { statusMessage?: string };
    errors.value = [err.statusMessage ?? "update failed"];
  }
}

async function logout() {
  await $fetch("/api/users/logout", { method: "POST" });
  user.value = null;
  await router.push("/");
}
</script>

<template>
  <div class="settings-page">
    <div class="container page">
      <div class="row">
        <div class="col-md-6 offset-md-3 col-xs-12">
          <h1 class="text-xs-center">Your Settings</h1>
          <ul v-if="errors.length" class="error-messages">
            <li v-for="e in errors" :key="e">{{ e }}</li>
          </ul>
          <form @submit.prevent="submit">
            <fieldset>
              <fieldset class="form-group">
                <input
                  v-model="form.image"
                  class="form-control"
                  type="text"
                  placeholder="URL of profile picture"
                />
              </fieldset>
              <fieldset class="form-group">
                <input
                  v-model="form.username"
                  class="form-control form-control-lg"
                  type="text"
                  placeholder="Your Name"
                  required
                />
              </fieldset>
              <fieldset class="form-group">
                <textarea
                  v-model="form.bio"
                  class="form-control form-control-lg"
                  rows="8"
                  placeholder="Short bio about you"
                />
              </fieldset>
              <fieldset class="form-group">
                <input
                  v-model="form.email"
                  class="form-control form-control-lg"
                  type="email"
                  placeholder="Email"
                  required
                />
              </fieldset>
              <fieldset class="form-group">
                <input
                  v-model="form.password"
                  class="form-control form-control-lg"
                  type="password"
                  placeholder="New Password (leave blank to keep)"
                />
              </fieldset>
              <button class="btn btn-lg btn-primary pull-xs-right" type="submit">
                Update Settings
              </button>
            </fieldset>
          </form>
          <hr />
          <button class="btn btn-outline-danger" type="button" @click="logout">
            Or click here to logout.
          </button>
        </div>
      </div>
    </div>
  </div>
</template>
