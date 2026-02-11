<template>
  <div id="login" :class="{ recaptcha: recaptcha }">
    <form @submit="submit">
      <img :src="logoURL" alt="File Browser" />
      <h1>{{ name }}</h1>

      <p v-if="reason != null" class="logout-message">
        {{ t(`login.logout_reasons.${reason}`) }}
      </p>

      <div v-if="error !== ''" class="wrong">{{ error }}</div>

      <a
        v-if="oidcLoginUrl"
        :href="oidcLoginUrl"
        class="button button--block button--oidc"
      >
        Login with Keycloak
      </a>

      <div
        v-if="oidcLoginUrl"
        class="or-separator"
      >
        OR
      </div>

      <input
        autofocus
        class="input input--block"
        type="text"
        autocapitalize="off"
        v-model="username"
        :placeholder="t('login.username')"
      />

      <input
        class="input input--block"
        type="password"
        v-model="password"
        :placeholder="t('login.password')"
      />

      <input
        class="input input--block"
        v-if="createMode"
        type="password"
        v-model="passwordConfirm"
        :placeholder="t('login.passwordConfirm')"
      />

      <div v-if="recaptcha" id="recaptcha"></div>

      <input
        class="button button--block"
        type="submit"
        :value="createMode ? t('login.signup') : t('login.submit')"
      />

      <p
        v-if="signup"
        @click="toggleMode"
      >
        {{ createMode ? t("login.loginInstead") : t("login.createAnAccount") }}
      </p>
    </form>
  </div>
</template>

<script setup lang="ts">
import { StatusError } from "@/api/utils";
import * as auth from "@/utils/auth";
import {
  name,
  logoURL,
  recaptcha,
  recaptchaKey,
  signup,
} from "@/utils/constants";

import { inject, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { useRoute, useRouter } from "vue-router";

declare global {
  interface Window {
    __OIDC_LOGIN_URL__?: string;
    __OIDC_LOGOUT_URL__?: string;
  }
}

const createMode = ref<boolean>(false);
const error = ref<string>("");
const username = ref<string>("");
const password = ref<string>("");
const passwordConfirm = ref<string>("");

const oidcLoginUrl = ref<string>("");

const route = useRoute();
const router = useRouter();
const { t } = useI18n({});

const $showError = inject<IToastError>("$showError")!;

const reason = route.query["logout-reason"] ?? null;

const toggleMode = () => {
  createMode.value = !createMode.value;
};

const submit = async (event: Event) => {
  event.preventDefault();
  event.stopPropagation();

  const redirect = (route.query.redirect || "/files/") as string;

  let captcha = "";

  if (recaptcha) {
    captcha = window.grecaptcha.getResponse();

    if (captcha === "") {
      error.value = t("login.wrongCredentials");
      return;
    }
  }

  if (createMode.value) {
    if (password.value !== passwordConfirm.value) {
      error.value = t("login.passwordsDontMatch");
      return;
    }
  }

  try {
    if (createMode.value) {
      await auth.signup(username.value, password.value);
    }

    await auth.login(username.value, password.value, captcha);

    router.push({ path: redirect });

  } catch (e: any) {

    if (e instanceof StatusError) {

      if (e.status === 409) {
        error.value = t("login.usernameTaken");

      } else if (e.status === 403) {
        error.value = t("login.wrongCredentials");

      } else if (e.status === 400) {

        const match = e.message.match(/minimum length is (\d+)/);

        if (match) {
          error.value = t("login.passwordTooShort", {
            min: match[1],
          });
        } else {
          error.value = e.message;
        }

      } else {
        $showError(e);
      }
    }
  }
};

onMounted(() => {

  if (window.__OIDC_LOGIN_URL__) {
    oidcLoginUrl.value = window.__OIDC_LOGIN_URL__;
  }

  const oidc = route.query["oidc"] ?? undefined as string | undefined;
  if (oidc != undefined && oidc == "done") {
    console.log("oidc is done proceeding to try to login!");
    (async () => {
      try {
        await auth.login("", "", "");

        const redirect = (route.query.redirect || "/files/") as string;
        router.replace({ path: redirect });
      } catch (err: any) {
        console.error("OIDC login failed:", err);
      }
    })();
  }

  if (!recaptcha) return;

  window.grecaptcha.ready(function () {
    window.grecaptcha.render("recaptcha", {
      sitekey: recaptchaKey,
    });
  });
});

function getCookie(name: string): string | null {
  const match = document.cookie.match(new RegExp('(^| )' + name + '=([^;]+)'));
  return match ? decodeURIComponent(match[2]) : null;
}

</script>

<style scoped>
.button--oidc {
  background: #1976d2;
  color: white;
  text-align: center;
  text-decoration: none;
  font-weight: 600;
}

.button--oidc:hover {
  background: #1565c0;
}

.or-separator {
  text-align: center;
  margin: 12px 0;
  opacity: 0.6;
  font-size: 0.9em;
}
</style>

