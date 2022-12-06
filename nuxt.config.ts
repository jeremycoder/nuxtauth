// https://nuxt.com/docs/api/configuration/nuxt-config
export default defineNuxtConfig({
  modules: ["@nuxtjs/tailwindcss"],

  runtimeConfig: {
    public: {
      muloziAccessTokenSecret: process.env.MULOZI_ACCESS_TOKEN_SECRET,
      muloziRefreshTokenSecret: process.env.MULOZI_REFRESH_TOKEN_SECRET,
    },
  },
});
