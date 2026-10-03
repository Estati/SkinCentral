export default {
  async fetch(request, env) {
    // Placeholder: just serves the normal site for now.
    return env.ASSETS.fetch(request);
  },
};
