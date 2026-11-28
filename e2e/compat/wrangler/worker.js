// The Worker that the compat workflow deploys with wrangler; the job then
// checks that the edge answers with exactly this text.
export default {
  async fetch(request) {
    return new Response("compat worker ok\n", { headers: { "content-type": "text/plain" } });
  },
};
