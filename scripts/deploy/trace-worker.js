// Self-test worker for the fleet: answers at the edge, no origin involved.
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const lines = [
      "fucloudflare edge OK",
      `host=${url.hostname}`,
      `path=${url.pathname}`,
      `client_ip=${request.cf.clientIp}`,
      `user_agent=${request.headers.get("user-agent")}`,
    ];
    return new Response(lines.join("\n") + "\n", {
      headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
    });
  },
};
