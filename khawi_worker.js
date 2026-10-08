export default {
  async fetch(request, env) {
    const cors = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type"
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: cors });
    }

    const url = new URL(request.url);

    if (url.pathname !== "/api/data") {
      return new Response("Not Found", { status: 404, headers: cors });
    }

    try {
      if (request.method === "GET") {
        const row = await env.DB.prepare(
          "SELECT data FROM khawi_state WHERE id = 1"
        ).first();

        const db = row ? JSON.parse(row.data) : {
          types: ["B","CH","BCH","CHM","شبكة"],
          entries: [],
          exits: []
        };

        return new Response(JSON.stringify({ db }), {
          headers: {
            ...cors,
            "Content-Type": "application/json",
            "Cache-Control": "no-store"
          }
        });
      }

      if (request.method === "POST") {
        const body = await request.json();

        if (body.type !== "save_state" || !body.data) {
          return new Response(
            JSON.stringify({ success: false, error: "Invalid request" }),
            { status: 400, headers: { ...cors, "Content-Type": "application/json" } }
          );
        }

        await env.DB.prepare(
          "INSERT OR REPLACE INTO khawi_state (id, data, updated_at) VALUES (1, ?, datetime('now'))"
        ).bind(JSON.stringify(body.data)).run();

        return new Response(JSON.stringify({ success: true }), {
          headers: { ...cors, "Content-Type": "application/json" }
        });
      }

      return new Response("Method Not Allowed", {
        status: 405,
        headers: cors
      });
    } catch (err) {
      return new Response(
        JSON.stringify({ success: false, error: String(err) }),
        { status: 500, headers: { ...cors, "Content-Type": "application/json" } }
      );
    }
  }
};