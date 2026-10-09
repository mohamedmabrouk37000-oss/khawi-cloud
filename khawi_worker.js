
const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Admin-Code",
  "Cache-Control": "no-store"
};

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { ...cors, "Content-Type": "application/json" }
  });

async function hashCode(code, pepper) {
  const bytes = new TextEncoder().encode(code + ":" + pepper);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

function randomToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

async function getUser(request, env) {
  const header = request.headers.get("Authorization") || "";
  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : "";

  if (!token) return null;

  const row = await env.DB.prepare(`
    SELECT s.user_id, u.status
    FROM khawi_sessions s
    JOIN khawi_users u ON u.user_id = s.user_id
    WHERE s.token = ? AND s.expires_at > ?
  `).bind(token, Math.floor(Date.now() / 1000)).first();

  if (!row || row.status !== "approved") return null;
  return row;
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: cors });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    if (!env.DB || !env.ADMIN_CODE || !env.APP_PEPPER) {
      return json({ error: "Server configuration incomplete" }, 500);
    }

    try {
      // إنشاء طلب تفعيل جديد
      if (path === "/api/register" && request.method === "POST") {
        const body = await request.json();
        const code = String(body.code || "").trim();

        if (code.length < 8 || code.length > 128) {
          return json({
            error: "الكود خاصو يكون بين 8 و128 حرف"
          }, 400);
        }

        const code_hash = await hashCode(code, env.APP_PEPPER);
        const existing = await env.DB.prepare(
          "SELECT status FROM khawi_users WHERE code_hash = ?"
        ).bind(code_hash).first();

        if (existing) {
          return json({
            error: "هاد الكود مسجل من قبل",
            status: existing.status
          }, 409);
        }

        const user_id = crypto.randomUUID();

        await env.DB.prepare(`
          INSERT INTO khawi_users
            (user_id, code_hash, status, role, created_at)
          VALUES (?, ?, 'pending', 'user', ?)
        `).bind(user_id, code_hash, Math.floor(Date.now() / 1000)).run();

        return json({
          success: true,
          status: "pending",
          message: "طلبك تسجل، تسنى موافقة المدير"
        }, 201);
      }

      // دخول المستخدم بكوده بعد موافقة المدير
      if (path === "/api/login" && request.method === "POST") {
        const body = await request.json();
        const code = String(body.code || "").trim();

        if (!code || code.length > 128) {
          return json({ error: "الكود غير صحيح" }, 400);
        }

        const code_hash = await hashCode(code, env.APP_PEPPER);
        const user = await env.DB.prepare(
          "SELECT user_id, status FROM khawi_users WHERE code_hash = ?"
        ).bind(code_hash).first();

        if (!user) {
          return json({ error: "الكود غير موجود، خاصك تسجل أولا" }, 404);
        }

        if (user.status === "pending") {
          return json({ error: "الحساب كيتسنى موافقة المدير" }, 403);
        }

        if (user.status !== "approved") {
          return json({ error: "هاد الحساب مرفوض أو موقوف" }, 403);
        }

        const token = randomToken();
        const expires = Math.floor(Date.now() / 1000) + 31536000;

        await env.DB.prepare(
          "INSERT INTO khawi_sessions (token, user_id, expires_at) VALUES (?, ?, ?)"
        ).bind(token, user.user_id, expires).run();

        return json({
          success: true,
          token,
          expires_at: expires
        });
      }

      // جميع عمليات المدير محمية بسر المدير
      if (path.startsWith("/api/admin/")) {
        const adminCode = request.headers.get("X-Admin-Code") || "";

        if (adminCode !== env.ADMIN_CODE) {
          return json({ error: "غير مسموح" }, 401);
        }

        if (path === "/api/admin/pending" && request.method === "GET") {
          const result = await env.DB.prepare(`
            SELECT user_id, status, created_at
            FROM khawi_users
            WHERE status = 'pending'
            ORDER BY created_at ASC
          `).all();

          return json({ users: result.results || [] });
        }

        if (path === "/api/admin/users" && request.method === "GET") {
          const result = await env.DB.prepare(`
            SELECT user_id, status, role, created_at
            FROM khawi_users
            ORDER BY created_at DESC
          `).all();

          return json({ users: result.results || [] });
        }

        if (path === "/api/admin/status" && request.method === "POST") {
          const body = await request.json();
          const user_id = String(body.user_id || "");
          const status = String(body.status || "");

          if (!user_id || ![
            "approved", "rejected", "suspended"
          ].includes(status)) {
            return json({ error: "المعلومات غير صحيحة" }, 400);
          }

          const result = await env.DB.prepare(
            "UPDATE khawi_users SET status = ? WHERE user_id = ? AND role = 'user'"
          ).bind(status, user_id).run();

          if (!result.meta || result.meta.changes === 0) {
            return json({ error: "الحساب غير موجود" }, 404);
          }

          if (status !== "approved") {
            await env.DB.prepare(
              "DELETE FROM khawi_sessions WHERE user_id = ?"
            ).bind(user_id).run();
          }

          return json({ success: true, status });
        }

        return json({ error: "المسار غير موجود" }, 404);
      }

      // تسجيل الخروج
      if (path === "/api/logout" && request.method === "POST") {
        const header = request.headers.get("Authorization") || "";
        const token = header.startsWith("Bearer ") ? header.slice(7) : "";

        if (token) {
          await env.DB.prepare(
            "DELETE FROM khawi_sessions WHERE token = ?"
          ).bind(token).run();
        }

        return json({ success: true });
      }

      // بيانات المستخدم الخاصة فقط
      if (path === "/api/data") {
        const user = await getUser(request, env);

        if (!user) {
          return json({ error: "خاصك تدخل بكود حساب مقبول" }, 401);
        }

        if (request.method === "GET") {
          const row = await env.DB.prepare(
            "SELECT data FROM khawi_user_state WHERE user_id = ?"
          ).bind(user.user_id).first();

          const db = row ? JSON.parse(row.data) : {
            types: ["B", "CH", "BCH", "CHM", "شبكة"],
            entries: [],
            exits: []
          };

          return json({ db });
        }

        if (request.method === "POST") {
          const body = await request.json();

          if (body.type !== "save_state" || !body.data ||
              typeof body.data !== "object" || Array.isArray(body.data)) {
            return json({ error: "المعلومات غير صحيحة" }, 400);
          }

          await env.DB.prepare(`
            INSERT INTO khawi_user_state (user_id, data, updated_at)
            VALUES (?, ?, datetime('now'))
            ON CONFLICT(user_id) DO UPDATE SET
              data = excluded.data,
              updated_at = excluded.updated_at
          `).bind(user.user_id, JSON.stringify(body.data)).run();

          return json({ success: true });
        }

        return json({ error: "Method Not Allowed" }, 405);
      }

      return json({ error: "Not Found" }, 404);
    } catch (err) {
      return json({ error: "Server error" }, 500);
    }
  }
};
