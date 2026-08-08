/**
 * D2R 장터 — 백엔드 API (Cloudflare Worker + D1)
 *
 * 필요한 설정 (대시보드 → Worker → Settings):
 *   1) Bindings → D1 database: 변수명 DB → d2r-market 데이터베이스 연결
 *   2) (권장) 아래 ALLOWED_ORIGIN 을 본인 GitHub Pages 주소로 수정
 *      세션은 D1에 저장되는 무작위 토큰 방식이라 별도 시크릿이 필요 없습니다.
 *
 * D1 스키마는 schema.sql 참고. README.md 에 5분 배포 가이드 있음.
 */

const ALLOWED_ORIGIN = "*"; // 예: "https://myname.github.io"
const TOKEN_TTL = 60 * 60 * 24 * 30; // 세션 30일
const PBKDF2_ITER = 100000;

const CORS = {
  "access-control-allow-origin": ALLOWED_ORIGIN,
  "access-control-allow-methods": "GET, POST, PATCH, DELETE, OPTIONS",
  "access-control-allow-headers": "content-type, authorization",
  "access-control-max-age": "86400",
};

const LIMITS = {
  username: /^[A-Za-z0-9_가-힣]{2,16}$/,
  password: [8, 72],
  title: 80, options: 1200, contact: 60, comment: 500,
  priceText: 120, priceRows: 8, itemName: 60, battletag: 40,
  message: 1000, reason: 300,
};
const ENUMS = {
  type: ["sell", "buy"],
  platform: ["pc", "switch", "ps", "xbox"],
  mode: ["sc", "hc"],
  ladder: ["ladder", "non"],
  version: ["classic", "lod", "rotw"],
  status: ["active", "done", "hidden"],
  price_mode: ["runes", "offer", "text"],
};

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
    try {
      const res = await route(request, env);
      return withCors(res);
    } catch (e) {
      if (e instanceof ApiError) return withCors(json({ error: e.message }, e.status));
      return withCors(json({ error: "서버 오류가 발생했습니다", detail: String(e).slice(0, 200) }, 500));
    }
  },
};

class ApiError extends Error { constructor(status, message) { super(message); this.status = status; } }
const fail = (status, message) => { throw new ApiError(status, message); };

async function route(request, env) {
  const url = new URL(request.url);
  const p = url.pathname.replace(/\/+$/, "") || "/";
  const m = request.method;

  if (p === "/" || p === "") return json({ ok: true, service: "d2r-market-api", docs: "README.md 참고" });

  // ── auth ──
  if (p === "/api/auth/signup" && m === "POST") return signup(request, env);
  if (p === "/api/auth/login" && m === "POST") return login(request, env);
  if (p === "/api/auth/logout" && m === "POST") return logout(request, env);
  if (p === "/api/auth/me" && m === "GET") {
    const user = await requireUser(request, env);
    const un = await env.DB.prepare("SELECT COUNT(*) AS n FROM messages WHERE to_id = ? AND read_at IS NULL")
      .bind(user.id).first();
    return json({ user: publicUser(user), unread: un ? un.n : 0 });
  }
  if (p === "/api/auth/recover" && m === "POST") return recover(request, env);
  if (p === "/api/auth/password" && m === "POST") return changePassword(request, env);
  if (p === "/api/auth/recovery-code" && m === "POST") return rotateRecovery(request, env);

  // ── 쪽지 · 신고 ──
  if (p === "/api/messages/threads" && m === "GET") return msgThreads(request, env);
  if (p === "/api/messages" && m === "POST") return msgSend(request, env);
  if (p === "/api/reports" && m === "POST") return createReport(request, env);
  if (p === "/api/admin/reports" && m === "GET") return adminReports(request, env);

  // ── listings ──
  if (p === "/api/listings" && m === "GET") return listListings(url, env);
  if (p === "/api/listings" && m === "POST") return createListing(request, env);

  let mm;
  if ((mm = p.match(/^\/api\/listings\/(\d+)$/))) {
    const id = Number(mm[1]);
    if (m === "GET") return getListing(id, env);
    if (m === "PATCH") return patchListing(id, request, env);
    if (m === "DELETE") return deleteListing(id, request, env);
  }
  if ((mm = p.match(/^\/api\/listings\/(\d+)\/comments$/)) && m === "POST")
    return addComment(Number(mm[1]), request, env);
  if ((mm = p.match(/^\/api\/comments\/(\d+)$/)) && m === "DELETE")
    return deleteComment(Number(mm[1]), request, env);
  if ((mm = p.match(/^\/api\/messages\/with\/([^/]+)$/)) && m === "GET")
    return msgWith(decodeURIComponent(mm[1]), request, env);
  if ((mm = p.match(/^\/api\/admin\/reports\/(\d+)$/)) && m === "PATCH")
    return adminCloseReport(Number(mm[1]), request, env);
  if ((mm = p.match(/^\/api\/admin\/listings\/(\d+)$/)) && m === "PATCH")
    return adminSetListing(Number(mm[1]), request, env);
  if ((mm = p.match(/^\/api\/admin\/comments\/(\d+)$/)) && m === "DELETE")
    return adminDelComment(Number(mm[1]), request, env);
  if ((mm = p.match(/^\/api\/admin\/users\/([^/]+)$/)) && m === "PATCH")
    return adminBanUser(decodeURIComponent(mm[1]), request, env);

  // ── 시세(완료 매물) ──
  if (p === "/api/stats" && m === "GET") return stats(url, env);

  return json({ error: "not found" }, 404);
}

/* ───────────────── auth ───────────────── */

async function signup(request, env) {
  const ip = clientIp(request);
  await limiter(env, "su:" + ip, 5, 3600);
  const b = await readJson(request);
  const username = str(b.username).trim();
  const password = str(b.password);
  const battletag = str(b.battletag).trim().slice(0, LIMITS.battletag);
  if (!LIMITS.username.test(username)) fail(400, "아이디는 한글/영문/숫자/_ 2~16자입니다");
  if (password.length < LIMITS.password[0] || password.length > LIMITS.password[1])
    fail(400, "비밀번호는 8자 이상이어야 합니다");

  const dupe = await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(username).first();
  if (dupe) fail(409, "이미 사용 중인 아이디입니다");

  const salt = randHex(16);
  const hash = await pbkdf2(password, salt);
  const rec = makeRecCode();
  const recSalt = randHex(16);
  const recHash = await pbkdf2(rec.normalized, recSalt);
  const now = ts();
  const r = await env.DB.prepare(
    "INSERT INTO users (username, pass_hash, salt, battletag, rec_hash, rec_salt, created_at) VALUES (?,?,?,?,?,?,?)"
  ).bind(username, hash, salt, battletag, recHash, recSalt, now).run();
  const userId = r.meta.last_row_id;
  const token = await createSession(env, userId);
  return json({
    token, user: { id: userId, username, battletag, is_admin: false },
    recovery_code: rec.display,
    notice: "복구 코드는 지금 한 번만 표시됩니다. 비밀번호 분실 시 유일한 복구 수단이니 반드시 보관하세요.",
  }, 201);
}

async function login(request, env) {
  const ip = clientIp(request);
  await limiter(env, "li:" + ip, 20, 600);
  const b = await readJson(request);
  const username = str(b.username).trim();
  const password = str(b.password);
  const u = await env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(username).first();
  const badCreds = () => fail(401, "아이디 또는 비밀번호가 올바르지 않습니다");
  if (!u) badCreds();
  const hash = await pbkdf2(password, u.salt);
  if (!timingSafeEq(hash, u.pass_hash)) badCreds();
  if (u.banned) fail(403, "이용이 제한된 계정입니다");
  const token = await createSession(env, u.id);
  return json({ token, user: publicUser(u) });
}

async function logout(request, env) {
  const token = bearer(request);
  if (token) await env.DB.prepare("DELETE FROM sessions WHERE token = ?").bind(token).run();
  return json({ ok: true });
}

async function createSession(env, userId) {
  const token = randHex(32);
  await env.DB.prepare("INSERT INTO sessions (token, user_id, expires_at) VALUES (?,?,?)")
    .bind(token, userId, ts() + TOKEN_TTL).run();
  return token;
}

async function getUser(request, env) {
  const token = bearer(request);
  if (!token) return null;
  const row = await env.DB.prepare(
    "SELECT u.id, u.username, u.battletag, u.is_admin, u.banned FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ? AND s.expires_at > ?"
  ).bind(token, ts()).first();
  return row || null;
}
async function requireUser(request, env) {
  const u = await getUser(request, env);
  if (!u) fail(401, "로그인이 필요합니다");
  if (u.banned) fail(403, "이용이 제한된 계정입니다");
  return u;
}
const publicUser = (u) => ({ id: u.id, username: u.username, battletag: u.battletag || "", is_admin: !!u.is_admin });

/* ───────────────── listings ───────────────── */

async function listListings(url, env) {
  const q = url.searchParams;
  const where = [];
  const args = [];
  const status = q.get("status") || "active";
  if (status !== "all") { where.push("l.status = ?"); args.push(oneOf(status, ENUMS.status, "status")); }
  for (const f of ["type", "platform", "mode", "ladder", "version"]) {
    const v = q.get(f);
    if (v) { where.push(`l.${f} = ?`); args.push(oneOf(v, ENUMS[f], f)); }
  }
  const seller = q.get("seller");
  if (seller) { where.push("u.username = ?"); args.push(seller.slice(0, 20)); }
  const kw = (q.get("q") || "").trim().slice(0, 60);
  if (kw) {
    const like = "%" + kw.replaceAll("%", "").replaceAll("_", "") + "%";
    where.push("(l.item_ko LIKE ? OR l.item_en LIKE ? OR l.title LIKE ?)");
    args.push(like, like, like);
  }
  const page = Math.max(0, Math.min(200, Number(q.get("page") || 0) | 0));
  const per = 20;
  const sql =
    "SELECT l.*, u.username FROM listings l JOIN users u ON u.id = l.user_id" +
    (where.length ? " WHERE " + where.join(" AND ") : "") +
    " ORDER BY l.updated_at DESC LIMIT ? OFFSET ?";
  const { results } = await env.DB.prepare(sql).bind(...args, per + 1, page * per).all();
  const more = results.length > per;
  return json({ listings: results.slice(0, per).map(rowToListing), more, page });
}

async function createListing(request, env) {
  const user = await requireUser(request, env);
  await limiter(env, "cl:" + user.id, 30, 3600);
  const b = await readJson(request);
  const v = validateListing(b);
  const now = ts();
  const r = await env.DB.prepare(
    `INSERT INTO listings (user_id, type, item_en, item_ko, title, options_text, price_mode, price_json, price_text,
     platform, mode, ladder, version, contact, status, created_at, updated_at)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'active', ?, ?)`
  ).bind(user.id, v.type, v.item_en, v.item_ko, v.title, v.options_text, v.price_mode, v.price_json, v.price_text,
    v.platform, v.mode, v.ladder, v.version, v.contact, now, now).run();
  return json({ id: r.meta.last_row_id }, 201);
}

async function getListing(id, env) {
  const l = await env.DB.prepare(
    "SELECT l.*, u.username, u.battletag FROM listings l JOIN users u ON u.id = l.user_id WHERE l.id = ?"
  ).bind(id).first();
  if (!l) fail(404, "매물을 찾을 수 없습니다");
  const { results: comments } = await env.DB.prepare(
    "SELECT c.id, c.body, c.created_at, u.username FROM comments c JOIN users u ON u.id = c.user_id WHERE c.listing_id = ? ORDER BY c.id ASC LIMIT 200"
  ).bind(id).all();
  return json({ listing: rowToListing(l, true), comments });
}

async function patchListing(id, request, env) {
  const user = await requireUser(request, env);
  const cur = await env.DB.prepare("SELECT * FROM listings WHERE id = ?").bind(id).first();
  if (!cur) fail(404, "매물을 찾을 수 없습니다");
  if (cur.user_id !== user.id) fail(403, "본인 매물만 수정할 수 있습니다");
  const b = await readJson(request);

  if (typeof b.status === "string" && Object.keys(b).length === 1) {
    const status = oneOf(b.status, ENUMS.status, "status");
    await env.DB.prepare("UPDATE listings SET status = ?, updated_at = ? WHERE id = ?")
      .bind(status, ts(), id).run();
    return json({ ok: true });
  }
  const v = validateListing({ ...rowToListing(cur, true), ...b });
  await env.DB.prepare(
    `UPDATE listings SET type=?, item_en=?, item_ko=?, title=?, options_text=?, price_mode=?, price_json=?, price_text=?,
     platform=?, mode=?, ladder=?, version=?, contact=?, updated_at=? WHERE id=?`
  ).bind(v.type, v.item_en, v.item_ko, v.title, v.options_text, v.price_mode, v.price_json, v.price_text,
    v.platform, v.mode, v.ladder, v.version, v.contact, ts(), id).run();
  return json({ ok: true });
}

async function deleteListing(id, request, env) {
  const user = await requireUser(request, env);
  const cur = await env.DB.prepare("SELECT user_id FROM listings WHERE id = ?").bind(id).first();
  if (!cur) fail(404, "매물을 찾을 수 없습니다");
  if (cur.user_id !== user.id) fail(403, "본인 매물만 삭제할 수 있습니다");
  await env.DB.batch([
    env.DB.prepare("DELETE FROM comments WHERE listing_id = ?").bind(id),
    env.DB.prepare("DELETE FROM listings WHERE id = ?").bind(id),
  ]);
  return json({ ok: true });
}

function validateListing(b) {
  const type = oneOf(b.type, ENUMS.type, "구분(팝니다/삽니다)");
  const item_ko = str(b.item_ko).trim().slice(0, LIMITS.itemName);
  const item_en = str(b.item_en).trim().slice(0, LIMITS.itemName);
  if (!item_ko && !item_en) fail(400, "아이템을 선택하거나 입력해 주세요");
  const price_mode = oneOf(b.price_mode || "runes", ENUMS.price_mode, "가격 방식");
  let price_json = "[]";
  if (price_mode === "runes") {
    const rows = Array.isArray(b.price_runes) ? b.price_runes.slice(0, LIMITS.priceRows) : [];
    const clean = rows
      .map((r) => ({ rune: str(r && r.rune).trim().slice(0, 20), qty: Math.max(1, Math.min(999, Number(r && r.qty) | 0)) }))
      .filter((r) => r.rune);
    if (!clean.length) fail(400, "룬 가격을 1개 이상 입력하거나 다른 가격 방식을 선택해 주세요");
    price_json = JSON.stringify(clean);
  }
  return {
    type, item_en: item_en || item_ko, item_ko: item_ko || item_en,
    title: str(b.title).trim().slice(0, LIMITS.title),
    options_text: str(b.options_text).slice(0, LIMITS.options),
    price_mode, price_json,
    price_text: str(b.price_text).trim().slice(0, LIMITS.priceText),
    platform: oneOf(b.platform || "pc", ENUMS.platform, "플랫폼"),
    mode: oneOf(b.mode || "sc", ENUMS.mode, "모드"),
    ladder: oneOf(b.ladder || "non", ENUMS.ladder, "래더"),
    version: oneOf(b.version || "rotw", ENUMS.version, "버전"),
    contact: str(b.contact).trim().slice(0, LIMITS.contact),
  };
}

function rowToListing(r, full = false) {
  let price_runes = [];
  try { price_runes = JSON.parse(r.price_json || "[]"); } catch (_) {}
  const out = {
    id: r.id, type: r.type, item_en: r.item_en, item_ko: r.item_ko, title: r.title || "",
    price_mode: r.price_mode, price_runes, price_text: r.price_text || "",
    platform: r.platform, mode: r.mode, ladder: r.ladder, version: r.version,
    status: r.status, username: r.username, created_at: r.created_at, updated_at: r.updated_at,
    options_text: full ? (r.options_text || "") : (r.options_text || "").slice(0, 160),
  };
  if (full) { out.contact = r.contact || ""; out.battletag = r.battletag || ""; }
  return out;
}

/* ───────────────── comments ───────────────── */

async function addComment(listingId, request, env) {
  const user = await requireUser(request, env);
  await limiter(env, "cm:" + user.id, 60, 3600);
  const l = await env.DB.prepare("SELECT id FROM listings WHERE id = ?").bind(listingId).first();
  if (!l) fail(404, "매물을 찾을 수 없습니다");
  const b = await readJson(request);
  const body = str(b.body).trim().slice(0, LIMITS.comment);
  if (!body) fail(400, "댓글 내용을 입력해 주세요");
  const r = await env.DB.prepare(
    "INSERT INTO comments (listing_id, user_id, body, created_at) VALUES (?,?,?,?)"
  ).bind(listingId, user.id, body, ts()).run();
  await env.DB.prepare("UPDATE listings SET updated_at = ? WHERE id = ?").bind(ts(), listingId).run();
  return json({ id: r.meta.last_row_id }, 201);
}

async function deleteComment(id, request, env) {
  const user = await requireUser(request, env);
  const c = await env.DB.prepare("SELECT user_id FROM comments WHERE id = ?").bind(id).first();
  if (!c) fail(404, "댓글을 찾을 수 없습니다");
  if (c.user_id !== user.id) fail(403, "본인 댓글만 삭제할 수 있습니다");
  await env.DB.prepare("DELETE FROM comments WHERE id = ?").bind(id).run();
  return json({ ok: true });
}

/* ───────────────── 시세 (거래완료 통계) ───────────────── */

async function stats(url, env) {
  const item = (url.searchParams.get("item") || "").trim().slice(0, 60);
  if (!item) fail(400, "item 파라미터가 필요합니다");
  const { results } = await env.DB.prepare(
    `SELECT l.id, l.type, l.item_ko, l.item_en, l.price_mode, l.price_json, l.price_text,
            l.platform, l.mode, l.ladder, l.version, l.updated_at, u.username
     FROM listings l JOIN users u ON u.id = l.user_id
     WHERE l.status = 'done' AND (l.item_en = ? OR l.item_ko = ?)
     ORDER BY l.updated_at DESC LIMIT 30`
  ).bind(item, item).all();
  return json({ completed: results.map(rowToListing) });
}

/* ───────────────── 계정 복구 · 변경 ───────────────── */

async function recover(request, env) {
  await limiter(env, "rc:" + clientIp(request), 5, 3600);
  const b = await readJson(request);
  const username = str(b.username).trim();
  const code = normRecCode(b.code);
  const newPw = str(b.new_password);
  if (newPw.length < LIMITS.password[0] || newPw.length > LIMITS.password[1])
    fail(400, "새 비밀번호는 8자 이상이어야 합니다");
  const u = await env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(username).first();
  const bad = () => fail(401, "아이디 또는 복구 코드가 올바르지 않습니다");
  if (!u || !u.rec_hash) bad();
  const h = await pbkdf2(code, u.rec_salt);
  if (!timingSafeEq(h, u.rec_hash)) bad();
  if (u.banned) fail(403, "이용이 제한된 계정입니다");
  const salt = randHex(16);
  const hash = await pbkdf2(newPw, salt);
  const rec = makeRecCode();
  const recSalt = randHex(16);
  const recHash = await pbkdf2(rec.normalized, recSalt);
  await env.DB.batch([
    env.DB.prepare("UPDATE users SET pass_hash=?, salt=?, rec_hash=?, rec_salt=? WHERE id=?")
      .bind(hash, salt, recHash, recSalt, u.id),
    env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(u.id),
  ]);
  const token = await createSession(env, u.id);
  return json({
    token, user: publicUser(u), recovery_code: rec.display,
    notice: "비밀번호가 재설정되었고, 새 복구 코드가 발급되었습니다. 이전 코드는 무효화되었습니다.",
  });
}

async function changePassword(request, env) {
  const user = await requireUser(request, env);
  const b = await readJson(request);
  const newPw = str(b.new_password);
  if (newPw.length < LIMITS.password[0] || newPw.length > LIMITS.password[1])
    fail(400, "새 비밀번호는 8자 이상이어야 합니다");
  const u = await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(user.id).first();
  const h = await pbkdf2(str(b.old_password), u.salt);
  if (!timingSafeEq(h, u.pass_hash)) fail(401, "현재 비밀번호가 올바르지 않습니다");
  const salt = randHex(16);
  const hash = await pbkdf2(newPw, salt);
  await env.DB.batch([
    env.DB.prepare("UPDATE users SET pass_hash=?, salt=? WHERE id=?").bind(hash, salt, u.id),
    env.DB.prepare("DELETE FROM sessions WHERE user_id = ? AND token != ?").bind(u.id, bearer(request)),
  ]);
  return json({ ok: true });
}

async function rotateRecovery(request, env) {
  const user = await requireUser(request, env);
  const b = await readJson(request);
  const u = await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(user.id).first();
  const h = await pbkdf2(str(b.password), u.salt);
  if (!timingSafeEq(h, u.pass_hash)) fail(401, "비밀번호가 올바르지 않습니다");
  const rec = makeRecCode();
  const recSalt = randHex(16);
  const recHash = await pbkdf2(rec.normalized, recSalt);
  await env.DB.prepare("UPDATE users SET rec_hash=?, rec_salt=? WHERE id=?").bind(recHash, recSalt, u.id).run();
  return json({ recovery_code: rec.display });
}

/* ───────────────── 쪽지 ───────────────── */

async function msgSend(request, env) {
  const user = await requireUser(request, env);
  await limiter(env, "ms:" + user.id, 60, 3600);
  const b = await readJson(request);
  const toName = str(b.to).trim();
  const body = str(b.body).trim().slice(0, LIMITS.message);
  if (!body) fail(400, "내용을 입력해 주세요");
  const to = await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(toName).first();
  if (!to) fail(404, "받는 사람을 찾을 수 없습니다");
  if (to.id === user.id) fail(400, "자신에게는 쪽지를 보낼 수 없습니다");
  let listingId = Number(b.listing_id) | 0;
  if (listingId) {
    const l = await env.DB.prepare("SELECT id FROM listings WHERE id = ?").bind(listingId).first();
    if (!l) listingId = 0;
  }
  const r = await env.DB.prepare(
    "INSERT INTO messages (from_id, to_id, listing_id, body, created_at) VALUES (?,?,?,?,?)"
  ).bind(user.id, to.id, listingId || null, body, ts()).run();
  return json({ id: r.meta.last_row_id }, 201);
}

async function msgThreads(request, env) {
  const user = await requireUser(request, env);
  const { results: lastMsgs } = await env.DB.prepare(
    `SELECT m.*, CASE WHEN m.from_id = ?1 THEN m.to_id ELSE m.from_id END AS other_id
     FROM messages m WHERE m.id IN (
       SELECT MAX(id) FROM messages WHERE from_id = ?1 OR to_id = ?1
       GROUP BY CASE WHEN from_id = ?1 THEN to_id ELSE from_id END
     ) ORDER BY m.id DESC LIMIT 50`
  ).bind(user.id).all();
  const { results: unreads } = await env.DB.prepare(
    "SELECT from_id AS other_id, COUNT(*) AS n FROM messages WHERE to_id = ? AND read_at IS NULL GROUP BY from_id"
  ).bind(user.id).all();
  const unreadMap = new Map(unreads.map((r) => [r.other_id, r.n]));
  const ids = [...new Set(lastMsgs.map((m) => m.other_id))];
  let names = new Map();
  if (ids.length) {
    const qs = ids.map(() => "?").join(",");
    const { results } = await env.DB.prepare(`SELECT id, username FROM users WHERE id IN (${qs})`).bind(...ids).all();
    names = new Map(results.map((r) => [r.id, r.username]));
  }
  return json({
    threads: lastMsgs.map((m) => ({
      username: names.get(m.other_id) || "?",
      last_body: m.body.slice(0, 80),
      last_at: m.created_at,
      mine: m.from_id === user.id,
      unread: unreadMap.get(m.other_id) || 0,
    })),
  });
}

async function msgWith(otherName, request, env) {
  const user = await requireUser(request, env);
  const other = await env.DB.prepare("SELECT id, username, battletag FROM users WHERE username = ?")
    .bind(otherName).first();
  if (!other) fail(404, "사용자를 찾을 수 없습니다");
  const { results } = await env.DB.prepare(
    `SELECT id, from_id, listing_id, body, created_at FROM messages
     WHERE (from_id = ?1 AND to_id = ?2) OR (from_id = ?2 AND to_id = ?1)
     ORDER BY id DESC LIMIT 100`
  ).bind(user.id, other.id).all();
  await env.DB.prepare("UPDATE messages SET read_at = ? WHERE to_id = ? AND from_id = ? AND read_at IS NULL")
    .bind(ts(), user.id, other.id).run();
  return json({
    with: { username: other.username, battletag: other.battletag || "" },
    messages: results.reverse().map((m) => ({
      id: m.id, mine: m.from_id === user.id, body: m.body, listing_id: m.listing_id, created_at: m.created_at,
    })),
  });
}

/* ───────────────── 신고 · 관리 ───────────────── */

async function createReport(request, env) {
  const user = await requireUser(request, env);
  await limiter(env, "rp:" + user.id, 10, 86400);
  const b = await readJson(request);
  const type = oneOf(b.target_type, ["listing", "comment", "user"], "신고 대상");
  let targetId = Number(b.target_id) | 0;
  if (type === "user" && !targetId) {
    const tu = await env.DB.prepare("SELECT id FROM users WHERE username = ?")
      .bind(str(b.target_username).trim()).first();
    if (!tu) fail(404, "신고할 사용자를 찾을 수 없습니다");
    targetId = tu.id;
  }
  const reason = str(b.reason).trim().slice(0, LIMITS.reason);
  if (!targetId || !reason) fail(400, "신고 대상과 사유를 입력해 주세요");
  const r = await env.DB.prepare(
    "INSERT INTO reports (reporter_id, target_type, target_id, reason, created_at) VALUES (?,?,?,?,?)"
  ).bind(user.id, type, targetId, reason, ts()).run();
  return json({ id: r.meta.last_row_id }, 201);
}

async function requireAdmin(request, env) {
  const user = await requireUser(request, env);
  if (!user.is_admin) fail(403, "관리자만 접근할 수 있습니다");
  return user;
}

async function adminReports(request, env) {
  await requireAdmin(request, env);
  const { results } = await env.DB.prepare(
    `SELECT r.*, u.username AS reporter FROM reports r JOIN users u ON u.id = r.reporter_id
     WHERE r.status = 'open' ORDER BY r.id DESC LIMIT 50`
  ).all();
  const pick = (t) => results.filter((r) => r.target_type === t).map((r) => r.target_id);
  const maps = { listing: new Map(), comment: new Map(), user: new Map() };
  const inQ = (n) => Array(n).fill("?").join(",");
  const lids = pick("listing");
  if (lids.length) {
    const { results: ls } = await env.DB.prepare(
      `SELECT l.id, l.item_ko, l.status, u.username FROM listings l JOIN users u ON u.id=l.user_id WHERE l.id IN (${inQ(lids.length)})`
    ).bind(...lids).all();
    for (const l of ls) maps.listing.set(l.id, { label: `[매물 #${l.id}] ${l.item_ko} · ${l.username} · ${l.status}`, owner: l.username, listing_id: l.id });
  }
  const cids = pick("comment");
  if (cids.length) {
    const { results: cs } = await env.DB.prepare(
      `SELECT c.id, c.body, c.listing_id, u.username FROM comments c JOIN users u ON u.id=c.user_id WHERE c.id IN (${inQ(cids.length)})`
    ).bind(...cids).all();
    for (const c of cs) maps.comment.set(c.id, { label: `[댓글 · 매물 #${c.listing_id}] ${c.username}: ${c.body.slice(0, 60)}`, owner: c.username, listing_id: c.listing_id });
  }
  const uids = pick("user");
  if (uids.length) {
    const { results: us } = await env.DB.prepare(
      `SELECT id, username, banned FROM users WHERE id IN (${inQ(uids.length)})`
    ).bind(...uids).all();
    for (const u2 of us) maps.user.set(u2.id, { label: `[사용자] ${u2.username}${u2.banned ? " (정지됨)" : ""}`, owner: u2.username });
  }
  return json({
    reports: results.map((r) => {
      const t = maps[r.target_type].get(r.target_id) || { label: "(대상이 삭제됨)", owner: null };
      return {
        id: r.id, target_type: r.target_type, target_id: r.target_id,
        reason: r.reason, reporter: r.reporter, created_at: r.created_at,
        summary: t.label, owner: t.owner, listing_id: t.listing_id || null,
      };
    }),
  });
}

async function adminCloseReport(id, request, env) {
  await requireAdmin(request, env);
  await env.DB.prepare("UPDATE reports SET status='closed' WHERE id = ?").bind(id).run();
  return json({ ok: true });
}
async function adminSetListing(id, request, env) {
  await requireAdmin(request, env);
  const b = await readJson(request);
  const status = oneOf(b.status, ENUMS.status, "status");
  await env.DB.prepare("UPDATE listings SET status=?, updated_at=? WHERE id=?").bind(status, ts(), id).run();
  return json({ ok: true });
}
async function adminDelComment(id, request, env) {
  await requireAdmin(request, env);
  await env.DB.prepare("DELETE FROM comments WHERE id = ?").bind(id).run();
  return json({ ok: true });
}
async function adminBanUser(username, request, env) {
  await requireAdmin(request, env);
  const b = await readJson(request);
  const banned = b.banned ? 1 : 0;
  const u = await env.DB.prepare("SELECT id, is_admin FROM users WHERE username = ?").bind(username).first();
  if (!u) fail(404, "사용자를 찾을 수 없습니다");
  if (u.is_admin) fail(400, "관리자 계정은 정지할 수 없습니다");
  await env.DB.batch([
    env.DB.prepare("UPDATE users SET banned=? WHERE id=?").bind(banned, u.id),
    env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(u.id),
  ]);
  return json({ ok: true, banned: !!banned });
}

/* ───────────────── helpers ───────────────── */

function makeRecCode() {
  const hexStr = randHex(10);
  return { display: hexStr.toUpperCase().match(/.{4}/g).join("-"), normalized: hexStr };
}
const normRecCode = (s) => str(s).toLowerCase().replace(/[^0-9a-f]/g, "");

async function limiter(env, key, max, windowSec) {
  try {
    const now = ts();
    const row = await env.DB.prepare("SELECT n, reset_at FROM rate_limits WHERE key = ?").bind(key).first();
    if (!row || row.reset_at <= now) {
      await env.DB.prepare(
        "INSERT INTO rate_limits (key, n, reset_at) VALUES (?, 1, ?) ON CONFLICT(key) DO UPDATE SET n = 1, reset_at = excluded.reset_at"
      ).bind(key, now + windowSec).run();
      return;
    }
    if (row.n >= max) fail(429, "요청이 너무 잦습니다. 잠시 후 다시 시도해 주세요");
    await env.DB.prepare("UPDATE rate_limits SET n = n + 1 WHERE key = ?").bind(key).run();
  } catch (e) {
    if (e instanceof ApiError) throw e; // 한도 초과는 그대로 반환, 그 외 오류는 무시(fail-open)
  }
}

async function readJson(request) {
  const text = await request.text();
  if (text.length > 20000) fail(413, "요청이 너무 큽니다");
  try { return JSON.parse(text || "{}"); } catch (_) { fail(400, "JSON 형식이 아닙니다"); }
}

function oneOf(v, list, label) {
  if (!list.includes(v)) fail(400, `${label} 값이 올바르지 않습니다`);
  return v;
}
const str = (v) => (typeof v === "string" ? v : "");
const ts = () => Math.floor(Date.now() / 1000);
const clientIp = (req) => req.headers.get("cf-connecting-ip") || "0.0.0.0";
const bearer = (req) => {
  const h = req.headers.get("authorization") || "";
  return h.startsWith("Bearer ") ? h.slice(7).trim() : "";
};

function randHex(bytes) {
  const a = new Uint8Array(bytes);
  crypto.getRandomValues(a);
  return [...a].map((x) => x.toString(16).padStart(2, "0")).join("");
}
async function pbkdf2(password, saltHex) {
  const enc = new TextEncoder();
  const salt = new Uint8Array(saltHex.match(/../g).map((h) => parseInt(h, 16)));
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITER, hash: "SHA-256" }, key, 256
  );
  return [...new Uint8Array(bits)].map((x) => x.toString(16).padStart(2, "0")).join("");
}
function timingSafeEq(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status, headers: { "content-type": "application/json; charset=utf-8" },
  });
}
function withCors(res) {
  const out = new Response(res.body, res);
  for (const [k, v] of Object.entries(CORS)) out.headers.set(k, v);
  return out;
}
