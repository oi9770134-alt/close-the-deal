// Close the Deal accounts: one email and password works on any phone, and the saved game follows the player.
// Cloudflare Pages Function. Needs a D1 binding named DB (tables ctd_accounts and ctd_tokens).
// Passwords are never stored: only a salted PBKDF2 hash. Sign-in tokens are stored hashed too.
const J = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('');
const rand = (n) => hex(crypto.getRandomValues(new Uint8Array(n)));
const enc = (s) => new TextEncoder().encode(s);
async function pbkdf2(pw, salt) {
  const key = await crypto.subtle.importKey('raw', enc(pw), 'PBKDF2', false, ['deriveBits']);
  return hex(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: enc(salt), iterations: 100000 }, key, 256));
}
const sha = async (s) => hex(await crypto.subtle.digest('SHA-256', enc(s)));
const same = (a, b) => { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i); return d === 0; };
const EMAIL = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const MAX = 1500000;

async function issue(env, email) {
  const token = rand(32), now = Date.now();
  await env.DB.prepare('INSERT INTO ctd_tokens (token_hash, email, created_at) VALUES (?,?,?)').bind(await sha(token), email, now).run();
  await env.DB.prepare('DELETE FROM ctd_tokens WHERE email = ? AND token_hash NOT IN (SELECT token_hash FROM ctd_tokens WHERE email = ? ORDER BY created_at DESC LIMIT 10)').bind(email, email).run();
  return token;
}
async function who(env, token) {
  if (!token || typeof token !== 'string') return null;
  const r = await env.DB.prepare('SELECT email FROM ctd_tokens WHERE token_hash = ?').bind(await sha(token)).first();
  return r ? r.email : null;
}

export async function onRequestPost({ request, env }) {
  if (!env.DB) return J({ error: 'not_configured', message: 'Accounts are not switched on yet.' }, 503);
  let b; try { b = await request.json(); } catch { return J({ error: 'bad_request', message: 'Bad request.' }, 400); }
  const op = b.op, email = String(b.email || '').trim().toLowerCase();
  try {
    if (op === 'signup') {
      const name = String(b.name || '').trim().slice(0, 40), pw = String(b.password || '');
      if (!name) return J({ error: 'bad_name', message: 'Please enter your name.' }, 400);
      if (!EMAIL.test(email)) return J({ error: 'bad_email', message: 'Please enter a valid email address.' }, 400);
      if (pw.length < 8 || pw.length > 200) return J({ error: 'weak_password', message: 'Your password needs at least 8 characters.' }, 400);
      if (await env.DB.prepare('SELECT 1 FROM ctd_accounts WHERE email = ?').bind(email).first()) return J({ error: 'exists', message: 'An account with this email already exists. Sign in instead.' }, 409);
      const salt = rand(16), now = Date.now(), data = b.snapshot ? JSON.stringify(b.snapshot) : null;
      if (data && data.length > MAX) return J({ error: 'too_big', message: 'Save is too large.' }, 413);
      await env.DB.prepare('INSERT INTO ctd_accounts (email, name, salt, hash, data, created_at, updated_at) VALUES (?,?,?,?,?,?,?)').bind(email, name, salt, await pbkdf2(pw, salt), data, now, now).run();
      return J({ ok: true, token: await issue(env, email), name });
    }
    if (op === 'login') {
      const a = await env.DB.prepare('SELECT name, salt, hash, data FROM ctd_accounts WHERE email = ?').bind(email).first();
      const h = await pbkdf2(String(b.password || ''), a ? a.salt : 'x'.repeat(32));
      if (!a || !same(h, a.hash)) return J({ error: 'bad_login', message: 'That email and password do not match an account.' }, 401);
      return J({ ok: true, token: await issue(env, email), name: a.name, snapshot: a.data ? JSON.parse(a.data) : null });
    }
    if (op === 'push') {
      const e = await who(env, b.token); if (!e) return J({ error: 'signin_required', message: 'Please sign in again.' }, 401);
      const data = JSON.stringify(b.snapshot || null); if (data.length > MAX) return J({ error: 'too_big', message: 'Save is too large.' }, 413);
      await env.DB.prepare('UPDATE ctd_accounts SET data = ?, updated_at = ? WHERE email = ?').bind(data, Date.now(), e).run();
      return J({ ok: true });
    }
    if (op === 'pull') {
      const e = await who(env, b.token); if (!e) return J({ error: 'signin_required', message: 'Please sign in again.' }, 401);
      const a = await env.DB.prepare('SELECT name, data FROM ctd_accounts WHERE email = ?').bind(e).first();
      return J({ ok: true, name: a?.name, snapshot: a?.data ? JSON.parse(a.data) : null });
    }
    return J({ error: 'bad_request', message: 'Bad request.' }, 400);
  } catch (e) { return J({ error: 'server', message: 'Something went wrong. Please try again.' }, 500); }
}
export const onRequest = () => J({ error: 'method', message: 'Use POST.' }, 405);
