import { json, cookie, randomId, hashPassword } from '../../_lib/auth.js';

async function digest(value) {
  const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2, '0')).join('');
}
function equalHex(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export async function onRequestPost({ request, env }) {
  try {
    const body = await request.json();
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '');
    if (!email || !password || email.length > 254 || password.length > 1024) {
      return json({ error: 'Email or password is incorrect' }, 401);
    }

    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    const rateKey = await digest(email + ':' + ip);
    const now = Math.floor(Date.now() / 1000);
    const attempt = await env.DB.prepare('SELECT attempts,window_started_at,blocked_until FROM dp_login_attempts WHERE id=?').bind(rateKey).first();
    if (attempt?.blocked_until > now) {
      return json({ error: 'Too many sign-in attempts. Try again in a few minutes.' }, 429, { 'Retry-After': String(attempt.blocked_until - now) });
    }

    const user = await env.DB.prepare('SELECT id,email,password_hash,role,status FROM dp_users WHERE email=?').bind(email).first();
    let valid = false;
    if (user) {
      const [salt, expected] = user.password_hash.split(':');
      const actual = await hashPassword(password, salt);
      valid = equalHex(actual, expected) && user.status === 'active';
    }

    if (!valid) {
      const withinWindow = attempt && now - attempt.window_started_at < 900;
      const count = withinWindow ? attempt.attempts + 1 : 1;
      const windowStart = withinWindow ? attempt.window_started_at : now;
      const blockedUntil = count >= 8 ? now + 900 : 0;
      await env.DB.prepare(`INSERT INTO dp_login_attempts (id,attempts,window_started_at,blocked_until)
        VALUES (?,?,?,?) ON CONFLICT(id) DO UPDATE SET attempts=excluded.attempts,
        window_started_at=excluded.window_started_at,blocked_until=excluded.blocked_until`)
        .bind(rateKey, count, windowStart, blockedUntil).run();
      return json({ error: 'Email or password is incorrect' }, 401);
    }

    await env.DB.prepare('DELETE FROM dp_login_attempts WHERE id=?').bind(rateKey).run();
    await env.DB.prepare("UPDATE dp_users SET last_login_at=datetime('now') WHERE id=?").bind(user.id).run();
    const token = randomId();
    await env.DB.prepare("INSERT INTO dp_sessions (id,user_id,expires_at) VALUES (?,?,datetime('now','+7 days'))").bind(token,user.id).run();
    return json({ ok:true,user:{id:user.id,email:user.email,role:user.role} },200,{ 'Set-Cookie':cookie('dp_session',token,604800) });
  } catch {
    return json({ error: 'Login failed' }, 500);
  }
}
