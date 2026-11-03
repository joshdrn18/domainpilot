import { json, cookie, randomId, hashPassword } from '../../../_lib/auth.js';
export async function onRequestPost({ request, env }) {
  try {
    const body = await request.json(), email = String(body.email || '').trim().toLowerCase(), password = String(body.password || '');
    const user = await env.DB.prepare('SELECT id,email,password_hash,role FROM dp_users WHERE email=?').bind(email).first();
    if (!user) return json({ error: 'Email or password is incorrect' }, 401);
    const [salt, expected] = user.password_hash.split(':');
    const actual = await hashPassword(password, salt);
    if (actual.length !== expected.length || !crypto.subtle.timingSafeEqual) {
      if (actual !== expected) return json({ error: 'Email or password is incorrect' }, 401);
    } else {
      const a = new TextEncoder().encode(actual), b = new TextEncoder().encode(expected);
      if (a.some((v,i)=>v!==b[i])) return json({ error: 'Email or password is incorrect' }, 401);
    }
    const token = randomId();
    await env.DB.prepare("INSERT INTO dp_sessions (id,user_id,expires_at) VALUES (?,?,datetime('now','+7 days'))").bind(token,user.id).run();
    return json({ ok:true,user:{id:user.id,email:user.email,role:user.role} },200,{ 'Set-Cookie':cookie('dp_session',token,604800) });
  } catch { return json({ error: 'Login failed' }, 500); }
}
