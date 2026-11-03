import { json, cookie, randomId, hashPassword } from '../../../_lib/auth.js';
export async function onRequestPost({ request, env }) {
  try {
    if (!env.DB || !env.ADMIN_SETUP_KEY) return json({ error: 'Setup is not configured' }, 503);
    const body = await request.json();
    if (body.setupKey !== env.ADMIN_SETUP_KEY) return json({ error: 'Invalid setup key' }, 403);
    const count = await env.DB.prepare('SELECT COUNT(*) AS total FROM dp_users').first();
    if (count.total > 0) return json({ error: 'Admin account has already been created' }, 409);
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '');
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ error: 'Enter a valid email address' }, 400);
    if (password.length < 12) return json({ error: 'Password must be at least 12 characters' }, 400);
    const id = randomId(16), salt = randomId(16), hash = await hashPassword(password, salt);
    await env.DB.prepare('INSERT INTO dp_users (id,email,password_hash,role) VALUES (?,?,?,?)').bind(id,email,salt+':'+hash,'admin').run();
    const token = randomId();
    await env.DB.prepare("INSERT INTO dp_sessions (id,user_id,expires_at) VALUES (?,?,datetime('now','+7 days'))").bind(token,id).run();
    return json({ ok: true, user: { id,email,role:'admin' } }, 201, { 'Set-Cookie': cookie('dp_session',token,604800) });
  } catch { return json({ error: 'Could not create admin account' }, 500); }
}
