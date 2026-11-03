const enc = new TextEncoder();
export function json(data, status = 200, headers = {}) {
  return Response.json(data, { status, headers: { 'Cache-Control': 'no-store', ...headers } });
}
export function cookie(name, value, maxAge) {
  return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}
export function randomId(bytes = 32) {
  const data = new Uint8Array(bytes); crypto.getRandomValues(data);
  return Array.from(data, b => b.toString(16).padStart(2, '0')).join('');
}
export async function hashPassword(password, salt) {
  const material = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: enc.encode(salt), iterations: 100000, hash: 'SHA-256' }, material, 256);
  return Array.from(new Uint8Array(bits), b => b.toString(16).padStart(2, '0')).join('');
}
export async function getUser(request, env) {
  const token = request.headers.get('Cookie')?.match(/(?:^|; )dp_session=([a-f0-9]{64})/)?.[1];
  if (!token) return null;
  const row = await env.DB.prepare("SELECT u.id,u.email,u.role FROM dp_sessions s JOIN dp_users u ON u.id=s.user_id WHERE s.id=? AND s.expires_at > datetime('now')").bind(token).first();
  return row || null;
}
