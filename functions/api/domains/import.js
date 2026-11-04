import { json, getUser, randomId } from '../../_lib/auth.js';

function normalizeDomain(value) {
  let input = String(value || '').trim().toLowerCase();
  if (!input) return '';
  return input.replace(/^https?:\\/\\//, '').split(/[/?#]/)[0].replace(/\\.$/, '');
}
function validDate(value) {
  if (!value) return true;
  if (!/^\\d{4}-\\d{2}-\\d{2}$/.test(value)) return false;
  const d = new Date(value + 'T00:00:00Z');
  return Number.isFinite(d.getTime()) && d.toISOString().slice(0, 10) === value;
}
export async function onRequestPost({ request, env }) {
  try {
    const user = await getUser(request, env);
    if (!user) return json({ error: 'Unauthorized' }, 401);
    const body = await request.json();
    if (!Array.isArray(body.domains) || !body.domains.length) return json({ error: 'Provide at least one CSV row' }, 400);
    if (body.domains.length > 100) return json({ error: 'A maximum of 100 rows can be imported at once' }, 400);
    const current = await env.DB.prepare('SELECT domain FROM dp_domains WHERE owner_id=?').bind(user.id).all();
    const seen = new Set((current.results || []).map(x => x.domain.toLowerCase()));
    let limit = Infinity;
    if (user.role !== 'admin') {
      const plan = await env.DB.prepare("SELECT p.domain_limit FROM dp_user_plans up JOIN dp_plans p ON p.id=up.plan_id WHERE up.user_id=? AND p.active=1 AND (up.expires_at IS NULL OR up.expires_at>=date('now'))").bind(user.id).first();
      limit = plan?.domain_limit ?? 5;
    }
    const count = current.results?.length || 0;
    const accepted = [], errors = [];
    for (let i = 0; i < body.domains.length; i++) {
      const row = body.domains[i] || {}; const line = i + 2;
      const domain = normalizeDomain(row.domain || row.hostname || row.url);
      const registrar = String(row.registrar || 'Unknown').trim().slice(0, 80) || 'Unknown';
      const expiry = String(row.expiry_date || row.expires || '').trim();
      const notes = String(row.notes || '').slice(0, 1000);
      if (!/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}$/.test(domain)) { errors.push({ row: line, domain, error: 'Invalid domain' }); continue; }
      if (!validDate(expiry)) { errors.push({ row: line, domain, error: 'Invalid expiry_date; use YYYY-MM-DD' }); continue; }
      if (seen.has(domain)) { errors.push({ row: line, domain, error: 'Duplicate domain' }); continue; }
      if (count + accepted.length >= limit) { errors.push({ row: line, domain, error: 'Plan domain limit reached' }); continue; }
      seen.add(domain); accepted.push({ id: randomId(16), domain, registrar, expiry: expiry || null, notes });
    }
    if (accepted.length) {
      const statements = [];
      for (const item of accepted) {
        statements.push(env.DB.prepare('INSERT INTO dp_domains (id,domain,registrar,expiry_date,status,notes,owner_id) VALUES (?,?,?,?,?,?,?)').bind(item.id, item.domain, item.registrar, item.expiry, 'active', item.notes, user.id));
        statements.push(env.DB.prepare('INSERT INTO dp_activity (domain_id,action,details,actor) VALUES (?,?,?,?)').bind(item.id, 'domain.created', 'Imported via CSV: ' + item.domain, user.email));
      }
      await env.DB.batch(statements);
    }
    return json({ ok: true, imported: accepted.length, errors, limit_reached: errors.some(x => x.error === 'Plan domain limit reached') });
  } catch { return json({ error: 'Could not import CSV rows' }, 500); }
 }