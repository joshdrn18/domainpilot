import { json, getUser } from '../_lib/auth.js';
import { inspectCertificate } from '../_lib/ssl.js';

async function canMonitor(user, env) {
  if (user.role === 'admin') return true;
  const plan = await env.DB.prepare("SELECT p.monitoring_enabled FROM dp_user_plans up JOIN dp_plans p ON p.id=up.plan_id WHERE up.user_id=? AND p.active=1 AND (up.expires_at IS NULL OR up.expires_at>=date('now'))").bind(user.id).first();
  return !!plan?.monitoring_enabled;
}

export async function onRequestGet({ request, env }) {
  try {
    const user = await getUser(request, env);
    if (!user) return json({ error: 'Unauthorized' }, 401);
    if (!await canMonitor(user, env)) return json({ error: 'SSL monitoring is not included in your current plan' }, 403);
    const result = await env.DB.prepare(`
      SELECT d.id,d.domain,s.status,s.issuer,s.not_after,s.days_remaining,s.source,s.details,s.checked_at
      FROM dp_domains d
      LEFT JOIN dp_ssl_checks s ON s.id=(
        SELECT x.id FROM dp_ssl_checks x WHERE x.domain_id=d.id ORDER BY x.checked_at DESC,x.id DESC LIMIT 1
      )
      WHERE (?='admin' OR d.owner_id=?)
      ORDER BY d.domain
    `).bind(user.role,user.id).all();
    return json({ certificates: result.results || [] });
  } catch {
    return json({ error: 'Could not load certificate inventory' }, 500);
  }
}

export async function onRequestPost({ request, env }) {
  try {
    const user = await getUser(request, env);
    if (!user) return json({ error: 'Unauthorized' }, 401);
    if (!await canMonitor(user, env)) return json({ error: 'SSL monitoring is not included in your current plan' }, 403);
    const body = await request.json().catch(() => ({}));
    const limit = Math.min(5, Math.max(1, Number(body.limit) || 5));
    const params = [user.role,user.id];
    let where = "(?='admin' OR d.owner_id=?)";
    if (body.domainId) {
      where += " AND d.id=?";
      params.push(String(body.domainId));
    } else if (body.cursor) {
      where += " AND d.id>?";
      params.push(String(body.cursor));
    }
    const domains = await env.DB.prepare(`SELECT d.id,d.domain FROM dp_domains d WHERE ${where} ORDER BY d.id LIMIT ?`).bind(...params,limit + 1).all();
    const rows = domains.results || [];
    const batch = rows.slice(0,limit);
    if (!batch.length) return json({ ok: true, checks: [], next_cursor: null, done: true });
    const checks = [];
    for (const domain of batch) {
      const result = await inspectCertificate(domain.domain);
      await env.DB.prepare('INSERT INTO dp_ssl_checks (domain_id,status,issuer,not_after,days_remaining,source,details) VALUES (?,?,?,?,?,?,?)')
        .bind(domain.id,result.status,result.issuer,result.not_after,result.days_remaining,result.source,result.details).run();
      checks.push({ id: domain.id, domain: domain.domain, ...result, checked_at: new Date().toISOString() });
    }
    await env.DB.prepare('INSERT INTO dp_activity (action,details,actor) VALUES (?,?,?)')
      .bind('ssl.scan',checks.length+' certificate transparency lookups completed',user.email).run();
    const nextCursor = rows.length > limit ? batch[batch.length - 1].id : null;
    return json({ ok: true, checks, next_cursor: nextCursor, done: !nextCursor });
  } catch {
    return json({ error: 'Could not inspect SSL certificates' }, 500);
  }
}
