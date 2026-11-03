import { json, getUser } from '../../_lib/auth.js';

export async function onRequestGet({ request, env }) {
  try {
    if (!await getUser(request, env)) return json({ error: 'Unauthorized' }, 401);
    const result = await env.DB.prepare(`
      SELECT d.id,d.domain,
        (SELECT c.status FROM dp_checks c WHERE c.domain_id=d.id AND c.check_type='https' ORDER BY c.checked_at DESC LIMIT 1) AS status,
        (SELECT c.response_ms FROM dp_checks c WHERE c.domain_id=d.id AND c.check_type='https' ORDER BY c.checked_at DESC LIMIT 1) AS response_ms,
        (SELECT c.checked_at FROM dp_checks c WHERE c.domain_id=d.id AND c.check_type='https' ORDER BY c.checked_at DESC LIMIT 1) AS checked_at,
        (SELECT c.details FROM dp_checks c WHERE c.domain_id=d.id AND c.check_type='https' ORDER BY c.checked_at DESC LIMIT 1) AS details
      FROM dp_domains d ORDER BY d.domain
    `).all();
    return json({ checks: result.results || [] });
  } catch {
    return json({ error: 'Could not load monitoring data' }, 500);
  }
}

export async function onRequestPost({ request, env }) {
  try {
    const user = await getUser(request, env);
    if (!user) return json({ error: 'Unauthorized' }, 401);
    const body = await request.json().catch(() => ({}));
    let domains;
    if (body.domainId) {
      const row = await env.DB.prepare('SELECT id,domain FROM dp_domains WHERE id=?').bind(String(body.domainId)).first();
      if (!row) return json({ error: 'Domain not found' }, 404);
      domains = [row];
    } else {
      const result = await env.DB.prepare('SELECT id,domain FROM dp_domains ORDER BY domain LIMIT 50').all();
      domains = result.results || [];
    }
    if (!domains.length) return json({ error: 'Add a domain before running checks' }, 400);
    const checks = await Promise.all(domains.map(async (domain) => {
      const started = Date.now();
      let status = 'down', details = 'HTTPS request failed', responseMs = null;
      try {
        const response = await fetch('https://' + domain.domain, {
          method: 'HEAD',
          redirect: 'manual',
          signal: AbortSignal.timeout(8000),
          headers: { 'User-Agent': 'DomainPilot-Monitor/1.0' }
        });
        responseMs = Date.now() - started;
        status = response.status < 500 ? 'up' : 'down';
        details = 'HTTPS responded with HTTP ' + response.status;
      } catch (error) {
        responseMs = Date.now() - started;
        details = String(error?.message || 'HTTPS connection failed').slice(0, 240);
      }
      await env.DB.prepare('INSERT INTO dp_checks (domain_id,check_type,status,response_ms,details) VALUES (?,?,?,?,?)')
        .bind(domain.id, 'https', status, responseMs, details).run();
      return { id: domain.id, domain: domain.domain, status, response_ms: responseMs, checked_at: new Date().toISOString(), details };
    }));
    await env.DB.prepare('INSERT INTO dp_activity (action,details,actor) VALUES (?,?,?)')
      .bind('monitoring.run', checks.length + ' HTTPS checks completed', user.email).run();
    return json({ ok: true, checks });
  } catch {
    return json({ error: 'Could not complete monitoring checks' }, 500);
  }
}
