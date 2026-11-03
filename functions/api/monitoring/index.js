import { json, getUser } from '../../_lib/auth.js';

export async function onRequestGet({ request, env }) {
  try {
    const user = await getUser(request, env); if (!user) return json({ error: 'Unauthorized' }, 401);
    if(user.role!=='admin'){const plan=await env.DB.prepare('SELECT p.monitoring_enabled FROM dp_user_plans up JOIN dp_plans p ON p.id=up.plan_id WHERE up.user_id=? AND p.active=1').bind(user.id).first();if(!plan?.monitoring_enabled)return json({error:'Monitoring is not included in your current plan'},403);}
    const result = await env.DB.prepare(`
      SELECT d.id,d.domain,
        (SELECT c.status FROM dp_checks c WHERE c.domain_id=d.id AND c.check_type='https' ORDER BY c.checked_at DESC LIMIT 1) AS status,
        (SELECT c.response_ms FROM dp_checks c WHERE c.domain_id=d.id AND c.check_type='https' ORDER BY c.checked_at DESC LIMIT 1) AS response_ms,
        (SELECT c.checked_at FROM dp_checks c WHERE c.domain_id=d.id AND c.check_type='https' ORDER BY c.checked_at DESC LIMIT 1) AS checked_at,
        (SELECT c.details FROM dp_checks c WHERE c.domain_id=d.id AND c.check_type='https' ORDER BY c.checked_at DESC LIMIT 1) AS details
      FROM dp_domains d WHERE (?='admin' OR d.owner_id=?) ORDER BY d.domain
    `).bind(user.role,user.id).all();
    return json({ checks: result.results || [] });
  } catch {
    return json({ error: 'Could not load monitoring data' }, 500);
  }
}

export async function onRequestPost({ request, env }) {
  try {
    const user = await getUser(request, env);
    if (!user) return json({ error: 'Unauthorized' }, 401);
    if(user.role!=='admin'){const plan=await env.DB.prepare('SELECT p.monitoring_enabled FROM dp_user_plans up JOIN dp_plans p ON p.id=up.plan_id WHERE up.user_id=? AND p.active=1').bind(user.id).first();if(!plan?.monitoring_enabled)return json({error:'Monitoring is not included in your current plan'},403);}
    const body = await request.json().catch(() => ({}));
    let domains;
    if (body.domainId) {
      const row = await env.DB.prepare("SELECT id,domain FROM dp_domains WHERE id=? AND (?='admin' OR owner_id=?)").bind(String(body.domainId),user.role,user.id).first();
      if (!row) return json({ error: 'Domain not found' }, 404);
      domains = [row];
    } else {
      const result = await env.DB.prepare("SELECT id,domain FROM dp_domains WHERE (?='admin' OR owner_id=?) ORDER BY domain LIMIT 20") .bind(user.role,user.id).all();
      domains = result.results || [];
    }
    if (!domains.length) return json({ error: 'Add a domain before running checks' }, 400);
    const checks = await Promise.all(domains.map(async (domain) => {
      const started = Date.now();
      let status = 'down', details = 'HTTPS request failed', responseMs = null;
      try {
        if (/\.(localhost|local|internal|test|invalid|example)$/i.test(domain.domain)) throw new Error('Reserved hostname cannot be checked');
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
