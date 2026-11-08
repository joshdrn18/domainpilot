import { json, getUser } from '../../_lib/auth.js';

function alertTitle(type) {
  if (type === 'https_down') return 'Domain is unreachable';
  if (type === 'https_recovered') return 'Domain recovered';
  return 'Monitoring notice';
}

async function queueTransitionAlert(env, domain, previousStatus, status, details) {
  if (status === previousStatus) return false;
  let alertType = null;
  if (status === 'down' && previousStatus !== 'down') alertType = 'https_down';
  if (status === 'up' && previousStatus === 'down') alertType = 'https_recovered';
  if (!alertType) return false;

  const hour = new Date().toISOString().slice(0, 13);
  const message = alertType === 'https_down'
    ? '🔴 DomainPilot: ' + domain.domain + ' is unreachable. ' + details
    : '🟢 DomainPilot: ' + domain.domain + ' has recovered. ' + details;
  const result = await env.DB.prepare(
    "INSERT OR IGNORE INTO dp_notifications (owner_id,domain_id,alert_key,alert_type,title,message,email_status) VALUES (?,?,?,?,?,?, 'pending')"
  ).bind(domain.owner_id, domain.id, 'https:' + domain.id + ':' + (alertType === 'https_down' ? 'down:' : 'recovered:') + hour, alertType, alertTitle(alertType), message).run();
  return !!result.meta?.changes;
}

export async function onRequestGet({ request, env }) {
  try {
    const user = await getUser(request, env); if (!user) return json({ error: 'Unauthorized' }, 401);
    if(user.role!=='admin'){const plan=await env.DB.prepare("SELECT p.monitoring_enabled FROM dp_user_plans up JOIN dp_plans p ON p.id=up.plan_id WHERE up.user_id=? AND p.active=1 AND (up.expires_at IS NULL OR up.expires_at>=date('now'))").bind(user.id).first();if(!plan?.monitoring_enabled)return json({error:'Monitoring is not included in your current plan'},403);}
    const [result, automation] = await Promise.all([
      env.DB.prepare(`
        SELECT d.id,d.domain,
          (SELECT c.status FROM dp_checks c WHERE c.domain_id=d.id AND c.check_type='https' ORDER BY c.checked_at DESC,c.id DESC LIMIT 1) AS status,
          (SELECT c.response_ms FROM dp_checks c WHERE c.domain_id=d.id AND c.check_type='https' ORDER BY c.checked_at DESC,c.id DESC LIMIT 1) AS response_ms,
          (SELECT c.checked_at FROM dp_checks c WHERE c.domain_id=d.id AND c.check_type='https' ORDER BY c.checked_at DESC,c.id DESC LIMIT 1) AS checked_at,
          (SELECT c.details FROM dp_checks c WHERE c.domain_id=d.id AND c.check_type='https' ORDER BY c.checked_at DESC,c.id DESC LIMIT 1) AS details
        FROM dp_domains d WHERE (?='admin' OR d.owner_id=?) ORDER BY d.domain
      `).bind(user.role,user.id).all(),
      user.role === 'admin'
        ? env.DB.prepare("SELECT checked_count,failed_count,details,started_at,finished_at FROM dp_monitor_runs ORDER BY id DESC LIMIT 1").first()
        : Promise.resolve(null)
    ]);
    return json({ checks: result.results || [], automation: automation || null });
  } catch {
    return json({ error: 'Could not load monitoring data' }, 500);
  }
}

export async function onRequestPost({ request, env }) {
  let runId = null;
  try {
    const user = await getUser(request, env);
    if (!user) return json({ error: 'Unauthorized' }, 401);
    if(user.role!=='admin'){const plan=await env.DB.prepare("SELECT p.monitoring_enabled FROM dp_user_plans up JOIN dp_plans p ON p.id=up.plan_id WHERE up.user_id=? AND p.active=1 AND (up.expires_at IS NULL OR up.expires_at>=date('now'))").bind(user.id).first();if(!plan?.monitoring_enabled)return json({error:'Monitoring is not included in your current plan'},403);}
    const body = await request.json().catch(() => ({}));
    let domains;
    if (body.domainId) {
      const row = await env.DB.prepare("SELECT id,domain,owner_id FROM dp_domains WHERE id=? AND (?='admin' OR owner_id=?)").bind(String(body.domainId),user.role,user.id).first();
      if (!row) return json({ error: 'Domain not found' }, 404);
      domains = [row];
    } else {
      const result = await env.DB.prepare("SELECT id,domain,owner_id FROM dp_domains WHERE (?='admin' OR owner_id=?) ORDER BY domain LIMIT 20").bind(user.role,user.id).all();
      domains = result.results || [];
    }
    if (!domains.length) return json({ error: 'Add a domain before running checks' }, 400);

    const startedAt = new Date().toISOString();
    const run = await env.DB.prepare("INSERT INTO dp_monitor_runs (run_type,checked_count,failed_count,details,started_at) VALUES ('manual',0,0,'Manual check in progress',datetime('now'))").run();
    runId = run.meta?.last_row_id;
    const alertsQueued = [];
    const checks = await Promise.all(domains.map(async (domain) => {
      const history = await env.DB.prepare("SELECT status FROM dp_checks WHERE domain_id=? AND check_type='https' ORDER BY checked_at DESC,id DESC LIMIT 2").bind(domain.id).all();
      const previous = history.results?.[0] || null;
      const beforePrevious = history.results?.[1] || null;
      const started = Date.now();
      let status = 'down', details = 'HTTPS request failed', responseMs = null;
      try {
        if (/\.(localhost|local|internal|test|invalid|example)$/i.test(domain.domain)) throw new Error('Reserved hostname cannot be checked');
        let response = await fetch('https://' + domain.domain, {
          method: 'HEAD', redirect: 'manual',
          signal: AbortSignal.timeout(8000),
          headers: { 'User-Agent': 'DomainPilot-Monitor/1.0' }
        });
        if (response.status === 405 || response.status === 501) {
          try { await response.body?.cancel(); } catch {}
          response = await fetch('https://' + domain.domain, {
            method: 'GET', redirect: 'manual',
            signal: AbortSignal.timeout(8000),
            headers: { 'User-Agent': 'DomainPilot-Monitor/1.0', 'Range': 'bytes=0-0' }
          });
          try { await response.body?.cancel(); } catch {}
          details = 'HEAD unsupported; GET fallback returned HTTP ' + response.status;
        } else {
          try { await response.body?.cancel(); } catch {}
          details = 'HTTPS responded with HTTP ' + response.status;
        }
        responseMs = Date.now() - started;
        status = response.status < 500 ? 'up' : 'down';
      } catch (error) {
        responseMs = Date.now() - started;
        details = String(error?.message || 'HTTPS connection failed').slice(0, 240);
      }
      await env.DB.prepare('INSERT INTO dp_checks (domain_id,check_type,status,response_ms,details) VALUES (?,?,?,?,?)')
        .bind(domain.id, 'https', status, responseMs, details).run();
      const confirmedDown = status === 'down' && previous?.status === 'down' && beforePrevious?.status !== 'down';
      const transitionFromDown = status === 'up' && previous?.status === 'down';
      if ((confirmedDown || transitionFromDown) &&
          await queueTransitionAlert(env, domain, previous?.status || null, status, details)) alertsQueued.push(domain.domain);
      return { id: domain.id, domain: domain.domain, status, response_ms: responseMs, checked_at: new Date().toISOString(), details };
    }));

    const failed = checks.filter(check => check.status !== 'up').length;
    await env.DB.prepare("UPDATE dp_monitor_runs SET checked_count=?,failed_count=?,details=?,finished_at=datetime('now') WHERE id=?")
      .bind(checks.length,failed,'Manual check; alerts queued ' + alertsQueued.length,runId).run();
    await env.DB.prepare('INSERT INTO dp_activity (action,details,actor) VALUES (?,?,?)')
      .bind('monitoring.run', checks.length + ' manual HTTPS checks completed; ' + failed + ' failed', user.email).run();
    return json({ ok: true, checks, run: { id: runId, checked_count: checks.length, failed_count: failed, alerts_queued: alertsQueued.length, started_at: startedAt, finished_at: new Date().toISOString() } });
  } catch {
    if (runId) {
      try { await env.DB.prepare("UPDATE dp_monitor_runs SET details='Manual monitoring run failed',finished_at=datetime('now') WHERE id=?").bind(runId).run(); } catch {}
    }
    return json({ error: 'Could not complete monitoring checks' }, 500);
  }
}
