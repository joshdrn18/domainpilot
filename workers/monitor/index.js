const ALERT_THRESHOLDS = [30, 14, 7, 3, 1, 0];
const BATCH_SIZE = 15;

function validDomain(value) {
  return /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(String(value || '').toLowerCase());
}

async function setting(db, key, fallback = '') {
  const row = await db.prepare('SELECT value FROM dp_settings WHERE key=?').bind(key).first();
  return row?.value ?? fallback;
}

async function inspectCertificate(domain) {
  if (!validDomain(domain)) return { status: 'unknown', issuer: null, not_after: null, days_remaining: null, details: 'Invalid hostname' };
  try {
    const url = new URL('https://crt.sh/');
    url.searchParams.set('q', domain);
    url.searchParams.set('output', 'json');
    const response = await fetch(url, {
      headers: { Accept: 'application/json', 'User-Agent': 'DomainPilot-Certificate-Monitor/1.0' },
      signal: AbortSignal.timeout(12000)
    });
    if (!response.ok) throw new Error('Certificate lookup HTTP ' + response.status);
    const records = await response.json();
    if (!Array.isArray(records) || !records.length) {
      return { status: 'unknown', issuer: null, not_after: null, days_remaining: null, details: 'No matching certificate transparency record' };
    }
    const matches = records.filter(record => {
      const names = String(record.name_value || record.common_name || '').toLowerCase().split(/[\n,\s]+/).filter(Boolean);
      return names.some(name => name === domain || name === '*.' + domain);
    });
    const candidates = (matches.length ? matches : records).filter(record => record.not_after && !Number.isNaN(Date.parse(record.not_after)));
    if (!candidates.length) return { status: 'unknown', issuer: null, not_after: null, days_remaining: null, details: 'No valid expiration date in certificate records' };
    candidates.sort((a, b) => Date.parse(b.not_before || 0) - Date.parse(a.not_before || 0));
    const latest = candidates[0];
    const notAfter = new Date(latest.not_after).toISOString();
    const days = Math.ceil((Date.parse(notAfter) - Date.now()) / 86400000);
    return {
      status: days < 0 ? 'expired' : days <= 30 ? 'expiring' : 'valid',
      issuer: String(latest.issuer_name || '').slice(0, 240) || null,
      not_after: notAfter,
      days_remaining: days,
      details: 'Latest matching certificate transparency record; not a live TLS handshake'
    };
  } catch (error) {
    return { status: 'unknown', issuer: null, not_after: null, days_remaining: null, details: String(error?.message || 'Certificate lookup failed').slice(0, 240), retryable: true };
  }
}

async function queueAlert(db, domainId, ownerId, alertKey, alertType, message, messages) {
  const title = alertType === 'https_down' ? 'Domain is unreachable'
    : alertType === 'https_recovered' ? 'Domain recovered'
    : alertType === 'ssl_expiry' ? 'SSL certificate notice'
    : 'Domain renewal reminder';
  const result = await db.prepare(
    "INSERT OR IGNORE INTO dp_notifications (owner_id,domain_id,alert_key,alert_type,title,message,email_status) VALUES (?,?,?,?,?,?, 'pending')"
  ).bind(ownerId, domainId, alertKey, alertType, title, message).run();
  if (result.meta?.changes) messages.push(message);
}

async function deliverPendingEmails(db, env) {
  if (!env.CF_API_TOKEN || !env.CF_ACCOUNT_ID || !env.EMAIL_FROM) {
    return { sent: 0, failed: 0, configured: false };
  }
  const result = await db.prepare(`
    SELECT n.id,n.title,n.message,u.email,COALESCE(p.email_enabled,1) AS email_enabled
    FROM dp_notifications n
    JOIN dp_users u ON u.id=n.owner_id
    LEFT JOIN dp_user_notification_settings p ON p.user_id=n.owner_id
    WHERE n.email_status IN ('pending','failed')
    ORDER BY n.created_at
    LIMIT 20
  `).all();
  let sent = 0, failed = 0;
  for (const item of result.results || []) {
    if (!item.email_enabled) {
      await db.prepare("UPDATE dp_notifications SET email_status='disabled' WHERE id=?").bind(item.id).run();
      continue;
    }
    try {
      const response = await fetch('https://api.cloudflare.com/client/v4/accounts/' + env.CF_ACCOUNT_ID + '/email/sending/send', {
        method: 'POST',
        headers: { 'Authorization': 'Bearer ' + env.CF_API_TOKEN, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          from: env.EMAIL_FROM,
          to: [item.email],
          subject: '[DomainPilot] ' + item.title,
          text: item.message + '\\n\\nManage your domains: https://domainpilot.pages.dev'
        }),
        signal: AbortSignal.timeout(12000)
      });
      const payload = await response.json().catch(() => ({}));
      const delivered = payload?.result?.delivered || [];
      const queued = payload?.result?.queued || [];
      if (response.ok && payload.success === true && (delivered.includes(item.email) || queued.includes(item.email))) {
        await db.prepare("UPDATE dp_notifications SET email_status='sent',email_sent_at=datetime('now') WHERE id=?").bind(item.id).run();
        sent++;
      } else {
        await db.prepare("UPDATE dp_notifications SET email_status='failed' WHERE id=?").bind(item.id).run();
        failed++;
      }
    } catch {
      await db.prepare("UPDATE dp_notifications SET email_status='failed' WHERE id=?").bind(item.id).run();
      failed++;
    }
  }
  return { sent, failed, configured: true };
}

async function checkDomain(db, domain, messages) {
  const previous = await db.prepare(
    "SELECT status FROM dp_checks WHERE domain_id=? AND check_type='https' ORDER BY checked_at DESC,id DESC LIMIT 1"
  ).bind(domain.id).first();

  let status = 'down', details = 'HTTPS request failed', responseMs = null;
  const started = Date.now();
  try {
    if (!validDomain(domain.domain) || /\.(localhost|local|internal|test|invalid|example)$/i.test(domain.domain)) {
      throw new Error('Reserved or invalid hostname');
    }
    const response = await fetch('https://' + domain.domain, {
      method: 'HEAD',
      redirect: 'manual',
      headers: { 'User-Agent': 'DomainPilot-Monitor/1.0' },
      signal: AbortSignal.timeout(8000)
    });
    responseMs = Date.now() - started;
    status = response.status < 500 ? 'up' : 'down';
    details = 'HTTPS responded with HTTP ' + response.status;
  } catch (error) {
    responseMs = Date.now() - started;
    details = String(error?.message || 'HTTPS connection failed').slice(0, 240);
  }

  await db.prepare('INSERT INTO dp_checks (domain_id,check_type,status,response_ms,details) VALUES (?,?,?,?,?)')
    .bind(domain.id, 'https', status, responseMs, details).run();

  if (status === 'down' && previous?.status !== 'down') {
    await queueAlert(db, domain.id, domain.owner_id, 'https:' + domain.id + ':down:' + new Date().toISOString().slice(0, 13), 'https_down',
      '🔴 DomainPilot: ' + domain.domain + ' is unreachable. ' + details, messages);
  } else if (status === 'up' && previous?.status === 'down') {
    await queueAlert(db, domain.id, domain.owner_id, 'https:' + domain.id + ':recovered:' + new Date().toISOString().slice(0, 13), 'https_recovered',
      '🟢 DomainPilot: ' + domain.domain + ' has recovered. ' + details, messages);
  }

  const previousCertificate = await db.prepare('SELECT days_remaining,not_after FROM dp_ssl_checks WHERE domain_id=? ORDER BY checked_at DESC,id DESC LIMIT 1').bind(domain.id).first();
  const certificate = await inspectCertificate(domain.domain);
  if (!certificate.retryable) {
    await db.prepare('INSERT INTO dp_ssl_checks (domain_id,status,issuer,not_after,days_remaining,source,details) VALUES (?,?,?,?,?,?,?)')
      .bind(domain.id,certificate.status,certificate.issuer,certificate.not_after,certificate.days_remaining,'crt.sh',certificate.details).run();
  }

  if (!certificate.retryable && certificate.not_after && certificate.days_remaining !== null) {
    const threshold = ALERT_THRESHOLDS.slice().sort((a,b) => a-b).find(value => certificate.days_remaining <= value);
    const isNewCertificate = previousCertificate?.not_after !== certificate.not_after;
    const crossed = previousCertificate?.days_remaining == null
      ? certificate.days_remaining <= 30
      : previousCertificate.days_remaining > (threshold ?? -1);
    if (threshold !== undefined && (isNewCertificate || crossed)) {
      await queueAlert(db, domain.id, domain.owner_id,
        'ssl:' + domain.id + ':' + certificate.not_after + ':' + threshold,
        'ssl_expiry',
        '🔐 DomainPilot SSL notice: ' + domain.domain + ' certificate transparency record ' + (certificate.days_remaining < 0 ? 'expired ' + Math.abs(certificate.days_remaining) + ' day(s) ago' : 'expires in ' + certificate.days_remaining + ' day(s)') + ' (' + certificate.not_after.slice(0,10) + '). Verify the live certificate with your hosting provider.',
        messages);
    }
  }

  if (domain.expiry_date) {
    const expiryMs = Date.parse(domain.expiry_date + 'T00:00:00Z');
    if (!Number.isNaN(expiryMs)) {
      const days = Math.ceil((expiryMs - Date.now()) / 86400000);
      const threshold = ALERT_THRESHOLDS.slice().sort((a,b) => a-b).find(value => days <= value);
      if (threshold !== undefined) {
        await queueAlert(db, domain.id, domain.owner_id,
          'domain-expiry:' + domain.id + ':' + domain.expiry_date + ':' + threshold,
          'domain_expiry',
          '📅 DomainPilot renewal reminder: ' + domain.domain + ' ' + (days < 0 ? 'expired ' + Math.abs(days) + ' day(s) ago' : 'expires in ' + days + ' day(s)') + ' (' + domain.expiry_date + ').',
          messages);
      }
    }
  }

  return status;
}

async function runScheduled(env) {
  const db = env.DB;
  const run = await db.prepare("INSERT INTO dp_monitor_runs (run_type,started_at) VALUES ('scheduled',datetime('now'))").run();
  const runId = run.meta?.last_row_id;
  let checked = 0, failed = 0;
  const messages = [];

  try {
    const cursor = await setting(db, 'monitor_cursor', '');
    const eligibleDomains = `
      SELECT d.id,d.domain,d.expiry_date,d.owner_id
      FROM dp_domains d
      JOIN dp_users u ON u.id=d.owner_id
      LEFT JOIN dp_user_plans up ON up.user_id=u.id
      LEFT JOIN dp_plans p ON p.id=up.plan_id
      WHERE d.status='active'
        AND (u.role='admin' OR (p.monitoring_enabled=1 AND p.active=1 AND (up.expires_at IS NULL OR up.expires_at>=date('now'))))
    `;
    let result = await db.prepare(eligibleDomains + ' AND d.id>? ORDER BY d.id LIMIT ?')
      .bind(cursor, BATCH_SIZE).all();
    let domains = result.results || [];
    if (!domains.length && cursor) {
      await db.prepare("INSERT INTO dp_settings (key,value,updated_at) VALUES ('monitor_cursor','',datetime('now')) ON CONFLICT(key) DO UPDATE SET value='',updated_at=datetime('now')").run();
      result = await db.prepare(eligibleDomains + ' ORDER BY d.id LIMIT ?').bind(BATCH_SIZE).all();
      domains = result.results || [];
    }

    for (const domain of domains) {
      try {
        const status = await checkDomain(db, domain, messages);
        checked++;
        if (status !== 'up') failed++;
      } catch (error) {
        failed++;
        messages.push('⚠️ DomainPilot monitor failed for ' + domain.domain + ': ' + String(error?.message || 'unknown error').slice(0,160));
      }
    }

    if (domains.length) {
      const lastId = domains[domains.length - 1].id;
      await db.prepare("INSERT INTO dp_settings (key,value,updated_at) VALUES ('monitor_cursor',?,datetime('now')) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=datetime('now')").bind(lastId).run();
    }

    const delivery = await deliverPendingEmails(db, env);

    await db.prepare("UPDATE dp_monitor_runs SET checked_count=?,failed_count=?,details=?,finished_at=datetime('now') WHERE id=?")
      .bind(checked,failed,domains.length ? 'Batch ' + domains.length + ' domains; alerts queued ' + messages.length + '; emails sent ' + delivery.sent : 'No active domains; emails sent ' + delivery.sent,runId).run();
    return { checked, failed, alerts_queued: messages.length, alerts_sent: delivery.sent, alerts_failed: delivery.failed };
  } catch (error) {
    await db.prepare("UPDATE dp_monitor_runs SET details=?,finished_at=datetime('now') WHERE id=?")
      .bind(String(error?.message || 'Scheduled monitor failed').slice(0,500),runId).run();
    throw error;
  }
}

export default {
  async scheduled(controller, env, ctx) {
    ctx.waitUntil(runScheduled(env).catch(error => console.error('DomainPilot scheduled monitor failed', error)));
  },
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/health') {
      const row = await env.DB.prepare('SELECT finished_at,checked_count,failed_count,details FROM dp_monitor_runs ORDER BY id DESC LIMIT 1').first();
      return Response.json({ ok: true, service: 'DomainPilot Monitor', schedule: '0 * * * *', last_run: row || null });
    }
    return new Response('Not found', { status: 404 });
  }
};
