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
    return { status: 'unknown', issuer: null, not_after: null, days_remaining: null, details: String(error?.message || 'Certificate lookup failed').slice(0, 240) };
  }
}

async function sendTelegram(env, chatId, text) {
  if (!env.TELEGRAM_BOT_TOKEN || !chatId || !text) return false;
  try {
    const response = await fetch('https://api.telegram.org/bot' + env.TELEGRAM_BOT_TOKEN + '/sendMessage', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: chatId, text: text.slice(0, 3900), disable_web_page_preview: true }),
      signal: AbortSignal.timeout(10000)
    });
    const result = await response.json();
    return response.ok && result.ok === true;
  } catch {
    return false;
  }
}

async function queueAlert(db, domainId, ownerId, alertKey, alertType, message, messages) {
  const result = await db.prepare(
    "INSERT OR IGNORE INTO dp_alert_events (domain_id,owner_id,alert_key,alert_type,message,delivery_status) VALUES (?,?,?,?,?,'pending')"
  ).bind(domainId, ownerId, alertKey, alertType, message).run();
  if (result.meta?.changes) messages.push(message);
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
  await db.prepare('INSERT INTO dp_ssl_checks (domain_id,status,issuer,not_after,days_remaining,source,details) VALUES (?,?,?,?,?,?,?)')
    .bind(domain.id,certificate.status,certificate.issuer,certificate.not_after,certificate.days_remaining,'crt.sh',certificate.details).run();

  if (certificate.not_after && certificate.days_remaining !== null) {
    const threshold = ALERT_THRESHOLDS.find(value => certificate.days_remaining <= value);
    const isNewCertificate = previousCertificate?.not_after !== certificate.not_after;
    const crossed = previousCertificate?.days_remaining == null
      ? certificate.days_remaining <= 30
      : previousCertificate.days_remaining > (threshold ?? -1);
    if (threshold !== undefined && (isNewCertificate || crossed)) {
      await queueAlert(db, domain.id, domain.owner_id,
        'ssl:' + domain.id + ':' + certificate.not_after + ':' + threshold,
        'ssl_expiry',
        '🔐 DomainPilot SSL notice: ' + domain.domain + ' has a certificate transparency record expiring in ' + certificate.days_remaining + ' day(s) (' + certificate.not_after.slice(0,10) + '). Verify the live certificate with your hosting provider.',
        messages);
    }
  }

  if (domain.expiry_date) {
    const expiryMs = Date.parse(domain.expiry_date + 'T00:00:00Z');
    if (!Number.isNaN(expiryMs)) {
      const days = Math.ceil((expiryMs - Date.now()) / 86400000);
      const threshold = ALERT_THRESHOLDS.find(value => days <= value);
      if (threshold !== undefined) {
        await queueAlert(db, domain.id, domain.owner_id,
          'domain-expiry:' + domain.id + ':' + domain.expiry_date + ':' + threshold,
          'domain_expiry',
          '📅 DomainPilot renewal reminder: ' + domain.domain + ' expires in ' + days + ' day(s) (' + domain.expiry_date + ').',
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
    let result = await db.prepare("SELECT id,domain,expiry_date,owner_id FROM dp_domains WHERE status='active' AND id>? ORDER BY id LIMIT ?")
      .bind(cursor, BATCH_SIZE).all();
    let domains = result.results || [];
    if (!domains.length && cursor) {
      await db.prepare("INSERT INTO dp_settings (key,value,updated_at) VALUES ('monitor_cursor','',datetime('now')) ON CONFLICT(key) DO UPDATE SET value='',updated_at=datetime('now')").run();
      result = await db.prepare("SELECT id,domain,expiry_date,owner_id FROM dp_domains WHERE status='active' ORDER BY id LIMIT ?").bind(BATCH_SIZE).all();
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

    const chatId = await setting(db, 'telegram_chat_id', '');
    const alertsEnabled = (await setting(db, 'telegram_alerts_enabled', '1')) !== '0';
    const pending = await db.prepare("SELECT id,message FROM dp_alert_events WHERE delivery_status IN ('pending','failed') ORDER BY created_at LIMIT 20").all();
    const allMessages = (pending.results || []).map(row => row.message).slice(0, 20);
    if (allMessages.length && alertsEnabled && env.TELEGRAM_BOT_TOKEN && chatId) {
      const delivered = await sendTelegram(env, chatId, 'DomainPilot automated report\n\n' + allMessages.join('\n\n'));
      if (delivered) {
        const ids = (pending.results || []).map(row => row.id);
        if (ids.length) {
          const placeholders = ids.map(() => '?').join(',');
          await db.prepare("UPDATE dp_alert_events SET delivery_status='sent',sent_at=datetime('now') WHERE id IN (" + placeholders + ")").bind(...ids).run();
        }
        for (const message of messages) {
          await db.prepare("UPDATE dp_alert_events SET delivery_status='sent',sent_at=datetime('now') WHERE message=? AND delivery_status='pending'").bind(message).run();
        }
      } else {
        await db.prepare("UPDATE dp_alert_events SET delivery_status='failed' WHERE delivery_status='pending'").run();
      }
    }

    await db.prepare("UPDATE dp_monitor_runs SET checked_count=?,failed_count=?,details=?,finished_at=datetime('now') WHERE id=?")
      .bind(checked,failed,domains.length ? 'Batch ' + domains.length + ' domains; alerts queued ' + messages.length : 'No active domains',runId).run();
    return { checked, failed, alerts: messages.length };
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
