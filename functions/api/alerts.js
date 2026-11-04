import { json, getUser } from '../_lib/auth.js';

async function requireAdmin(request, env) {
  const user = await getUser(request, env);
  if (!user) return { response: json({ error: 'Unauthorized' }, 401) };
  if (user.role !== 'admin') return { response: json({ error: 'Administrator access required' }, 403) };
  return { user };
}

export async function onRequestGet({ request, env }) {
  try {
    const access = await requireAdmin(request, env);
    if (access.response) return access.response;
    const [chat, enabled, events, run] = await Promise.all([
      env.DB.prepare("SELECT value FROM dp_settings WHERE key='telegram_chat_id'").first(),
      env.DB.prepare("SELECT value FROM dp_settings WHERE key='telegram_alerts_enabled'").first(),
      env.DB.prepare("SELECT id,domain_id,alert_type,message,delivery_status,created_at,sent_at FROM dp_alert_events ORDER BY created_at DESC LIMIT 50").all(),
      env.DB.prepare("SELECT id,checked_count,failed_count,details,started_at,finished_at FROM dp_monitor_runs ORDER BY id DESC LIMIT 1").first()
    ]);
    return json({
      chat_id: chat?.value || '',
      enabled: enabled?.value !== '0',
      events: events.results || [],
      last_run: run || null,
      token_configured: false
    });
  } catch {
    return json({ error: 'Could not load alert settings' }, 500);
  }
}

export async function onRequestPost({ request, env }) {
  try {
    const access = await requireAdmin(request, env);
    if (access.response) return access.response;
    const body = await request.json().catch(() => ({}));
    const chatId = String(body.chat_id || '').trim();
    const enabled = body.enabled === false ? '0' : '1';
    if (chatId.length > 80 || (chatId && !/^-?\d+$/.test(chatId))) return json({ error: 'Telegram chat ID must be numeric' }, 400);
    await env.DB.batch([
      env.DB.prepare("INSERT INTO dp_settings (key,value,updated_at) VALUES ('telegram_chat_id',?,datetime('now')) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=datetime('now')").bind(chatId),
      env.DB.prepare("INSERT INTO dp_settings (key,value,updated_at) VALUES ('telegram_alerts_enabled',?,datetime('now')) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=datetime('now')").bind(enabled)
    ]);
    await env.DB.prepare('INSERT INTO dp_activity (action,details,actor) VALUES (?,?,?)')
      .bind('alerts.settings_updated',enabled === '1' ? 'Telegram alerts enabled' : 'Telegram alerts paused',access.user.email).run();
    return json({ ok: true, chat_id: chatId, enabled: enabled === '1' });
  } catch {
    return json({ error: 'Could not save alert settings' }, 500);
  }
}
