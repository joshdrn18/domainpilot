import { json, getUser } from '../_lib/auth.js';

async function access(request, env) {
  const user = await getUser(request, env);
  if (!user) return { response: json({ error: 'Unauthorized' }, 401) };
  const plan = await env.DB.prepare(
    "SELECT p.id,p.name,p.custom_alerts,p.active,up.expires_at FROM dp_user_plans up JOIN dp_plans p ON p.id=up.plan_id WHERE up.user_id=?"
  ).bind(user.id).first();
  const allowed = user.role === 'admin' || (!!plan?.custom_alerts && !!plan?.active && (!plan.expires_at || plan.expires_at >= new Date().toISOString().slice(0,10)));
  return { user, plan, allowed };
}

export async function onRequestGet({ request, env }) {
  try {
    const current = await access(request, env);
    if (current.response) return current.response;
    const [settings, events] = await Promise.all([
      env.DB.prepare('SELECT telegram_chat_id,enabled,updated_at FROM dp_user_alert_settings WHERE user_id=?').bind(current.user.id).first(),
      env.DB.prepare('SELECT id,alert_type,message,delivery_status,created_at,sent_at FROM dp_alert_events WHERE owner_id=? ORDER BY created_at DESC LIMIT 50').bind(current.user.id).all()
    ]);
    return json({
      allowed: current.allowed,
      plan: current.plan?.name || (current.user.role === 'admin' ? 'Admin Unlimited' : 'Free'),
      chat_id: settings?.telegram_chat_id || '',
      enabled: settings?.enabled !== 0,
      events: events.results || []
    });
  } catch {
    return json({ error: 'Could not load notification settings' }, 500);
  }
}

export async function onRequestPost({ request, env }) {
  try {
    const current = await access(request, env);
    if (current.response) return current.response;
    if (!current.allowed) return json({ error: 'Custom alerts are not included in your current plan' }, 403);
    const body = await request.json().catch(() => ({}));
    const chatId = String(body.chat_id || '').trim();
    const enabled = body.enabled === false ? 0 : 1;
    if (chatId.length > 80 || (chatId && !/^-?\d+$/.test(chatId))) return json({ error: 'Telegram chat ID must be numeric' }, 400);
    await env.DB.prepare(
      "INSERT INTO dp_user_alert_settings (user_id,telegram_chat_id,enabled,updated_at) VALUES (?,?,?,datetime('now')) ON CONFLICT(user_id) DO UPDATE SET telegram_chat_id=excluded.telegram_chat_id,enabled=excluded.enabled,updated_at=datetime('now')"
    ).bind(current.user.id,chatId,enabled).run();
    if (enabled) {
      await env.DB.prepare("UPDATE dp_alert_events SET delivery_status='pending' WHERE owner_id=? AND delivery_status IN ('failed','disabled')").bind(current.user.id).run();
    } else {
      await env.DB.prepare("UPDATE dp_alert_events SET delivery_status='disabled' WHERE owner_id=? AND delivery_status IN ('pending','failed')").bind(current.user.id).run();
    }
    await env.DB.prepare('INSERT INTO dp_activity (action,details,actor) VALUES (?,?,?)')
      .bind('alerts.settings_updated',enabled ? 'Telegram alerts enabled' : 'Telegram alerts paused',current.user.email).run();
    return json({ ok: true, chat_id: chatId, enabled: !!enabled });
  } catch {
    return json({ error: 'Could not save notification settings' }, 500);
  }
}
