import { json, getUser } from '../_lib/auth.js';

export async function onRequestGet({ request, env }) {
  const user = await getUser(request, env);
  if (!user) return json({ error: 'Unauthorized' }, 401);
  try {
    const [settings, events] = await Promise.all([
      env.DB.prepare('SELECT email_enabled FROM dp_user_notification_settings WHERE user_id=?').bind(user.id).first(),
      env.DB.prepare('SELECT id,alert_type,message,delivery_status,created_at,sent_at FROM dp_alert_events WHERE owner_id=? ORDER BY created_at DESC LIMIT 50').bind(user.id).all()
    ]);
    return json({
      plan: user.role === 'admin' ? 'Admin Unlimited' : 'Account',
      allowed: true,
      email_enabled: settings?.email_enabled !== 0,
      email_configured: !!(env.CF_API_TOKEN && env.CF_ACCOUNT_ID && env.EMAIL_FROM),
      events: events.results || []
    });
  } catch {
    return json({ error: 'Could not load notification settings' }, 500);
  }
}

export async function onRequestPost({ request, env }) {
  const user = await getUser(request, env);
  if (!user) return json({ error: 'Unauthorized' }, 401);
  try {
    const body = await request.json().catch(() => ({}));
    const emailEnabled = body.email_enabled === false ? 0 : 1;
    await env.DB.prepare("INSERT INTO dp_user_notification_settings (user_id,email_enabled,updated_at) VALUES (?,?,datetime('now')) ON CONFLICT(user_id) DO UPDATE SET email_enabled=excluded.email_enabled,updated_at=datetime('now')").bind(user.id,emailEnabled).run();
    await env.DB.prepare('INSERT INTO dp_activity (action,details,actor) VALUES (?,?,?)').bind('notifications.preferences_updated',emailEnabled ? 'Email notifications enabled' : 'Email notifications paused',user.email).run();
    return json({ ok: true, email_enabled: !!emailEnabled, email_configured: !!(env.CF_API_TOKEN && env.CF_ACCOUNT_ID && env.EMAIL_FROM) });
  } catch {
    return json({ error: 'Could not save notification settings' }, 500);
  }
}
