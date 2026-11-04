import { json, getUser, randomId, hashPassword } from '../_lib/auth.js';

async function admin(request, env) {
  const user = await getUser(request, env);
  if (!user) return { error: json({ error: 'Unauthorized' }, 401) };
  if (user.role !== 'admin') return { error: json({ error: 'Administrator access required' }, 403) };
  return { user };
}
const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const validDomain = value => /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(value);
async function audit(env, action, details, actor) {
  await env.DB.prepare('INSERT INTO dp_activity (action,details,actor) VALUES (?,?,?)')
    .bind(action, String(details || '').slice(0, 500), actor).run();
}

export async function onRequestGet({ request, env }) {
  try {
    const access = await admin(request, env);
    if (access.error) return access.error;
    const [users, domains, plans, activity, checks, settings, sessions] = await Promise.all([
      env.DB.prepare("SELECT u.id,u.email,u.role,u.status,u.created_at,u.last_login_at,COALESCE(up.plan_id,CASE WHEN u.role='admin' THEN 'unlimited' ELSE 'free' END) AS plan_id,up.expires_at,(SELECT COUNT(*) FROM dp_domains d WHERE d.owner_id=u.id) AS domain_count FROM dp_users u LEFT JOIN dp_user_plans up ON up.user_id=u.id ORDER BY u.created_at DESC").all(),
      env.DB.prepare("SELECT d.id,d.domain,d.registrar,d.expiry_date,d.status,d.notes,d.nameservers,d.created_at,d.owner_id,u.email AS owner_email FROM dp_domains d LEFT JOIN dp_users u ON u.id=d.owner_id ORDER BY d.created_at DESC LIMIT 500").all(),
      env.DB.prepare("SELECT id,name,domain_limit,monitoring_enabled,custom_alerts,price_monthly,active FROM dp_plans ORDER BY price_monthly,id").all(),
      env.DB.prepare("SELECT id,action,details,actor,created_at FROM dp_activity ORDER BY created_at DESC LIMIT 100").all(),
      env.DB.prepare("SELECT COUNT(*) AS total,SUM(CASE WHEN status='up' THEN 1 ELSE 0 END) AS up,SUM(CASE WHEN status='down' THEN 1 ELSE 0 END) AS down,MAX(checked_at) AS last_check FROM dp_checks").first(),
      env.DB.prepare("SELECT key,value,updated_at FROM dp_settings ORDER BY key").all(),
      env.DB.prepare("SELECT s.user_id,u.email,s.created_at,s.expires_at FROM dp_sessions s JOIN dp_users u ON u.id=s.user_id WHERE s.expires_at>datetime('now') ORDER BY s.created_at DESC LIMIT 100").all()
    ]);
    const [sslStats, alertStats, monitorRun, alertEvents] = await Promise.all([
      env.DB.prepare("SELECT COUNT(*) AS total,SUM(CASE WHEN status='valid' THEN 1 ELSE 0 END) AS valid,SUM(CASE WHEN status='expiring' THEN 1 ELSE 0 END) AS expiring,SUM(CASE WHEN status='expired' THEN 1 ELSE 0 END) AS expired,MAX(checked_at) AS last_check FROM dp_ssl_checks").first(),
      env.DB.prepare("SELECT COUNT(*) AS total,SUM(CASE WHEN email_status='sent' THEN 1 ELSE 0 END) AS sent,SUM(CASE WHEN email_status IN ('pending','failed') THEN 1 ELSE 0 END) AS pending FROM dp_notifications").first(),
      env.DB.prepare("SELECT id,checked_count,failed_count,details,started_at,finished_at FROM dp_monitor_runs ORDER BY id DESC LIMIT 1").first(),
      env.DB.prepare("SELECT id,owner_id,alert_type,title,message,email_status AS delivery_status,created_at,email_sent_at AS sent_at FROM dp_notifications ORDER BY created_at DESC LIMIT 50").all()
    ]);
    const stats = await env.DB.prepare("SELECT (SELECT COUNT(*) FROM dp_users) AS users,(SELECT COUNT(*) FROM dp_domains) AS domains,(SELECT COUNT(*) FROM dp_activity) AS events,(SELECT COUNT(*) FROM dp_sessions WHERE expires_at>datetime('now')) AS active_sessions").first();
    return json({ stats, users: users.results || [], domains: domains.results || [], plans: plans.results || [], activity: activity.results || [], monitoring: checks || {}, ssl: sslStats || {}, alerts: alertStats || {}, alert_events: alertEvents.results || [], monitor_run: monitorRun || null, settings: settings.results || [], sessions: sessions.results || [] });
  } catch (error) {
    return json({ error: 'Could not load administrator data' }, 500);
  }
}

export async function onRequestPost({ request, env }) {
  try {
    const access = await admin(request, env);
    if (access.error) return access.error;
    const body = await request.json();
    const action = String(body.action || '');
    const actor = access.user.email;

    if (action === 'create_user') {
      const email = String(body.email || '').trim().toLowerCase();
      const password = String(body.password || '');
      const plan = String(body.plan || 'free');
      if (!emailPattern.test(email) || email.length > 254) return json({ error: 'Enter a valid email address' }, 400);
      if (password.length < 12 || password.length > 128) return json({ error: 'Password must contain 12–128 characters' }, 400);
      const allowed = await env.DB.prepare('SELECT id FROM dp_plans WHERE id=? AND active=1').bind(plan).first();
      if (!allowed) return json({ error: 'Selected plan is unavailable' }, 400);
      const id = randomId(16), salt = randomId(16), hash = await hashPassword(password, salt);
      await env.DB.prepare("INSERT INTO dp_users (id,email,password_hash,role,status) VALUES (?,?,?,'user','active')").bind(id,email,salt+':'+hash).run();
      await env.DB.prepare('INSERT INTO dp_user_plans (user_id,plan_id) VALUES (?,?)').bind(id,plan).run();
      await audit(env,'admin.user.created',email+' · '+plan,actor);
      return json({ ok: true, id, email }, 201);
    }

    if (action === 'update_user') {
      const id = String(body.user_id || '');
      const email = String(body.email || '').trim().toLowerCase();
      if (!id || !emailPattern.test(email) || email.length > 254) return json({ error: 'Enter a valid email address' }, 400);
      const target = await env.DB.prepare('SELECT id,email,role FROM dp_users WHERE id=?').bind(id).first();
      if (!target) return json({ error: 'User not found' }, 404);
      if (target.role === 'admin' && id !== access.user.id) return json({ error: 'Other administrator accounts cannot be edited here' }, 400);
      await env.DB.prepare('UPDATE dp_users SET email=? WHERE id=?').bind(email,id).run();
      await audit(env,'admin.user.email_updated',target.email+' → '+email,actor);
      return json({ ok: true, email });
    }

    if (action === 'reset_user_password') {
      const id = String(body.user_id || '');
      const password = String(body.new_password || '');
      if (password.length < 12 || password.length > 128) return json({ error: 'New sign-in secret must contain 12–128 characters' }, 400);
      const target = await env.DB.prepare('SELECT id,email,role FROM dp_users WHERE id=?').bind(id).first();
      if (!target) return json({ error: 'User not found' }, 404);
      if (target.role === 'admin' && id !== access.user.id) return json({ error: 'Other administrator passwords cannot be reset here' }, 400);
      const salt = randomId(16), hash = await hashPassword(password,salt);
      await env.DB.prepare('UPDATE dp_users SET password_hash=? WHERE id=?').bind(salt+':'+hash,id).run();
      await env.DB.prepare('DELETE FROM dp_sessions WHERE user_id=?').bind(id).run();
      await audit(env,'admin.user.password_reset',target.email+' · all sessions revoked',actor);
      return json({ ok: true, sessions_revoked: true });
    }

    if (action === 'set_user_status') {
      const id = String(body.user_id || ''), status = String(body.status || '');
      if (!['active','suspended'].includes(status)) return json({ error: 'Invalid account status' }, 400);
      const target = await env.DB.prepare('SELECT id,email,role FROM dp_users WHERE id=?').bind(id).first();
      if (!target) return json({ error: 'User not found' }, 404);
      if (target.role === 'admin' || target.id === access.user.id) return json({ error: 'Administrator accounts cannot be suspended here' }, 400);
      await env.DB.prepare('UPDATE dp_users SET status=? WHERE id=?').bind(status,id).run();
      if (status === 'suspended') await env.DB.prepare('DELETE FROM dp_sessions WHERE user_id=?').bind(id).run();
      await audit(env,'admin.user.'+status,target.email,actor);
      return json({ ok: true });
    }

    if (action === 'delete_user') {
      const id = String(body.user_id || '');
      const target = await env.DB.prepare('SELECT id,email,role FROM dp_users WHERE id=?').bind(id).first();
      if (!target) return json({ error: 'User not found' }, 404);
      if (target.role === 'admin' || target.id === access.user.id) return json({ error: 'Administrator accounts cannot be deleted here' }, 400);
      await env.DB.batch([
        env.DB.prepare('DELETE FROM dp_checks WHERE domain_id IN (SELECT id FROM dp_domains WHERE owner_id=?)').bind(id),
        env.DB.prepare('DELETE FROM dp_ssl_checks WHERE domain_id IN (SELECT id FROM dp_domains WHERE owner_id=?)').bind(id),
        env.DB.prepare('DELETE FROM dp_activity WHERE domain_id IN (SELECT id FROM dp_domains WHERE owner_id=?)').bind(id),
        env.DB.prepare('DELETE FROM dp_domains WHERE owner_id=?').bind(id),
        env.DB.prepare('DELETE FROM dp_sessions WHERE user_id=?').bind(id),
        env.DB.prepare('DELETE FROM dp_user_plans WHERE user_id=?').bind(id),
        env.DB.prepare('DELETE FROM dp_user_alert_settings WHERE user_id=?').bind(id),
        env.DB.prepare('DELETE FROM dp_user_notification_settings WHERE user_id=?').bind(id),
        env.DB.prepare('DELETE FROM dp_notifications WHERE owner_id=?').bind(id),
        env.DB.prepare('DELETE FROM dp_user_notification_settings WHERE user_id=?').bind(id),
        env.DB.prepare('DELETE FROM dp_notifications WHERE owner_id=?').bind(id),
        env.DB.prepare('DELETE FROM dp_alert_events WHERE owner_id=?').bind(id),
        env.DB.prepare('DELETE FROM dp_users WHERE id=?').bind(id)
      ]);
      await audit(env,'admin.user.deleted',target.email,actor);
      return json({ ok: true });
    }

    if (action === 'set_user_plan') {
      const id = String(body.user_id || ''), plan = String(body.plan || '');
      const target = await env.DB.prepare('SELECT id,email,role FROM dp_users WHERE id=?').bind(id).first();
      const selected = await env.DB.prepare('SELECT id FROM dp_plans WHERE id=? AND active=1').bind(plan).first();
      if (!target || !selected) return json({ error: 'User or active plan not found' }, 404);
      if (target.role === 'admin') return json({ error: 'Admin plan is unlimited and cannot be changed' }, 400);
      const expiry = body.expires_at ? String(body.expires_at).trim() : null;
      if (expiry && (!/^\d{4}-\d{2}-\d{2}$/.test(expiry) || Number.isNaN(Date.parse(expiry+'T00:00:00Z')))) return json({ error: 'Expiry must be a valid YYYY-MM-DD date' }, 400);
      await env.DB.prepare("INSERT INTO dp_user_plans (user_id,plan_id,expires_at) VALUES (?,?,?) ON CONFLICT(user_id) DO UPDATE SET plan_id=excluded.plan_id,expires_at=excluded.expires_at,updated_at=datetime('now')").bind(id,plan,expiry).run();
      await audit(env,'admin.user.plan_changed',target.email+' · '+plan+(expiry?' · until '+expiry:''),actor);
      return json({ ok: true });
    }

    if (action === 'update_plan') {
      const id = String(body.plan_id || '');
      const current = await env.DB.prepare('SELECT id FROM dp_plans WHERE id=?').bind(id).first();
      if (!current || id === 'unlimited') return json({ error: 'This plan cannot be edited' }, 400);
      const name = String(body.name || '').trim();
      const limit = Number(body.domain_limit), price = Number(body.price_monthly);
      if (!name || name.length > 60 || !Number.isInteger(limit) || limit < 1 || limit > 10000 || !Number.isSafeInteger(price) || price < 0 || price > 1000000000) return json({ error: 'Invalid plan settings' }, 400);
      const active = body.active ? 1 : 0;
      const monitoring = body.monitoring_enabled ? 1 : 0;
      const alerts = body.custom_alerts ? 1 : 0;
      await env.DB.prepare('UPDATE dp_plans SET name=?,domain_limit=?,monitoring_enabled=?,custom_alerts=?,price_monthly=?,active=? WHERE id=?')
        .bind(name,limit,monitoring,alerts,price,active,id).run();
      await audit(env,'admin.plan.updated',id+' · '+name+' · '+price+' monthly',actor);
      return json({ ok: true });
    }

    if (action === 'admin_update_domain') {
      const id = String(body.domain_id || '');
      const domain = String(body.domain || '').trim().toLowerCase();
      const registrar = String(body.registrar || 'Unknown').trim().slice(0,80);
      const expiry = body.expiry_date ? String(body.expiry_date) : null;
      const status = String(body.status || 'active');
      const notes = String(body.notes || '').slice(0,1000);
      if (!id || !validDomain(domain)) return json({ error: 'Enter a valid domain name' }, 400);
      if (expiry && !/^\d{4}-\d{2}-\d{2}$/.test(expiry)) return json({ error: 'Invalid expiration date' }, 400);
      if (!['active','inactive','expired'].includes(status)) return json({ error: 'Invalid domain status' }, 400);
      const existing = await env.DB.prepare('SELECT id,domain FROM dp_domains WHERE id=?').bind(id).first();
      if (!existing) return json({ error: 'Domain not found' }, 404);
      await env.DB.prepare("UPDATE dp_domains SET domain=?,registrar=?,expiry_date=?,status=?,notes=?,updated_at=datetime('now') WHERE id=?")
        .bind(domain,registrar,expiry,status,notes,id).run();
      await audit(env,'admin.domain.updated',existing.domain+' → '+domain,actor);
      return json({ ok: true });
    }

    if (action === 'admin_delete_domain') {
      const id = String(body.domain_id || '');
      const existing = await env.DB.prepare('SELECT id,domain FROM dp_domains WHERE id=?').bind(id).first();
      if (!existing) return json({ error: 'Domain not found' }, 404);
      await env.DB.batch([
        env.DB.prepare('DELETE FROM dp_checks WHERE domain_id=?').bind(id),
        env.DB.prepare('DELETE FROM dp_ssl_checks WHERE domain_id=?').bind(id),
        env.DB.prepare("UPDATE dp_alert_events SET delivery_status='disabled' WHERE domain_id=? AND delivery_status IN ('pending','failed')").bind(id),
        env.DB.prepare('DELETE FROM dp_activity WHERE domain_id=?').bind(id),
        env.DB.prepare('DELETE FROM dp_domains WHERE id=?').bind(id)
      ]);
      await audit(env,'admin.domain.deleted',existing.domain,actor);
      return json({ ok: true });
    }

    if (action === 'update_setting') {
      const key = String(body.key || '').trim();
      const value = String(body.value ?? '').trim();
      if (!/^[a-z0-9_.-]{2,80}$/i.test(key) || value.length > 1000) return json({ error: 'Invalid setting' }, 400);
      await env.DB.prepare("INSERT INTO dp_settings (key,value,updated_at) VALUES (?,?,datetime('now')) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=datetime('now')").bind(key,value).run();
      await audit(env,'admin.setting.updated',key,actor);
      return json({ ok: true });
    }

    if (action === 'revoke_sessions') {
      const id = String(body.user_id || '');
      if (!id || id === access.user.id) return json({ error: 'Cannot revoke your current administrator session' }, 400);
      const target = await env.DB.prepare('SELECT id,email FROM dp_users WHERE id=?').bind(id).first();
      if (!target) return json({ error: 'User not found' }, 404);
      await env.DB.prepare('DELETE FROM dp_sessions WHERE user_id=?').bind(id).run();
      await audit(env,'admin.sessions.revoked',target.email,actor);
      return json({ ok: true });
    }
    return json({ error: 'Unknown administrator action' }, 400);
  } catch (error) {
    const message = String(error?.message || '');
    if (/UNIQUE constraint/i.test(message)) return json({ error: 'That email or domain is already in use' }, 409);
    return json({ error: 'Administrator action failed' }, 500);
  }
}
