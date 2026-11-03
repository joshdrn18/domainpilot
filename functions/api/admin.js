import { json, getUser, randomId, hashPassword } from '../_lib/auth.js';

async function admin(request, env) {
  const user = await getUser(request, env);
  if (!user) return { error: json({ error: 'Unauthorized' }, 401) };
  if (user.role !== 'admin') return { error: json({ error: 'Administrator access required' }, 403) };
  return { user };
}

export async function onRequestGet({ request, env }) {
  try {
    const access = await admin(request, env);
    if (access.error) return access.error;
    const [users, domains, plans, activity, checks, settings, sessions] = await Promise.all([
      env.DB.prepare("SELECT u.id,u.email,u.role,u.status,u.created_at,u.last_login_at,COALESCE(up.plan_id,CASE WHEN u.role='admin' THEN 'unlimited' ELSE 'free' END) AS plan_id,up.expires_at,(SELECT COUNT(*) FROM dp_domains d WHERE d.owner_id=u.id) AS domain_count FROM dp_users u LEFT JOIN dp_user_plans up ON up.user_id=u.id ORDER BY u.created_at DESC").all(),
      env.DB.prepare("SELECT d.id,d.domain,d.registrar,d.expiry_date,d.status,d.created_at,u.email AS owner_email FROM dp_domains d LEFT JOIN dp_users u ON u.id=d.owner_id ORDER BY d.created_at DESC LIMIT 500").all(),
      env.DB.prepare("SELECT id,name,domain_limit,monitoring_enabled,custom_alerts,price_monthly,active FROM dp_plans ORDER BY price_monthly,id").all(),
      env.DB.prepare("SELECT id,action,details,actor,created_at FROM dp_activity ORDER BY created_at DESC LIMIT 50").all(),
      env.DB.prepare("SELECT COUNT(*) AS total,SUM(CASE WHEN status='up' THEN 1 ELSE 0 END) AS up,SUM(CASE WHEN status='down' THEN 1 ELSE 0 END) AS down,MAX(checked_at) AS last_check FROM dp_checks").first(),
      env.DB.prepare("SELECT key,value,updated_at FROM dp_settings ORDER BY key").all(),
      env.DB.prepare("SELECT s.user_id,u.email,s.created_at,s.expires_at FROM dp_sessions s JOIN dp_users u ON u.id=s.user_id WHERE s.expires_at>datetime('now') ORDER BY s.created_at DESC LIMIT 100").all()
    ]);
    const stats = await env.DB.prepare("SELECT (SELECT COUNT(*) FROM dp_users) AS users,(SELECT COUNT(*) FROM dp_domains) AS domains,(SELECT COUNT(*) FROM dp_activity) AS events,(SELECT COUNT(*) FROM dp_sessions WHERE expires_at>datetime('now')) AS active_sessions").first();
    return json({ stats, users: users.results || [], domains: domains.results || [], plans: plans.results || [], activity: activity.results || [], monitoring: checks || {}, settings: settings.results || [], sessions: sessions.results || [] });
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
    if (action === 'create_user') {
      const email = String(body.email || '').trim().toLowerCase();
      const password = String(body.password || '');
      const plan = String(body.plan || 'free');
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) return json({ error: 'Enter a valid email address' }, 400);
      if (password.length < 12 || password.length > 128) return json({ error: 'Password must contain 12–128 characters' }, 400);
      const allowed = await env.DB.prepare('SELECT id FROM dp_plans WHERE id=? AND active=1').bind(plan).first();
      if (!allowed) return json({ error: 'Selected plan is unavailable' }, 400);
      const id = randomId(16), salt = randomId(16), hash = await hashPassword(password, salt);
      await env.DB.prepare("INSERT INTO dp_users (id,email,password_hash,role,status) VALUES (?,?,?,'user','active')").bind(id,email,salt+':'+hash).run();
      await env.DB.prepare('INSERT INTO dp_user_plans (user_id,plan_id) VALUES (?,?)').bind(id,plan).run();
      await env.DB.prepare('INSERT INTO dp_activity (action,details,actor) VALUES (?,?,?)').bind('admin.user.created',email+' · '+plan,access.user.email).run();
      return json({ ok: true, id, email }, 201);
    }
    if (action === 'set_user_status') {
      const id = String(body.user_id || ''), status = String(body.status || '');
      if (!['active','suspended'].includes(status)) return json({ error: 'Invalid account status' }, 400);
      const target = await env.DB.prepare('SELECT id,email,role FROM dp_users WHERE id=?').bind(id).first();
      if (!target) return json({ error: 'User not found' }, 404);
      if (target.role === 'admin' || target.id === access.user.id) return json({ error: 'Administrator accounts cannot be suspended here' }, 400);
      await env.DB.prepare('UPDATE dp_users SET status=? WHERE id=?').bind(status,id).run();
      if (status === 'suspended') await env.DB.prepare('DELETE FROM dp_sessions WHERE user_id=?').bind(id).run();
      await env.DB.prepare('INSERT INTO dp_activity (action,details,actor) VALUES (?,?,?)').bind('admin.user.'+status,target.email,access.user.email).run();
      return json({ ok: true });
    }
    if (action === 'set_user_plan') {
      const id = String(body.user_id || ''), plan = String(body.plan || '');
      const target = await env.DB.prepare('SELECT id,email,role FROM dp_users WHERE id=?').bind(id).first();
      const selected = await env.DB.prepare('SELECT id FROM dp_plans WHERE id=? AND active=1').bind(plan).first();
      if (!target || !selected) return json({ error: 'User or plan not found' }, 404);
      if (target.role === 'admin') return json({ error: 'Admin plan is unlimited and cannot be changed' }, 400);
      await env.DB.prepare("INSERT INTO dp_user_plans (user_id,plan_id) VALUES (?,?) ON CONFLICT(user_id) DO UPDATE SET plan_id=excluded.plan_id,updated_at=datetime('now')").bind(id,plan).run();
      await env.DB.prepare('INSERT INTO dp_activity (action,details,actor) VALUES (?,?,?)').bind('admin.user.plan_changed',target.email+' · '+plan,access.user.email).run();
      return json({ ok: true });
    }
    if (action === 'update_plan') {
      const id = String(body.plan_id || '');
      const limit = Number(body.domain_limit);
      if (!['free','pro'].includes(id) || !Number.isInteger(limit) || limit < 1 || limit > 10000) return json({ error: 'Invalid plan settings' }, 400);
      await env.DB.prepare('UPDATE dp_plans SET domain_limit=?,monitoring_enabled=?,custom_alerts=? WHERE id=?').bind(limit,body.monitoring_enabled?1:0,body.custom_alerts?1:0,id).run();
      await env.DB.prepare('INSERT INTO dp_activity (action,details,actor) VALUES (?,?,?)').bind('admin.plan.updated',id+' · limit '+limit,access.user.email).run();
      return json({ ok: true });
    }
    if (action === 'update_setting') {
      const key = String(body.key || '').trim();
      const value = String(body.value ?? '').trim();
      if (!/^[a-z0-9_.-]{2,80}$/i.test(key) || value.length > 1000) return json({ error: 'Invalid setting' }, 400);
      await env.DB.prepare("INSERT INTO dp_settings (key,value,updated_at) VALUES (?,?,datetime('now')) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=datetime('now')").bind(key,value).run();
      await env.DB.prepare('INSERT INTO dp_activity (action,details,actor) VALUES (?,?,?)').bind('admin.setting.updated',key,access.user.email).run();
      return json({ ok: true });
    }
    if (action === 'revoke_sessions') {
      const id = String(body.user_id || '');
      if (!id || id === access.user.id) return json({ error: 'Cannot revoke your current administrator session' }, 400);
      await env.DB.prepare('DELETE FROM dp_sessions WHERE user_id=?').bind(id).run();
      await env.DB.prepare('INSERT INTO dp_activity (action,details,actor) VALUES (?,?,?)').bind('admin.sessions.revoked',id,access.user.email).run();
      return json({ ok: true });
    }
    return json({ error: 'Unknown administrator action' }, 400);
  } catch (error) {
    const message = String(error?.message || '');
    if (/UNIQUE constraint/i.test(message)) return json({ error: 'An account with this email already exists' }, 409);
    return json({ error: 'Administrator action failed' }, 500);
  }
}
