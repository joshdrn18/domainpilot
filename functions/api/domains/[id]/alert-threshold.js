import { json, getUser } from '../../../_lib/auth.js';

const DEFAULT_THRESHOLD = 2;
const MIN_THRESHOLD = 2;
const MAX_THRESHOLD = 10;

export async function onRequestPost({ request, env, params }) {
  try {
    const user = await getUser(request, env);
    if (!user) return json({ error: 'Unauthorized' }, 401);
    if (user.role !== 'admin') {
      const plan = await env.DB.prepare("SELECT p.monitoring_enabled FROM dp_user_plans up JOIN dp_plans p ON p.id=up.plan_id WHERE up.user_id=? AND p.active=1 AND (up.expires_at IS NULL OR up.expires_at>=date('now'))").bind(user.id).first();
      if (!plan?.monitoring_enabled) return json({ error: 'Monitoring is not included in your current plan' }, 403);
    }
    const id = String(params.id || '');
    const domain = await env.DB.prepare("SELECT id FROM dp_domains WHERE id=? AND (?='admin' OR owner_id=?)").bind(id,user.role,user.id).first();
    if (!domain) return json({ error: 'Domain not found' }, 404);
    const body = await request.json().catch(() => ({}));
    const threshold = Number(body.failure_threshold);
    if (!Number.isInteger(threshold) || threshold < MIN_THRESHOLD || threshold > MAX_THRESHOLD) {
      return json({ error: 'Failure threshold must be an integer from 2 to 10' }, 400);
    }
    await env.DB.prepare("INSERT INTO dp_settings (key,value,updated_at) VALUES (?,?,datetime('now')) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=datetime('now')")
      .bind('monitor_failure_threshold:' + id, String(threshold)).run();
    await env.DB.prepare("INSERT INTO dp_activity (action,domain_id,details,actor) VALUES (?,?,?,?)")
      .bind('monitoring.threshold.updated',id,'Downtime alert threshold set to ' + threshold + ' consecutive failed checks',user.email).run();
    return json({ ok: true, domain_id: id, failure_threshold: threshold });
  } catch {
    return json({ error: 'Could not save domain alert threshold' }, 500);
  }
}
