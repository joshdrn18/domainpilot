import { json, getUser } from '../../../_lib/auth.js';

export async function onRequestGet({ request, env, params }) {
  try {
    const user = await getUser(request, env);
    if (!user) return json({ error: 'Unauthorized' }, 401);
    const id = String(params.id || '');
    const domain = await env.DB.prepare(
      "SELECT id,domain,registrar,expiry_date,status,nameservers,notes,created_at,updated_at FROM dp_domains WHERE id=? AND (?='admin' OR owner_id=?)"
    ).bind(id,user.role,user.id).first();
    if (!domain) return json({ error: 'Domain not found' }, 404);

    const [checks, certificates, activity] = await Promise.all([
      env.DB.prepare("SELECT id,check_type,status,response_ms,details,checked_at FROM dp_checks WHERE domain_id=? ORDER BY checked_at DESC,id DESC LIMIT 50").bind(id).all(),
      env.DB.prepare("SELECT id,status,issuer,not_after,days_remaining,source,details,checked_at FROM dp_ssl_checks WHERE domain_id=? ORDER BY checked_at DESC,id DESC LIMIT 50").bind(id).all(),
      env.DB.prepare("SELECT id,action,details,actor,created_at FROM dp_activity WHERE domain_id=? ORDER BY created_at DESC,id DESC LIMIT 50").bind(id).all()
    ]);
    return json({
      domain,
      checks: checks.results || [],
      certificates: certificates.results || [],
      activity: activity.results || []
    });
  } catch {
    return json({ error: 'Could not load domain history' }, 500);
  }
}
