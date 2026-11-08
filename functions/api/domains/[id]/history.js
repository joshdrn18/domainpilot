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

    const searchParams = new URL(request.url).searchParams;
    const requestedLimit = Number.parseInt(searchParams.get('limit') || '50', 10);
    const limit = Number.isFinite(requestedLimit) ? Math.min(1000, Math.max(1, requestedLimit)) : 50;
    const since = searchParams.get('since');
    if (since && (!/^\d{4}-\d{2}-\d{2}T/.test(since) || !Number.isFinite(Date.parse(since)))) {
      return json({ error: 'Invalid history start time' }, 400);
    }
    const checksQuery = since
      ? env.DB.prepare("SELECT id,check_type,status,response_ms,details,checked_at FROM dp_checks WHERE domain_id=? AND checked_at>=? ORDER BY checked_at DESC,id DESC LIMIT ?").bind(id,since,limit+1)
      : env.DB.prepare("SELECT id,check_type,status,response_ms,details,checked_at FROM dp_checks WHERE domain_id=? ORDER BY checked_at DESC,id DESC LIMIT ?").bind(id,limit+1);
    const [checks, certificates, activity] = await Promise.all([
      checksQuery.all(),
      env.DB.prepare("SELECT id,status,issuer,not_after,days_remaining,source,details,checked_at FROM dp_ssl_checks WHERE domain_id=? ORDER BY checked_at DESC,id DESC LIMIT 50").bind(id).all(),
      env.DB.prepare("SELECT id,action,details,actor,created_at FROM dp_activity WHERE domain_id=? ORDER BY created_at DESC,id DESC LIMIT 50").bind(id).all()
    ]);
    return json({
      domain,
      checks: (checks.results || []).slice(0, limit),
      history_limit: limit,
      history_truncated: (checks.results || []).length > limit,
      history_since: since || null,
      certificates: certificates.results || [],
      activity: activity.results || []
    });
  } catch {
    return json({ error: 'Could not load domain history' }, 500);
  }
}
