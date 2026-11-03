import { json, getUser } from '../_lib/auth.js';

export async function onRequestGet({ request, env }) {
  try {
    const user = await getUser(request, env);
    if (!user) return json({ error: 'Unauthorized' }, 401);
    const result = await env.DB.prepare(
      "SELECT a.id,a.action,a.details,a.actor,a.created_at,d.domain FROM dp_activity a LEFT JOIN dp_domains d ON d.id=a.domain_id ORDER BY a.created_at DESC LIMIT 100"
    ).all();
    return json({ activity: result.results || [] });
  } catch {
    return json({ error: 'Could not load activity' }, 500);
  }
}
