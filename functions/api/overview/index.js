import { json, getUser } from '../../_lib/auth.js';

export async function onRequestGet({ request, env }) {
  try {
    const user = await getUser(request, env);
    if (!user) return json({ error: 'Unauthorized' }, 401);
    let monitoringEnabled = user.role === 'admin';
    if (!monitoringEnabled) {
      const plan = await env.DB.prepare("SELECT p.monitoring_enabled FROM dp_user_plans up JOIN dp_plans p ON p.id=up.plan_id WHERE up.user_id=? AND p.active=1 AND (up.expires_at IS NULL OR up.expires_at>=date('now'))").bind(user.id).first();
      monitoringEnabled = !!plan?.monitoring_enabled;
    }
    const scope = "(?='admin' OR d.owner_id=?)";
    const ssl = await env.DB.prepare("SELECT COUNT(*) AS checked, SUM(CASE WHEN latest.status='valid' THEN 1 ELSE 0 END) AS valid, SUM(CASE WHEN latest.status='expiring' THEN 1 ELSE 0 END) AS expiring, SUM(CASE WHEN latest.status='expired' THEN 1 ELSE 0 END) AS expired, SUM(CASE WHEN latest.status='unknown' THEN 1 ELSE 0 END) AS unknown FROM dp_domains d JOIN (SELECT s.domain_id,s.status FROM dp_ssl_checks s WHERE s.id=(SELECT x.id FROM dp_ssl_checks x WHERE x.domain_id=s.domain_id ORDER BY x.checked_at DESC,x.id DESC LIMIT 1)) latest ON latest.domain_id=d.id WHERE "+scope).bind(user.role,user.id).first();
    const uptime = await env.DB.prepare("SELECT COUNT(*) AS total, SUM(CASE WHEN c.status='up' THEN 1 ELSE 0 END) AS up, SUM(CASE WHEN c.status='down' THEN 1 ELSE 0 END) AS down, MAX(c.checked_at) AS last_checked FROM dp_checks c JOIN dp_domains d ON d.id=c.domain_id WHERE "+scope+" AND c.check_type='https' AND c.checked_at>=datetime('now','-30 days')").bind(user.role,user.id).first();
    const latest = await env.DB.prepare("SELECT c.status,c.checked_at FROM dp_checks c JOIN dp_domains d ON d.id=c.domain_id WHERE "+scope+" AND c.check_type='https' ORDER BY c.checked_at DESC,c.id DESC LIMIT 1").bind(user.role,user.id).first();
    const total = Number(uptime?.total || 0), up = Number(uptime?.up || 0);
    return json({ monitoring_enabled: monitoringEnabled, ssl: { checked:Number(ssl?.checked||0), valid:Number(ssl?.valid||0), expiring:Number(ssl?.expiring||0), expired:Number(ssl?.expired||0), unknown:Number(ssl?.unknown||0) }, uptime: { percentage:total?Math.round(up/total*1000)/10:null, samples:total, up, down:Number(uptime?.down||0), last_checked:uptime?.last_checked||latest?.checked_at||null, latest_status:latest?.status||null, window_days:30 } });
  } catch { return json({ error: 'Could not load overview health metrics' }, 500); }
}