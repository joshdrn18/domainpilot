export async function onRequestGet({ env }) {
  try {
    if (!env.DB) {
      return Response.json({ ok: false, service: 'DomainPilot API', error: 'D1 binding DB is missing' }, { status: 503 });
    }
    const result = await env.DB.prepare(
      "SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'dp_%' ORDER BY name"
    ).all();
    const required = ['dp_domains', 'dp_activity', 'dp_checks', 'dp_settings', 'dp_users', 'dp_sessions', 'dp_login_attempts', 'dp_plans', 'dp_user_plans', 'dp_ssl_checks', 'dp_alert_events', 'dp_monitor_runs', 'dp_user_alert_settings'];
    const found = new Set((result.results || []).map((row) => row.name));
    const missing = required.filter((name) => !found.has(name));
    return Response.json({
      ok: missing.length === 0,
      service: 'DomainPilot API',
      version: '0.4.0',
      database: missing.length === 0 ? 'connected' : 'schema_incomplete',
      tables: required.length - missing.length,
      missing
    }, { status: missing.length === 0 ? 200 : 503, headers: { 'Cache-Control': 'no-store' } });
  } catch (error) {
    return Response.json({
      ok: false,
      service: 'DomainPilot API',
      error: 'Database check failed'
    }, { status: 500, headers: { 'Cache-Control': 'no-store' } });
  }
}
