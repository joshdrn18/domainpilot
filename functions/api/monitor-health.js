import { json, getUser } from '../_lib/auth.js';

const MONITOR_HEALTH_URL = 'https://domainpilot-monitor.joshdrn18.workers.dev/health';

export async function onRequestGet({ request, env }) {
  const user = await getUser(request, env);
  if (!user) return json({ error: 'Unauthorized' }, 401);

  try {
    const response = await fetch(MONITOR_HEALTH_URL, {
      headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(5000)
    });
    if (!response.ok) {
      return json({ monitor_available: false, email_configured: false }, 503);
    }

    const health = await response.json();
    return json({
      monitor_available: health.ok === true,
      email_configured: health.email_configured === true,
      last_run: health.last_run || null
    });
  } catch {
    return json({ monitor_available: false, email_configured: false }, 503);
  }
}
