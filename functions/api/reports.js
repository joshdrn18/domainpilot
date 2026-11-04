import { json, getUser } from '../_lib/auth.js';

function csv(value) {
  const text = value == null ? '' : String(value);
  return '"' + text.replace(/"/g, '""') + '"';
}

export async function onRequestGet({ request, env }) {
  try {
    const user = await getUser(request, env);
    if (!user) return json({ error: 'Unauthorized' }, 401);

    const rows = await env.DB.prepare(`
      SELECT
        d.domain,
        d.registrar,
        d.expiry_date,
        d.status AS domain_status,
        d.notes,
        u.email AS owner_email,
        (SELECT c.status FROM dp_checks c
          WHERE c.domain_id=d.id AND c.check_type='https'
          ORDER BY c.checked_at DESC,c.id DESC LIMIT 1) AS https_status,
        (SELECT c.response_ms FROM dp_checks c
          WHERE c.domain_id=d.id AND c.check_type='https'
          ORDER BY c.checked_at DESC,c.id DESC LIMIT 1) AS https_response_ms,
        (SELECT c.checked_at FROM dp_checks c
          WHERE c.domain_id=d.id AND c.check_type='https'
          ORDER BY c.checked_at DESC,c.id DESC LIMIT 1) AS https_checked_at,
        (SELECT s.status FROM dp_ssl_checks s
          WHERE s.domain_id=d.id
          ORDER BY s.checked_at DESC,s.id DESC LIMIT 1) AS ssl_status,
        (SELECT s.issuer FROM dp_ssl_checks s
          WHERE s.domain_id=d.id
          ORDER BY s.checked_at DESC,s.id DESC LIMIT 1) AS ssl_issuer,
        (SELECT s.not_after FROM dp_ssl_checks s
          WHERE s.domain_id=d.id
          ORDER BY s.checked_at DESC,s.id DESC LIMIT 1) AS ssl_not_after,
        (SELECT s.days_remaining FROM dp_ssl_checks s
          WHERE s.domain_id=d.id
          ORDER BY s.checked_at DESC,s.id DESC LIMIT 1) AS ssl_days_remaining,
        (SELECT s.source FROM dp_ssl_checks s
          WHERE s.domain_id=d.id
          ORDER BY s.checked_at DESC,s.id DESC LIMIT 1) AS ssl_source,
        (SELECT s.checked_at FROM dp_ssl_checks s
          WHERE s.domain_id=d.id
          ORDER BY s.checked_at DESC,s.id DESC LIMIT 1) AS ssl_checked_at
      FROM dp_domains d
      JOIN dp_users u ON u.id=d.owner_id
      WHERE (?='admin' OR d.owner_id=?)
      ORDER BY d.domain COLLATE NOCASE
    `).bind(user.role, user.id).all();

    const columns = [
      ['Domain','domain'],['Registrar','registrar'],['Domain expiry','expiry_date'],
      ['Domain status','domain_status'],['Notes','notes'],
      ...(user.role === 'admin' ? [['Owner email','owner_email']] : []),
      ['HTTPS status','https_status'],['HTTPS response ms','https_response_ms'],
      ['HTTPS last checked','https_checked_at'],['SSL status','ssl_status'],
      ['SSL issuer','ssl_issuer'],['SSL expires at','ssl_not_after'],
      ['SSL days remaining','ssl_days_remaining'],['SSL data source','ssl_source'],
      ['SSL last checked','ssl_checked_at']
    ];
    const output = [
      columns.map(([label]) => csv(label)).join(','),
      ...(rows.results || []).map(row => columns.map(([,key]) => csv(row[key])).join(','))
    ].join('\r\n');
    const date = new Date().toISOString().slice(0,10);
    return new Response('\uFEFF' + output, {
      headers: {
        'Content-Type': 'text/csv; charset=utf-8',
        'Content-Disposition': 'attachment; filename="domainpilot-report-' + date + '.csv"',
        'Cache-Control': 'no-store'
      }
    });
  } catch {
    return json({ error: 'Could not generate portfolio report' }, 500);
  }
}
