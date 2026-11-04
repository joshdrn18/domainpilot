import { getUser } from '../../_lib/auth.js';
export async function onRequestGet({ request, env }) {
  const user = await getUser(request, env);
  if (!user) return Response.json({ error: 'Unauthorized' }, { status: 401, headers: { 'Cache-Control': 'no-store' } });
  try {
    const result = await env.DB.prepare("SELECT domain,registrar,expiry_date,status,notes,created_at FROM dp_domains WHERE (?='admin' OR owner_id=?) ORDER BY domain").bind(user.role, user.id).all();
    const fields = ['domain','registrar','expiry_date','status','notes','created_at'];
    const quote = value => '"' + String(value ?? '').replace(/"/g, '""') + '"';
    const csv = [fields.join(','), ...(result.results || []).map(row => fields.map(key => quote(row[key])).join(','))].join('\r\n');
    return new Response('\uFEFF' + csv, { headers: { 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': 'attachment; filename="domainpilot-domains.csv"', 'Cache-Control': 'no-store' } });
  } catch { return Response.json({ error: 'Could not export domains' }, { status: 500, headers: { 'Cache-Control': 'no-store' } }); }
}