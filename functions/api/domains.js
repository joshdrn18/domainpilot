import { json, getUser, randomId } from '../_lib/auth.js';
export async function onRequestGet({ request, env }) {
  try {
    const user=await getUser(request,env); if(!user) return json({error:'Unauthorized'},401);
    const result=await env.DB.prepare('SELECT id,domain,registrar,expiry_date,status,nameservers,notes,created_at,updated_at FROM dp_domains WHERE owner_id=? ORDER BY COALESCE(expiry_date,\'9999-12-31\'),domain').bind(user.id).all();
    return json({domains:result.results||[]});
  } catch { return json({error:'Could not load domains'},500); }
}
export async function onRequestPost({ request, env }) {
  try {
    const user=await getUser(request,env); if(!user) return json({error:'Unauthorized'},401);
    const body=await request.json();
    const domain=String(body.domain||'').trim().toLowerCase().replace(/^https?:\/\//,'').replace(/\/$/,'');
    if(domain.length>253 || !/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain)) return json({error:'Enter a valid domain name'},400);
    const registrar=String(body.registrar||'Unknown').trim().slice(0,80);
    const expiry=body.expiry_date ? String(body.expiry_date) : null;
    if(expiry && !/^\d{4}-\d{2}-\d{2}$/.test(expiry)) return json({error:'Invalid expiration date'},400);
    const id=randomId(16);
    await env.DB.prepare('INSERT INTO dp_domains (id,domain,registrar,expiry_date,status,notes,owner_id) VALUES (?,?,?,?,?,?,?)').bind(id,domain,registrar,expiry,'active',String(body.notes||'').slice(0,1000),user.id).run();
    await env.DB.prepare('INSERT INTO dp_activity (domain_id,action,details,actor) VALUES (?,?,?,?)').bind(id,'domain.created',domain,user.email).run();
    return json({ok:true,domain:{id,domain,registrar,expiry_date:expiry,status:'active'}},201);
  } catch(error) { return json({error:'Domain may already exist or could not be saved'},409); }
}
