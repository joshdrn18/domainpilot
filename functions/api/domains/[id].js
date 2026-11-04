import { json, getUser } from '../../_lib/auth.js';
export async function onRequestPatch({ request, env, params }) {
  try {
    const user=await getUser(request,env); if(!user) return json({error:'Unauthorized'},401);
    const body=await request.json(), id=String(params.id);
    const current=await env.DB.prepare("SELECT id FROM dp_domains WHERE id=? AND (?='admin' OR owner_id=?)").bind(id,user.role,user.id).first();
    if(!current) return json({error:'Domain not found'},404);
    const registrar=String(body.registrar||'Unknown').trim().slice(0,80);
    const expiry=body.expiry_date ? String(body.expiry_date) : null;
    if(expiry && !/^\d{4}-\d{2}-\d{2}$/.test(expiry)) return json({error:'Invalid expiration date'},400);
    await env.DB.prepare("UPDATE dp_domains SET registrar=?,expiry_date=?,notes=?,updated_at=datetime('now') WHERE id=? AND (?='admin' OR owner_id=?)").bind(registrar,expiry,String(body.notes||'').slice(0,1000),id,user.role,user.id).run();
    await env.DB.prepare('INSERT INTO dp_activity (domain_id,action,details,actor) VALUES (?,?,?,?)').bind(id,'domain.updated','Domain details updated',user.email).run();
    return json({ok:true});
  } catch { return json({error:'Could not update domain'},500); }
}
export async function onRequestDelete({ request, env, params }) {
  try {
    const user=await getUser(request,env); if(!user) return json({error:'Unauthorized'},401);
    const id=String(params.id);
    const row=await env.DB.prepare("SELECT domain FROM dp_domains WHERE id=? AND (?='admin' OR owner_id=?)").bind(id,user.role,user.id).first();
    if(!row) return json({error:'Domain not found'},404);
    await env.DB.prepare('INSERT INTO dp_activity (domain_id,action,details,actor) VALUES (?,?,?,?)').bind(id,'domain.deleted',row.domain,user.email).run();
    await env.DB.batch([
      env.DB.prepare('DELETE FROM dp_checks WHERE domain_id=?').bind(id),
      env.DB.prepare('DELETE FROM dp_ssl_checks WHERE domain_id=?').bind(id),
      env.DB.prepare("DELETE FROM dp_domains WHERE id=? AND (?='admin' OR owner_id=?)").bind(id,user.role,user.id)
    ]);
    return json({ok:true});
  } catch { return json({error:'Could not delete domain'},500); }
}
