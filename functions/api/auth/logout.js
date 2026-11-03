import { json, cookie, getUser } from '../../../_lib/auth.js';
export async function onRequestPost({ request, env }) {
  try {
    const token=request.headers.get('Cookie')?.match(/(?:^|; )dp_session=([a-f0-9]{64})/)?.[1];
    if(token) await env.DB.prepare('DELETE FROM dp_sessions WHERE id=?').bind(token).run();
    return json({ok:true},200,{'Set-Cookie':cookie('dp_session','',0)});
  } catch { return json({error:'Logout failed'},500); }
}
