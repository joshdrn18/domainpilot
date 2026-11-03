import { json, getUser } from '../../../_lib/auth.js';
export async function onRequestGet({ request, env }) {
  try { const user=await getUser(request,env); return user ? json({authenticated:true,user}) : json({authenticated:false},401); }
  catch { return json({error:'Could not verify session'},500); }
}
