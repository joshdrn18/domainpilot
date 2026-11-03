import { json } from '../../_lib/auth.js';

// Initial administrator provisioning has already been completed.
// Keep this route closed so no public account-creation path remains.
export async function onRequestPost() {
  return json({ error: 'Administrator setup is permanently closed' }, 410);
}
