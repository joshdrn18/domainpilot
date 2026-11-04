const validDomain = value => /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(value);

export async function inspectCertificate(domain) {
  const hostname = String(domain || '').trim().toLowerCase();
  if (!validDomain(hostname)) {
    return { status: 'unknown', issuer: null, not_after: null, days_remaining: null, source: 'crt.sh', details: 'Invalid hostname' };
  }

  try {
    const url = new URL('https://crt.sh/');
    url.searchParams.set('q', hostname);
    url.searchParams.set('output', 'json');
    const response = await fetch(url, {
      headers: { 'Accept': 'application/json', 'User-Agent': 'DomainPilot-Certificate-Monitor/1.0' },
      signal: AbortSignal.timeout(12000)
    });
    if (!response.ok) throw new Error('Certificate transparency service returned HTTP ' + response.status);
    const records = await response.json();
    if (!Array.isArray(records) || !records.length) {
      return { status: 'unknown', issuer: null, not_after: null, days_remaining: null, source: 'crt.sh', details: 'No matching certificate transparency record was found' };
    }

    const matches = records.filter(record => {
      const names = String(record.name_value || record.common_name || '').toLowerCase().split(/[\n,\s]+/).filter(Boolean);
      return names.some(name => name === hostname || name === '*.' + hostname);
    });
    const candidates = (matches.length ? matches : records).filter(record => record.not_after && !Number.isNaN(Date.parse(record.not_after)));
    if (!candidates.length) {
      return { status: 'unknown', issuer: null, not_after: null, days_remaining: null, source: 'crt.sh', details: 'Certificate records did not contain a valid expiration date' };
    }

    candidates.sort((a, b) => Date.parse(b.not_before || 0) - Date.parse(a.not_before || 0));
    const latest = candidates[0];
    const notAfter = new Date(latest.not_after).toISOString();
    const days = Math.ceil((Date.parse(notAfter) - Date.now()) / 86400000);
    const status = days < 0 ? 'expired' : days <= 30 ? 'expiring' : 'valid';
    return {
      status,
      issuer: String(latest.issuer_name || '').slice(0, 240) || null,
      not_after: notAfter,
      days_remaining: days,
      source: 'crt.sh',
      details: 'Latest matching certificate transparency record; not a live TLS handshake'
    };
  } catch (error) {
    return { status: 'unknown', issuer: null, not_after: null, days_remaining: null, source: 'crt.sh', details: String(error?.message || 'Certificate lookup failed').slice(0, 240) };
  }
}
