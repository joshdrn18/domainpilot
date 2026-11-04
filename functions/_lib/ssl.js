const validDomain = value => /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(value);

function covers(hostname, pattern) {
  const name = String(pattern || '').toLowerCase().replace(/\.$/, '');
  if (name === hostname) return true;
  if (!name.startsWith('*.')) return false;
  const suffix = name.slice(2);
  return hostname.endsWith('.' + suffix) &&
    hostname.split('.').length === suffix.split('.').length + 1;
}

function certificateResult(record, source, issuerValue) {
  const notAfter = new Date(record.not_after).toISOString();
  const days = Math.ceil((Date.parse(notAfter) - Date.now()) / 86400000);
  return {
    status: days < 0 ? 'expired' : days <= 30 ? 'expiring' : 'valid',
    issuer: String(issuerValue || '').slice(0, 240) || null,
    not_after: notAfter,
    days_remaining: days,
    source,
    details: 'Latest matching certificate transparency record; not a live TLS handshake'
  };
}

export async function inspectCertificate(domain) {
  const hostname = String(domain || '').trim().toLowerCase();
  if (!validDomain(hostname)) {
    return { status: 'unknown', issuer: null, not_after: null, days_remaining: null, source: 'certificate-transparency', details: 'Invalid hostname' };
  }

  const errors = [];

  // Prefer SSLMate Cert Spotter; crt.sh remains the fallback for CT history.
  try {
    const url = new URL('https://api.certspotter.com/v1/issuances');
    url.searchParams.set('domain', hostname);
    url.searchParams.set('include_subdomains', 'false');
    url.searchParams.set('match_wildcards', 'true');
    url.searchParams.append('expand', 'dns_names');
    url.searchParams.append('expand', 'issuer');
    const response = await fetch(url, {
      headers: { 'Accept': 'application/json', 'User-Agent': 'DomainPilot-Certificate-Monitor/1.0' },
      signal: AbortSignal.timeout(9000)
    });
    if (!response.ok) throw new Error('Cert Spotter returned HTTP ' + response.status);
    const records = await response.json();
    if (!Array.isArray(records)) throw new Error('Cert Spotter returned an invalid response');
    const candidates = records.filter(record =>
      Array.isArray(record.dns_names) &&
      record.dns_names.some(name => covers(hostname, name)) &&
      record.not_after && !Number.isNaN(Date.parse(record.not_after))
    );
    if (candidates.length) {
      candidates.sort((a, b) => Date.parse(b.not_before || 0) - Date.parse(a.not_before || 0));
      const latest = candidates[0];
      return certificateResult(latest, 'certspotter', latest.issuer?.friendly_name || latest.issuer?.name);
    }
  } catch (error) {
    errors.push('Cert Spotter: ' + String(error?.message || 'lookup failed').slice(0, 140));
  }

  try {
    const url = new URL('https://crt.sh/');
    url.searchParams.set('q', hostname);
    url.searchParams.set('output', 'json');
    const response = await fetch(url, {
      headers: { 'Accept': 'application/json', 'User-Agent': 'DomainPilot-Certificate-Monitor/1.0' },
      signal: AbortSignal.timeout(9000)
    });
    if (!response.ok) throw new Error('crt.sh returned HTTP ' + response.status);
    const records = await response.json();
    if (!Array.isArray(records)) throw new Error('crt.sh returned an invalid response');
    const candidates = records.filter(record => {
      const names = String(record.name_value || record.common_name || '').toLowerCase().split(/[\n,\s]+/).filter(Boolean);
      return names.some(name => covers(hostname, name)) &&
        record.not_after && !Number.isNaN(Date.parse(record.not_after));
    });
    if (candidates.length) {
      candidates.sort((a, b) => Date.parse(b.not_before || 0) - Date.parse(a.not_before || 0));
      const latest = candidates[0];
      return certificateResult(latest, 'crt.sh', latest.issuer_name);
    }
    if (errors.length) {
      return { status: 'unknown', issuer: null, not_after: null, days_remaining: null, source: 'certificate-transparency', details: (errors.join('; ') + '; crt.sh returned no matching records').slice(0, 240), retryable: true };
    }
    return { status: 'unknown', issuer: null, not_after: null, days_remaining: null, source: 'crt.sh', details: 'No matching certificate transparency record was found' };
  } catch (error) {
    errors.push('crt.sh: ' + String(error?.message || 'lookup failed').slice(0, 140));
    return { status: 'unknown', issuer: null, not_after: null, days_remaining: null, source: 'certificate-transparency', details: errors.join('; ').slice(0, 240), retryable: true };
  }
}
