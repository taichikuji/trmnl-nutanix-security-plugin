// Nutanix's public portal endpoints are undocumented.
const SOURCE = 'https://portal.nutanix.com';
const TIMEOUT_MS = 4500;
const PAGE_SIZE = 20;
const PRODUCTS = new Map([
  ['aos', 'AOS'],
  ['ahv', 'AHV'],
  ['prism', 'Prism'],
  ['files', 'Files'],
  ['ndb', 'NDB'],
  ['witnessvm', 'WitnessVM'],
  ['witness_service', 'Witness Service'],
]);

function text(value) {
  return typeof value === 'string' || typeof value === 'number' ? String(value) : '';
}

function publicPdf(value) {
  const url = text(value);
  return /^https:\/\/download\.nutanix\.com\/alerts\/Security_Advisory_[a-zA-Z0-9_.-]+\.pdf(?:\?[^\s]*)?$/i.test(url) ? url : '';
}

function listText(value) {
  if (typeof value === 'string') {
    const list = value.trim();
    if (!list.startsWith('[')) return list;

    // Some portal responses encode lists as strings with single-quoted items.
    // NXVD list items are identifiers, so keep only well-formed quoted items.
    if (!/^\[\s*(?:(?:'[^'\r\n]*'|"[^"\r\n]*")\s*(?:,\s*|(?=\])))*\]$/.test(list)) return '';
    value = Array.from(list.matchAll(/'([^']*)'|"([^"]*)"/g), (match) => match[1] ?? match[2]);
  }
  return Array.isArray(value) ? value.map(text).filter(Boolean).join(', ') : '';
}

function advisoryData(entries) {
  const body = entries.map((entry) => ({
    advisoryNumber: text(entry.advisoryNumber),
    criticality: text(entry.criticality),
    date: text(entry.date),
    affectedVersions: text(entry.affectedVersions),
    summary: text(entry.summary),
    href: publicPdf(entry.href),
  }));
  // The layout reverses publication order to feature the most recent advisory.
  body.sort((left, right) => (Date.parse(left.date) || 0) - (Date.parse(right.date) || 0));
  return {
    mode: 'advisories',
    feed_state: entries.length ? 'LIVE' : 'EMPTY',
    content: { body },
  };
}

function vulnerabilityData(entries, product) {
  const rows = entries
    .filter((entry) => entry.status === 'Released' && (!product || entry.productName === product))
    .slice(0, PAGE_SIZE)
    .map((entry) => {
      const cvss = text(entry.cvss).trim();
      return {
        cesa: text(entry.cesa),
        cve: listText(entry.cveList),
        product: entry.productName,
        severity: text(entry.severity),
        cvss: cvss && Number(cvss) >= 0 && Number(cvss) <= 10 ? cvss : '',
        package: text(entry.package),
        fixed: listText(entry.fixedReleases),
      };
    });

  // totalCount and pageCount have both returned the current page's length.
  return {
    mode: 'nxvd',
    feed_state: rows.length ? 'LIVE' : 'EMPTY',
    nxvd: {
      total: rows.length,
      critical: rows.filter((row) => row.severity === 'Critical').length,
      high: rows.filter((row) => row.severity === 'High').length,
      rows,
    },
  };
}

function sourceFailure(mode, reason, message, startedAt) {
  console.error(`Nutanix ${mode}: ${reason} after ${Date.now() - startedAt}ms`);
  return { mode, feed_state: 'ERROR', source_error: reason, source_message: message };
}

async function run(input) {
  const fields = input?.trmnl?.plugin_settings?.custom_fields_values;
  const mode = fields?.table_type === 'nxvd' ? 'nxvd' : 'advisories';
  const isNxvd = mode === 'nxvd';
  const product = PRODUCTS.get(fields?.nxvd_product);
  const url = SOURCE + (isNxvd ? '/api/v1/vulnerabilities' : '/api/v1/pages/securityAdvisories');
  const startedAt = Date.now();
  const signal = AbortSignal.timeout(TIMEOUT_MS);
  const options = { signal, redirect: 'error' };
  if (isNxvd) {
    // CESA order can return an empty public first page. CVSS order returns
    // high-scoring records in one bounded request, with optional product filtering.
    const body = { page: 1, pageSize: PAGE_SIZE, sort: 'DESC', sortColumn: 'CVSS' };
    if (product) body.product = [product];
    Object.assign(options, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json, text/plain, */*',
        'Origin': SOURCE,
        'Referer': SOURCE + '/',
      },
      body: JSON.stringify(body),
    });
  }

  let data;
  try {
    const response = await fetch(url, options);
    if (!response.ok) {
      return sourceFailure(mode, `HTTP ${response.status}`, `Nutanix returned HTTP ${response.status}.`, startedAt);
    }
    data = await response.json();
  } catch (error) {
    if (signal.aborted || ['TimeoutError', 'AbortError'].includes(error?.name)) {
      return sourceFailure(mode, 'TIMEOUT', 'Nutanix did not respond within 4.5 seconds.', startedAt);
    }
    if (error?.name === 'SyntaxError') {
      return sourceFailure(mode, 'INVALID JSON', 'Nutanix returned an unreadable response.', startedAt);
    }
    return sourceFailure(mode, 'NETWORK ERROR', 'Could not reach the Nutanix source.', startedAt);
  }

  const entries = isNxvd ? data?.vulnerabilities : data?.content?.body;
  const validEntry = isNxvd
    ? (entry) => typeof entry?.status === 'string' && typeof entry.productName === 'string'
    : (entry) => Boolean(text(entry?.advisoryNumber));
  if (!Array.isArray(entries) || !entries.every(validEntry)) {
    return sourceFailure(mode, 'UNEXPECTED DATA', 'The Nutanix response format changed.', startedAt);
  }
  return isNxvd ? vulnerabilityData(entries, product) : advisoryData(entries);
}
