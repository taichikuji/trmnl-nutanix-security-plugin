// Nutanix's public portal endpoints are undocumented.
const SOURCE = 'https://portal.nutanix.com';
const TIMEOUT_MS = 4500;
const PAGE_SIZE = 20;
const SAVED_STATE_BYTES = 8192;
// The largest view uses one featured item and sixteen table rows.
const DISPLAY_LIMIT = 17;
const ADVISORY_CRITICALITY = ['informational', 'low', 'medium', 'high', 'critical'];
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

function advisoryData(entries, criticalityFirst) {
  // The layout reverses this order and only the featured item shows affected versions.
  const sorted = [...entries].sort((left, right) => {
    const byDate = (Date.parse(text(left.date)) || 0) - (Date.parse(text(right.date)) || 0);
    if (!criticalityFirst) return byDate;

    const leftRank = ADVISORY_CRITICALITY.indexOf(text(left.criticality).trim().toLowerCase());
    const rightRank = ADVISORY_CRITICALITY.indexOf(text(right.criticality).trim().toLowerCase());
    return leftRank - rightRank || byDate;
  }).slice(-DISPLAY_LIMIT);
  const body = sorted.map((entry, index) => ({
    advisoryNumber: text(entry.advisoryNumber),
    criticality: text(entry.criticality),
    date: text(entry.date),
    summary: text(entry.summary),
    ...(index === sorted.length - 1 ? { affectedVersions: text(entry.affectedVersions) } : {}),
  }));
  return {
    mode: 'advisories',
    feed_state: entries.length ? 'LIVE' : 'EMPTY',
    content: { body, criticality_first: criticalityFirst },
  };
}

function vulnerabilityData(entries, product) {
  const rows = entries
    .filter((entry) => entry.status === 'Released' && (!product || entry.productName === product))
    .slice(0, DISPLAY_LIMIT)
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

  return {
    mode: 'nxvd',
    feed_state: rows.length ? 'LIVE' : 'EMPTY',
    nxvd: { rows },
  };
}

async function run(input) {
  const fields = input?.trmnl?.plugin_settings?.custom_fields_values;
  const mode = fields?.table_type === 'nxvd' ? 'nxvd' : 'advisories';
  const isNxvd = mode === 'nxvd';
  const product = PRODUCTS.get(fields?.nxvd_product);
  const criticalityFirst = fields?.advisory_sort === 'criticality';
  const selection = isNxvd ? `nxvd:${product ?? 'all'}` : `advisories:${criticalityFirst ? 'criticality' : 'latest'}`;
  const saved = input?.trmnl?.state;
  const url = SOURCE + (isNxvd ? '/api/v1/vulnerabilities' : '/api/v1/pages/securityAdvisories');
  const portal_url = SOURCE + (isNxvd
    ? '/page/security/security-vulnerabilities/list?softwareType=' + encodeURIComponent(product ?? 'All')
    : '/page/security/security-advisories/list');
  const startedAt = Date.now();
  const sourceFailure = (reason, message) => {
    console.error(`Nutanix ${mode}: ${reason} after ${Date.now() - startedAt}ms`);
    const error = { source_error: reason, source_message: message, portal_url };
    if (saved?.selection === selection && saved.data?.mode === mode && saved.data.feed_state === 'LIVE' &&
        typeof saved.saved_at === 'string' && Number.isFinite(Date.parse(saved.saved_at))) {
      return { ...saved.data, ...error, feed_state: 'STALE', saved_at: saved.saved_at };
    }
    return { mode, ...error, feed_state: 'ERROR' };
  };
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
      return sourceFailure(`HTTP ${response.status}`, `Nutanix returned HTTP ${response.status}.`);
    }
    data = await response.json();
  } catch (error) {
    if (signal.aborted || ['TimeoutError', 'AbortError'].includes(error?.name)) {
      return sourceFailure('TIMEOUT', 'Nutanix did not respond within 4.5 seconds.');
    }
    if (error?.name === 'SyntaxError') {
      return sourceFailure('INVALID JSON', 'Nutanix returned an unreadable response.');
    }
    return sourceFailure('NETWORK ERROR', 'Could not reach the Nutanix source.');
  }

  const entries = isNxvd ? data?.vulnerabilities : data?.content?.body;
  const validEntry = isNxvd
    ? (entry) => typeof entry?.status === 'string' && typeof entry.productName === 'string'
    : (entry) => Boolean(text(entry?.advisoryNumber));
  if (!Array.isArray(entries) || !entries.every(validEntry)) {
    return sourceFailure('UNEXPECTED DATA', 'The Nutanix response format changed.');
  }

  const result = isNxvd ? vulnerabilityData(entries, product) : advisoryData(entries, criticalityFirst);
  const snapshot = { selection, saved_at: new Date().toISOString(), data: result };
  const output = { ...result, portal_url };
  if (Buffer.byteLength(JSON.stringify(snapshot)) <= SAVED_STATE_BYTES) {
    output.trmnl_state = snapshot;
  }
  return output;
}
