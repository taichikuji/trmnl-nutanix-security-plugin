const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const test = require('node:test');
const vm = require('node:vm');

const transform = readFileSync(require.resolve('../src/transform.js'), 'utf8');
const portal = 'https://portal.nutanix.com';
const nxvdUrl = portal + '/api/v1/vulnerabilities';
const advisoryUrl = portal + '/api/v1/pages/securityAdvisories';
const expectedPage = { page: 1, pageSize: 20, sort: 'DESC', sortColumn: 'CVSS' };

const vulnerability = {
  cesa: 'RHSA-2026:1000',
  cveList: ['CVE-2026-1000'],
  productName: 'AOS',
  severity: 'Critical',
  cvss: 9.8,
  package: 'openssl',
  fixedReleases: ['aos.7.6'],
  status: 'Released',
};

const advisory = {
  advisoryNumber: 61,
  criticality: 'High',
  date: 'November 18, 2026',
  affectedVersions: 'AOS',
  summary: 'Security update available',
  href: 'https://download.nutanix.com/alerts/Security_Advisory_0061.pdf',
};

async function refresh(fields, response, state) {
  const requests = [];
  const logs = [];
  const run = vm.runInNewContext(transform + '\nrun', {
    AbortSignal,
    Buffer,
    console: { error: (message) => logs.push(message) },
    fetch: async (url, options) => {
      requests.push({ url, options });
      if (response instanceof Error) throw response;
      return response;
    },
  });
  const data = await run({ trmnl: { plugin_settings: { custom_fields_values: fields }, state } });
  assert.equal(requests.length, 1);
  assert.equal(requests[0].options.redirect, 'error');
  return { data: JSON.parse(JSON.stringify(data)), request: requests[0], logs };
}

function json(data) {
  return { ok: true, json: async () => data };
}

function nxvd(rows, counts = rows.length) {
  return json({ vulnerabilities: rows, totalCount: counts, pageCount: counts });
}

test('Advisories default to one GET and keep only fields used by the table or featured advisory', async () => {
  const entries = [
    { ...advisory, advisoryNumber: 62, date: 'November 19, 2026', affectedVersions: 'AHV', href: 'https://private.example/2' },
    { ...advisory, docUrl: 'https://private.example/1' },
  ];
  const { request, data } = await refresh(undefined, json({ content: { body: entries } }));
  assert.equal(request.url, advisoryUrl);
  assert.equal(request.options.method ?? 'GET', 'GET');
  assert.equal(request.options.body, undefined);
  const { trmnl_state: saved, portal_url, ...display } = data;
  assert.equal(portal_url, portal + '/page/security/security-advisories/list');
  assert.deepEqual(display, {
    mode: 'advisories', feed_state: 'LIVE',
    content: { criticality_first: false, body: [
      { advisoryNumber: '61', criticality: 'High', date: 'November 18, 2026', summary: 'Security update available' },
      { advisoryNumber: '62', criticality: 'High', date: 'November 19, 2026', summary: 'Security update available', affectedVersions: 'AHV' },
    ] },
  });
  assert.deepEqual(saved.data, display);
});

test('Advisory order ranks criticality first and breaks ties by publication date', async () => {
  const entries = [
    { ...advisory, advisoryNumber: 'old-critical', date: 'November 15, 2026', criticality: 'Critical' },
    { ...advisory, advisoryNumber: 'medium', date: 'November 16, 2026', criticality: 'Medium' },
    { ...advisory, advisoryNumber: 'new-critical', date: 'November 17, 2026', criticality: ' critical ', affectedVersions: 'AHV' },
    { ...advisory, advisoryNumber: 'latest', date: 'November 19, 2026' },
    { ...advisory, advisoryNumber: 'unrated', date: 'November 18, 2026', criticality: null },
  ];
  const payload = json({ content: { body: entries } });
  const { request, data } = await refresh({ advisory_sort: 'criticality' }, payload);
  assert.equal(request.url, advisoryUrl);
  assert.equal(data.content.criticality_first, true);
  assert.deepEqual(data.content.body.map((row) => row.advisoryNumber),
    ['unrated', 'medium', 'latest', 'old-critical', 'new-critical']);
  assert.equal(data.content.body.at(-1).affectedVersions, 'AHV');
  assert.equal(data.content.body.at(-2).affectedVersions, undefined);

  for (const advisory_sort of ['latest', 'unknown']) {
    const result = await refresh({ advisory_sort }, payload);
    assert.equal(result.data.content.criticality_first, false);
    assert.equal(result.data.content.body.at(-1).advisoryNumber, 'latest');
  }
});

test('NXVD requests one 20-row CVSS page instead of exporting the feed', async () => {
  const { request, data } = await refresh({ table_type: 'nxvd', advisory_sort: 'criticality' }, nxvd([vulnerability], 2837));
  assert.equal(request.url, nxvdUrl);
  assert.equal(request.options.method, 'POST');
  assert.equal(request.options.headers['Content-Type'], 'application/json');
  assert.equal(request.options.headers.Accept, 'application/json, text/plain, */*');
  assert.equal(request.options.headers.Origin, portal);
  assert.equal(request.options.headers.Referer, portal + '/');
  assert.deepEqual(JSON.parse(request.options.body), expectedPage);
  assert.equal(data.feed_state, 'LIVE');
  assert.deepEqual(data.nxvd, { rows: [{
    cesa: vulnerability.cesa, cve: 'CVE-2026-1000', product: 'AOS', severity: 'Critical',
    cvss: '9.8', package: 'openssl', fixed: 'aos.7.6',
  }] });
});

test('Advisories keep only the leading 17 items after sorting', async () => {
  const entries = Array.from({ length: 20 }, (_, index) => ({
    ...advisory,
    advisoryNumber: index + 1,
    date: `November ${index + 1}, 2026`,
    criticality: index === 0 ? 'Critical' : 'High',
  }));
  const payload = json({ content: { body: entries } });
  const latest = await refresh({ advisory_sort: 'latest' }, payload);
  assert.deepEqual(latest.data.content.body.map(row => row.advisoryNumber),
    ['4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20']);

  const criticality = await refresh({ advisory_sort: 'criticality' }, payload);
  assert.deepEqual(criticality.data.content.body.map(row => row.advisoryNumber),
    ['5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '1']);
});

test('NXVD maps every saved product option to the portal product array', async () => {
  const products = {
    aos: 'AOS', ahv: 'AHV', prism: 'Prism', files: 'Files', ndb: 'NDB',
    witnessvm: 'WitnessVM', witness_service: 'Witness Service',
  };
  for (const [key, productName] of Object.entries(products)) {
    const result = await refresh({ table_type: 'nxvd', nxvd_product: key }, nxvd([
      { ...vulnerability, productName },
      { ...vulnerability, productName: 'Other' },
      { ...vulnerability, productName, status: 'Pending Release' },
    ]));
    assert.deepEqual(JSON.parse(result.request.options.body), { ...expectedPage, product: [productName] });
    assert.equal(result.data.portal_url,
      portal + '/page/security/security-vulnerabilities/list?softwareType=' + encodeURIComponent(productName));
    assert.equal(result.data.nxvd.rows.length, 1);
    assert.equal(result.data.nxvd.rows[0].product, productName);
  }
});

test('All and unknown products use the same unfiltered request', async () => {
  for (const product of ['all', 'constructor']) {
    const { request, data } = await refresh({ table_type: 'nxvd', nxvd_product: product }, nxvd([]));
    assert.deepEqual(JSON.parse(request.options.body), expectedPage);
    assert.equal(data.portal_url, portal + '/page/security/security-vulnerabilities/list?softwareType=All');
  }
});

test('NXVD preserves the response order and caps oversized pages', async () => {
  const rows = Array.from({ length: 25 }, (_, i) => ({
    ...vulnerability,
    cesa: String(i),
    status: i < 2 ? 'Pending Release' : 'Released',
    jira: 'PRIVATE-123',
    docUrl: 'https://private.example',
  }));
  const { data } = await refresh({ table_type: 'nxvd' }, nxvd(rows, 3000));
  assert.deepEqual(data.nxvd.rows.map((row) => row.cesa), rows.slice(2, 19).map((row) => row.cesa));
  assert.doesNotMatch(JSON.stringify(data), /PRIVATE|private\.example|jira|docUrl/);
});

test('NXVD reads quoted lists, keeps zero CVSS, and handles unavailable values', async () => {
  const { data } = await refresh({ table_type: 'nxvd' }, nxvd([
    { ...vulnerability, cesa: null, cveList: "['CVE-2026-1000', 'CVE-2026-1001']", fixedReleases: '["aos.7.5", "aos.7.6"]', cvss: 0 },
    { ...vulnerability, cveList: '[]', fixedReleases: "['aos.7.6', injected()]", cvss: null },
    { ...vulnerability, cveList: { secret: 'hidden' }, fixedReleases: null, cvss: 42 },
  ]));
  assert.deepEqual(data.nxvd.rows.map(({ cve, fixed, cvss }) => [cve, fixed, cvss]), [
    ['CVE-2026-1000, CVE-2026-1001', 'aos.7.5, aos.7.6', '0'], ['', '', ''], ['', '', ''],
  ]);
  assert.equal(data.nxvd.rows[0].cesa, '');
});

test('valid empty responses and pages with only pending releases remain unknown', async () => {
  for (const response of [nxvd([]), nxvd([{ ...vulnerability, status: 'Pending Release' }])]) {
    const { data } = await refresh({ table_type: 'nxvd' }, response);
    assert.equal(data.feed_state, 'EMPTY');
    assert.deepEqual(data.nxvd.rows, []);
  }
  const { data } = await refresh({}, json({ content: { body: [] } }));
  assert.equal(data.feed_state, 'EMPTY');
});

const timeout = Object.assign(new Error('PRIVATE'), { name: 'TimeoutError' });

test('Both feeds show a matching saved snapshot after a timeout and update it after recovery', async () => {
  for (const [fields, response, dataKey] of [
    [{ table_type: 'nxvd', nxvd_product: 'aos' }, nxvd([vulnerability]), 'nxvd'],
    [{ advisory_sort: 'criticality' }, json({ content: { body: [advisory] } }), 'content'],
  ]) {
    const first = await refresh(fields, response);
    const saved = first.data.trmnl_state;
    assert.ok(Number.isFinite(Date.parse(saved.saved_at)));
    assert.ok(Buffer.byteLength(JSON.stringify(saved)) <= 8192);
    if (dataKey === 'nxvd') Object.assign(saved.data.nxvd, { total: 1, critical: 1, high: 0 });

    const failed = await refresh(fields, timeout, saved);
    assert.equal(failed.data.feed_state, 'STALE');
    assert.equal(failed.data.source_error, 'TIMEOUT');
    assert.equal(failed.data.saved_at, saved.saved_at);
    assert.deepEqual(failed.data[dataKey], saved.data[dataKey]);
    assert.equal(failed.data.portal_url, first.data.portal_url);
    assert.equal(failed.data.trmnl_state, undefined);
    assert.doesNotMatch(JSON.stringify(failed.data), /PRIVATE/);

    const recovered = await refresh(fields, response, saved);
    assert.equal(recovered.data.feed_state, 'LIVE');
    assert.equal(recovered.data.saved_at, undefined);
    assert.equal(recovered.data.trmnl_state.selection, saved.selection);
  }
});

test('A timeout only reuses state for the selected feed, product, and advisory order', async () => {
  const aos = await refresh({ table_type: 'nxvd', nxvd_product: 'aos' }, nxvd([vulnerability]));
  const latest = await refresh({}, json({ content: { body: [advisory] } }));
  for (const [fields, state] of [
    [{ table_type: 'nxvd' }, aos.data.trmnl_state],
    [{ table_type: 'nxvd', nxvd_product: 'ahv' }, aos.data.trmnl_state],
    [{ table_type: 'advisories' }, aos.data.trmnl_state],
    [{ advisory_sort: 'criticality' }, latest.data.trmnl_state],
  ]) {
    const failed = await refresh(fields, timeout, state);
    assert.equal(failed.data.feed_state, 'ERROR');
    assert.equal(failed.data.saved_at, undefined);
  }
});

test('A successful empty refresh replaces the previous snapshot', async () => {
  const fields = { table_type: 'nxvd' };
  const first = await refresh(fields, nxvd([vulnerability]));
  const empty = await refresh(fields, nxvd([]), first.data.trmnl_state);
  assert.equal(empty.data.trmnl_state.data.feed_state, 'EMPTY');
  const failed = await refresh(fields, timeout, empty.data.trmnl_state);
  assert.equal(failed.data.feed_state, 'ERROR');
});

test('A snapshot above the UTF-8 storage limit keeps the live result and skips the state write', async () => {
  const response = json({ content: { body: [{ ...advisory, summary: 'á'.repeat(4200) }] } });
  const { data } = await refresh({}, response);
  assert.equal(data.feed_state, 'LIVE');
  assert.equal(data.content.body[0].summary.length, 4200);
  assert.equal(data.trmnl_state, undefined);
});

const errors = [
  ['HTTP 503', { ok: false, status: 503 }],
  ['INVALID JSON', { ok: true, json: async () => { throw new SyntaxError('PRIVATE'); } }],
  ['UNEXPECTED DATA', json({ vulnerabilities: [null] })],
  ['UNEXPECTED DATA', json({ wrong_shape: 'PRIVATE' })],
  ['NETWORK ERROR', new TypeError('PRIVATE')],
  ['TIMEOUT', timeout],
];

for (const [index, [reason, response]] of errors.entries()) {
  test(`NXVD reports ${reason} without leaking upstream details (${index + 1})`, async () => {
    const { data, logs } = await refresh({ table_type: 'nxvd' }, response);
    assert.equal(data.feed_state, 'ERROR');
    assert.equal(data.source_error, reason);
    assert.match(logs[0], /Nutanix nxvd: .* after \d+ms/);
    assert.doesNotMatch(JSON.stringify({ data, logs }), /PRIVATE/);
  });
}
