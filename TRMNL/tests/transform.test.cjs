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

async function refresh(fields, response) {
  const requests = [];
  const logs = [];
  const run = vm.runInNewContext(transform + '\nrun', {
    AbortSignal,
    console: { error: (message) => logs.push(message) },
    fetch: async (url, options) => {
      requests.push({ url, options });
      if (response instanceof Error) throw response;
      return response;
    },
  });
  const data = await run({ trmnl: { plugin_settings: { custom_fields_values: fields } } });
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

test('Advisories default to one GET and preserve the validated table fields', async () => {
  const entries = [
    { ...advisory, docUrl: 'https://private.example/1' },
    { ...advisory, advisoryNumber: 62, href: 'https://private.example/2' },
  ];
  const { request, data } = await refresh(undefined, json({ content: { body: entries } }));
  assert.equal(request.url, advisoryUrl);
  assert.equal(request.options.method ?? 'GET', 'GET');
  assert.equal(request.options.body, undefined);
  assert.deepEqual(data, {
    mode: 'advisories', feed_state: 'LIVE',
    content: { body: [
      { ...advisory, advisoryNumber: '61' },
      { ...advisory, advisoryNumber: '62', href: '' },
    ] },
  });
});

test('NXVD requests one 20-row CVSS page instead of exporting the feed', async () => {
  const { request, data } = await refresh({ table_type: 'nxvd' }, nxvd([vulnerability], 2837));
  assert.equal(request.url, nxvdUrl);
  assert.equal(request.options.method, 'POST');
  assert.equal(request.options.headers['Content-Type'], 'application/json');
  assert.equal(request.options.headers.Accept, 'application/json, text/plain, */*');
  assert.equal(request.options.headers.Origin, portal);
  assert.equal(request.options.headers.Referer, portal + '/');
  assert.deepEqual(JSON.parse(request.options.body), expectedPage);
  assert.equal(data.feed_state, 'LIVE');
  assert.equal(data.nxvd.total, 1);
  assert.equal(data.nxvd.critical, 1);
  assert.deepEqual(data.nxvd.rows[0], {
    cesa: vulnerability.cesa, cve: 'CVE-2026-1000', product: 'AOS', severity: 'Critical',
    cvss: '9.8', package: 'openssl', fixed: 'aos.7.6',
  });
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
    assert.equal(result.data.nxvd.total, 1);
    assert.equal(result.data.nxvd.rows[0].product, productName);
  }
});

test('All and unknown products use the same unfiltered request', async () => {
  for (const product of ['all', 'constructor']) {
    const { request } = await refresh({ table_type: 'nxvd', nxvd_product: product }, nxvd([]));
    assert.deepEqual(JSON.parse(request.options.body), expectedPage);
  }
});

test('NXVD counts retained rows, preserves the response order, and caps oversized pages', async () => {
  const rows = Array.from({ length: 25 }, (_, i) => ({
    ...vulnerability,
    cesa: String(i),
    severity: i < 10 ? 'Critical' : 'High',
    status: i < 2 ? 'Pending Release' : 'Released',
    jira: 'PRIVATE-123',
    docUrl: 'https://private.example',
  }));
  const { data } = await refresh({ table_type: 'nxvd' }, nxvd(rows, 3000));
  assert.equal(data.nxvd.total, 20);
  assert.equal(data.nxvd.critical, 8);
  assert.equal(data.nxvd.high, 12);
  assert.deepEqual(data.nxvd.rows.map((row) => row.cesa), rows.slice(2, 22).map((row) => row.cesa));
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

const errors = [
  ['HTTP 503', { ok: false, status: 503 }],
  ['INVALID JSON', { ok: true, json: async () => { throw new SyntaxError('PRIVATE'); } }],
  ['UNEXPECTED DATA', json({ vulnerabilities: [null] })],
  ['UNEXPECTED DATA', json({ wrong_shape: 'PRIVATE' })],
  ['NETWORK ERROR', new TypeError('PRIVATE')],
  ['TIMEOUT', Object.assign(new Error('PRIVATE'), { name: 'TimeoutError' })],
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
