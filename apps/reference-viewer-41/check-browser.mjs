import assert from 'node:assert/strict';
import { mkdir, readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createServer } from 'vite';
import { chromium } from 'playwright';

const input = process.argv[2] ?? 'synthetic-example.json';
const output = resolve(process.argv[3] ?? 'test-results');
const snapshot = JSON.parse(await readFile(input, 'utf8'));
const server = await createServer({ server: { host: '127.0.0.1', port: 0 }, logLevel: 'error' });
let browser;
try {
  await server.listen();
  const address = server.httpServer.address();
  const origin = `http://127.0.0.1:${address.port}`;
  browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 800, height: 600 }, deviceScaleFactor: 1 });
  const errors = [], externalRequests = [];
  page.on('pageerror', error => errors.push(String(error)));
  await page.route('**/*', route => {
    if (new URL(route.request().url()).origin !== origin) {
      externalRequests.push(route.request().url());
      return route.abort();
    }
    return route.continue();
  });
  await page.goto(origin);
  await page.getByLabel('Load local snapshot').setInputFiles(resolve(input));
  await page.getByRole('heading', { name: snapshot.squad.clubLabel, exact: true }).waitFor();
  const expectedNames = snapshot.squad.rows.map(row => row.name);
  assert.deepEqual(await page.locator('tbody tr .player-name').allTextContents(), expectedNames.map(name =>
    name === snapshot.squad.rows.find(row => row.id === snapshot.profile.playerId).name ? `${name} — open captured profile` : name));
  const before = await page.locator('tbody').innerText();
  const displayed = await page.locator('tbody tr').allTextContents();
  assert.equal(displayed.length, snapshot.squad.rows.length);
  for (let i = 0; i < displayed.length; i++) {
    for (const key of ['position', 'form', 'morale', 'condition', 'apps', 'averageRating', 'value']) {
      assert.ok(displayed[i].includes(snapshot.squad.rows[i][key]), `Missing displayed field ${key} at row ${i}`);
    }
  }
  assert.ok(await page.getByRole('button', { name: 'Tactics', exact: true }).isDisabled());
  assert.ok(await page.getByRole('button', { name: 'Continue Game', exact: true }).isDisabled());
  assert.equal(await page.locator('tbody button').count(), 1, 'Only the evidenced profile is available');
  await mkdir(output, { recursive: true });
  await page.screenshot({ path: resolve(output, 'squad.png') });
  const fit = await page.locator('.table-wrap').evaluate(element => element.scrollHeight <= element.clientHeight);
  assert.ok(fit, 'All retained visible roster rows must fit at 800 × 600');
  await page.locator('tbody button').click();
  await page.getByRole('heading', { name: snapshot.profile.title, exact: true }).waitFor();
  assert.equal(await page.locator('.source-label').innerText(), snapshot.kind === 'captured-read-only' ? 'CAPTURED · READ ONLY' : 'SYNTHETIC EXAMPLE');
  const labels = snapshot.profile.attributeColumns.flat().map(attribute => attribute.label);
  for (const label of labels) assert.ok(await page.locator('dt').getByText(label, { exact: true }).isVisible());
  const expectedAttributes = snapshot.profile.attributeColumns.map((column, index) => [
    ...column,
    ...(index === 2 ? [
      { label: 'Preferred Foot', value: snapshot.profile.preferredFoot },
      { label: 'Form', value: snapshot.profile.form },
      { label: 'Morale', value: snapshot.profile.morale },
      { label: 'Condition', value: snapshot.profile.condition },
    ] : []),
  ]).flat();
  assert.deepEqual(await page.locator('dl dt').allTextContents(), expectedAttributes.map(attribute => attribute.label));
  assert.deepEqual(await page.locator('dl dd').allTextContents(), expectedAttributes.map(attribute => attribute.value));
  assert.equal(await page.locator('.profile h2').innerText(), snapshot.profile.bio);
  await page.screenshot({ path: resolve(output, 'profile.png') });
  await page.getByRole('button', { name: 'Back', exact: true }).click();
  assert.equal(await page.locator('tbody').innerText(), before, 'Back preserves captured order/formatting');
  await page.getByLabel('Load local snapshot').setInputFiles({ name: 'invalid.json', mimeType: 'application/json', buffer: Buffer.from('{"command":"advance"}') });
  await page.getByRole('alert').waitFor();
  assert.equal(await page.locator('tbody').count(), 0, 'Malformed file clears the prior captured display');
  await page.getByRole('button', { name: 'Synthetic example', exact: true }).click();
  assert.equal(await page.locator('.source-label').innerText(), 'SYNTHETIC EXAMPLE');
  assert.deepEqual(errors, []);
  assert.deepEqual(externalRequests, [], 'Viewer must not contact an external data service');
  console.log(JSON.stringify({ browser: 'pass', viewport: [800, 600], dataKind: snapshot.kind,
    rows: snapshot.squad.rows.length, attributes: labels.length, navigation: 'squad -> profile -> Back',
    invalidSnapshotRejected: true, unsupportedCommandsDisabled: true, externalRequests: 0 }));
} finally {
  await browser?.close();
  await server.close();
}
