import assert from 'node:assert/strict';
import { mkdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createServer } from 'vite';
import { chromium } from 'playwright';

const output = resolve('test-results');
const server = await createServer({ server: { host: '127.0.0.1', port: 0 }, logLevel: 'error' });
let browser;
try {
  await server.listen();
  const address = server.httpServer.address();
  const origin = `http://127.0.0.1:${address.port}`;
  browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 840, height: 680 }, deviceScaleFactor: 1 });
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
  await mkdir(output, { recursive: true });
  assert.deepEqual(await page.locator('.game').evaluate(element => [element.clientWidth, element.clientHeight]), [800, 600]);
  await page.locator('.game').screenshot({ path: resolve(output, 'setup.png') });

  await page.getByRole('button', { name: 'Restore Saved Game' }).click();
  await page.getByRole('heading', { name: 'Restore Saved Game' }).waitFor();
  assert.ok(await page.getByRole('button', { name: 'Ok', exact: true }).isDisabled());
  await page.getByRole('button', { name: 'Cancel' }).click();
  await page.getByRole('heading', { name: 'Setup Game' }).waitFor();
  await page.getByRole('button', { name: 'Restore Saved Game' }).click();
  await page.getByRole('button', { name: 'demo-season.sav' }).click();
  await page.getByRole('button', { name: 'Ok', exact: true }).click();
  await page.getByRole('heading', { name: 'Evening Fixtures' }).waitFor();
  await page.locator('.game').screenshot({ path: resolve(output, 'fixtures.png') });
  const fixtureCount = await page.locator('.fixture-row').count();
  assert.equal(fixtureCount, 4);
  assert.ok(await page.getByRole('button', { name: 'Back', exact: true }).isDisabled());

  await page.getByRole('button', { name: 'Brackenford', exact: true }).first().click();
  await page.getByRole('heading', { name: 'Brackenford Athletic' }).waitFor();
  assert.equal(await page.locator('.roster tbody tr').count(), 13);
  const rosterBefore = await page.locator('.roster tbody').innerText();
  await page.locator('.game').screenshot({ path: resolve(output, 'squad.png') });
  await page.getByRole('button', { name: 'Milo Fenwick' }).click();
  await page.getByRole('heading', { name: /Milo Fenwick/ }).waitFor();
  assert.equal(await page.locator('.attribute').count(), 35, '31 attributes plus four displayed conditions');
  await page.locator('.game').screenshot({ path: resolve(output, 'profile.png') });
  await page.getByRole('button', { name: 'Back', exact: true }).click();
  await page.getByRole('heading', { name: 'Brackenford Athletic' }).waitFor();
  assert.equal(await page.locator('.roster tbody').innerText(), rosterBefore, 'Profile Back restores the squad');
  await page.getByRole('button', { name: 'Back', exact: true }).click();
  await page.getByRole('heading', { name: 'Evening Fixtures' }).waitFor();
  for (const [shortName, fullName] of [
    ['Northmere', 'Northmere Rovers'], ['Westhaven', 'Westhaven City'],
    ['Moorwick', 'Moorwick United'], ['Copperdale', 'Copperdale Town'],
    ['Thornby', 'Thornby Rangers'], ['Seabourne', 'Seabourne AFC'],
    ['Eldersfield', 'Eldersfield Wanderers'],
  ]) {
    await page.getByRole('button', { name: shortName, exact: true }).first().click();
    await page.getByRole('heading', { name: fullName }).waitFor();
    assert.equal(await page.locator('.roster tbody tr').count(), 6, `${shortName} squad is populated`);
    await page.locator('.roster tbody tr .name button').first().click();
    await page.locator('.player-screen').waitFor();
    await page.getByRole('button', { name: 'Back', exact: true }).click();
    await page.getByRole('heading', { name: fullName }).waitFor();
    await page.getByRole('button', { name: 'Back', exact: true }).click();
    await page.getByRole('heading', { name: 'Evening Fixtures' }).waitFor();
  }
  await page.getByRole('button', { name: 'Adrian Selby' }).click();
  await page.getByRole('menu', { name: 'manager menu' }).waitFor();
  await page.getByRole('menuitem', { name: 'Brackenford Squad' }).click();
  await page.getByRole('heading', { name: 'Brackenford Athletic' }).waitFor();
  await page.getByRole('button', { name: 'Back', exact: true }).click();
  await page.getByRole('heading', { name: 'Evening Fixtures' }).waitFor();

  await page.getByRole('button', { name: 'Start at results' }).click();
  await page.getByRole('heading', { name: 'Evening Results' }).waitFor();
  await page.locator('.game').screenshot({ path: resolve(output, 'results.png') });
  await page.getByRole('button', { name: 'Brackenford', exact: true }).first().click();
  await page.getByRole('heading', { name: 'Brackenford Athletic' }).waitFor();
  await page.goBack();
  await page.getByRole('heading', { name: 'Evening Results' }).waitFor();
  await page.getByRole('button', { name: 'Continue Game' }).click();
  await page.getByRole('dialog').waitFor();
  await page.keyboard.press('Escape');
  assert.equal(await page.getByRole('dialog').count(), 0);
  await page.getByRole('button', { name: 'Reset to menu' }).click();
  await page.getByRole('heading', { name: 'Setup Game' }).waitFor();
  assert.deepEqual(errors, []);
  assert.deepEqual(externalRequests, []);
  console.log(JSON.stringify({ browser: 'pass', viewport: [800, 600], fixtures: fixtureCount,
    rosterRows: 13, journey: 'restore -> fixtures -> squad -> player -> Back -> Back',
    visitorSquads: 7, managerMenu: 'squad and Back', restoreCancel: 'menu',
    resultsReturn: 'browser Back', dialogDismissal: 'Escape', reset: 'menu', externalRequests: 0 }));
} finally {
  await browser?.close();
  await server.close();
}
