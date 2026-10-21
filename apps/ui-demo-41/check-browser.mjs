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
  await page.getByRole('button', { name: 'Brackenford', exact: true }).first().click();
  await page.getByRole('button', { name: 'Finances & Info' }).click();
  await page.getByRole('heading', { name: 'General Info' }).waitFor();
  await page.locator('.game').screenshot({ path: resolve(output, 'club-info.png') });
  await page.locator('.uic-club-modes').getByRole('button', { name: /View/ }).click();
  await page.keyboard.press('Escape');
  assert.equal(await page.getByRole('menu', { name: 'View choices' }).count(), 0);
  await page.locator('.uic-club-modes').getByRole('button', { name: /View/ }).click();
  await page.getByRole('heading', { name: 'General Info' }).click();
  assert.equal(await page.getByRole('menu', { name: 'View choices' }).count(), 0);
  await page.locator('.uic-club-modes').getByRole('button', { name: /View/ }).click();
  await page.getByRole('menuitemradio', { name: /Stats/ }).click();
  await page.getByRole('heading', { name: 'Stats' }).waitFor();
  await page.locator('.uic-stat-line button').first().click();
  await page.locator('.player-screen').waitFor();
  await page.getByRole('button', { name: 'Back', exact: true }).click();
  await page.getByRole('heading', { name: 'Stats' }).waitFor();
  await page.locator('.uic-club-modes').getByRole('button', { name: /View/ }).click();
  await page.getByRole('menuitemradio', { name: /Finances/ }).click();
  await page.getByRole('heading', { name: 'Finances' }).waitFor();
  await page.locator('.game').screenshot({ path: resolve(output, 'club-finances.png') });
  await page.getByRole('button', { name: 'Transfers', exact: true }).click();
  await page.getByRole('heading', { name: /Players In/ }).waitFor();
  await page.locator('.uic-club-modes').getByRole('button', { name: /View/ }).click();
  await page.getByRole('menuitemradio', { name: /Staff Out/ }).click();
  await page.getByRole('heading', { name: /Staff Out/ }).waitFor();
  await page.locator('.game').screenshot({ path: resolve(output, 'transfers.png') });
  await page.getByRole('button', { name: 'Next Match', exact: true }).click();
  await page.locator('.uic-club-modes').getByRole('heading', { name: /Northmere/ }).waitFor();
  await page.locator('.game').screenshot({ path: resolve(output, 'next-match.png') });
  await page.getByRole('button', { name: 'Fixtures', exact: true }).click();
  assert.ok(await page.locator('.uic-club-modes').getByText('Northmere').count());
  await page.getByRole('button', { name: 'Squad', exact: true }).click();
  await page.locator('.subtools').getByRole('button', { name: /View/ }).click();
  await page.keyboard.press('Escape');
  assert.equal(await page.getByRole('menu', { name: 'Squad View' }).count(), 0);
  await page.locator('.subtools').getByRole('button', { name: /View/ }).click();
  await page.getByRole('menuitem', { name: /Attributes/ }).click();
  await page.getByRole('menuitem', { name: /Mental/ }).click();
  await page.getByRole('button', { name: 'Milo Fenwick' }).click();
  await page.getByRole('heading', { name: /Milo Fenwick/ }).waitFor();
  for (const tab of ['Injuries & Bans', 'Contract', 'Transfer', 'History']) {
    await page.getByRole('button', { name: tab, exact: true }).click();
    await page.locator('.pmd-body').waitFor();
    if (tab === 'Contract' || tab === 'History') await page.locator('.game').screenshot({ path: resolve(output, `player-${tab.toLowerCase()}.png`) });
  }
  await page.locator('.pmd-body').getByRole('button', { name: /View/ }).click();
  await page.keyboard.press('Escape');
  assert.equal(await page.getByRole('menu', { name: 'Player history views' }).count(), 0);
  await page.locator('.pmd-body').getByRole('button', { name: /View/ }).click();
  await page.getByRole('menuitemradio', { name: /Bans/ }).click();
  await page.getByLabel('No fictional ban history entries').waitFor();
  await page.getByRole('button', { name: 'Back', exact: true }).click();
  await page.getByRole('heading', { name: 'Brackenford Athletic' }).waitFor();
  assert.ok(await page.getByRole('heading', { name: 'Attributes Info' }).isVisible(), 'profile Back restores squad attribute view');
  await page.locator('.bottom-strip').getByRole('button', { name: /^Training/ }).click();
  await page.getByRole('heading', { name: 'Brackenford Training' }).waitFor();
  await page.getByRole('button', { name: /General \(13\)/ }).click();
  await page.locator('.training-tools').getByRole('button', { name: /View/ }).click();
  await page.keyboard.press('Escape');
  assert.equal(await page.getByRole('menu', { name: 'Training View' }).count(), 0);
  await page.locator('.training-tools').getByRole('button', { name: /View/ }).click();
  await page.getByRole('menuitem', { name: 'Attributes' }).click();
  await page.getByRole('menuitem', { name: /Mental/ }).click();
  await page.locator('.game').screenshot({ path: resolve(output, 'training.png') });
  await page.locator('.training-tools').getByRole('button', { name: /View/ }).click();
  await page.getByRole('button', { name: 'Cancel', exact: true }).click();
  await page.getByRole('heading', { name: 'Brackenford Training' }).waitFor();
  await page.getByRole('button', { name: 'Cancel', exact: true }).click();
  await page.getByRole('heading', { name: 'Brackenford Athletic' }).waitFor();
  await page.locator('.bottom-strip').getByRole('button', { name: /^Tactics/ }).click();
  await page.getByRole('heading', { name: 'Brackenford Athletic Tactics' }).waitFor();
  await page.getByRole('button', { name: 'With Ball' }).click();
  await page.locator('.game').screenshot({ path: resolve(output, 'tactics.png') });
  await page.getByRole('button', { name: 'Cancel', exact: true }).click();
  await page.getByRole('heading', { name: 'Brackenford Athletic' }).waitFor();
  await page.locator('.bottom-strip').getByRole('button', { name: /^History/ }).click();
  await page.getByRole('heading', { name: 'Brackenford History' }).waitFor();
  await page.locator('.history-toolbar').getByRole('button', { name: /View/ }).click();
  await page.keyboard.press('Escape');
  assert.equal(await page.getByRole('menu', { name: 'History View' }).count(), 0);
  await page.locator('.history-toolbar').getByRole('button', { name: /View/ }).click();
  await page.getByRole('menuitem', { name: /This Season/ }).click();
  await page.getByRole('heading', { name: 'This Season' }).waitFor();
  await page.locator('.game').screenshot({ path: resolve(output, 'club-history.png') });
  await page.getByRole('button', { name: 'Back', exact: true }).click();
  await page.getByRole('heading', { name: 'Brackenford Athletic' }).waitFor();
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

  await page.locator('.fixture-toolbar').getByRole('button', { name: 'Competition' }).click();
  await page.getByRole('navigation', { name: 'Cup views' }).waitFor();
  await page.getByRole('heading', { name: 'Group A' }).waitFor();
  await page.locator('.game').screenshot({ path: resolve(output, 'competition-stages.png') });
  await page.getByRole('button', { name: /^Group/ }).click();
  await page.getByRole('menuitemradio', { name: 'Group B' }).click();
  await page.getByRole('heading', { name: 'Group B' }).waitFor();
  await page.getByRole('navigation', { name: 'Cup views' }).getByRole('button', { name: 'Results' }).click();
  await page.getByRole('navigation', { name: 'Cup views' }).getByRole('button', { name: 'Fixtures' }).click();
  await page.getByRole('navigation', { name: 'Cup views' }).getByRole('button', { name: 'Schedule' }).click();
  await page.getByRole('table', { name: 'Competition schedule' }).waitFor();
  await page.getByRole('button', { name: 'Back', exact: true }).click();
  await page.getByRole('heading', { name: 'Evening Fixtures' }).waitFor();
  await page.getByRole('button', { name: 'Brackenford', exact: true }).first().click();
  await page.locator('.bottom-strip').getByRole('button', { name: /^Second Division/ }).click();
  await page.getByRole('navigation', { name: 'League views' }).waitFor();
  await page.getByRole('table', { name: 'League table' }).waitFor();
  await page.locator('.game').screenshot({ path: resolve(output, 'league-table.png') });
  await page.getByRole('button', { name: 'Back', exact: true }).click();
  await page.getByRole('heading', { name: 'Brackenford Athletic' }).waitFor();
  await page.locator('.bottom-strip').getByRole('button', { name: /^Last Match/ }).click();
  await page.getByRole('navigation', { name: 'Match views' }).getByRole('button', { name: 'Match Overview' }).click();
  await page.locator('.game').screenshot({ path: resolve(output, 'last-match-overview.png') });
  for (const name of ['Match Stats', 'Action Zones', 'Match Report']) {
    await page.getByRole('navigation', { name: 'Match views' }).getByRole('button', { name }).click();
    await page.locator('.match-content').waitFor();
  }
  await page.getByRole('button', { name: 'Back', exact: true }).click();
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
  await page.getByRole('button', { name: 'Static match reference' }).click();
  await page.getByLabel('Static match phase').selectOption('half-time');
  await page.getByRole('navigation', { name: 'Match views' }).getByRole('button', { name: 'Match Overview' }).click();
  assert.match(await page.locator('.match-scoreboard').innerText(), /1\s+Westhaven\s+0/);
  await page.locator('.game').screenshot({ path: resolve(output, 'static-match-half-time.png') });
  await page.getByRole('button', { name: 'Start at fixtures' }).click();
  await page.getByRole('button', { name: 'Find', exact: true }).click();
  await page.getByRole('menuitem', { name: 'Player', exact: true }).click();
  await page.getByRole('heading', { name: 'Find Player' }).waitFor();
  await page.getByRole('navigation', { name: 'Find categories' }).getByRole('button', { name: 'Club' }).click();
  await page.getByRole('heading', { name: 'Find Club' }).waitFor();
  await page.getByRole('navigation', { name: 'Find categories' }).getByRole('button', { name: 'Player', exact: true }).click();
  await page.getByLabel('Search fictional results').fill('Milo');
  await page.locator('.gsc-find-row').getByText('Milo Fenwick').click();
  await page.getByRole('heading', { name: /Milo Fenwick/ }).waitFor();
  await page.getByRole('button', { name: 'Back', exact: true }).click();
  assert.equal(await page.getByLabel('Search fictional results').inputValue(), 'Milo', 'Find query survives player profile and Back');
  await page.locator('.game').screenshot({ path: resolve(output, 'find-player.png') });
  await page.getByRole('button', { name: 'Back', exact: true }).click();
  await page.getByRole('heading', { name: 'Evening Fixtures' }).waitFor();
  await page.getByRole('button', { name: 'You Have News' }).click();
  await page.getByRole('navigation', { name: 'News categories' }).getByRole('button', { name: 'Messages' }).click();
  await page.locator('.game').screenshot({ path: resolve(output, 'news-messages.png') });
  await page.getByRole('button', { name: 'Back', exact: true }).click();
  await page.getByRole('heading', { name: 'Evening Fixtures' }).waitFor();
  await page.getByRole('button', { name: 'Adrian Selby' }).click();
  await page.getByRole('menuitem', { name: 'Manager Stats' }).click();
  await page.getByRole('heading', { name: 'Manager Stats' }).waitFor();
  await page.getByRole('button', { name: 'Back', exact: true }).click();
  await page.getByRole('button', { name: 'Game Options' }).click();
  await page.getByRole('menuitem', { name: 'Game Settings' }).click();
  await page.getByRole('dialog', { name: 'Game Settings' }).getByRole('button', { name: 'Cancel' }).click();
  await page.getByRole('heading', { name: 'Evening Fixtures' }).waitFor();
  await page.getByRole('button', { name: 'Reset to menu' }).click();
  await page.getByRole('heading', { name: 'Setup Game' }).waitFor();
  assert.deepEqual(errors, []);
  assert.deepEqual(externalRequests, []);
  console.log(JSON.stringify({ browser: 'pass', viewport: [800, 600], fixtures: fixtureCount,
    rosterRows: 13, journey: 'restore -> fixtures -> squad -> player -> Back -> Back',
    visitorSquads: 7, managerMenu: 'squad and Back', restoreCancel: 'menu',
    clubModes: ['info', 'transfers', 'next match', 'fixtures'],
    playerModes: ['injuries', 'contract', 'transfer', 'history'],
    bottomModes: ['training', 'tactics', 'club history'], localMenus: 'Escape and outside click',
    resultsReturn: 'browser Back', dialogDismissal: 'Escape', reset: 'menu', externalRequests: 0 }));
} finally {
  await browser?.close();
  await server.close();
}
