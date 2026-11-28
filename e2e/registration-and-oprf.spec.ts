import { expect, test } from '@playwright/test';

test('password edits and reset retire earlier comparisons, including pending runs', async ({ page }) => {
  await page.goto('.');
  const exhibit = page.locator('#exhibit-oprf');
  const password = exhibit.getByRole('textbox');
  const run = exhibit.getByRole('button', { name: 'Run OPRF', exact: true });
  const cards = exhibit.locator('.oprf-run-card');
  const status = exhibit.locator('.oprf-status');
  await run.click();
  await expect(cards).toHaveCount(1);
  await exhibit.getByRole('button', { name: 'Run again (fresh r)' }).click();
  await expect(cards).toHaveCount(2);
  await expect(status).toContainText('Same password');
  await password.fill('second example');
  await expect(cards).toHaveCount(0);
  await expect(status).toContainText('start a new comparison');
  await run.click();
  await expect(cards).toHaveCount(1);
  await expect(status).toContainText('Run 1 recorded');
  // Dispatch both events in the same turn, before the pending run can complete.
  for (const change of ['edit', 'reset']) {
    await exhibit.evaluate((element, action) => {
      const input = element.querySelector('input')!;
      const buttons = Array.from(element.querySelectorAll('button'));
      buttons.find(button => button.textContent === 'Run OPRF')!.click();
      if (action === 'edit') {
        input.value += '!';
        input.dispatchEvent(new Event('input', { bubbles: true }));
      } else {
        buttons.find(button => button.textContent === 'Reset')!.click();
      }
    }, change);
    await expect(run).toBeEnabled();
    await expect(cards).toHaveCount(0);
    await expect(status).not.toContainText('Run 1 recorded');
  }
  await password.fill('');
  await run.click();
  await expect(cards).toHaveCount(0);
  await expect(status).toContainText('Enter a password');
});

test('the registration record shows the three client uploads and their total', async ({ page }) => {
  await page.goto('.');
  const panel = page.locator('#ex3-panel-reg');
  await panel.getByRole('button', { name: 'Register', exact: true }).click();
  const record = panel.locator('.reg-result');
  await expect(record).toContainText('client uploaded 129 bytes');
  for (const [field, bytes] of [['client_public_key', 33], ['masking_key', 32], ['envelope', 64]] as const) {
    await expect(record.getByRole('region', {
      name: new RegExp('^' + field + ' \\(client → server\\): ' + bytes + ' bytes,'),
    })).toHaveCount(1);
  }
});
