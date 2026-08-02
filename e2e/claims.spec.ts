import { expect, test } from '@playwright/test';
import type { Page } from '@playwright/test';

test('the internal-mode envelope is described as authentication, not encryption', async ({ page }) => {
  await page.goto('.');

  const hero = page.locator('.cl-hero-desc');
  await expect(hero).toContainText('authenticated envelope');
  await expect(hero).toContainText('nonce + HMAC authentication tag (no ciphertext)');

  const body = page.locator('body');
  await expect(body).not.toContainText('encrypted-envelope');
  await expect(body).not.toContainText('encrypted envelope');
  await expect(body).not.toContainText('decrypt the envelope');
});

/** Register, then step KE1 → KE2 → KE3 → verify, leaving the 3DH reveal open. */
async function completeLogin(page: Page): Promise<void> {
  await page.goto('.');
  await page.getByRole('button', { name: 'Register' }).first().click();
  await expect(page.locator('.reg-result')).toBeVisible({ timeout: 60000 });
  await page.getByRole('tab', { name: 'LOGIN' }).click();
  for (const step of [/^Start login/, /^Send KE2/, /^Send KE3/, /^Server verifies/]) {
    await page.getByRole('button', { name: step }).click();
    await expect(page.getByRole('button', { name: step })).toHaveCount(0, { timeout: 60000 });
  }
  await expect(page.locator('.fs-poke')).toBeVisible({ timeout: 60000 });
}

/**
 * The forward-secrecy panel must *measure* the property, not narrate it. This
 * pins both directions of the experiment it runs:
 *
 *   positive — 3DH: the attacker holds the leaked session key AND both
 *              long-term secret keys AND the transcript, and still cannot open
 *              the next session;
 *   negative — static-only: the same attacker, the same stolen keys, the same
 *              key schedule minus the ephemeral terms, opens both sessions.
 *
 * If the negative row ever stops reporting a break, the exhibit has stopped
 * demonstrating what forward secrecy costs, and this fails.
 */
test('the forward-secrecy panel computes the attack in both directions', async ({ page }) => {
  test.setTimeout(180000);
  await completeLogin(page);

  await page.getByRole('button', { name: /run the attack/i }).click();

  const verdict = page.locator('.fs-verdict');
  await expect(verdict).toBeVisible({ timeout: 120000 });

  const rows = page.locator('.fs-fact');
  await expect(rows).toHaveCount(5);

  // Positive case: forward secrecy holds, and it holds because the AEAD said so.
  await expect(rows.nth(1)).toContainText('Leaked session key A vs. session B traffic');
  await expect(rows.nth(1)).toContainText('GCM tag rejected');
  await expect(rows.nth(1)).toHaveAttribute('data-fs-measured', 'attacker-blocked');

  await expect(rows.nth(3)).toContainText('one guess at dh1');
  await expect(rows.nth(3)).toContainText('did NOT decrypt');
  await expect(rows.nth(3)).toHaveAttribute('data-fs-measured', 'attacker-blocked');

  // The attacker really did rebuild two of the three DH terms — otherwise the
  // "blocked" result above would prove nothing about dh1 in particular.
  await expect(rows.nth(2)).toContainText('dh2 matches the real dh2');
  await expect(rows.nth(2)).toContainText('dh3 matches the real dh3');
  await expect(rows.nth(2)).toHaveAttribute('data-fs-measured', 'attacker-won');

  // Negative case: the static-only scheme is broken, and that break is reached,
  // not asserted — both sessions decrypt under the recomputed long-term key.
  await expect(rows.nth(4)).toContainText('static-only scheme');
  await expect(rows.nth(4)).toContainText('long-term shared secret recomputed exactly');
  await expect(rows.nth(4)).toContainText('session A traffic DECRYPTED');
  await expect(rows.nth(4)).toContainText('session B traffic DECRYPTED');
  await expect(rows.nth(4)).toHaveAttribute('data-fs-measured', 'attacker-won');

  await expect(verdict).toHaveAttribute('data-fs-verdict', 'held');
  await expect(verdict).toContainText('forward secrecy HELD');
  await expect(verdict).toContainText('opened both sessions');
});

/**
 * The old panel stated three conclusions in prose and computed none of them.
 * Guard against a regression back to that shape.
 */
test('the forward-secrecy panel does not assert its conclusions in prose', async ({ page }) => {
  test.setTimeout(180000);
  await completeLogin(page);

  const poke = page.locator('.fs-poke');
  await expect(poke).not.toContainText('Past and future logins are safe');
  await expect(poke).not.toContainText('stealing the long-term keys once would regenerate');
});
