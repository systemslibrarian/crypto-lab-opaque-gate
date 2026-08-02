import { expect, test } from '@playwright/test';

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
