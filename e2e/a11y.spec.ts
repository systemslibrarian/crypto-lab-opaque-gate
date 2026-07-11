import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. Deploys are already gated on functional tests; this
 * gates them on accessibility the same way. Scans the full page with every
 * collapsible expanded and every tab panel revealed, in both themes.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/**
 * Reveal everything axe would otherwise skip: expand any <details>, force all
 * tab panels visible (the login tabpanel is hidden until its tab is clicked),
 * drop [hidden]/display:none on class-toggled panels, and neutralise
 * animations/transitions/opacity so a mid-fade frame can't invent a phantom
 * contrast failure.
 */
async function revealAll(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `*,*::before,*::after{
      animation:none!important;
      transition:none!important;
      opacity:1!important;
    }`,
  });
  await page.evaluate(() => {
    for (const details of document.querySelectorAll('details')) {
      (details as HTMLDetailsElement).open = true;
    }
    // Reveal every tabpanel so its contents are scanned.
    for (const panel of document.querySelectorAll<HTMLElement>('.protocol-panel')) {
      panel.classList.add('active');
      panel.hidden = false;
      panel.style.display = 'block';
    }
    // Generic: un-hide anything the app collapsed.
    for (const el of document.querySelectorAll<HTMLElement>('[hidden]')) {
      el.hidden = false;
    }
  });
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await revealAll(page);
  await scan(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await revealAll(page);
  await scan(page);
});
