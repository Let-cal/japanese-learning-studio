import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

test('public sample works without login; route heading and title follow navigation', async ({ page }) => {
  await page.goto('/demo');
  await expect(page.getByRole('heading', { name: 'A little practice, a clearer tomorrow.' })).toBeVisible();
  await expect(page.getByText('Sample workspace', { exact: true })).toBeVisible();
  await page.getByRole('navigation', { name: 'Study' }).getByRole('link', { name: 'Library' }).click();
  await expect(page).toHaveURL(/\/demo\/library$/);
  await expect(page).toHaveTitle('Library · Japanese Learning Studio sample');
  await expect(page.getByRole('heading', { name: 'Your sample wordbook' })).toBeFocused();
  await page.getByRole('searchbox').fill('みなおす');
  await expect(page.getByText('見直す', { exact: true })).toBeVisible();
  await expect(page.getByText('続ける', { exact: true })).toHaveCount(0);
});

test('sample practice reveals a prepared example, resets only its state, and effects persist', async ({ page }) => {
  await page.goto('/demo/practice');
  await page.evaluate(() => localStorage.setItem('unrelated-owner-marker', 'keep'));
  await page.getByRole('button', { name: 'Turn effects off' }).click();
  await page.getByRole('button', { name: 'Show sample meaning' }).click();
  await expect(page.getByText('xem lại; cân nhắc lại', { exact: true })).toBeVisible();
  await expect(page.locator('.sample-answer p').last()).toHaveAttribute('lang', 'vi');
  await page.reload();
  await expect(page.getByRole('button', { name: 'Turn effects on' })).toBeVisible();
  await page.getByRole('link', { name: 'Demo guide' }).click();
  await page.getByRole('button', { name: 'Reset sample workspace' }).click();
  await expect(page.getByRole('status')).toContainText('Sample workspace reset');
  expect(await page.evaluate(() => localStorage.getItem('unrelated-owner-marker'))).toBe('keep');
  await page.goto('/demo/practice');
  await expect(page.getByRole('button', { name: 'Show sample meaning' })).toBeVisible();
});

test('OS reduced motion remains effective and keyboard skip link reaches content', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('/demo');
  await expect(page.locator('[data-effects="off"]')).toBeVisible();
  await page.getByRole('button', { name: 'Turn effects off' }).click();
  await page.getByRole('button', { name: 'Turn effects on' }).click();
  await expect(page.locator('[data-effects="off"]')).toBeVisible();
  await page.reload();
  await page.keyboard.press('Tab');
  await expect(page.getByRole('link', { name: 'Skip to content' })).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.locator('main')).toBeFocused();
  await page.getByRole('navigation', { name: 'Study' }).getByRole('link', { name: 'Practice' }).focus();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('heading', { name: 'Notice. Recall. Look again.' })).toBeFocused();
  await page.getByRole('button', { name: 'Show sample meaning' }).focus();
  await page.keyboard.press('Enter');
  await expect(page.getByText('xem lại; cân nhắc lại', { exact: true })).toBeVisible();
});

for (const width of [320, 390, 768, 1024, 1440]) {
  test(`sample is usable at ${width}px with no overflow or axe violations`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    for (const route of ['', '/library', '/practice', '/progress', '/guide']) {
      await page.goto(`/demo${route}`);
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
      await expect(page.getByRole('navigation', { name: 'Study' })).toBeVisible();
      const result = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze();
      expect(result.violations).toEqual([]);
      await page.screenshot({ path: `artifacts/task1/sample-${width}-${route.slice(1) || 'today'}.png`, fullPage: true });
    }
  });
}

test('public browser makes no provider calls or private credential bundle references', async ({ page }) => {
  const requests: string[] = [];
  page.on('request', request => requests.push(request.url()));
  await page.goto('/demo');
  const scripts = await page.locator('script[src]').evaluateAll(nodes => nodes.map(node => (node as HTMLScriptElement).src));
  for (const script of scripts) {
    const source = await (await page.request.get(script)).text();
    expect(source).not.toMatch(/SUPABASE_SERVICE_ROLE_KEY|GOOGLE_CLIENT_SECRET|GEMINI_API_KEY|DATABASE_URL/);
  }
  expect(requests.filter(url => !url.startsWith('http://127.0.0.1:3101'))).toEqual([]);
});

test('sample reveal and effects remain usable when browser storage is blocked', async ({ page }) => {
  await page.addInitScript(() => {
    for (const method of ['getItem', 'setItem', 'removeItem']) Object.defineProperty(Storage.prototype, method, { value: () => { throw new DOMException('Storage disabled', 'SecurityError'); } });
  });
  await page.goto('/demo/practice');
  await page.getByRole('button', { name: 'Show sample meaning' }).click();
  await expect(page.getByText('xem lại; cân nhắc lại', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Turn effects off' }).click();
  await expect(page.getByRole('button', { name: 'Turn effects on' })).toBeVisible();
});

test('sample actions remain usable when storage reads work but writes exceed quota', async ({ page }) => {
  await page.addInitScript(() => {
    Object.defineProperty(Storage.prototype, 'setItem', { value: () => { throw new DOMException('Quota exceeded', 'QuotaExceededError'); } });
  });
  await page.goto('/demo/practice');
  await page.getByRole('button', { name: 'Show sample meaning' }).click();
  await expect(page.getByText('xem lại; cân nhắc lại', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Turn effects off' }).click();
  await expect(page.getByRole('button', { name: 'Turn effects on' })).toBeVisible();
  await page.getByRole('link', { name: 'Demo guide' }).click();
  await page.getByRole('button', { name: 'Reset sample workspace' }).click();
  await page.getByRole('navigation', { name: 'Study' }).getByRole('link', { name: 'Practice' }).click();
  await expect(page.getByRole('button', { name: 'Show sample meaning' })).toBeVisible();
});
