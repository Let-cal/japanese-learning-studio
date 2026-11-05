import { test, expect, type Page } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

async function selectFirstTwo(page: Page) {
  const words = page.getByRole('group', { name: '1. Sample words' });
  await words.getByRole('checkbox', { name: /準備/ }).uncheck();
  await words.getByRole('checkbox', { name: /休憩/ }).uncheck();
}

test('exact subset, all abilities, format rejection, pending help and a real partial summary', async ({ page }) => {
  await page.goto('/demo/practice');
  await selectFirstTwo(page);
  await expect(page.getByRole('status')).toContainText('2 selected words · 2 words with questions · 6 ability questions');
  await page.getByRole('button', { name: 'Start sample practice' }).click();
  const meaning = page.getByRole('textbox', { name: 'Meaning answer' });
  await expect(meaning).toHaveAttribute('lang', 'vi');
  await expect(page.locator('.recall-prompt [lang="ja"]')).toHaveText('見直す — 週末に、来週の計画を見直します。');
  await expect(meaning).toBeFocused();
  await page.getByRole('button', { name: 'Confirm answer' }).click();
  await expect(page.locator('#sample-input-error')).toContainText('No answer was recorded');
  await meaning.fill('みなおす');
  await page.getByRole('button', { name: 'Confirm answer' }).click();
  await expect(meaning).toHaveValue('みなおす');
  await expect(meaning).toBeFocused();
  await expect(page.locator('#sample-input-error')).toContainText('Use Vietnamese');
  await expect(page.getByRole('button', { name: 'Next question →' })).toHaveCount(0);
  await meaning.fill('  xem lại  ');
  await page.getByRole('button', { name: 'Confirm answer' }).click();
  await expect(page.getByRole('status', { name: 'Answer feedback' })).toContainText('Matched the reviewed sample');
  await expect(page.getByRole('status', { name: 'Answer feedback' })).toBeFocused();
  await page.getByRole('button', { name: 'Next question →' }).click();
  const kana = page.getByRole('textbox', { name: 'Kana answer' });
  await expect(kana).toHaveAttribute('lang', 'ja');
  await kana.fill('minaosu');
  await page.getByRole('button', { name: 'Confirm answer' }).click();
  await expect(page.locator('#sample-input-error')).toContainText('Use kana only');
  await expect(kana).toBeFocused();
  await kana.fill('みなす');
  await page.getByRole('button', { name: 'Confirm answer' }).click();
  await expect(page.getByRole('status', { name: 'Answer feedback' })).toContainText('Incorrect for this sample');
  await page.getByRole('button', { name: 'Next question →' }).click();
  const options = page.getByRole('radio');
  await expect(options).toHaveCount(2);
  await expect(page.locator('.recall-prompt [lang="ja"]')).toHaveText('みなおす');
  await expect(page.locator('.recall-prompt [lang="vi"]')).toHaveText('xem lại; cân nhắc lại');
  await page.getByRole('radio', { name: '続ける', exact: true }).check();
  await page.getByRole('radio', { name: '見直す', exact: true }).check();
  await expect(page.getByRole('status', { name: 'Answer feedback' })).toHaveCount(0);
  await page.getByRole('button', { name: 'Confirm answer' }).click();
  await page.getByRole('button', { name: 'Next question →' }).click();
  await page.getByRole('button', { name: 'Show sample help' }).click();
  await expect(page.getByText('Assisted practice', { exact: true })).toBeVisible();
  await page.getByRole('textbox', { name: 'Meaning answer' }).fill('làm mãi một việc');
  await page.getByRole('button', { name: 'Confirm answer' }).click();
  await expect(page.getByRole('status', { name: 'Answer feedback' })).toContainText('Pending — meaning needs review · Assisted');
  await page.getByRole('button', { name: 'Finish now' }).click();
  await expect(page.getByRole('heading', { name: 'Your sample practice summary' })).toBeFocused();
  await expect(page.getByText('4 of 6 questions answered. 2 untested.', { exact: true })).toBeVisible();
  const rows = page.getByRole('row');
  await expect(rows.filter({ has: page.getByRole('rowheader', { name: 'Meaning', exact: true }) }).locator('th, td')).toHaveText(['Meaning', '2 / 2', '1', '0', '1', '1', '0']);
  expect(await page.locator('.raw-answer').first().textContent()).toBe('  xem lại  ');
  await expect(page.locator('.answer-history li')).toHaveCount(4);
  await expect(page.locator('.raw-answer').first()).toHaveAttribute('lang', 'vi');
  await expect(page.locator('.raw-answer').nth(1)).toHaveAttribute('lang', 'ja');
  await expect(page.locator('.answer-history li').nth(2).locator('.history-prompt [lang="ja"]')).toHaveText('みなおす');
  await expect(page.locator('.answer-history li').nth(2).locator('.history-prompt [lang="vi"]')).toHaveText('xem lại; cân nhắc lại');
  await page.reload();
  await expect(page.getByRole('button', { name: 'Start sample practice' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Your sample practice summary' })).toHaveCount(0);
});

test('single word excludes Kanji without padding; empty selections cannot start', async ({ page }) => {
  await page.goto('/demo/practice');
  await selectFirstTwo(page);
  await page.getByRole('checkbox', { name: /続ける/ }).uncheck();
  await expect(page.getByRole('status')).toContainText('1 selected words · 1 words with questions · 2 ability questions');
  await expect(page.getByRole('status')).toContainText('Needs at least two distinct selected words; no extra words added.');
  await page.getByRole('checkbox', { name: /Meaning/ }).uncheck();
  await page.getByRole('checkbox', { name: /Kana/ }).uncheck();
  await expect(page.getByRole('button', { name: 'Start sample practice' })).toBeDisabled();
  await page.getByRole('checkbox', { name: /Kanji/ }).uncheck();
  await expect(page.getByRole('status')).toContainText('Select at least one ability.');
  await page.getByRole('checkbox', { name: /見直す/ }).uncheck();
  await expect(page.getByRole('status')).toContainText('Select at least one sample word.');
});

test('IME Enter does not commit; keyboard confirms and finish without an answer stays untested', async ({ page }) => {
  await page.goto('/demo/practice');
  await page.getByRole('button', { name: 'Start sample practice' }).focus();
  await page.keyboard.press('Enter');
  const input = page.getByRole('textbox', { name: 'Meaning answer' });
  await input.fill('xem lại');
  await input.dispatchEvent('compositionstart');
  await page.keyboard.press('Enter');
  await expect(page.getByRole('status', { name: 'Answer feedback' })).toHaveCount(0);
  await expect(input).toHaveValue('xem lại');
  await input.dispatchEvent('compositionend');
  await page.keyboard.press('Enter');
  await expect(page.getByRole('status', { name: 'Answer feedback' })).toContainText('Matched');
  await page.getByRole('button', { name: 'Next question →' }).click();
  await page.getByRole('button', { name: 'Finish now' }).click();
  await expect(page.getByText('1 of 12 questions answered. 11 untested.', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Build another sample' }).click();
  await page.getByRole('button', { name: 'Start sample practice' }).click();
  await page.getByRole('button', { name: 'Finish now' }).click();
  await expect(page.getByText('0 of 12 questions answered. 12 untested.', { exact: true })).toBeVisible();
});

for (const width of [320, 768, 1440]) {
  test(`recall builder, question and partial results stay accessible at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await page.goto('/demo/practice');
    await page.getByRole('radio', { name: 'Shuffle selected words' }).check();
    await expect(page.locator('.scope-note ol li')).toHaveCount(4);
    for (const stage of ['builder', 'question', 'result']) {
      if (stage === 'question') await page.getByRole('button', { name: 'Start sample practice' }).click();
      if (stage === 'result') await page.getByRole('button', { name: 'Finish now' }).click();
      if (stage === 'result' && width < 1440) {
        const summary = page.getByRole('region', { name: 'Sample results by ability' });
        await summary.focus();
        await expect(summary).toBeFocused();
        await summary.press('ArrowRight');
        await expect.poll(() => summary.evaluate(node => node.scrollLeft)).toBeGreaterThan(0);
      }
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
      expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze()).violations).toEqual([]);
      await expect(page.locator('[data-effects="off"]')).toBeVisible();
    }
  });
}
