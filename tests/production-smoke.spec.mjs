import { expect, test } from '@playwright/test';

const baseURL = process.env.UI_BASE_URL || 'https://clash.910501.xyz';

test('生产登录页可用且无前端异常', async ({ page }) => {
  const errors = [];
  const failedRequests = [];
  page.on('pageerror', (error) => errors.push(error.message));
  page.on('console', (message) => {
    if (message.type() === 'error') errors.push(message.text());
  });
  page.on('requestfailed', (request) => {
    failedRequests.push(`${request.url()} :: ${request.failure()?.errorText || 'unknown'}`);
  });

  const response = await page.goto(baseURL, { waitUntil: 'domcontentloaded' });
  expect(response?.status()).toBe(200);
  await expect(page.getByRole('heading', { name: '欢迎回来' })).toBeVisible({ timeout: 30_000 });
  await expect(page.getByRole('textbox', { name: '用户名' })).toBeVisible();
  await expect(page.getByRole('textbox', { name: '密码', exact: true })).toBeVisible();
  const csrfToken = page.locator('form[action="/sub/auth/login"] input[name="csrf_token"]');
  await expect(csrfToken).toHaveAttribute('value', /.+/);

  await page.setViewportSize({ width: 390, height: 844 });
  await expect(page.getByRole('button', { name: '安全登录' })).toBeVisible();
  const widths = await page.evaluate(() => ({
    scroll: document.documentElement.scrollWidth,
    client: document.documentElement.clientWidth,
  }));
  expect(widths.scroll).toBe(widths.client);
  const applicationFailures = failedRequests.filter(
    (failure) => !failure.startsWith('https://static.cloudflareinsights.com/'),
  );
  const applicationErrors = errors.filter(
    (error) => !(failedRequests.some((failure) => failure.startsWith('https://static.cloudflareinsights.com/'))
      && error === 'Failed to load resource: net::ERR_CONNECTION_CLOSED'),
  );
  expect(applicationFailures).toEqual([]);
  expect(applicationErrors, failedRequests.join('\n')).toEqual([]);
});
