import { expect, test } from '@playwright/test';

const baseURL = process.env.UI_BASE_URL || 'http://127.0.0.1:18501';

test('节点工作流和响应式契约保持可用', async ({ page }) => {
  test.setTimeout(90_000);
  const username = `ui-${Date.now()}`;
  await page.goto(`${baseURL}/?auth=register`);
  for (const text of ['WireGuard', 'Mihomo Meta v1.19.29', 'OpenClash', 'Nikki', 'Clash Verge Rev', 'FlClash']) {
    await expect(page.getByText(text, { exact: false }).first()).toBeVisible();
  }
  await expect(page.getByText(/注册后账号处于待配置状态/)).toBeVisible();
  await page.setViewportSize({ width: 390, height: 844 });
  let widths = await page.evaluate(() => ({
    scroll: document.documentElement.scrollWidth,
    client: document.documentElement.clientWidth,
  }));
  expect(widths.scroll).toBe(widths.client);
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.getByRole('textbox', { name: '用户名' }).fill(username);
  await page.getByRole('textbox', { name: '密码', exact: true }).fill('Browser-test-2026!');
  await page.getByRole('textbox', { name: '确认密码' }).fill('Browser-test-2026!');
  await page.getByRole('button', { name: '注册并进入控制台' }).click();
  await expect(page.getByRole('heading', { name: '配置工作台' })).toBeVisible();

  await page.getByRole('tab', { name: '导入节点' }).click();
  await expect(page.getByText('来源名称')).toHaveCount(0);
  await expect(page.getByText(/导入来源（/)).toHaveCount(0);
  const yamlInput = page.locator('textarea').first();
  await expect(yamlInput).toBeVisible({ timeout: 45_000 });
  await yamlInput.fill(
    '[{name: Alpha, type: ss, server: 1.1.1.1, port: 1001, cipher: aes-128-gcm, password: test-a},' +
    '{name: Beta, type: ss, server: 2.2.2.2, port: 1002, cipher: aes-128-gcm, password: test-b},' +
    '{name: Gamma, type: ss, server: 3.3.3.3, port: 1003, cipher: aes-128-gcm, password: test-c}]',
  );
  await page.getByRole('button', { name: '解析并加入草稿' }).click();
  await expect(page.getByText('已加入草稿：3 个新节点。')).toBeVisible();

  await page.getByRole('tab', { name: '节点管理' }).click();
  const components = page.locator('[data-testid="stCustomComponentV1"]');
  await expect(components).toHaveCount(3, { timeout: 30_000 });
  const firstHandle = components.nth(0).contentFrame().getByRole('button');
  const lastHandle = components.nth(2).contentFrame().getByRole('button');
  await firstHandle.dragTo(lastHandle);
  await expect(page.locator('.node-card-summary strong')).toHaveText(['Beta', 'Gamma', 'Alpha']);

  await page.getByRole('button', { name: '编辑' }).first().click();
  const editor = page.getByRole('textbox', { name: '节点配置 YAML' });
  await expect(editor).toBeVisible();
  await expect(editor).not.toHaveValue(/_source_name|_source_id/);

  await page.getByRole('tab', { name: '分流规则' }).click();
  for (const title of ['DustinWin 预设规则目标', '单条规则（0）', '添加新规则集']) {
    const details = page.locator('details').filter({ hasText: title }).first();
    await expect(details).toBeVisible({ timeout: 30_000 });
    expect(await details.evaluate((element) => element.open)).toBe(false);
  }

  await page.getByRole('tab', { name: '生成与检查' }).click();
  await page.getByRole('button', { name: '检查草稿' }).click();
  await expect(page.getByText('草稿已通过结构检查和 mihomo 内核校验，可以发布。')).toBeVisible({ timeout: 45_000 });
  await expect(page.getByRole('tabpanel', { name: '生成与检查' }).getByText('发布差异')).toBeVisible();

  await page.setViewportSize({ width: 390, height: 844 });
  widths = await page.evaluate(() => ({
    scroll: document.documentElement.scrollWidth,
    client: document.documentElement.clientWidth,
  }));
  expect(widths.scroll).toBe(widths.client);
});
