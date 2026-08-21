import { expect, test } from '@playwright/test';

const baseURL = process.env.UI_BASE_URL || 'http://127.0.0.1:18501';
const apiBaseURL = process.env.UI_API_BASE_URL;

test('节点工作流和响应式契约保持可用', async ({ page }) => {
  test.setTimeout(360_000);
  const username = `ui-${Date.now()}`;
  await page.goto(`${baseURL}/?auth=register`);
  for (const text of [
    'Shadowsocks',
    'VMess',
    'VLESS',
    'Trojan',
    'AnyTLS',
    'Hysteria2',
    'TUIC',
    'Mihomo Meta v1.19.29',
    'OpenClash',
    'Nikki',
    'Clash Verge Rev',
    'FlClash',
  ]) {
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
  if (apiBaseURL) {
    const csrfToken = await page.locator('form.auth-form[action="/sub/auth/register"] input[name="csrf_token"]').inputValue();
    const registerResponse = await page.request.post(`${apiBaseURL}/sub/auth/register`, {
      form: {
        username,
        password: 'Browser-test-2026!',
        password_confirm: 'Browser-test-2026!',
        csrf_token: csrfToken,
      },
      headers: { Origin: baseURL },
      maxRedirects: 0,
    });
    expect(registerResponse.status()).toBe(303);
    expect(registerResponse.headers().location).toBe('/');
    await page.goto(baseURL);
  } else {
    await page.getByRole('button', { name: '注册并进入控制台' }).click();
  }
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

  // Invalid raw edits must fail in the shared importer before Streamlit can
  // replace the in-memory node or persist a contaminated draft.
  for (const invalidPort of ['true', 'false', '443.0', '443.5']) {
    await editor.fill(`- name: Beta\n  type: ss\n  server: 2.2.2.2\n  port: ${invalidPort}\n  cipher: aes-128-gcm\n  password: test-b\n`);
    await page.getByRole('button', { name: '保存修改' }).click();
    const editError = page.getByRole('alert').last();
    await expect(editError).toBeVisible({ timeout: 30_000 });
    await expect(editError).toContainText('YAML 解析错误');
    await expect(editError).toContainText('端口');
    await expect(page.locator('.node-card-summary').filter({ hasText: 'Beta' })).toContainText('2.2.2.2:1002');
    await expect(editor).toBeVisible();
  }
  await page.reload({ waitUntil: 'domcontentloaded' });
  await expect(page.getByRole('heading', { name: '配置工作台' })).toBeVisible({ timeout: 45_000 });
  await page.getByRole('tab', { name: '节点管理' }).click();
  await expect(page.locator('[data-testid="stCustomComponentV1"]')).toHaveCount(3, { timeout: 30_000 });
  await expect(page.locator('.node-card-summary').filter({ hasText: 'Beta' })).toContainText('2.2.2.2:1002');

  // Exercise the real Streamlit manual form: the checkbox must reach the
  // shared builder so the generated YAML contains the selected dialer-proxy.
  await page.getByRole('tab', { name: '导入节点' }).click();
  const manualModeRadio = page.getByRole('radio', { name: '手动添加' });
  await manualModeRadio.check({ force: true });
  await expect(manualModeRadio).toBeChecked();
  await expect(page.getByRole('textbox', { name: '节点名称' })).toBeVisible({ timeout: 30_000 });
  await page.getByRole('textbox', { name: '节点名称' }).fill('Chain-Node');
  await page.getByRole('textbox', { name: '服务器地址' }).fill('chain.example.com');
  await page.getByRole('spinbutton', { name: '端口' }).fill('9443');
  await page.getByRole('textbox', { name: '密码', exact: true }).fill('chain-password');
  const dialerCheckbox = page.getByRole('checkbox', { name: '使用链式代理 (dialer-proxy)' });
  await dialerCheckbox.click({ force: true });
  await expect(page.getByRole('checkbox', { name: '使用链式代理 (dialer-proxy)' })).toBeChecked();
  const dialerSelect = page.getByRole('combobox', { name: '选择前置代理节点' });
  await expect(dialerSelect).toBeVisible({ timeout: 30_000 });
  await dialerSelect.click();
  await page.getByRole('option', { name: 'Alpha', exact: true }).click();
  const manualYaml = page.getByRole('textbox', { name: '当前节点 YAML（可手动编辑）' });
  await expect(manualYaml).toHaveValue(/dialer-proxy:\s*Alpha/);
  await page.getByRole('button', { name: '校验并添加节点' }).click();
  await expect(page.getByText("节点 'Chain-Node' 已添加。", { exact: true })).toBeVisible({ timeout: 30_000 });

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
