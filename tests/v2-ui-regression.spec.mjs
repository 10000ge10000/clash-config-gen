import { expect, test } from '@playwright/test';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { access, mkdtemp, readFile, rm } from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

test.describe.configure({ mode: 'serial' });

const repoRoot = fileURLToPath(new URL('..', import.meta.url));
const adminUsername = 'e2e-admin';
const adminPassword = 'E2e-admin-password-2026!';
const temporaryUserPassword = 'E2e-temporary-password-2026!';

let serverProcess;
let serverTempDir;
let baseURL;
let serverOutput = '';

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function availablePort() {
  const listener = net.createServer();
  await new Promise((resolve, reject) => {
    listener.once('error', reject);
    listener.listen(0, '127.0.0.1', resolve);
  });
  const address = listener.address();
  const port = typeof address === 'object' && address ? address.port : 0;
  await new Promise((resolve, reject) => listener.close((error) => (error ? reject(error) : resolve())));
  return port;
}

async function waitForHealth(url) {
  let lastError = '服务尚未就绪';
  for (let attempt = 0; attempt < 120; attempt += 1) {
    if (serverProcess && serverProcess.exitCode !== null) {
      throw new Error(`FastAPI 提前退出（${serverProcess.exitCode}）：${serverOutput.slice(-4000)}`);
    }
    try {
      const response = await fetch(`${url}/health`, { signal: AbortSignal.timeout(1000) });
      if (response.ok) {
        const body = await response.json();
        if (body && body.status === 'ok') return;
        lastError = `健康检查返回非 ready：${JSON.stringify(body)}`;
      } else {
        lastError = `健康检查 HTTP ${response.status}`;
      }
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error);
    }
    await delay(250);
  }
  throw new Error(`FastAPI 健康检查超时：${lastError}\n${serverOutput.slice(-4000)}`);
}

async function startIsolatedServer() {
  serverTempDir = await mkdtemp(path.join(os.tmpdir(), 'clash-config-gen-v2-'));
  const port = await availablePort();
  baseURL = `http://127.0.0.1:${port}`;
  const sourcePath = path.join(repoRoot, 'src');
  const databasePath = path.join(serverTempDir, 'e2e.sqlite3');
  const rulesetPath = path.join(serverTempDir, 'rulesets');
  const cachePath = path.join(serverTempDir, 'ruleset-cache');
  const environment = {
    ...process.env,
    PYTHONPATH: [sourcePath, process.env.PYTHONPATH].filter(Boolean).join(path.delimiter),
    APP_DB_PATH: databasePath,
    RULESET_DIR: rulesetPath,
    RULESET_CACHE_DIR: cachePath,
    RULESET_CACHE_ENABLED: 'false',
    PUBLIC_BASE_URL: baseURL,
    CSRF_SECRET: 'e2e-disposable-csrf-secret-2026-long',
    AUTH_COOKIE_SECURE: 'false',
    ALLOW_REGISTRATION: 'true',
    MIHOMO_VALIDATE_ENABLED: 'false',
    ADMIN_USERNAME: adminUsername,
    ADMIN_PASSWORD: adminPassword,
  };

  serverProcess = spawn(
    process.env.PYTHON || 'python',
    ['-m', 'uvicorn', 'api:app', '--host', '127.0.0.1', '--port', String(port)],
    { cwd: repoRoot, env: environment, stdio: ['ignore', 'pipe', 'pipe'] },
  );
  serverProcess.stdout.on('data', (chunk) => {
    serverOutput = `${serverOutput}${chunk}`.slice(-12000);
  });
  serverProcess.stderr.on('data', (chunk) => {
    serverOutput = `${serverOutput}${chunk}`.slice(-12000);
  });
  await waitForHealth(baseURL);
}

async function stopIsolatedServer() {
  const child = serverProcess;
  serverProcess = undefined;
  if (child && child.exitCode === null && !child.killed) {
    child.kill('SIGTERM');
    await Promise.race([once(child, 'exit'), delay(5000)]);
    if (child.exitCode === null) {
      child.kill();
      await Promise.race([once(child, 'exit'), delay(2000)]);
    }
  }
  if (serverTempDir) {
    const exactTempDir = serverTempDir;
    serverTempDir = undefined;
    await rm(exactTempDir, { recursive: true, force: true });
  }
}

async function waitForSaved(page) {
  await expect.poll(
    () => page.evaluate(() => window.v2State && {
      dirty: window.v2State.dirtyGeneration,
      saved: window.v2State.savedGeneration,
      saveInFlight: window.v2State.saveInFlight,
      globalSaving: window.v2State.globalSaving,
    }),
    { timeout: 15_000, message: 'V2 草稿未在预期时间内保存' },
  ).toEqual({ dirty: expect.any(Number), saved: expect.any(Number), saveInFlight: false, globalSaving: false });
  await expect.poll(
    () => page.evaluate(() => window.v2State && window.v2State.dirtyGeneration === window.v2State.savedGeneration),
    { timeout: 15_000, message: 'V2 草稿代数未收敛' },
  ).toBe(true);
  await expect(page.locator('#draftStatus')).toHaveText('草稿已保存', { timeout: 15_000 });
}

async function state(page, expression) {
  return page.evaluate(expression);
}

async function importMethod(page, method, value) {
  await page.locator(`.method-card[data-method="${method}"]`).click();
  await page.locator('#importInput').fill(value);
  const responsePromise = page.waitForResponse((response) => response.url() === `${baseURL}/api/import`);
  await page.locator('#importBtn').click();
  return responsePromise;
}

function trackPageFailures(page) {
  const pageErrors = [];
  const failedRequests = [];
  const unexpectedResponses = [];
  const expectedResponses = [];
  const expectedConsoleAllowances = new Map();
  const observedConsoleErrors = [];

  function consoleAllowanceKey(status, message) {
    return `${status}\u0000${message}`;
  }

  function resourceStatusConsoleKey(message) {
    const match = /^Failed to load resource: the server responded with a status of (\d{3}) \(/.exec(message);
    return match ? consoleAllowanceKey(Number(match[1]), message) : undefined;
  }

  function consumeConsoleAllowance(allowances, key) {
    const count = allowances.get(key) || 0;
    if (!count) return false;
    if (count === 1) allowances.delete(key);
    else allowances.set(key, count - 1);
    return true;
  }

  page.on('pageerror', (error) => pageErrors.push(error.message));
  page.on('console', (message) => {
    if (message.type() !== 'error') return;
    const text = message.text();
    const key = resourceStatusConsoleKey(text);
    if (key && consumeConsoleAllowance(expectedConsoleAllowances, key)) return;
    observedConsoleErrors.push({ key, text });
  });
  page.on('requestfailed', (request) => {
    failedRequests.push(`${request.method()} ${request.url()} :: ${request.failure()?.errorText || 'unknown'}`);
  });
  page.on('response', (response) => {
    if (response.ok()) return;
    const request = response.request();
    const expectedIndex = expectedResponses.findIndex((entry) => entry.match(response, request));
    if (expectedIndex >= 0) {
      const expected = expectedResponses.splice(expectedIndex, 1)[0];
      if (expected.consoleError) {
        const key = consoleAllowanceKey(response.status(), expected.consoleError);
        expectedConsoleAllowances.set(key, (expectedConsoleAllowances.get(key) || 0) + 1);
      }
      return;
    }
    unexpectedResponses.push(`${request.method()} ${response.status()} ${response.url()}`);
  });

  return {
    allowResponse(match, description, consoleError) {
      expectedResponses.push({ match, description, consoleError });
    },
    assertClean() {
      const unmatchedExpectedConsoleAllowances = new Map(expectedConsoleAllowances);
      const unmatchedObservedConsoleErrors = [];
      for (const observed of observedConsoleErrors) {
        if (observed.key && consumeConsoleAllowance(unmatchedExpectedConsoleAllowances, observed.key)) continue;
        unmatchedObservedConsoleErrors.push(observed.text);
      }

      expect(expectedResponses.map((entry) => entry.description)).toEqual([]);
      expect(failedRequests).toEqual([]);
      expect(unexpectedResponses).toEqual([]);
      expect(pageErrors).toEqual([]);
      expect(unmatchedExpectedConsoleAllowances).toEqual(new Map());
      expect(unmatchedObservedConsoleErrors).toEqual([]);
    },
    diagnostics() {
      return {
        pageErrors,
        consoleErrors: observedConsoleErrors.map((entry) => entry.text),
        failedRequests,
        unexpectedResponses,
        expectedResponses,
        expectedConsoleErrors: Array.from(expectedConsoleAllowances.entries()),
      };
    },
  };
}

test.beforeAll(async () => {
  try {
    await startIsolatedServer();
  } catch (error) {
    await stopIsolatedServer();
    throw error;
  }
});

test.afterAll(async () => {
  await stopIsolatedServer();
});

// 生产页面默认不暴露内部状态；测试在页面脚本执行前打开调试开关，
// 让 window.v2State / window.saveChain 可用于断言与驱动保存链。
// 标题含“生产路径”的用例不注入，验证生产环境下调试对象不会暴露。
test.beforeEach(async ({ page }, testInfo) => {
  if (testInfo.title.includes('生产路径')) return;
  await page.addInitScript(() => {
    window.__CCG_DEBUG__ = true;
  });
});

test('V2 真实 FastAPI 工作台端到端流程、隔离持久化与响应式契约', async ({ page }) => {
  test.setTimeout(240_000);
  const tracker = trackPageFailures(page);
  const response = await page.goto(`${baseURL}/`, { waitUntil: 'domcontentloaded' });
  expect(response?.status()).toBe(200);

  await expect(page.locator('#loginOverlay')).toHaveClass(/active/);
  expect(await state(page, () => ({ authCsrf: Boolean(window.v2State.authCsrf), csrfToken: Boolean(window.v2State.csrfToken) }))).toEqual({ authCsrf: true, csrfToken: false });
  await page.locator('#loginForm input[name="username"]').fill(adminUsername);
  await page.locator('#loginForm input[name="password"]').fill(adminPassword);
  const loginResponsePromise = page.waitForResponse((loginResponse) => loginResponse.url() === `${baseURL}/api/auth/login`);
  await page.locator('#loginForm button[type="submit"]').click();
  const loginResponse = await loginResponsePromise;
  expect(loginResponse.status(), await loginResponse.text()).toBe(200);
  await expect(page.locator('#loginOverlay')).not.toHaveClass(/active/, { timeout: 15_000 });
  await expect.poll(() => page.evaluate(() => window.v2State.loading), { timeout: 30_000 }).toBe(false);
  expect(await state(page, () => ({
    authenticated: window.v2State.authenticated,
    username: window.v2State.user && window.v2State.user.username,
    loading: window.v2State.loading,
    saveError: window.v2State.saveError,
  }))).toMatchObject({ authenticated: true, username: adminUsername, loading: false, saveError: null });
  await expect(page.locator('#nodeGrid')).toContainText('暂无节点');
  await expect(page.locator('#nodeGrid .node-card')).toHaveCount(0);
  const draftSubscriptionUrl = await page.locator('#subUrl').textContent();
  expect(draftSubscriptionUrl).toMatch(new RegExp(`^${baseURL.replace(/[.*+?^${}()|[\\]\\]/g, '\\$&')}/sub/[^\\s]+$`));
  await expect(page.locator('#subscriptionCardStatus')).toHaveText('● 草稿');
  const initialText = await page.locator('body').innerText();
  expect(initialText).not.toMatch(/(?:demo\s+(?:node|yaml|subscription)|fake\s+latency|static\s+subscription)/i);
  expect(initialText).not.toMatch(/运行时延迟\s*[:：]\s*\d+\s*ms/i);

  for (const [tabId, tabName, panelId] of [
    ['#step-tab-1', '导入节点', '#step1'],
    ['#step-tab-2', '节点管理', '#step2'],
    ['#step-tab-3', '规则与全局', '#step3'],
    ['#step-tab-4', '校验与发布', '#step4'],
  ]) {
    const tab = page.locator(tabId);
    await tab.click();
    await expect(tab).toHaveAttribute('aria-selected', 'true');
    await expect(page.locator(panelId)).toBeVisible();
  }

  await page.locator('#step-tab-1').click();
  const yamlImportResponse = await importMethod(page, 'yaml', `proxies:\n  - name: YAML-Node\n    type: ss\n    server: yaml.example.com\n    port: 443\n    cipher: aes-128-gcm\n    password: yaml-password\n`);
  expect(yamlImportResponse.status(), await yamlImportResponse.text()).toBe(200);
  await expect(page.locator('#nodeGrid .node-card')).toHaveCount(1, { timeout: 15_000 });
  await expect(page.locator('#nodeGrid')).toContainText('YAML-Node');
  await expect(page.locator('#nodeCount')).toHaveText('1');

  const shareImportResponse = await importMethod(page, 'share', 'ss://aes-128-gcm:share-password@share.example.com:8443#Share-Node');
  expect(shareImportResponse.status(), await shareImportResponse.text()).toBe(200);
  await expect(page.locator('#nodeGrid .node-card')).toHaveCount(2, { timeout: 15_000 });
  await expect(page.locator('#nodeGrid')).toContainText('ss-share.example.com');
  await expect(page.locator('#nodeCount')).toHaveText('2');

  const privateImportUrl = 'http://127.0.0.1:9/private-subscription';
  tracker.allowResponse(
    (responseItem, request) => request.method() === 'POST' && responseItem.status() === 400 && responseItem.url() === `${baseURL}/api/import`,
    '预期的私有地址导入拒绝',
    'Failed to load resource: the server responded with a status of 400 (Bad Request)',
  );
  const privateImportResponse = await importMethod(page, 'url', privateImportUrl);
  expect(privateImportResponse.status()).toBe(400);
  await expect(page.locator('.toast').filter({ hasText: 'URL 解析到内网、本机或保留地址，已拒绝服务端访问' }).last()).toBeVisible({ timeout: 15_000 });
  await expect(page.locator('#nodeGrid .node-card')).toHaveCount(2);

  await page.locator('#step-tab-2').click();
  await page.locator('#addNodeBtn').click();
  const nodeForm = page.locator('#nodeFormPanel');
  await expect(nodeForm).toBeVisible();
  await expect(page.locator('#nodeFormTitle')).toHaveText(/添加节点 · ss/);
  await nodeForm.getByLabel('节点名称').fill('Manual-Node');
  await nodeForm.getByLabel('服务器地址').fill('manual.example.com');
  await nodeForm.getByLabel('端口').fill('9443');
  await nodeForm.getByLabel('密码').fill('manual-password');
  await nodeForm.getByRole('button', { name: '保存节点草稿' }).click();
  await expect(page.locator('#nodeGrid .node-card')).toHaveCount(3, { timeout: 15_000 });
  await expect(page.locator('#nodeGrid')).toContainText('Manual-Node');

  const manualCard = page.locator('#nodeGrid .node-card').filter({ hasText: 'Manual-Node' }).first();
  await manualCard.getByRole('button', { name: '编辑' }).click();
  await nodeForm.getByRole('button', { name: '编辑原始 YAML' }).click();
  await nodeForm.getByLabel('节点原始 YAML').fill(`name: Manual-Edited\ntype: ss\nserver: manual-edited.example.com\nport: 9444\ncipher: aes-128-gcm\npassword: edited-password\nudp: true\nx-e2e-extra: preserved\n`);
  await nodeForm.getByRole('button', { name: '保存节点草稿' }).click();
  await expect(page.locator('#nodeGrid')).toContainText('Manual-Edited');
  expect(await state(page, () => window.v2State.config.proxies.find((node) => node.name === 'Manual-Edited')['x-e2e-extra'])).toBe('preserved');
  await waitForSaved(page);

  await page.locator('#nodeGrid .node-card').filter({ hasText: 'Manual-Edited' }).getByRole('button', { name: '编辑' }).click();
  await nodeForm.getByRole('button', { name: '编辑原始 YAML' }).click();
  expect(await state(page, () => window.v2State.nodeForm.raw)).toBe(true);
  for (const invalidPort of ['true', 'false', '443.0', '443.5']) {
    tracker.allowResponse(
      (responseItem, request) => request.method() === 'POST' && responseItem.status() === 400 && responseItem.url() === `${baseURL}/api/import`,
      `预期非法端口 ${invalidPort} 被拒绝`,
      'Failed to load resource: the server responded with a status of 400 (Bad Request)',
    );
    await nodeForm.getByLabel('节点原始 YAML').fill(`name: Manual-Edited\ntype: ss\nserver: manual-edited.example.com\nport: ${invalidPort}\ncipher: aes-128-gcm\npassword: edited-password\nudp: true\nx-e2e-extra: preserved\n`);
    await expect(nodeForm.getByLabel('节点原始 YAML')).toHaveValue(new RegExp(`port: ${invalidPort.replace('.', '\\.')}`));
    const invalidImport = page.waitForResponse((item) => item.url() === `${baseURL}/api/import`);
    await nodeForm.getByRole('button', { name: '保存节点草稿' }).click();
    const invalidImportResponse = await invalidImport;
    expect(invalidImportResponse.status(), await invalidImportResponse.text()).toBe(400);
    await expect(page.locator('.toast').filter({ hasText: '端口' }).last()).toBeVisible({ timeout: 15_000 });
    expect(await state(page, () => ({ raw: window.v2State.nodeForm.raw, value: document.querySelector('#nodeRawEditor')?.value || '' }))).toMatchObject({ raw: true });
    expect(await state(page, () => document.querySelector('#nodeRawEditor')?.value || '')).toContain(`port: ${invalidPort}`);
    expect(await state(page, () => window.v2State.config.proxies.find((node) => node.name === 'Manual-Edited').port)).toBe(9444);
  }
  await nodeForm.getByLabel('节点原始 YAML').fill(`name: Manual-Edited\ntype: ss\nserver: manual-edited.example.com\nport: 9444\ncipher: aes-128-gcm\npassword: edited-password\nudp: true\nx-e2e-extra: preserved\n`);
  const restoreImport = page.waitForResponse((item) => item.url() === `${baseURL}/api/import` && item.status() === 200);
  await nodeForm.getByRole('button', { name: '保存节点草稿' }).click();
  await restoreImport;
  await expect(page.locator('#nodeGrid')).toContainText('Manual-Edited');

  await page.locator('#nodeGrid .node-card').filter({ hasText: 'Manual-Edited' }).getByRole('button', { name: '上移' }).click();
  const namesAfterReorder = await state(page, () => window.v2State.config.proxies.map((node) => node.name));
  expect(namesAfterReorder).toEqual(['YAML-Node', 'Manual-Edited', 'ss-share.example.com']);
  page.once('dialog', (dialog) => dialog.accept());
  await page.locator('#nodeGrid .node-card').filter({ hasText: 'YAML-Node' }).getByRole('button', { name: '删除' }).click();
  await expect(page.locator('#nodeGrid .node-card')).toHaveCount(2);
  await waitForSaved(page);

  await page.locator('#step-tab-3').click();
  const speedSettings = page.locator('#globalSchemaPanel details').filter({ hasText: '测速与性能' }).first();
  await speedSettings.locator('summary').click();
  const tolerance = page.locator('#globalSchemaPanel [data-field-key="url_test_tolerance"]');
  await expect(tolerance).toBeVisible();
  await tolerance.fill('42');
  await tolerance.press('Tab');
  await waitForSaved(page);
  expect(await state(page, () => window.v2State.config.global_config.url_test_tolerance)).toBe(42);

  await expect(page.locator('#presetDesktopBtn')).toBeEnabled({ timeout: 5000 });
  await expect(page.locator('#presetRouterBtn')).toBeEnabled({ timeout: 5000 });
  await expect(page.locator('#modeDesktopBtn')).toBeEnabled({ timeout: 5000 });
  await expect(page.locator('#modeRouterBtn')).toBeEnabled({ timeout: 5000 });
  await page.locator('#presetDesktopBtn').click();
  await waitForSaved(page);
  expect(await state(page, () => window.v2State.config.global_config.generation_profile)).toBe('desktop-full');
  await page.locator('#presetRouterBtn').click();
  await waitForSaved(page);
  expect(await state(page, () => window.v2State.config.global_config.generation_profile)).toBe('openclash-router');
  await expect(page.locator('#modeDesktopBtn')).toBeEnabled({ timeout: 5000 });
  await page.locator('#modeDesktopBtn').click();
  await waitForSaved(page);
  await expect(page.locator('#modeRouterBtn')).toBeEnabled({ timeout: 5000 });
  await page.locator('#modeRouterBtn').click();
  await waitForSaved(page);
  expect(await state(page, () => ({
    profile: window.v2State.config.global_config.generation_profile,
    desktop: window.v2State.config.global_config.is_desktop,
  }))).toEqual({ profile: 'openclash-router', desktop: false });

  const ruleSource = page.locator('#ruleSource');
  await ruleSource.selectOption('lhie1规则');
  await waitForSaved(page);
  await ruleSource.selectOption('none');
  await waitForSaved(page);
  await ruleSource.selectOption('dustinwin规则');
  await waitForSaved(page);

  const providerTargets = page.locator('#providerTargetsPanel');
  await expect(providerTargets).toBeVisible();
  const dustinTarget = providerTargets.locator('select').first();
  // 目标下拉为懒填充：获得焦点后才填入全部候选。
  await dustinTarget.focus();
  const dustinOptions = await dustinTarget.locator('option').evaluateAll((options) => options.map((option) => option.value));
  const dustinDefault = await dustinTarget.inputValue();
  const dustinReplacement = dustinOptions.find((value) => value !== dustinDefault);
  expect(dustinReplacement).toBeTruthy();
  await dustinTarget.selectOption(dustinReplacement);
  await waitForSaved(page);
  expect(Object.keys(await state(page, () => window.v2State.config.global_config.dustinwin_provider_targets))).toHaveLength(1);
  await providerTargets.getByRole('button', { name: '恢复当前规则源默认目标' }).click();
  await waitForSaved(page);
  expect(await state(page, () => window.v2State.config.global_config.dustinwin_provider_targets)).toEqual({});

  await ruleSource.selectOption('lhie1规则');
  await waitForSaved(page);
  await expect(providerTargets).toBeVisible();
  const lhieTarget = providerTargets.locator('select').first();
  await lhieTarget.focus();
  const lhieOptions = await lhieTarget.locator('option').evaluateAll((options) => options.map((option) => option.value));
  const lhieDefault = await lhieTarget.inputValue();
  const lhieReplacement = lhieOptions.find((value) => value !== lhieDefault);
  expect(lhieReplacement).toBeTruthy();
  await lhieTarget.selectOption(lhieReplacement);
  await waitForSaved(page);
  expect(Object.keys(await state(page, () => window.v2State.config.global_config.lhie1_provider_targets))).toHaveLength(1);
  await providerTargets.getByRole('button', { name: '恢复当前规则源默认目标' }).click();
  await waitForSaved(page);
  expect(await state(page, () => window.v2State.config.global_config.lhie1_provider_targets)).toEqual({});

  expect(await page.locator('#ruleTarget option').evaluateAll((options) => options.map((option) => option.value))).not.toContain('no-resolve');
  expect(await page.locator('#rulesetTarget option').evaluateAll((options) => options.map((option) => option.value))).not.toContain('no-resolve');
  await ruleSource.selectOption('none');
  await waitForSaved(page);
  await page.locator('#ruleValue').fill('one.example.test');
  await page.locator('#addRuleBtn').click();
  await waitForSaved(page);
  await page.locator('#ruleValue').fill('two.example.test');
  await page.locator('#addRuleBtn').click();
  await waitForSaved(page);
  expect(await state(page, () => window.v2State.config.custom_rules)).toHaveLength(2);
  await page.locator('#ruleList .rule-item').nth(1).getByRole('button', { name: '上移' }).click();
  await waitForSaved(page);
  expect((await state(page, () => window.v2State.config.custom_rules))[0]).toContain('two.example.test');
  await page.locator('#ruleList .rule-item').first().getByRole('button', { name: '删除' }).click();
  await waitForSaved(page);
  expect(await state(page, () => window.v2State.config.custom_rules)).toHaveLength(1);
  await ruleSource.selectOption('dustinwin规则');
  await waitForSaved(page);

  const httpRulesetUrl = 'http://127.0.0.1:9/e2e-rules.list';
  await page.locator('#rulesetAlias').fill('e2e-http');
  await page.locator('#rulesetUrl').fill(httpRulesetUrl);
  await page.locator('#rulesetSaveBtn').click();
  await waitForSaved(page);
  await expect(page.locator('#rulesetPanel .ruleset-name')).toContainText('e2e-http');
  // 保存后 renderAll 会重建表单；为“测试 URL”重新填入当前表单值，确保请求走到后端。
  await page.locator('#rulesetAlias').fill('e2e-http');
  await page.locator('#rulesetUrl').fill(httpRulesetUrl);
  tracker.allowResponse(
    (responseItem, request) => request.method() === 'POST' && responseItem.status() === 400 && responseItem.url() === `${baseURL}/api/ruleset/test-url`,
    '预期的私有地址规则集 URL 拒绝',
    'Failed to load resource: the server responded with a status of 400 (Bad Request)',
  );
  await page.locator('#rulesetTestUrlBtn').click();
  await expect(page.locator('#rulesetMessage')).toContainText('URL 解析到内网、本机或保留地址，已拒绝服务端访问');

  await page.locator('#rulesetFileModeBtn').click();
  await page.locator('#rulesetAlias').fill('e2e-file');
  await page.locator('#rulesetFile').setInputFiles({
    name: 'e2e-file.yaml',
    mimeType: 'text/yaml',
    buffer: Buffer.from('payload:\n  - DOMAIN-SUFFIX,file.example.test\n', 'utf8'),
  });
  await page.locator('#rulesetUploadBtn').click();
  await waitForSaved(page);
  await expect(page.locator('#rulesetPanel .ruleset-name').filter({ hasText: 'e2e-file' })).toHaveCount(1);
  expect(await state(page, () => window.v2State.config.custom_rule_providers['e2e-file'].type)).toBe('http');
  expect(await state(page, () => window.v2State.config.custom_rule_providers['e2e-file'].proxy)).toBe('DIRECT');
  const uploadedProviderPath = await state(page, () => window.v2State.config.custom_rule_providers['e2e-file'].path);
  expect(uploadedProviderPath).toMatch(/^\.\/ruleset\/users\/\d+\/e2e-file--[0-9a-f]{64}\.yaml$/);
  const uploadedPhysicalPath = path.join(serverTempDir, 'rulesets', ...uploadedProviderPath.split('/').slice(2));
  await access(uploadedPhysicalPath);

  await page.locator('#step-tab-4').click();
  await page.locator('#validateBtn').click();
  await expect(page.locator('#validationStatus')).toHaveText('校验通过，可选择发布', { timeout: 30_000 });
  await expect(page.locator('#checkResults')).toBeVisible();
  await expect(page.locator('#checkResults')).toHaveClass(/show/);
  const validationChecks = await state(page, () => window.v2State.validation && window.v2State.validation.checks);
  expect(Array.isArray(validationChecks)).toBe(true);
  await expect(page.locator('#checkResults > .check-item, #checkResults > .check-empty')).toHaveCount(validationChecks.length ? validationChecks.length : 1);
  await expect(page.locator('#yamlWrap')).toHaveClass(/show/);
  await expect(page.locator('#validationStats')).not.toBeEmpty();
  await expect(page.locator('#publishDiff')).toHaveClass(/show/);

  const downloadPromise = page.waitForEvent('download');
  await page.locator('#downloadYamlBtn').click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBe('config.yaml');
  const downloadedPath = await download.path();
  expect(downloadedPath).toBeTruthy();
  const downloadedYaml = await readFile(downloadedPath, 'utf8');
  expect(downloadedYaml.trim().length).toBeGreaterThan(0);
  expect(downloadedYaml).toContain('proxies:');

  await page.locator('#publishBtn').click();
  await expect(page.locator('#subscriptionCardStatus')).toHaveText('● 已发布', { timeout: 30_000 });
  const publishedUrl = await page.locator('#subUrl').textContent();
  expect(publishedUrl).toMatch(new RegExp(`^${baseURL.replace(/[.*+?^${}()|[\\]\\]/g, '\\$&')}/sub/[^\\s]+$`));
  const publishedSubscription = await page.evaluate(async (url) => {
    const subscriptionResponse = await fetch(url);
    return {
      status: subscriptionResponse.status,
      contentType: subscriptionResponse.headers.get('content-type') || '',
      body: await subscriptionResponse.text(),
    };
  }, publishedUrl);
  expect(publishedSubscription.status).toBe(200);
  expect(publishedSubscription.contentType).toMatch(/yaml/i);
  expect(publishedSubscription.body).toContain('proxies:');
  expect(publishedSubscription.body).not.toMatch(/<html|<!doctype/i);
  expect(publishedSubscription.body).toContain('e2e-file');
  const privateProviderBlock = publishedSubscription.body.match(/  e2e-file:\n([\s\S]*?)(?=\n  [A-Za-z0-9_-]+:|\n[^ ]|$)/);
  expect(privateProviderBlock).toBeTruthy();
  expect(privateProviderBlock[1]).toContain('proxy: DIRECT');
  const privateRulesetUrlMatch = publishedSubscription.body.match(/url:\s*(https?:\/\/[^\s"']+\/ruleset\/user\/[^\s"']+)/);
  expect(privateRulesetUrlMatch).toBeTruthy();
  const privateRulesetResponse = await page.evaluate(async (url) => {
    const rulesetResponse = await fetch(url);
    return { status: rulesetResponse.status, body: await rulesetResponse.text() };
  }, privateRulesetUrlMatch[1]);
  expect(privateRulesetResponse.status).toBe(200);
  expect(privateRulesetResponse.body).toContain('file.example.test');

  await page.locator('#step-tab-3').click();
  await page.getByRole('button', { name: '移除规则集 e2e-file' }).click();
  await waitForSaved(page);
  await expect(page.locator('#rulesetPanel .ruleset-name').filter({ hasText: 'e2e-file' })).toHaveCount(0);
  expect(await state(page, () => Object.prototype.hasOwnProperty.call(window.v2State.config.custom_rule_providers, 'e2e-file'))).toBe(false);
  await expect(page.locator('#rulesetMessage')).toContainText('发布后清理旧版本');
  await access(uploadedPhysicalPath);
  await page.locator('#step-tab-4').click();
  await page.locator('#validateBtn').click();
  await expect(page.locator('#validationStatus')).toHaveText('校验通过，可选择发布', { timeout: 30_000 });
  await page.locator('#publishBtn').click();
  await expect(page.locator('#subscriptionCardStatus')).toHaveText('● 已发布', { timeout: 30_000 });
  await expect.poll(async () => {
    try {
      await access(uploadedPhysicalPath);
      return true;
    } catch {
      return false;
    }
  }).toBe(false);

  const oldSubscriptionUrl = publishedUrl;
  page.once('dialog', (dialog) => dialog.accept());
  await page.locator('#resetTokenBtn').click();
  await expect.poll(() => page.locator('#subUrl').textContent(), { timeout: 15_000 }).not.toBe(oldSubscriptionUrl);
  const newSubscriptionUrl = await page.locator('#subUrl').textContent();
  expect(newSubscriptionUrl).not.toBe(oldSubscriptionUrl);
  tracker.allowResponse(
    (responseItem, request) => request.method() === 'GET' && responseItem.status() === 404 && responseItem.url() === oldSubscriptionUrl,
    '预期的旧订阅 Token 失效',
    'Failed to load resource: the server responded with a status of 404 (Not Found)',
  );
  const oldSubscription = await page.evaluate(async (url) => {
    const subscriptionResponse = await fetch(url);
    return { status: subscriptionResponse.status, body: await subscriptionResponse.text() };
  }, oldSubscriptionUrl);
  expect(oldSubscription.status).not.toBe(200);
  const newSubscription = await page.evaluate(async (url) => {
    const subscriptionResponse = await fetch(url);
    return {
      status: subscriptionResponse.status,
      contentType: subscriptionResponse.headers.get('content-type') || '',
      body: await subscriptionResponse.text(),
    };
  }, newSubscriptionUrl);
  expect(newSubscription.status).toBe(200);
  expect(newSubscription.contentType).toMatch(/yaml/i);
  expect(newSubscription.body).toContain('proxies:');

  await expect(page.locator('#adminPanelHost .admin-list .admin-name')).toContainText(adminUsername, { timeout: 15_000 });
  const temporaryUsername = `e2e-user-${Date.now()}`;
  await page.locator('#adminUsername').fill(temporaryUsername);
  await page.locator('#adminPassword').fill(temporaryUserPassword);
  await page.locator('#adminCreateForm').getByRole('button', { name: '创建用户' }).click();
  const temporaryRow = page.locator('#adminPanelHost .admin-row').filter({ hasText: temporaryUsername }).first();
  await expect(temporaryRow).toContainText('普通用户 · 已启用', { timeout: 15_000 });
  await temporaryRow.getByRole('button', { name: '停用' }).click();
  await expect.poll(() => temporaryRow.textContent(), { timeout: 15_000 }).toContain('普通用户 · 已停用');
  await page.locator('#adminPanelHost .admin-row').filter({ hasText: temporaryUsername }).first().getByRole('button', { name: '启用' }).click();
  await expect.poll(
    () => page.locator('#adminPanelHost .admin-row').filter({ hasText: temporaryUsername }).first().textContent(),
    { timeout: 15_000 },
  ).toContain('普通用户 · 已启用');
  await page.locator('#adminPanelHost .admin-row').filter({ hasText: temporaryUsername }).first().getByRole('button', { name: '重置 Token' }).click();
  await expect(page.locator('#adminPanelHost .admin-result')).toContainText('临时订阅 URL：', { timeout: 15_000 });
  await page.locator('#adminPanelHost .admin-row').filter({ hasText: temporaryUsername }).first().getByRole('button', { name: '删除' }).click();
  await expect(page.getByRole('button', { name: '确认删除' })).toBeVisible();
  await page.getByRole('button', { name: '确认删除' }).click();
  await expect(page.locator('#adminPanelHost .admin-row').filter({ hasText: temporaryUsername })).toHaveCount(0, { timeout: 15_000 });
  const listedUsers = await page.evaluate(async () => (await (await fetch('/api/users')).json()).users);
  expect(listedUsers.some((user) => user.username === temporaryUsername)).toBe(false);

  await page.reload({ waitUntil: 'domcontentloaded' });
  await expect(page.locator('#loginOverlay')).not.toHaveClass(/active/, { timeout: 15_000 });
  await expect(page.locator('#nodeGrid .node-card')).toHaveCount(2, { timeout: 15_000 });
  await expect(page.locator('#nodeGrid')).toContainText('Manual-Edited');
  await expect(page.locator('#nodeGrid')).toContainText('ss-share.example.com');
  await expect(page.locator('#subUrl')).toHaveText(newSubscriptionUrl);
  await page.locator('#step-tab-3').click();
  await expect(page.locator('#ruleSource')).toHaveValue('dustinwin规则');
  await page.locator('#globalSchemaPanel details').filter({ hasText: '测速与性能' }).first().locator('summary').click();
  await expect(page.locator('#globalSchemaPanel [data-field-key="url_test_tolerance"]')).toHaveValue('42');
  expect(await state(page, () => ({
    customRules: window.v2State.config.custom_rules,
    providers: window.v2State.config.custom_rule_providers,
    profile: window.v2State.config.global_config.generation_profile,
    desktop: window.v2State.config.global_config.is_desktop,
  }))).toMatchObject({
    customRules: [expect.stringContaining('one.example.test')],
    profile: 'openclash-router',
    desktop: false,
  });
  expect(await state(page, () => Object.prototype.hasOwnProperty.call(window.v2State.config.custom_rule_providers, 'e2e-file'))).toBe(false);
  expect(await state(page, () => Object.prototype.hasOwnProperty.call(window.v2State.config.custom_rule_providers, 'e2e-http'))).toBe(true);
  expect(await state(page, () => window.v2State.config.global_config.url_test_tolerance)).toBe(42);

  await page.locator('#step-tab-4').click();
  await page.setViewportSize({ width: 390, height: 844 });
  const dimensions = await page.evaluate(() => ({
    scrollWidth: document.documentElement.scrollWidth,
    clientWidth: document.documentElement.clientWidth,
  }));
  expect(dimensions.scrollWidth).toBeLessThanOrEqual(dimensions.clientWidth);
  await expect(page.locator('#workspaceNav')).toBeVisible();
  await expect(page.locator('#validateBtn')).toBeVisible();
  await expect(page.locator('#resetTokenBtn')).toBeVisible();

  tracker.assertClean();
});

test('V2 移除文件规则集只保存草稿并保留待发布清理版本', async ({ page }) => {
  test.setTimeout(60_000);
  const tracker = trackPageFailures(page);
  const response = await page.goto(`${baseURL}/`, { waitUntil: 'domcontentloaded' });
  expect(response?.status()).toBe(200);
  await expect(page.locator('#loginOverlay')).toHaveClass(/active/);
  await page.locator('#loginForm input[name="username"]').fill(adminUsername);
  await page.locator('#loginForm input[name="password"]').fill(adminPassword);
  const loginResponsePromise = page.waitForResponse((loginResponse) => loginResponse.url() === `${baseURL}/api/auth/login`);
  await page.locator('#loginForm button[type="submit"]').click();
  const loginResponse = await loginResponsePromise;
  expect(loginResponse.status(), await loginResponse.text()).toBe(200);
  await expect(page.locator('#loginOverlay')).not.toHaveClass(/active/, { timeout: 15_000 });
  await page.locator('#step-tab-3').click();
  await page.locator('#rulesetFileModeBtn').click();
  await page.locator('#rulesetAlias').fill('e2e-delete-failure');
  await page.locator('#rulesetFile').setInputFiles({
    name: 'e2e-delete-failure.yaml',
    mimeType: 'text/yaml',
    buffer: Buffer.from('payload:\n  - DOMAIN-SUFFIX,delete-failure.example.test\n', 'utf8'),
  });
  const uploadResponsePromise = page.waitForResponse((uploadResponse) => uploadResponse.url() === `${baseURL}/api/ruleset/upload`);
  await page.locator('#rulesetUploadBtn').click();
  const uploadResponse = await uploadResponsePromise;
  expect(uploadResponse.status(), await uploadResponse.text()).toBe(200);
  await waitForSaved(page);
  expect(await state(page, () => window.v2State.config.custom_rule_providers['e2e-delete-failure'].type)).toBe('http');

  const providerPath = await state(page, () => window.v2State.config.custom_rule_providers['e2e-delete-failure'].path);
  const physicalPath = path.join(serverTempDir, 'rulesets', ...providerPath.split('/').slice(2));
  await access(physicalPath);
  let deleteCalls = 0;
  await page.route(`${baseURL}/api/ruleset/delete`, async (route) => {
    deleteCalls += 1;
    await route.fulfill({
      status: 503,
      contentType: 'application/json',
      body: JSON.stringify({ ok: false, error: '不应调用旧删除接口' }),
    });
  });
  await page.getByRole('button', { name: '移除规则集 e2e-delete-failure' }).click();
  await waitForSaved(page);
  await expect(page.locator('#rulesetMessage')).toContainText('发布后清理旧版本');
  expect(await state(page, () => Object.prototype.hasOwnProperty.call(window.v2State.config.custom_rule_providers, 'e2e-delete-failure'))).toBe(false);
  await access(physicalPath);
  expect(deleteCalls).toBe(0);
  await page.unroute(`${baseURL}/api/ruleset/delete`);
  tracker.assertClean();
});

test('V2 节点字段表单往返保留 Reality、传输容器和高级嵌套字段', async ({ page }) => {
  test.setTimeout(120_000);
  const tracker = trackPageFailures(page);
  const response = await page.goto(`${baseURL}/`, { waitUntil: 'domcontentloaded' });
  expect(response?.status()).toBe(200);
  await expect(page.locator('#loginOverlay')).toHaveClass(/active/);
  await page.locator('#loginForm input[name="username"]').fill(adminUsername);
  await page.locator('#loginForm input[name="password"]').fill(adminPassword);
  const loginResponsePromise = page.waitForResponse((loginResponse) => loginResponse.url() === `${baseURL}/api/auth/login`);
  await page.locator('#loginForm button[type="submit"]').click();
  expect((await loginResponsePromise).status()).toBe(200);
  await expect(page.locator('#loginOverlay')).not.toHaveClass(/active/, { timeout: 15_000 });

  const advancedYaml = `proxies:
  - name: VLESS-Reality-No-Flow
    type: vless
    server: reality.example.com
    port: 443
    uuid: 123e4567-e89b-12d3-a456-426614174000
    tls: true
    network: tcp
    reality-opts:
      public-key: AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA
      short-id: 1234abcd
    x-advanced:
      nested:
        keep: true
  - name: VMess-WS-Roundtrip
    type: vmess
    server: ws.example.com
    port: 443
    uuid: 123e4567-e89b-12d3-a456-426614174001
    alterId: 0
    cipher: auto
    network: ws
    ws-opts:
      path: /socket
      headers:
        Host: cdn.example.com
  - name: VMess-gRPC-Roundtrip
    type: vmess
    server: grpc-vmess.example.com
    port: 443
    uuid: 123e4567-e89b-12d3-a456-426614174004
    alterId: 0
    cipher: auto
    network: grpc
    grpc-opts:
      grpc-service-name: vmess-tunnel
  - name: SS-Plugin-Roundtrip
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-128-gcm
    password: ss-password
    plugin: obfs
    plugin-opts:
      mode: tls
      host: cdn.example.com
  - name: VLESS-H2-Roundtrip
    type: vless
    server: h2.example.com
    port: 443
    uuid: 123e4567-e89b-12d3-a456-426614174002
    network: h2
    h2-opts:
      path: /h2
      host: [h2.example.com]
  - name: Trojan-gRPC-Roundtrip
    type: trojan
    server: grpc.example.com
    port: 443
    password: trojan-password
    network: grpc
    grpc-opts:
      grpc-service-name: tunnel
  - name: Hysteria2-QUIC-Roundtrip
    type: hysteria2
    server: hy2.example.com
    port: 443
    password: hy2-password
    up: 50 Mbps
    down: 100 Mbps
    hop-interval: 30
    quic-params:
      initial-stream-receive-window: 123456
      max-stream-receive-window: 234567
      initial-connection-receive-window: 345678
      max-connection-receive-window: 456789
  - name: TUIC-Roundtrip
    type: tuic
    server: tuic.example.com
    port: 443
    uuid: 123e4567-e89b-12d3-a456-426614174003
    password: tuic-password
    congestion-controller: bbr
    alpn: [h3]
    udp-relay-mode: native
    heartbeat-interval: 10000
`;
  await page.locator('#step-tab-1').click();
  const importResponse = await importMethod(page, 'yaml', advancedYaml);
  expect(importResponse.status(), await importResponse.text()).toBe(200);
  await expect(page.locator('#nodeGrid .node-card')).toHaveCount(10, { timeout: 15_000 });

  await page.locator('#step-tab-2').click();
  const names = [
    'VLESS-Reality-No-Flow',
    'VMess-WS-Roundtrip',
    'VMess-gRPC-Roundtrip',
    'SS-Plugin-Roundtrip',
    'VLESS-H2-Roundtrip',
    'Trojan-gRPC-Roundtrip',
    'Hysteria2-QUIC-Roundtrip',
    'TUIC-Roundtrip',
  ];
  for (const name of names) {
    const card = page.locator('#nodeGrid .node-card').filter({ hasText: name }).first();
    await card.getByRole('button', { name: '编辑' }).click();
    await expect(page.locator('#nodeFormPanel')).toBeVisible();
    await page.locator('#nodeFormPanel').getByRole('button', { name: '保存节点草稿' }).click();
    await expect(page.locator('#nodeGrid .node-card').filter({ hasText: name })).toHaveCount(1);
  }
  await waitForSaved(page);
  expect(await state(page, () => {
    const nodes = Object.fromEntries(window.v2State.config.proxies.map((node) => [node.name, node]));
    return {
      reality: nodes['VLESS-Reality-No-Flow']['reality-opts'],
      advanced: nodes['VLESS-Reality-No-Flow']['x-advanced'],
      ws: nodes['VMess-WS-Roundtrip']['ws-opts'],
      vmessGrpc: nodes['VMess-gRPC-Roundtrip']['grpc-opts'],
      ssPlugin: {
        plugin: nodes['SS-Plugin-Roundtrip'].plugin,
        options: nodes['SS-Plugin-Roundtrip']['plugin-opts'],
      },
      h2: nodes['VLESS-H2-Roundtrip']['h2-opts'],
      grpc: nodes['Trojan-gRPC-Roundtrip']['grpc-opts'],
      quic: nodes['Hysteria2-QUIC-Roundtrip']['quic-params'],
      tuic: {
        relay: nodes['TUIC-Roundtrip']['udp-relay-mode'],
        heartbeat: nodes['TUIC-Roundtrip']['heartbeat-interval'],
      },
    };
  })).toEqual({
    reality: { 'public-key': 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA', 'short-id': '1234abcd' },
    advanced: { nested: { keep: true } },
    ws: { path: '/socket', headers: { Host: 'cdn.example.com' } },
    vmessGrpc: { 'grpc-service-name': 'vmess-tunnel' },
    ssPlugin: {
      plugin: 'obfs',
      options: { mode: 'tls', host: 'cdn.example.com' },
    },
    h2: { path: '/h2', host: ['h2.example.com'] },
    grpc: { 'grpc-service-name': 'tunnel' },
    quic: {
      'initial-stream-receive-window': 123456,
      'max-stream-receive-window': 234567,
      'initial-connection-receive-window': 345678,
      'max-connection-receive-window': 456789,
    },
      tuic: { relay: 'native', heartbeat: 10000 },
  });
  expect(await state(page, () => window.v2State.config.proxies.find((node) => node.name === 'SS-Plugin-Roundtrip').network)).toBeUndefined();
  tracker.assertClean();
});

test('V2 修补回归：新增节点默认值、smux/链式代理、MATCH 规则与预设模式同步', async ({ page }) => {
  test.setTimeout(150_000);
  const tracker = trackPageFailures(page);
  const response = await page.goto(`${baseURL}/`, { waitUntil: 'domcontentloaded' });
  expect(response?.status()).toBe(200);
  await expect(page.locator('#loginOverlay')).toHaveClass(/active/);
  await page.locator('#loginForm input[name="username"]').fill(adminUsername);
  await page.locator('#loginForm input[name="password"]').fill(adminPassword);
  const loginResponsePromise = page.waitForResponse((loginResponse) => loginResponse.url() === `${baseURL}/api/auth/login`);
  await page.locator('#loginForm button[type="submit"]').click();
  expect((await loginResponsePromise).status()).toBe(200);
  await expect(page.locator('#loginOverlay')).not.toHaveClass(/active/, { timeout: 15_000 });

  await page.locator('#step-tab-2').click();

  // --- 1. 新增 vmess 节点：TLS 默认勾选（schema default，不再被空回填覆盖） ---
  async function openManualForm(protocol) {
    await page.locator(`#protocolPills [data-protocol="${protocol}"]`).click();
    await page.locator('#addNodeBtn').click();
    await expect(page.locator('#nodeFormPanel')).toBeVisible();
  }
  function fieldControl(key) {
    return page.locator(`#nodeSchemaFields [data-field-key="${key}"]`);
  }

  await openManualForm('vmess');
  expect(await fieldControl('node_tls').isChecked()).toBe(true);
  await fieldControl('node_name').fill('Default-TLS-VMess');
  await fieldControl('node_server').fill('tls.example.com');
  await fieldControl('node_uuid').fill('123e4567-e89b-12d3-a456-426614174010');
  // --- 2. smux 与链式代理字段出现在表单并可配置 ---
  await fieldControl('enable_smux').check();
  await fieldControl('smux_protocol').selectOption('yamux');
  // vmess 的 Brutal 默认关闭，手动勾选并填写速率。
  expect(await fieldControl('smux_brutal_enabled').isChecked()).toBe(false);
  await expect(fieldControl('smux_brutal_enabled')).toBeVisible();
  await fieldControl('smux_brutal_enabled').click();
  await expect(fieldControl('smux_brutal_up')).toBeVisible();
  await fieldControl('smux_brutal_up').fill('200');
  await fieldControl('use_dialer_proxy').check();
  await expect(fieldControl('dialer_proxy_name')).toBeVisible();
  await fieldControl('dialer_proxy_name').fill('Default-TLS-VMess-Chain');
  await page.locator('#saveNodeBtn').click();
  await expect(page.locator('#nodeGrid .node-card').filter({ hasText: 'Default-TLS-VMess' })).toHaveCount(1, { timeout: 15_000 });

  // 链式上游节点（trojan），供 datalist 候选与 dialer-proxy 引用
  await openManualForm('trojan');
  await fieldControl('node_name').fill('Default-TLS-VMess-Chain');
  await fieldControl('node_server').fill('chain.example.com');
  await fieldControl('node_password').fill('chain-password');
  await page.locator('#saveNodeBtn').click();
  await expect(page.locator('#nodeGrid .node-card').filter({ hasText: 'Default-TLS-VMess-Chain' })).toHaveCount(1, { timeout: 15_000 });

  // --- 3. 新增 anytls：跳过证书验证默认勾选 ---
  await openManualForm('anytls');
  expect(await fieldControl('anytls_skip_cert_verify').isChecked()).toBe(true);
  expect(await fieldControl('anytls_sni').inputValue()).toBe('www.bing.com');
  await page.locator('#cancelNodeBtn').click();

  // --- 4. 新增 hysteria2：端口跳跃默认勾选 ---
  await openManualForm('hysteria2');
  expect(await fieldControl('enable_port_hopping').isChecked()).toBe(true);
  expect(await fieldControl('hy2_sni').inputValue()).toBe('www.bing.com');
  await page.locator('#cancelNodeBtn').click();

  await waitForSaved(page);
  expect(await state(page, () => {
    const nodes = Object.fromEntries(window.v2State.config.proxies.map((node) => [node.name, node]));
    const manual = nodes['Default-TLS-VMess'];
    return {
      tls: manual.tls,
      udp: manual.udp,
      smux: manual.smux,
      dialer: manual['dialer-proxy'],
      sourceName: manual._source_name,
    };
  })).toEqual({
    tls: true,
    udp: true,
    smux: { enabled: true, protocol: 'yamux', 'max-connections': 4, 'brutal-opts': { enabled: true, up: '200 Mbps', down: '100 Mbps' } },
    dialer: 'Default-TLS-VMess-Chain',
    sourceName: '手动添加',
  });

  // --- 3b. vless 的 Brutal 默认关闭（防止非 Linux 客户端握手报错） ---
  await openManualForm('vless');
  await fieldControl('enable_smux').click();
  await expect(fieldControl('smux_brutal_enabled')).toBeVisible();
  expect(await fieldControl('smux_brutal_enabled').isChecked()).toBe(false);
  await page.locator('#cancelNodeBtn').click();

  // --- 5. MATCH 兜底规则：值为空合法，生成两段 MATCH,target ---
  await page.locator('#step-tab-3').click();
  await page.locator('#ruleType').selectOption('MATCH');
  await expect(page.locator('#ruleValue')).toBeDisabled();
  await page.locator('#ruleTarget').fill('Proxy');
  await page.locator('#addRuleBtn').click();
  await expect(page.locator('#ruleList .rule-item').filter({ hasText: 'MATCH' })).toHaveCount(1);
  await waitForSaved(page);
  expect(await state(page, () => window.v2State.config.custom_rules)).toContain('MATCH,Proxy');

  // --- 6. 规则目标支持手动输入自定义策略名 ---
  await page.locator('#ruleType').selectOption('DOMAIN-SUFFIX');
  await page.locator('#ruleValue').fill('manual-target.example.com');
  await page.locator('#ruleTarget').fill('自定义策略组');
  await page.locator('#addRuleBtn').click();
  await waitForSaved(page);
  expect(await state(page, () => window.v2State.config.custom_rules)).toContain('DOMAIN-SUFFIX,manual-target.example.com,自定义策略组');

  // --- 7. 路由器模式下点完整客户端预设：模式同步切回桌面 ---
  await page.locator('#modeRouterBtn').click();
  await expect.poll(() => state(page, () => window.v2State.config.global_config.is_desktop), { timeout: 10_000 }).toBe(false);
  await page.locator('#presetDesktopBtn').click();
  await expect.poll(() => state(page, () => ({
    isDesktop: window.v2State.config.global_config.is_desktop,
    profile: window.v2State.config.global_config.generation_profile,
    enableDns: window.v2State.config.global_config.enable_dns,
    enableTun: window.v2State.config.global_config.enable_tun,
  })), { timeout: 10_000 }).toEqual({
    isDesktop: true,
    profile: 'desktop-full',
    enableDns: true,
    enableTun: true,
  });

  // --- 8. raw 模式输出真 YAML 且保存不假失败（reality 无 short-id 的导入节点） ---
  await page.locator('#step-tab-1').click();
  const realityYaml = `proxies:
  - name: Reality-No-ShortId
    type: vless
    server: reality2.example.com
    port: 443
    uuid: 123e4567-e89b-12d3-a456-426614174020
    tls: true
    flow: xtls-rprx-vision
    reality-opts:
      public-key: AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA`;
  const realityImport = await importMethod(page, 'yaml', realityYaml);
  expect(realityImport.status(), await realityImport.text()).toBe(200);
  await page.locator('#step-tab-2').click();
  await expect(page.locator('#nodeGrid .node-card').filter({ hasText: 'Reality-No-ShortId' })).toHaveCount(1, { timeout: 15_000 });
  const card = page.locator('#nodeGrid .node-card').filter({ hasText: 'Reality-No-ShortId' }).first();
  await card.getByRole('button', { name: '编辑' }).click();
  await expect(page.locator('#nodeFormPanel')).toBeVisible();
  await page.locator('#toggleRawNodeBtn').click();
  const rawText = await page.locator('#nodeRawEditor').inputValue();
  expect(rawText).toContain('name: Reality-No-ShortId');
  expect(rawText).toContain('reality-opts:');
  expect(rawText).not.toContain('"reality-opts"');
  await page.locator('#saveNodeBtn').click();
  await expect(page.locator('#nodeGrid .node-card').filter({ hasText: 'Reality-No-ShortId' })).toHaveCount(1);
  await waitForSaved(page);
  expect(await state(page, () => {
    const node = window.v2State.config.proxies.find((item) => item.name === 'Reality-No-ShortId');
    return { flow: node.flow, reality: node['reality-opts'] };
  })).toEqual({ flow: 'xtls-rprx-vision', reality: { 'public-key': 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA' } });

  tracker.assertClean();
});

test('V2 后续增强回归：拖拽排序、上传恢复、ALPN 多值、TUIC SNI 与发布名单', async ({ page }) => {
  test.setTimeout(150_000);
  const tracker = trackPageFailures(page);
  const response = await page.goto(`${baseURL}/`, { waitUntil: 'domcontentloaded' });
  expect(response?.status()).toBe(200);
  await expect(page.locator('#loginOverlay')).toHaveClass(/active/);
  // 注册输入框带格式约束提示
  await expect(page.locator('#registerTabBtn')).toBeVisible();
  const usernameInput = page.locator('#registerForm input[name="username"]');
  expect(await usernameInput.getAttribute('minlength')).toBe('3');
  expect(await page.locator('#registerForm input[name="password"]').getAttribute('minlength')).toBe('8');
  await page.locator('#loginTabBtn').click();
  await page.locator('#loginForm input[name="username"]').fill(adminUsername);
  await page.locator('#loginForm input[name="password"]').fill(adminPassword);
  const loginResponsePromise = page.waitForResponse((loginResponse) => loginResponse.url() === `${baseURL}/api/auth/login`);
  await page.locator('#loginForm button[type="submit"]').click();
  expect((await loginResponsePromise).status()).toBe(200);
  await expect(page.locator('#loginOverlay')).not.toHaveClass(/active/, { timeout: 15_000 });

  // serial 模式下前面用例共用 admin 草稿；先清空，保证节点索引可预期。
  // 必须等 bootstrap 拉完 /api/config 再清，否则会被随后的渲染覆盖回服务器数据。
  await page.waitForFunction(
    () => window.v2State && window.v2State.authenticated && !window.v2State.loading,
    null,
    { timeout: 15_000 },
  );
  // 走产品自身的保存链（markDirty + flushDraftSave），避免裸 fetch 与 reload 竞态。
  const resetState = await page.evaluate(async () => {
    const before = window.v2State.config.proxies.length;
    window.v2State.config.proxies = [];
    window.v2State.config.custom_rules = [];
    window.v2State.config.custom_rule_providers = {};
    window.saveChain.markDirty();
    await window.saveChain.flushDraftSave();
    await new Promise((resolve) => setTimeout(resolve, 300));
    return {
      before,
      afterLocal: window.v2State.config.proxies.length,
      dirty: window.v2State.dirtyGeneration,
      saved: window.v2State.savedGeneration,
      saveInFlight: window.v2State.saveInFlight,
    };
  });
  console.log('resetState:', JSON.stringify(resetState));
  expect(resetState.afterLocal).toBe(0);
  expect(resetState.saved).toBe(resetState.dirty);

  // --- 1. 导入含 ALPN 数组与自定义 SNI 的节点 ---
  await page.locator('#step-tab-1').click();
  const hybridYaml = [
    'proxies:',
    '  - name: Hybrid-First',
    '    type: hysteria2',
    '    server: hybrid.example.com',
    '    port: 443',
    '    password: pw',
    '    alpn: [h3, h3-29]',
    '  - name: TUIC-CustomSni',
    '    type: tuic',
    '    server: tuic-cs.example.com',
    '    port: 443',
    '    uuid: 123e4567-e89b-12d3-a456-426614174030',
    '    password: pw',
    '    sni: custom.sni.example.com',
    '  - name: Hybrid-Third',
    '    type: ss',
    '    server: third.example.com',
    '    port: 8388',
    '    cipher: aes-128-gcm',
    '    password: pw',
  ].join('\n');
  const importResponse = await importMethod(page, 'yaml', hybridYaml);
  expect(importResponse.status(), await importResponse.text()).toBe(200);
  await expect(page.locator('#nodeGrid .node-card')).toHaveCount(3, { timeout: 15_000 });

  // --- 2. ALPN 数组与 TUIC SNI 编辑往返不丢失 ---
  await page.locator('#step-tab-2').click();
  const hybridCard = page.locator('#nodeGrid .node-card').filter({ hasText: 'Hybrid-First' }).first();
  await hybridCard.getByRole('button', { name: '编辑' }).click();
  await expect(page.locator('#nodeFormPanel')).toBeVisible();
  expect(await page.locator('[data-field-key="hy2_alpn"]').inputValue()).toBe('h3,h3-29');
  await page.locator('#saveNodeBtn').click();
  await expect(page.locator('#nodeGrid .node-card').filter({ hasText: 'Hybrid-First' })).toHaveCount(1);

  const tuicCard = page.locator('#nodeGrid .node-card').filter({ hasText: 'TUIC-CustomSni' }).first();
  await tuicCard.getByRole('button', { name: '编辑' }).click();
  await expect(page.locator('#nodeFormPanel')).toBeVisible();
  expect(await page.locator('[data-field-key="tuic_sni"]').inputValue()).toBe('custom.sni.example.com');
  await page.locator('#saveNodeBtn').click();
  await expect(page.locator('#nodeGrid .node-card').filter({ hasText: 'TUIC-CustomSni' })).toHaveCount(1);
  await waitForSaved(page);
  expect(await state(page, () => {
    const nodes = Object.fromEntries(window.v2State.config.proxies.map((node) => [node.name, node]));
    return { alpn: nodes['Hybrid-First'].alpn, sni: nodes['TUIC-CustomSni'].sni };
  })).toEqual({ alpn: ['h3', 'h3-29'], sni: 'custom.sni.example.com' });

  // --- 3. 拖拽排序（HTML5 DnD 事件）---
  // 先把表单编辑的保存链冲刷完毕，避免防抖窗口内编辑响应与拖拽交错。
  await state(page, () => window.saveChain.flushDraftSave());
  const dragTrace = await page.evaluate(() => {
    window.__dragTrace = [];
    const cards = document.querySelectorAll('#nodeGrid .node-card');
    const from = cards[2]; // Hybrid-Third
    const to = cards[0];   // 拖到第一位
    ['dragstart', 'dragover', 'drop'].forEach((type) => {
      from.addEventListener(type, () => window.__dragTrace.push('from:' + type));
      to.addEventListener(type, () => window.__dragTrace.push('to:' + type));
    });
    const dataTransfer = new DataTransfer();
    from.dispatchEvent(new DragEvent('dragstart', { bubbles: true, dataTransfer }));
    const afterStart = window.v2State.config.proxies.map((node) => node.name);
    to.dispatchEvent(new DragEvent('dragover', { bubbles: true, cancelable: true, dataTransfer }));
    to.dispatchEvent(new DragEvent('drop', { bubbles: true, cancelable: true, dataTransfer }));
    from.dispatchEvent(new DragEvent('dragend', { bubbles: true, dataTransfer }));
    return {
      trace: window.__dragTrace,
      order: Array.from(cards).map((card) => card.dataset.index),
      namesAtStart: afterStart,
      namesAfterDrop: window.v2State.config.proxies.map((node) => node.name),
      dirty: window.v2State.dirtyGeneration,
      saved: window.v2State.savedGeneration,
    };
  });
  expect(dragTrace.trace).toContain('to:drop');
  expect(dragTrace.namesAfterDrop[0]).toBe('Hybrid-Third');
  // 保存链是防抖+单飞队列，轮询等待最终顺序收敛而非瞬时快照。
  await expect.poll(
    () => state(page, () => window.v2State.config.proxies.map((node) => node.name)),
    { timeout: 20_000, message: '拖拽排序未在保存链收敛后保持' },
  ).toEqual(['Hybrid-Third', 'Hybrid-First', 'TUIC-CustomSni']);
  await waitForSaved(page);

  // --- 4. 上传配置文件恢复（setInputFiles）---
  await page.locator('#step-tab-1').click();
  const uploadYaml = ['proxies:', '  - name: Restored-By-Upload', '    type: ss', '    server: upload.example.com', '    port: 8388', '    cipher: aes-128-gcm', '    password: pw'].join('\n');
  const uploadPromise = page.waitForResponse((uploadResponse) => uploadResponse.url() === `${baseURL}/api/import`);
  await page.locator('#uploadConfigInput').setInputFiles({
    name: 'old-config.yaml',
    mimeType: 'text/yaml',
    buffer: Buffer.from(uploadYaml, 'utf-8'),
  });
  expect((await uploadPromise).status()).toBe(200);
  await expect(page.locator('#nodeGrid .node-card').filter({ hasText: 'Restored-By-Upload' })).toHaveCount(1, { timeout: 15_000 });

  // --- 5. 校验返回发布差异节点名单 ---
  await page.locator('#step-tab-4').click();
  const validatePromise = page.waitForResponse((validateResponse) => validateResponse.url() === `${baseURL}/api/validate`);
  await page.locator('#validateBtn').click();
  const validateResponse = await validatePromise;
  expect(validateResponse.status()).toBe(200);
  const validatePayload = await validateResponse.json();
  expect(validatePayload.publish_diff.added_proxies).toEqual(
    expect.arrayContaining(['Hybrid-First', 'TUIC-CustomSni', 'Hybrid-Third', 'Restored-By-Upload']),
  );

  tracker.assertClean();
});

test('V2 会话与可访问性回归：375px 视口、节点表单竞态、退出清空与会话过期重登', async ({ page }) => {
  test.setTimeout(180_000);
  const tracker = trackPageFailures(page);
  const noHorizontalScroll = async () => {
    const size = await page.evaluate(() => ({
      scrollWidth: document.documentElement.scrollWidth,
      clientWidth: document.documentElement.clientWidth,
    }));
    expect(size.scrollWidth).toBeLessThanOrEqual(size.clientWidth);
  };
  async function loginAs(username, password) {
    await page.locator('#loginTabBtn').click();
    await page.locator('#loginForm input[name="username"]').fill(username);
    await page.locator('#loginForm input[name="password"]').fill(password);
    // 只取第一次登录响应：退出后再登录必须首个请求即成功，不能先 403 再重试。
    const loginResponsePromise = page.waitForResponse((loginResponse) => loginResponse.url() === `${baseURL}/api/auth/login`);
    await page.locator('#loginForm button[type="submit"]').click();
    const loginResponse = await loginResponsePromise;
    expect(loginResponse.status(), await loginResponse.text()).toBe(200);
    await expect(page.locator('#loginOverlay')).not.toHaveClass(/active/, { timeout: 15_000 });
    await page.waitForFunction(
      () => window.v2State && window.v2State.authenticated && !window.v2State.loading,
      null,
      { timeout: 15_000 },
    );
  }

  // --- 1. 375px 视口下的登录层：产品名统一、label 关联、首个输入框聚焦、焦点陷阱、Esc 不关闭 ---
  await page.setViewportSize({ width: 375, height: 812 });
  const response = await page.goto(`${baseURL}/`, { waitUntil: 'domcontentloaded' });
  expect(response?.status()).toBe(200);
  await expect(page).toHaveTitle(/^Clash Config Gen/);
  await expect(page.locator('.logo-text')).toContainText('Clash Config Gen');
  await expect(page.locator('.logo-text')).not.toContainText('OpenClash');
  await expect(page.locator('#loginOverlay')).toHaveClass(/active/);
  await expect(page.locator('#loginForm').getByLabel('用户名')).toHaveAttribute('id', 'loginUsername');
  await expect(page.locator('#loginForm').getByLabel('密码')).toHaveAttribute('id', 'loginPassword');
  await expect(page.locator('#registerForm').getByLabel('确认密码')).toHaveAttribute('id', 'registerPasswordConfirm');
  await expect(page.locator('#loginUsername')).toBeFocused();
  for (let index = 0; index < 8; index += 1) {
    await page.keyboard.press(index % 3 === 2 ? 'Shift+Tab' : 'Tab');
    expect(await page.evaluate(() => Boolean(document.activeElement && document.activeElement.closest('#loginOverlay .login-card')))).toBe(true);
  }
  await page.keyboard.press('Escape');
  await expect(page.locator('#loginOverlay')).toHaveClass(/active/);
  await noHorizontalScroll();

  await loginAs(adminUsername, adminPassword);
  for (const tabId of ['#step-tab-1', '#step-tab-2', '#step-tab-3', '#step-tab-4']) {
    const tab = page.locator(tabId);
    // ≤1180px 时导航只显示数字，必须有可读的 aria-label。
    await expect(tab).toHaveAttribute('aria-label', /^步骤 \d：/);
    await tab.click();
    await expect(tab).toHaveAttribute('aria-selected', 'true');
    await noHorizontalScroll();
  }
  await expect(page.locator('#workspaceNav')).toBeVisible();

  // 用户菜单按钮的 aria-expanded 随开合更新。
  const avatar = page.locator('#userAvatar');
  await expect(avatar).toHaveAttribute('aria-haspopup', 'true');
  await expect(avatar).toHaveAttribute('aria-expanded', 'false');
  await avatar.click();
  await expect(avatar).toHaveAttribute('aria-expanded', 'true');
  await avatar.focus();
  await page.keyboard.press('Escape');
  await expect(avatar).toHaveAttribute('aria-expanded', 'false');

  // 减少动态效果：无限循环背景动画被停用。
  await page.emulateMedia({ reducedMotion: 'reduce' });
  expect(await page.evaluate(() => getComputedStyle(document.querySelector('.bg-grid')).animationName)).toBe('none');
  await page.emulateMedia({ reducedMotion: 'no-preference' });

  // --- 2. 节点表单与自动保存/排序竞态 ---
  await page.evaluate(async () => {
    window.v2State.config.proxies = [];
    window.v2State.config.custom_rules = [];
    window.v2State.config.custom_rule_providers = {};
    window.saveChain.markDirty();
    await window.saveChain.flushDraftSave();
  });
  await waitForSaved(page);
  await page.locator('#step-tab-1').click();
  const raceYaml = ['A', 'B', 'C'].map((suffix) => [
    `  - name: Race-${suffix}`,
    '    type: ss',
    `    server: ${suffix.toLowerCase()}.example.com`,
    '    port: 8388',
    '    cipher: aes-128-gcm',
    '    password: race-password',
  ].join('\n'));
  const raceImport = await importMethod(page, 'yaml', `proxies:\n${raceYaml.join('\n')}\n`);
  expect(raceImport.status(), await raceImport.text()).toBe(200);
  await waitForSaved(page);
  await page.locator('#step-tab-2').click();
  await expect(page.locator('#nodeGrid .node-card')).toHaveCount(3, { timeout: 15_000 });

  const nodeForm = page.locator('#nodeFormPanel');
  const cardFor = (name) => page.locator('#nodeGrid .node-card').filter({ hasText: name }).first();
  await cardFor('Race-B').getByRole('button', { name: '编辑' }).click();
  await expect(nodeForm).toBeVisible();
  // 编辑中的节点禁止排序、删除与拖拽。
  await expect(cardFor('Race-B').getByRole('button', { name: '上移' })).toBeDisabled();
  await expect(cardFor('Race-B').getByRole('button', { name: '下移' })).toBeDisabled();
  await expect(cardFor('Race-B').getByRole('button', { name: '删除' })).toBeDisabled();
  expect(await cardFor('Race-B').getAttribute('draggable')).toBe('false');

  const serverInput = nodeForm.getByLabel('服务器地址');
  await serverInput.fill('race-b-edited.example.com');
  // 表单未保存时移动另一个节点：编辑节点索引改变，且自动保存回包触发 renderAll。
  const reorderSave = page.waitForResponse((item) => item.url() === `${baseURL}/api/config` && item.request().method() === 'PUT');
  await cardFor('Race-C').getByRole('button', { name: '上移' }).click();
  expect((await reorderSave).status()).toBe(200);
  await waitForSaved(page);
  // 回包不得重建表单，用户输入保留；锁定跟随节点到新位置。
  await expect(serverInput).toHaveValue('race-b-edited.example.com');
  await expect(cardFor('Race-B').getByRole('button', { name: '删除' })).toBeDisabled();
  await nodeForm.getByRole('button', { name: '保存节点草稿' }).click();
  await expect(nodeForm).toBeHidden({ timeout: 15_000 });
  await waitForSaved(page);
  expect(await state(page, () => window.v2State.config.proxies.map((node) => `${node.name}@${node.server}`))).toEqual([
    'Race-A@a.example.com',
    'Race-C@c.example.com',
    'Race-B@race-b-edited.example.com',
  ]);

  // /api/node/build 挂起期间保存回包整体替换 state.config：必须写回原节点，不能追加重复节点。
  await cardFor('Race-A').getByRole('button', { name: '编辑' }).click();
  await expect(nodeForm).toBeVisible();
  await nodeForm.getByLabel('端口').fill('9555');
  let releaseBuild;
  const buildGate = new Promise((resolve) => { releaseBuild = resolve; });
  await page.route(`${baseURL}/api/node/build`, async (route) => {
    await buildGate;
    await route.continue();
  });
  await nodeForm.getByRole('button', { name: '保存节点草稿' }).click();
  await page.evaluate(async () => {
    window.v2State.config.custom_rules = window.v2State.config.custom_rules.concat(['DOMAIN-SUFFIX,race.example.test,Proxy']);
    window.saveChain.markDirty();
    await window.saveChain.flushDraftSave();
  });
  releaseBuild();
  await expect(nodeForm).toBeHidden({ timeout: 15_000 });
  await page.unroute(`${baseURL}/api/node/build`);
  await waitForSaved(page);
  expect(await state(page, () => window.v2State.config.proxies.map((node) => `${node.name}:${node.port}`))).toEqual([
    'Race-A:9555',
    'Race-C:8388',
    'Race-B:8388',
  ]);
  expect(await state(page, () => window.v2State.config.custom_rules)).toContain('DOMAIN-SUFFIX,race.example.test,Proxy');

  // --- 3. 退出登录清空上一用户的节点、订阅链接与管理员结果中的明文 Token ---
  const temporaryUsername = `e2e-logout-${Date.now()}`;
  await page.locator('#adminUsername').fill(temporaryUsername);
  await page.locator('#adminPassword').fill(temporaryUserPassword);
  await page.locator('#adminPanelHost').getByRole('button', { name: '创建用户' }).click();
  const temporaryRow = page.locator('#adminPanelHost .admin-row').filter({ hasText: temporaryUsername }).first();
  await expect(temporaryRow).toBeVisible({ timeout: 15_000 });
  await temporaryRow.getByRole('button', { name: '重置 Token' }).click();
  await expect(page.locator('#adminPanelHost .admin-result')).toContainText('Token：', { timeout: 15_000 });
  const adminResultText = await page.locator('#adminPanelHost .admin-result').textContent();
  const plainToken = String(adminResultText || '').split('Token：')[1].trim();
  expect(plainToken.length).toBeGreaterThan(8);
  const ownSubscriptionUrl = String(await page.locator('#subUrl').textContent());
  expect(ownSubscriptionUrl).toContain('/sub/');

  await avatar.click();
  await page.locator('#userDropdown').getByRole('button', { name: '退出登录' }).click();
  await expect(page.locator('#loginOverlay')).toHaveClass(/active/, { timeout: 15_000 });
  await expect(page.locator('#loginUsername')).toBeFocused();
  // 退出后登录层不得预填上一用户的明文密码（登录表单已在登录成功时重置，showAuthOverlay 再清空一次）。
  await expect(page.locator('#loginPassword')).toHaveValue('');
  await expect(page.locator('#loginUsername')).toHaveValue('');
  await expect(page.locator('#nodeGrid .node-card')).toHaveCount(0);
  await expect(page.locator('#subUrl')).toHaveText('尚未发布订阅');
  await expect(page.locator('#adminPanelHost')).toBeHidden();
  await expect(page.locator('#adminPanelHost .admin-result')).toHaveCount(0);
  const bodyAfterLogout = await page.evaluate(() => document.body.textContent || '');
  expect(bodyAfterLogout).not.toContain(plainToken);
  expect(bodyAfterLogout).not.toContain(ownSubscriptionUrl);
  expect(bodyAfterLogout).not.toContain('Race-A');
  expect(await state(page, () => ({
    authCsrf: Boolean(window.v2State.authCsrf),
    csrfToken: window.v2State.csrfToken,
    adminResult: window.v2State.adminResult,
    proxies: window.v2State.config.proxies.length,
  }))).toEqual({ authCsrf: true, csrfToken: '', adminResult: '', proxies: 0 });

  // 退出后再登录：首个登录请求必须使用 auth 用途 token 直接成功。
  await loginAs(adminUsername, adminPassword);
  await expect(page.locator('#nodeGrid .node-card')).toHaveCount(3, { timeout: 15_000 });

  // --- 4. 会话中途过期：弹出登录层，同一用户重登后可保留并保存未保存修改 ---
  await page.locator('#step-tab-3').click();
  await page.context().clearCookies();
  tracker.allowResponse(
    (responseItem, request) => request.method() === 'PUT' && responseItem.status() === 401 && responseItem.url() === `${baseURL}/api/config`,
    '会话过期后的草稿保存被拒绝',
    'Failed to load resource: the server responded with a status of 401 (Unauthorized)',
  );
  await page.locator('#ruleType').selectOption('DOMAIN-SUFFIX');
  await page.locator('#ruleValue').fill('expired.example.test');
  await page.locator('#ruleTarget').fill('Proxy');
  await page.locator('#addRuleBtn').click();
  await expect(page.locator('#loginOverlay')).toHaveClass(/active/, { timeout: 15_000 });
  expect(await state(page, () => window.v2State.dirtyGeneration > window.v2State.savedGeneration)).toBe(true);
  const keepDialog = new Promise((resolve) => {
    page.once('dialog', async (dialog) => {
      const message = dialog.message();
      await dialog.accept();
      resolve(message);
    });
  });
  await loginAs(adminUsername, adminPassword);
  expect(await keepDialog).toContain('登录过期前有尚未保存的修改');
  await waitForSaved(page);
  expect(await state(page, () => window.v2State.config.custom_rules)).toContain('DOMAIN-SUFFIX,expired.example.test,Proxy');

  tracker.assertClean();
});

test('V2 主页外置资源与 CSP（生产路径）：响应头收紧、无调试对象暴露且可正常登录使用', async ({ page }) => {
  const violations = [];
  page.on('console', (message) => {
    if (/Content Security Policy|Refused to (?:execute|load|apply)/i.test(message.text())) violations.push(message.text());
  });
  await page.addInitScript(() => {
    window.__cspViolations = [];
    document.addEventListener('securitypolicyviolation', (event) => {
      window.__cspViolations.push(`${event.violatedDirective} ${event.blockedURI}`);
    });
  });
  const response = await page.goto(`${baseURL}/`, { waitUntil: 'load' });
  expect(response?.status()).toBe(200);
  const csp = response?.headers()['content-security-policy'] || '';
  expect(csp).toContain("script-src 'self'");
  await expect(page.locator('#loginOverlay')).toHaveClass(/active/);
  // 生产路径不注入 __CCG_DEBUG__：内部状态与保存链不得挂到全局。
  expect(await page.evaluate(() => ({ state: typeof window.v2State, chain: typeof window.saveChain }))).toEqual({ state: 'undefined', chain: 'undefined' });
  const inline = await page.evaluate(() => ({
    scripts: Array.from(document.querySelectorAll('script:not([src])')).length,
    handlers: Array.from(document.querySelectorAll('*')).filter((el) => el.getAttributeNames().some((name) => name.startsWith('on'))).length,
  }));
  expect(inline).toEqual({ scripts: 0, handlers: 0 });
  expect(await page.evaluate(() => window.__cspViolations)).toEqual([]);
  expect(violations).toEqual([]);

  // 生产路径下页面仍可正常登录并加载工作台。
  await page.locator('#loginForm input[name="username"]').fill(adminUsername);
  await page.locator('#loginForm input[name="password"]').fill(adminPassword);
  await page.locator('#loginForm button[type="submit"]').click();
  await expect(page.locator('#loginOverlay')).not.toHaveClass(/active/, { timeout: 15_000 });
  await expect(page.locator('#userAvatar')).toHaveAttribute('title', adminUsername, { timeout: 15_000 });
  await expect(page.locator('#draftStatus')).not.toHaveText('登录后加载你的独立草稿');
  await page.locator('#step-tab-2').click();
  await expect(page.locator('#step2')).toBeVisible();
  expect(await page.evaluate(() => typeof window.v2State)).toBe('undefined');
  expect(await page.evaluate(() => window.__cspViolations)).toEqual([]);
});

// 换号与迟到回包回归共用的辅助：以管理员身份创建一个普通用户。
async function createPlainUser(page, username, password) {
  const status = await page.evaluate(async ({ name, secret }) => {
    const response = await fetch(`/api/users/${encodeURIComponent(name)}`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': window.v2State.csrfToken },
      body: JSON.stringify({ password: secret, is_admin: false }),
    });
    return response.status;
  }, { name: username, secret: password });
  expect(status).toBe(200);
}

async function signInViaForm(page, username, password) {
  await page.locator('#loginTabBtn').click();
  await page.locator('#loginForm input[name="username"]').fill(username);
  await page.locator('#loginForm input[name="password"]').fill(password);
  await page.locator('#loginForm button[type="submit"]').click();
  await expect(page.locator('#loginOverlay')).not.toHaveClass(/active/, { timeout: 15_000 });
  await page.waitForFunction(
    () => window.v2State && window.v2State.authenticated && !window.v2State.loading,
    null,
    { timeout: 15_000 },
  );
}

test('V2 换号回归：会话过期后用另一账号登录应清空节点、订阅链接与 YAML 区', async ({ page }) => {
  test.setTimeout(120_000);
  await page.goto(`${baseURL}/`, { waitUntil: 'domcontentloaded' });
  await signInViaForm(page, adminUsername, adminPassword);
  const otherUser = `e2e-swap-${Date.now()}`;
  await createPlainUser(page, otherUser, temporaryUserPassword);

  await page.locator('#step-tab-1').click();
  const imported = await importMethod(page, 'yaml', 'proxies:\n  - name: Swap-A\n    type: ss\n    server: swap-a.example.com\n    port: 8388\n    cipher: aes-128-gcm\n    password: swap-password\n');
  expect(imported.status(), await imported.text()).toBe(200);
  await waitForSaved(page);
  await page.locator('#step-tab-4').click();
  await page.locator('#validateBtn').click();
  await expect(page.locator('#yamlWrap')).toHaveClass(/show/, { timeout: 30_000 });
  await expect(page.locator('#yamlCode')).toContainText('Swap-A');
  const adminSubscriptionUrl = String(await page.locator('#subUrl').textContent());
  expect(adminSubscriptionUrl).toContain('/sub/');

  // 会话过期：清 Cookie 后触发一次写入，弹出登录层。
  await page.context().clearCookies();
  await page.locator('#step-tab-3').click();
  await page.locator('#ruleType').selectOption('DOMAIN-SUFFIX');
  await page.locator('#ruleValue').fill('swap.example.test');
  await page.locator('#ruleTarget').fill('Swap-Policy-A');
  await page.locator('#addRuleBtn').click();
  await expect(page.locator('#loginOverlay')).toHaveClass(/active/, { timeout: 15_000 });
  await expect(page.locator('#loginPassword')).toHaveValue('');

  // 换另一账号登录：上一用户的节点、订阅链接、YAML 与规则输入框都不得残留。
  await signInViaForm(page, otherUser, temporaryUserPassword);
  await expect(page.locator('#nodeGrid .node-card')).toHaveCount(0, { timeout: 15_000 });
  await expect(page.locator('#yamlCode')).not.toContainText('Swap-A');
  await expect(page.locator('#yamlWrap')).not.toHaveClass(/show/);
  expect(String(await page.locator('#subUrl').textContent())).not.toBe(adminSubscriptionUrl);
  await expect(page.locator('#ruleValue')).toHaveValue('');
  // 目标策略框被清空后 renderRules 会回填默认策略，只要不是上一用户填写的值即可。
  await expect(page.locator('#ruleTarget')).not.toHaveValue('Swap-Policy-A');
  const snapshot = await page.evaluate(() => ({
    username: window.v2State.user && window.v2State.user.username,
    proxies: window.v2State.config.proxies.length,
    rules: window.v2State.config.custom_rules,
    body: document.body.textContent || '',
  }));
  expect(snapshot.username).toBe(otherUser);
  expect(snapshot.proxies).toBe(0);
  expect(snapshot.rules.join('\n')).not.toContain('swap.example.test');
  expect(snapshot.body).not.toContain('Swap-A');
  expect(snapshot.body).not.toContain(adminSubscriptionUrl);
});

test('V2 迟到回包回归：/api/validate 挂起期间退出并换号登录，放行后不得写回上一用户 YAML', async ({ page }) => {
  test.setTimeout(120_000);
  await page.goto(`${baseURL}/`, { waitUntil: 'domcontentloaded' });
  await signInViaForm(page, adminUsername, adminPassword);
  const otherUser = `e2e-late-${Date.now()}`;
  await createPlainUser(page, otherUser, temporaryUserPassword);

  await page.locator('#step-tab-1').click();
  const imported = await importMethod(page, 'yaml', 'proxies:\n  - name: Late-A\n    type: ss\n    server: late-a.example.com\n    port: 8388\n    cipher: aes-128-gcm\n    password: late-password\n');
  expect(imported.status(), await imported.text()).toBe(200);
  await waitForSaved(page);
  await page.locator('#step-tab-4').click();

  // 在发出请求时立即用 A 的会话取回真实回包，再挂起到换号之后才交给页面。
  let releaseValidate;
  const validateGate = new Promise((resolve) => { releaseValidate = resolve; });
  let heldBody = '';
  let validateHeld;
  const validateIntercepted = new Promise((resolve) => { validateHeld = resolve; });
  await page.route(`${baseURL}/api/validate`, async (route) => {
    const upstream = await route.fetch();
    heldBody = await upstream.text();
    validateHeld();
    await validateGate;
    await route.fulfill({ response: upstream, body: heldBody });
  });
  await page.locator('#validateBtn').click();
  await validateIntercepted;
  expect(heldBody).toContain('Late-A');

  await page.locator('#userAvatar').click();
  await page.locator('#userDropdown').getByRole('button', { name: '退出登录' }).click();
  await expect(page.locator('#loginOverlay')).toHaveClass(/active/, { timeout: 15_000 });
  await expect(page.locator('#loginPassword')).toHaveValue('');
  await signInViaForm(page, otherUser, temporaryUserPassword);
  // 让新用户草稿代数与 A 发起校验时一致（均为 1），旧回包若未被丢弃就会通过代数比对并写入页面。
  await page.locator('#step-tab-1').click();
  const lateImport = await importMethod(page, 'yaml', 'proxies:\n  - name: Late-B\n    type: ss\n    server: late-b.example.com\n    port: 8388\n    cipher: aes-128-gcm\n    password: late-b-password\n');
  expect(lateImport.status(), await lateImport.text()).toBe(200);
  await waitForSaved(page);
  await page.locator('#step-tab-4').click();

  releaseValidate();
  await page.waitForTimeout(800);
  await page.unroute(`${baseURL}/api/validate`);
  await expect(page.locator('#yamlCode')).not.toContainText('Late-A');
  await expect(page.locator('#yamlWrap')).not.toHaveClass(/show/);
  expect(await page.evaluate(() => ({
    validation: window.v2State.validation,
    proxies: window.v2State.config.proxies.map((node) => node.name),
    validateInFlight: window.v2State.validateInFlight,
  }))).toEqual({ validation: null, proxies: ['Late-B'], validateInFlight: false });
  await expect(page.locator('#validateBtn')).toBeEnabled();
});

test('V2 渲染性能回归：保存回包复用卡片、筛选只隐藏、全局设置跨组可见性与焦点保留、目标下拉懒填充', async ({ page }) => {
  test.setTimeout(180_000);
  const tracker = trackPageFailures(page);
  await page.goto(`${baseURL}/`, { waitUntil: 'domcontentloaded' });
  await signInViaForm(page, adminUsername, adminPassword);

  // serial 模式下前面用例共用 admin 草稿；先经产品保存链清空节点与规则。
  await page.evaluate(async () => {
    window.v2State.config.proxies = [];
    window.v2State.config.custom_rules = [];
    window.v2State.config.custom_rule_providers = {};
    window.saveChain.markDirty();
    await window.saveChain.flushDraftSave();
  });
  await waitForSaved(page);

  await page.locator('#step-tab-1').click();
  const perfYaml = ['A', 'B', 'C', 'D'].map((suffix) => [
    `  - name: Perf-${suffix}`,
    '    type: ss',
    `    server: perf-${suffix.toLowerCase()}.example.com`,
    '    port: 8388',
    '    cipher: aes-128-gcm',
    '    password: perf-password',
  ].join('\n'));
  const perfImport = await importMethod(page, 'yaml', `proxies:\n${perfYaml.join('\n')}\n`);
  expect(perfImport.status(), await perfImport.text()).toBe(200);
  await waitForSaved(page);
  await page.locator('#step-tab-2').click();
  const cards = page.locator('#nodeGrid .node-card');
  await expect(cards).toHaveCount(4, { timeout: 15_000 });

  // --- 1. 保存回包不重建节点卡片：同一元素引用保留，且不再重放 popIn 入场动画 ---
  // 等首次出现的入场动画（含 400ms 兜底）结束。
  await expect.poll(() => page.evaluate(() => document.querySelectorAll('#nodeGrid .node-card.is-entering').length), { timeout: 5_000 }).toBe(0);
  await page.evaluate(() => {
    document.querySelectorAll('#nodeGrid .node-card').forEach((card) => { card.__perfMark = card.textContent.match(/Perf-[A-D]/)[0]; });
  });
  const afterSave = await page.evaluate(async () => {
    window.v2State.config.custom_rules = window.v2State.config.custom_rules.concat(['DOMAIN-SUFFIX,perf.example.test,Proxy']);
    window.saveChain.markDirty();
    await window.saveChain.flushDraftSave();
    const nodeCards = Array.from(document.querySelectorAll('#nodeGrid .node-card'));
    return {
      marks: nodeCards.map((card) => card.__perfMark || null),
      entering: nodeCards.filter((card) => card.classList.contains('is-entering')).length,
      popIn: document.getAnimations().filter((animation) => animation.animationName === 'popIn'
        && animation.effect && animation.effect.target && animation.effect.target.closest
        && animation.effect.target.closest('#nodeGrid')).length,
    };
  });
  expect(afterSave).toEqual({ marks: ['Perf-A', 'Perf-B', 'Perf-C', 'Perf-D'], entering: 0, popIn: 0 });
  await waitForSaved(page);

  // 排序只移动对应卡片，元素引用不变，也不触发入场动画。
  await page.locator('#nodeGrid .node-card').filter({ hasText: 'Perf-C' }).getByRole('button', { name: '上移' }).click();
  await waitForSaved(page);
  expect(await page.evaluate(() => Array.from(document.querySelectorAll('#nodeGrid .node-card')).map((card) => ({
    mark: card.__perfMark || null,
    index: card.dataset.index,
    entering: card.classList.contains('is-entering'),
  })))).toEqual([
    { mark: 'Perf-A', index: '0', entering: false },
    { mark: 'Perf-C', index: '1', entering: false },
    { mark: 'Perf-B', index: '2', entering: false },
    { mark: 'Perf-D', index: '3', entering: false },
  ]);
  expect(await state(page, () => window.v2State.config.proxies.map((node) => node.name))).toEqual(['Perf-A', 'Perf-C', 'Perf-B', 'Perf-D']);

  // --- 2. 搜索只隐藏不匹配卡片，匹配卡片元素引用不变 ---
  await page.locator('#nodeSearch').fill('perf-b');
  await expect(page.locator('#nodeGrid .node-card:not([data-hidden="true"])')).toHaveCount(1, { timeout: 5_000 });
  await expect(cards).toHaveCount(4);
  expect(await page.evaluate(() => Array.from(document.querySelectorAll('#nodeGrid .node-card')).map((card) => ({
    mark: card.__perfMark || null,
    hidden: card.dataset.hidden === 'true',
  })))).toEqual([
    { mark: 'Perf-A', hidden: true },
    { mark: 'Perf-C', hidden: true },
    { mark: 'Perf-B', hidden: false },
    { mark: 'Perf-D', hidden: true },
  ]);
  await expect(page.locator('#nodeGrid .node-card').filter({ hasText: 'Perf-B' })).toBeVisible();
  await expect(page.locator('#nodeGrid .node-card').filter({ hasText: 'Perf-A' })).toBeHidden();
  await page.locator('#nodeSearch').fill('');
  await expect(page.locator('#nodeGrid .node-card:not([data-hidden="true"])')).toHaveCount(4, { timeout: 5_000 });
  expect(await page.evaluate(() => Array.from(document.querySelectorAll('#nodeGrid .node-card')).map((card) => card.__perfMark || null))).toEqual(['Perf-A', 'Perf-C', 'Perf-B', 'Perf-D']);

  // --- 3. 全局设置：非“基础”组字段输入不会误隐藏依赖 is_desktop / enable_core_options 的字段 ---
  await page.locator('#step-tab-3').click();
  await expect(page.locator('#modeDesktopBtn')).toBeEnabled({ timeout: 5_000 });
  await page.locator('#modeDesktopBtn').click();
  await waitForSaved(page);
  expect(await state(page, () => window.v2State.config.global_config.is_desktop)).toBe(true);
  const panel = page.locator('#globalSchemaPanel');
  const speedGroup = panel.locator('details[data-group="speed"]');
  const dnsGroup = panel.locator('details[data-group="dns"]');
  if (!(await speedGroup.evaluate((details) => details.open))) await speedGroup.locator('summary').click();
  // 手动收起默认展开的 DNS 分组，保存回包后应保持收起。
  if (await dnsGroup.evaluate((details) => details.open)) await dnsGroup.locator('summary').click();
  const visibilityMap = () => page.evaluate(() => Object.fromEntries(
    Array.from(document.querySelectorAll('#globalSchemaPanel [data-field-key]')).map((control) => [
      control.dataset.fieldKey,
      !control.closest('.schema-field').classList.contains('schema-field-hidden'),
    ]),
  ));
  const beforeVisibility = await visibilityMap();
  expect(beforeVisibility.find_process_mode).toBe(true);
  const tolerance = panel.locator('[data-field-key="url_test_tolerance"]');
  await tolerance.click();
  await page.keyboard.type('7');
  expect(await visibilityMap()).toEqual(beforeVisibility);
  await expect(panel.locator('[data-field-key="find_process_mode"]')).toBeVisible();

  // A 字段 change 后立即聚焦 B 输入：保存回包不得覆盖 B 的未提交输入、不得抢走焦点或改变分组展开状态。
  await tolerance.fill('55');
  const testUrl = panel.locator('[data-field-key="url_test_url"]');
  const originalTestUrl = await testUrl.inputValue();
  const toleranceSave = page.waitForResponse((item) => item.url() === `${baseURL}/api/config` && item.request().method() === 'PUT');
  await testUrl.click();
  // macOS 下 End 键不移动光标，直接把光标放到末尾再输入。
  await testUrl.evaluate((input) => input.setSelectionRange(input.value.length, input.value.length));
  await page.keyboard.type('?perf=1');
  expect((await toleranceSave).status()).toBe(200);
  await waitForSaved(page);
  expect(await state(page, () => window.v2State.config.global_config.url_test_tolerance)).toBe(55);
  await expect(testUrl).toBeFocused();
  await expect(testUrl).toHaveValue(`${originalTestUrl}?perf=1`);
  expect(await state(page, () => window.v2State.config.global_config.url_test_url)).toBe(originalTestUrl);
  expect(await speedGroup.evaluate((details) => details.open)).toBe(true);
  expect(await dnsGroup.evaluate((details) => details.open)).toBe(false);
  await testUrl.fill(originalTestUrl);
  await testUrl.press('Tab');
  await waitForSaved(page);
  expect(await state(page, () => window.v2State.config.global_config.url_test_url)).toBe(originalTestUrl);

  // --- 4. 规则源目标下拉：初始只含当前值，交互后懒填充，可选择节点并正确写回 ---
  await page.locator('#ruleSource').selectOption('dustinwin规则');
  await waitForSaved(page);
  const providerTargets = page.locator('#providerTargetsPanel');
  await expect(providerTargets).toBeVisible();
  const firstTarget = providerTargets.locator('select').first();
  await expect(firstTarget.locator('option')).toHaveCount(1);
  const providerName = await firstTarget.evaluate((select) => select.closest('.target-row').querySelector('.target-name').textContent);
  const initialValue = await firstTarget.inputValue();
  await firstTarget.focus();
  const lazyOptions = await firstTarget.locator('option').evaluateAll((options) => options.map((option) => option.value));
  expect(lazyOptions.length).toBeGreaterThan(1);
  expect(lazyOptions).toContain('Perf-B');
  expect(lazyOptions).not.toContain('no-resolve');
  expect(new Set(lazyOptions).size).toBe(lazyOptions.length);
  await expect(firstTarget).toHaveValue(initialValue);
  await firstTarget.evaluate((select) => { select.__perfMark = 'target-select'; });
  await firstTarget.selectOption('Perf-B');
  await waitForSaved(page);
  expect(await state(page, () => window.v2State.config.global_config.dustinwin_provider_targets)).toEqual({ [providerName]: 'Perf-B' });
  await expect(firstTarget).toHaveValue('Perf-B');
  expect(await firstTarget.evaluate((select) => select.__perfMark || null)).toBe('target-select');
  await providerTargets.getByRole('button', { name: '恢复当前规则源默认目标' }).click();
  await waitForSaved(page);
  expect(await state(page, () => window.v2State.config.global_config.dustinwin_provider_targets)).toEqual({});
  await expect(providerTargets.locator('select').first()).toHaveValue(initialValue);

  tracker.assertClean();
});
