(function () {
  "use strict";

  var DRAFT_KEYS = [
    "proxies",
    "global_config",
    "custom_rules",
    "custom_rule_providers",
    "selected_rule_type",
    "import_sources"
  ];

  var state = {
    user: null,
    csrfToken: "",
    authCsrf: "",
    authenticated: false,
    loading: true,
    config: emptyDraft(),
    subscription: {},
    nodeFormSchema: {},
    globalConfigSchema: {},
    presets: {},
    dnsPresets: {},
    providerDefaults: {},
    allTargets: [],
    counts: {},
    warnings: [],
    importMethod: "yaml",
    nodeProtocol: "",
    nodeQuery: "",
    nodeForm: { open: false, index: null, protocol: "", raw: false },
    dirtyGeneration: 0,
    savedGeneration: 0,
    saveTimer: null,
    saveSequence: Promise.resolve(),
    savePending: 0,
    saveInFlight: false,
    saveError: null,
    validation: null,
    validatedGeneration: -1,
    validatedSignature: "",
    validateInFlight: false,
    publishInFlight: false,
    globalSaving: false,
    rulesetMode: "http",
    rulesetUrlTest: { url: "", ok: false },
    rulesetMessage: "",
    adminUsers: [],
    adminLoading: false,
    adminLoaded: false,
    adminConfirmDelete: null,
    adminResult: "",
    // 最近一次服务端确认的草稿快照；用户取消覆盖损坏草稿时据此回滚本地修改。
    serverConfig: emptyDraft(),
    // 会话中途过期时记录过期前的用户名，重新登录后据此判断是否保留本地未保存修改。
    sessionExpiredUser: "",
    // 登录主体代数：退出、换号、重新登录时递增；进行中请求的迟到回包据此识别并丢弃，避免写回上一用户数据。
    authEpoch: 0
  };

  function isStale(epoch) {
    return epoch !== state.authEpoch;
  }

  // 递增代数并释放所有“进行中”标志：旧请求的回包会被丢弃，不会再有机会复位这些标志。
  function bumpAuthEpoch() {
    state.authEpoch += 1;
    state.saveSequence = Promise.resolve();
    state.savePending = 0;
    state.saveInFlight = false;
    state.validateInFlight = false;
    state.publishInFlight = false;
    state.globalSaving = false;
  }

  // 内部状态默认不挂到全局；仅在测试/调试开关打开时暴露：
  // 页面脚本执行前设置 window.__CCG_DEBUG__ = true（Playwright addInitScript），
  // 或本地 localStorage 中 "ccg-debug" 为 "1"。
  function debugHooksEnabled() {
    if (window.__CCG_DEBUG__ === true) return true;
    try { return window.localStorage.getItem("ccg-debug") === "1"; } catch (_) { return false; }
  }
  var DEBUG_HOOKS = debugHooksEnabled();
  if (DEBUG_HOOKS) window.v2State = state;

  function $(id) {
    return document.getElementById(id);
  }

  function emptyDraft() {
    return {
      proxies: [],
      global_config: {},
      custom_rules: [],
      custom_rule_providers: {},
      selected_rule_type: "",
      import_sources: []
    };
  }

  function isObject(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value);
  }

  function clone(value) {
    if (value === undefined) return value;
    try {
      if (typeof structuredClone === "function") return structuredClone(value);
    } catch (_) {}
    try { return JSON.parse(JSON.stringify(value)); } catch (_) { return value; }
  }

  function canonicalDraft(payload) {
    var source = payload && isObject(payload.config) ? payload.config : (payload || {});
    return {
      proxies: Array.isArray(source.proxies) ? clone(source.proxies) : [],
      global_config: isObject(source.global_config) ? clone(source.global_config) : {},
      custom_rules: Array.isArray(source.custom_rules) ? clone(source.custom_rules) : [],
      custom_rule_providers: isObject(source.custom_rule_providers) ? clone(source.custom_rule_providers) : {},
      selected_rule_type: typeof source.selected_rule_type === "string" ? source.selected_rule_type : "",
      import_sources: Array.isArray(source.import_sources) ? clone(source.import_sources) : []
    };
  }

  function setText(idOrElement, value, fallback) {
    var element = typeof idOrElement === "string" ? $(idOrElement) : idOrElement;
    if (!element) return;
    if (value === undefined || value === null || value === "") {
      element.textContent = fallback === undefined ? "—" : String(fallback);
    } else {
      element.textContent = String(value);
    }
  }

  function clearElement(element) {
    if (!element) return;
    while (element.firstChild) element.removeChild(element.firstChild);
  }

  function appendText(parent, value, className) {
    var node = document.createElement("span");
    if (className) node.className = className;
    node.textContent = value === undefined || value === null ? "" : String(value);
    parent.appendChild(node);
    return node;
  }

  function makeButton(label, className, handler) {
    var button = document.createElement("button");
    button.type = "button";
    button.className = className || "btn";
    button.textContent = label;
    if (handler) button.addEventListener("click", handler);
    return button;
  }

  function showToast(message, type) {
    var wrap = $("toastWrap");
    if (!wrap) return;
    var item = document.createElement("div");
    item.className = "toast" + (type === "info" ? " info" : "");
    var icon = document.createElement("span");
    icon.className = "t-ico";
    icon.textContent = type === "error" ? "!" : (type === "info" ? "i" : "✓");
    var text = document.createElement("span");
    text.textContent = message === undefined || message === null ? "请求失败" : String(message);
    item.appendChild(icon);
    item.appendChild(text);
    wrap.appendChild(item);
    window.setTimeout(function () {
      item.classList.add("out");
      window.setTimeout(function () { if (item.parentNode) item.parentNode.removeChild(item); }, 420);
    }, 3200);
  }

  window.toast = showToast;

  function statusLabel(label, tone) {
    var text = $("serviceStatus");
    if (text) text.textContent = label || "—";
    setText("footerServiceStatus", label, "—");
    var top = document.querySelector(".sub-status");
    if (top) {
      top.classList.toggle("status-error", tone === "error");
      top.classList.toggle("status-warn", tone === "warn");
    }
  }

  function updateDraftStatus() {
    if (state.loading) {
      statusLabel("正在加载", "warn");
      setText("draftStatus", "正在加载后端草稿…");
      return;
    }
    if (state.saveError) {
      statusLabel("保存失败", "error");
      setText("draftStatus", "草稿保存失败：" + state.saveError);
      return;
    }
    if (state.dirtyGeneration !== state.savedGeneration) {
      statusLabel("草稿未保存", "warn");
      setText("draftStatus", "草稿有未保存修改，正在等待保存");
      return;
    }
    statusLabel(state.authenticated ? "后端已连接" : "未登录", state.authenticated ? "ok" : "warn");
    setText("draftStatus", state.authenticated ? "草稿已保存" : "请登录后继续");
  }

  function legacyError(data) {
    if (!data) return "请求失败";
    if (typeof data.error === "string" && data.error) return data.error;
    if (typeof data.message === "string" && data.message) return data.message;
    if (typeof data.detail === "string" && data.detail) return data.detail;
    if (isObject(data.detail)) {
      if (typeof data.detail.error === "string") return data.detail.error;
      if (typeof data.detail.message === "string") return data.detail.message;
    }
    return "请求失败";
  }

  function errorDetails(data) {
    if (!data) return null;
    if (data.details !== undefined) return data.details;
    if (data.detail && isObject(data.detail)) return data.detail;
    return null;
  }

  function parseResponse(response) {
    return response.text().then(function (raw) {
      if (!raw) return {};
      try { return JSON.parse(raw); } catch (_) { return { ok: false, error: raw }; }
    });
  }

  function ApiError(message, status, details, payload) {
    this.name = "ApiError";
    this.message = message || "请求失败";
    this.status = status || 0;
    this.details = details || null;
    this.payload = payload || null;
  }
  ApiError.prototype = Object.create(Error.prototype);
  ApiError.prototype.constructor = ApiError;

  async function refreshSession() {
    var response = await fetch("/api/session", {
      credentials: "include",
      headers: { Accept: "application/json" }
    });
    var data = await parseResponse(response);
    if (data && data.csrf_token) {
      // /api/session 按登录态签发不同用途的 token：未登录时是 auth 用途（仅登录/注册可用），
      // 已登录时是 api 用途。两者分开存放，避免拿 api token 提交登录而被 403。
      if (data.authenticated) {
        state.csrfToken = data.csrf_token;
      } else {
        state.authCsrf = data.csrf_token;
        state.csrfToken = "";
      }
    }
    if (data && data.authenticated) {
      var previousUser = state.user;
      var accountChanged = Boolean(previousUser && data.user && previousUser.id !== undefined && data.user.id !== undefined && previousUser.id !== data.user.id);
      // 会话已被换成另一个账号（如其他标签页登录了别人）：先清空上一用户的全部本地数据。
      if (accountChanged) {
        resetUserState();
        data.accountChanged = true;
      }
      state.authenticated = true;
      state.user = data.user || state.user;
      renderUserPanel(state.user);
    } else {
      // 从已登录变为未登录说明会话中途过期，记下用户名供重新登录后判断。
      if (state.authenticated && state.user && state.user.username) state.sessionExpiredUser = String(state.user.username);
      state.authenticated = false;
      state.user = null;
    }
    return data;
  }

  async function apiRequest(path, options) {
    var opts = options || {};
    var method = String(opts.method || "GET").toUpperCase();
    var attempt = 0;
    while (true) {
      var headers = {};
      var suppliedHeaders = opts.headers || {};
      Object.keys(suppliedHeaders).forEach(function (key) { headers[key] = suppliedHeaders[key]; });
      headers.Accept = headers.Accept || "application/json";
      var body = opts.body;
      if (body !== undefined && body !== null && !(body instanceof FormData)) {
        if (isObject(body) && opts.csrfField) {
          // 登录/注册只接受 auth 用途 token，不能回退到 api 用途 token。
          body = clone(body);
          body[opts.csrfField] = state.authCsrf || "";
        }
        if (isObject(body) || Array.isArray(body)) {
          headers["Content-Type"] = headers["Content-Type"] || "application/json";
          body = JSON.stringify(body);
        }
      }
      if (method !== "GET" && method !== "HEAD") {
        headers["X-CSRF-Token"] = opts.csrfOverride || state.csrfToken || state.authCsrf || "";
      }
      var response;
      try {
        response = await fetch(path, {
          method: method,
          credentials: "include",
          headers: headers,
          body: body
        });
      } catch (networkError) {
        throw new ApiError("网络请求失败，请检查服务是否可用", 0, null, null);
      }
      var data = await parseResponse(response);
      var session = null;
      if (opts.csrfField) {
        // 登录/注册：403 多为 auth token 过期或用途不符，刷新一次 auth token 后重试；
        // 401 是用户名或密码错误，不重试。
        if (response.status === 403 && attempt === 0) {
          attempt += 1;
          session = await refreshSession();
          if (session && !session.authenticated && session.csrf_token) continue;
        }
      } else if (
        (response.status === 401 || response.status === 403) &&
        attempt === 0 &&
        !opts.skipSessionRefresh &&
        path !== "/api/session"
      ) {
        attempt += 1;
        session = await refreshSession();
        if (session && session.accountChanged) {
          // 换号：绝不重试原写请求（否则旧账号数据会写进新账号）；按新账号重新载入数据。
          var changedError = new ApiError("登录账号已变化，已载入当前账号的数据，请重新操作", response.status, null, null);
          changedError.accountChanged = true;
          showToast(changedError.message, "info");
          loadBootstrap();
          throw changedError;
        }
        if (session && session.authenticated) continue;
      }
      if (!response.ok || (data && data.ok === false && !opts.allowNotOk)) {
        var apiError = new ApiError(legacyError(data), response.status, errorDetails(data), data);
        if ((response.status === 401 || response.status === 403) && session && !session.authenticated && !opts.csrfField) {
          // 会话中途过期（刷新会话后确认已未登录）：弹出登录层，不能只弹 toast 后让后续保存被静默跳过。
          apiError.sessionExpired = true;
          handleSessionExpired(session);
        }
        throw apiError;
      }
      return data || {};
    }
  }

  function displayApiError(error, fallback) {
    var message = error && error.message ? error.message : (fallback || "请求失败");
    // 会话过期已由登录层和专门提示处理，避免重复弹出错误 toast。
    if (error && (error.sessionExpired || error.accountChanged)) return message;
    showToast(message, "error");
    return message;
  }

  function draftPayload() {
    var payload = {};
    DRAFT_KEYS.forEach(function (key) { payload[key] = clone(state.config[key]); });
    return payload;
  }

  function updateServerFields(payload) {
    if (!payload || !isObject(payload)) return;
    if (payload.subscription) state.subscription = clone(payload.subscription);
    if (payload.counts || payload.statistics) state.counts = clone(payload.counts || payload.statistics);
    if (Array.isArray(payload.all_targets)) state.allTargets = clone(payload.all_targets);
    if (Array.isArray(payload.warnings)) state.warnings = clone(payload.warnings);
    if (Array.isArray(payload.warnings) && payload.warnings.some(function (warning) {
      return String(warning).indexOf("历史草稿字段损坏") >= 0;
    })) {
      state.draftCorrupted = true;
    } else if (payload.config || payload.proxies) {
      state.draftCorrupted = false;
      state.draftCorruptionAcknowledged = false;
    }
    if (isObject(payload.provider_defaults)) state.providerDefaults = clone(payload.provider_defaults);
    if (isObject(payload.presets)) state.presets = clone(payload.presets);
    if (isObject(payload.dns_presets)) state.dnsPresets = clone(payload.dns_presets);
    if (payload.user) {
      state.user = clone(payload.user);
      state.authenticated = true;
      renderUserPanel(state.user);
    }
  }

  function applyBootstrap(payload, resetGeneration) {
    if (!payload) return;
    state.config = canonicalDraft(payload);
    state.serverConfig = clone(state.config);
    updateServerFields(payload);
    state.nodeFormSchema = isObject(payload.node_form_schema) ? clone(payload.node_form_schema) : {};
    state.globalConfigSchema = isObject(payload.global_config_schema) ? clone(payload.global_config_schema) : {};
    state.presets = isObject(payload.presets) ? clone(payload.presets) : {};
    state.dnsPresets = isObject(payload.dns_presets) ? clone(payload.dns_presets) : state.presets;
    state.providerDefaults = isObject(payload.provider_defaults) ? clone(payload.provider_defaults) : {};
    state.loading = false;
    state.saveError = null;
    if (resetGeneration) {
      state.dirtyGeneration = 0;
      state.savedGeneration = 0;
      state.validation = null;
      state.validatedGeneration = -1;
      state.validatedSignature = "";
      // 上一用户的校验结果与导入提示不能残留在页面上。
      renderValidation(null);
      if ($("importMessages")) { clearElement($("importMessages")); $("importMessages").hidden = true; }
    }
    renderAll();
    updateDraftStatus();
  }

  function applyServerResponse(payload, generation) {
    if (!payload || generation !== state.dirtyGeneration) return false;
    state.config = canonicalDraft(payload);
    state.serverConfig = clone(state.config);
    updateServerFields(payload);
    if (payload.node_form_schema) state.nodeFormSchema = clone(payload.node_form_schema);
    if (payload.global_config_schema) state.globalConfigSchema = clone(payload.global_config_schema);
    if (payload.presets) state.presets = clone(payload.presets);
    if (payload.dns_presets) state.dnsPresets = clone(payload.dns_presets);
    if (payload.provider_defaults) state.providerDefaults = clone(payload.provider_defaults);
    state.savedGeneration = generation;
    state.saveError = null;
    renderAll();
    updateDraftStatus();
    return true;
  }

  function scheduleDraftSave() {
    if (state.saveTimer) window.clearTimeout(state.saveTimer);
    state.saveTimer = window.setTimeout(function () {
      state.saveTimer = null;
      // 失败已通过 saveError 状态与提示呈现；这里吞掉拒绝，避免未处理的 Promise 拒绝。
      if (state.dirtyGeneration > state.savedGeneration) saveChain(state.dirtyGeneration).catch(function () {});
    }, 650);
  }

  function queueDraftSave(generation) {
    if (!state.authenticated || generation !== state.dirtyGeneration) {
      // 排队期间又有新修改：跳过过期快照，但必须重新排队，否则最新修改会静默丢失。
      if (state.authenticated && state.dirtyGeneration > state.savedGeneration) scheduleDraftSave();
      return state.saveSequence;
    }
    var snapshot = draftPayload();
    var epoch = state.authEpoch;
    state.savePending += 1;
    state.saveInFlight = true;
    state.saveSequence = state.saveSequence
      .catch(function () {})
      .then(function () {
        return apiRequest("/api/config", {
          method: "PUT",
          body: snapshot
        }).then(function (payload) {
          if (!isStale(epoch) && generation === state.dirtyGeneration) {
            applyServerResponse(payload, generation);
          }
          return payload;
        });
      })
      .catch(function (error) {
        if (!isStale(epoch) && generation === state.dirtyGeneration) {
          state.saveError = error && error.message ? error.message : "保存失败";
          updateDraftStatus();
          // 会话过期时已弹出登录层并提示，这里不再重复 toast。
          if (!(error && error.sessionExpired)) showToast(state.saveError, "error");
        }
        throw error;
      })
      .then(function (payload) {
        if (isStale(epoch)) return payload;
        state.savePending = Math.max(0, state.savePending - 1);
        state.saveInFlight = state.savePending > 0;
        // renderAll() runs before this flag is cleared; refresh the controls again
        // so a completed save cannot leave global actions disabled.
        updateGlobalActionButtons();
        return payload;
      }, function (error) {
        if (isStale(epoch)) throw error;
        state.savePending = Math.max(0, state.savePending - 1);
        state.saveInFlight = state.savePending > 0;
        // A failed save must release the same global mode/DNS controls.
        updateGlobalActionButtons();
        throw error;
      });
    return state.saveSequence;
  }

  // 调用方已改动本地状态后才进入 markDirty：用户取消时把本地草稿回滚到最近一次
  // 服务端确认的版本并重绘，保持本地与服务端一致。
  function rollbackToServerDraft() {
    state.config = canonicalDraft(state.serverConfig || emptyDraft());
    renderAll();
    updateDraftStatus();
    showToast("已取消修改，服务器上的原草稿未被覆盖", "info");
  }

  // 返回 true 表示修改已登记并排队保存；返回 false 表示用户取消、本地修改已回滚，
  // 调用方应停止后续的保存/提示流程。
  function markDirty() {
    // 历史草稿解析失败时后端返回空草稿；第一次改动保存前必须让用户明确知晓
    // 保存会覆盖原始数据，避免静默清空。
    if (state.draftCorrupted && !state.draftCorruptionAcknowledged) {
      var proceed = window.confirm("检测到服务器上的历史草稿字段损坏，当前显示的是空草稿。\n\n继续保存将用当前内容覆盖原始草稿（包括全部节点与规则）。确定继续吗？");
      if (!proceed) {
        rollbackToServerDraft();
        return false;
      }
      state.draftCorruptionAcknowledged = true;
    }
    state.dirtyGeneration += 1;
    state.validation = null;
    state.validatedGeneration = -1;
    state.validatedSignature = "";
    state.saveError = null;
    renderValidation(null);
    updateDraftStatus();
    scheduleDraftSave();
    return true;
  }

  // 是否存在尚未落盘的修改（含 650ms 去抖窗口内待保存、正在保存中的请求）。
  function hasUnsavedChanges() {
    return Boolean(state.saveTimer) || state.saveInFlight || state.dirtyGeneration > state.savedGeneration;
  }

  async function flushDraftSave() {
    if (state.saveTimer) {
      window.clearTimeout(state.saveTimer);
      state.saveTimer = null;
    }
    if (!state.authenticated) return;
    var epoch = state.authEpoch;
    while (state.dirtyGeneration > state.savedGeneration) {
      var generation = state.dirtyGeneration;
      try {
        await queueDraftSave(generation);
      } catch (error) {
        throw error;
      }
      if (isStale(epoch)) return;
      if (generation === state.dirtyGeneration) break;
    }
    await state.saveSequence;
    if (isStale(epoch)) return;
    updateDraftStatus();
  }

  function saveChain(generation) {
    return queueDraftSave(generation === undefined ? state.dirtyGeneration : generation);
  }
  saveChain.markDirty = markDirty;
  saveChain.flushDraftSave = flushDraftSave;
  saveChain.queueDraftSave = queueDraftSave;
  if (DEBUG_HOOKS) window.saveChain = saveChain;

  // 登录层打开时让背景区域不可聚焦、不可交互（配合焦点陷阱，Tab 只在对话框内循环）。
  function setBackgroundInert(inert) {
    [document.querySelector(".topbar"), $("layout"), document.querySelector(".statusbar")].forEach(function (element) {
      if (!element) return;
      element.inert = inert;
      if (inert) element.setAttribute("aria-hidden", "true");
      else element.removeAttribute("aria-hidden");
    });
  }

  function loginFocusableElements() {
    var card = document.querySelector("#loginOverlay .login-card");
    if (!card) return [];
    return Array.prototype.slice.call(card.querySelectorAll("button, input, select, textarea, a[href], [tabindex]")).filter(function (element) {
      if (element.disabled || element.hidden || element.getAttribute("tabindex") === "-1") return false;
      // display:none 的面板（未激活的登录/注册页）不参与焦点循环。
      return element.getClientRects().length > 0;
    });
  }

  function focusFirstLoginInput() {
    var pane = document.querySelector("#loginOverlay .login-pane.active");
    var input = pane && pane.querySelector("input:not([type=checkbox])");
    var target = input || loginFocusableElements()[0];
    if (target && typeof target.focus === "function") target.focus();
  }

  // 焦点陷阱：登录是强制的，Tab / Shift+Tab 在对话框内循环，Esc 不关闭。
  function trapLoginFocus(event) {
    var overlay = $("loginOverlay");
    if (!overlay || !overlay.classList.contains("active")) return;
    if (event.key === "Escape") {
      event.preventDefault();
      return;
    }
    if (event.key !== "Tab") return;
    var items = loginFocusableElements();
    if (!items.length) {
      event.preventDefault();
      return;
    }
    var first = items[0];
    var last = items[items.length - 1];
    var active = document.activeElement;
    var inside = overlay.contains(active);
    if (event.shiftKey && (active === first || !inside)) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && (active === last || !inside)) {
      event.preventDefault();
      first.focus();
    }
  }

  function showAuthOverlay(session) {
    state.loading = false;
    state.authenticated = false;
    state.authCsrf = (session && session.csrf_token) || state.authCsrf || "";
    closeUserDropdown();
    document.body.classList.add("login-overlay");
    var overlay = $("loginOverlay");
    var wasActive = Boolean(overlay && overlay.classList.contains("active"));
    // 登录层首次出现时清空全部密码框，避免上一用户的明文密码残留在 DOM 中。
    if (!wasActive) {
      ["loginPassword", "registerPassword", "registerPasswordConfirm"].forEach(function (id) {
        if ($(id)) $(id).value = "";
      });
    }
    if (overlay) overlay.classList.add("active");
    setBackgroundInert(true);
    var registerAllowed = !session || session.allow_registration !== false;
    var registerTab = $("registerTabBtn");
    if (registerTab) registerTab.hidden = !registerAllowed;
    if (!registerAllowed) showAuthPane("login");
    setText("serviceStatus", "未登录");
    setText("draftStatus", "登录后加载你的独立草稿");
    if (!wasActive) focusFirstLoginInput();
  }

  function hideAuthOverlay() {
    document.body.classList.remove("login-overlay");
    var overlay = $("loginOverlay");
    if (overlay) overlay.classList.remove("active");
    setBackgroundInert(false);
  }

  // 会话中途过期（接口返回 401 且会话刷新后仍未登录）：弹出登录层。
  // 本地草稿与未保存修改保留在内存中，重新登录后由 completeAuthentication 决定保留或重载。
  function handleSessionExpired(session) {
    var overlay = $("loginOverlay");
    if (overlay && overlay.classList.contains("active")) return;
    showAuthOverlay(session);
    showToast(hasUnsavedChanges() ? "登录已过期，请重新登录；未保存的修改仍保留在本页" : "登录已过期，请重新登录", "error");
  }

  function showAuthPane(name) {
    var login = name === "login";
    if ($("loginTabBtn")) {
      $("loginTabBtn").classList.toggle("active", login);
      $("loginTabBtn").setAttribute("aria-selected", login ? "true" : "false");
    }
    if ($("registerTabBtn")) {
      $("registerTabBtn").classList.toggle("active", !login);
      $("registerTabBtn").setAttribute("aria-selected", login ? "false" : "true");
    }
    if ($("loginPane")) $("loginPane").classList.toggle("active", login);
    if ($("registerPane")) $("registerPane").classList.toggle("active", !login);
  }

  function renderUserPanel(user) {
    var avatar = $("userAvatar");
    var dropdown = $("userDropdown");
    if (!avatar || !dropdown) return;
    clearElement(dropdown);
    if (!user || !user.username) {
      avatar.textContent = "U";
      avatar.title = "未登录";
      closeUserDropdown();
      return;
    }
    avatar.textContent = String(user.username).slice(0, 1).toUpperCase();
    avatar.title = String(user.username);
    var name = document.createElement("div");
    name.className = "ud-name";
    name.textContent = "欢迎，" + String(user.username);
    dropdown.appendChild(name);
    dropdown.appendChild(makeButton("退出登录", "danger", logout));
  }

  function setUserDropdownOpen(open) {
    var dropdown = $("userDropdown");
    var avatar = $("userAvatar");
    if (dropdown) dropdown.classList.toggle("open", open);
    if (avatar) avatar.setAttribute("aria-expanded", open ? "true" : "false");
  }

  function closeUserDropdown() {
    setUserDropdownOpen(false);
  }

  function toggleUserDropdown() {
    var dropdown = $("userDropdown");
    if (dropdown) setUserDropdownOpen(!dropdown.classList.contains("open"));
  }

  // 清空上一用户在本页留下的全部数据（草稿、订阅链接、校验结果、管理员操作结果中的明文 Token 等），
  // 不处理登录态与 CSRF token，由调用方负责。
  function resetUserState() {
    if (state.saveTimer) {
      window.clearTimeout(state.saveTimer);
      state.saveTimer = null;
    }
    state.config = emptyDraft();
    state.serverConfig = emptyDraft();
    state.subscription = {};
    state.counts = {};
    state.warnings = [];
    state.allTargets = [];
    state.nodeQuery = "";
    state.nodeProtocol = "";
    state.nodeForm = { open: false, index: null, protocol: "", raw: false };
    state.dirtyGeneration = 0;
    state.savedGeneration = 0;
    state.saveError = null;
    state.validation = null;
    state.validatedGeneration = -1;
    state.validatedSignature = "";
    state.rulesetUrlTest = { url: "", ok: false };
    state.rulesetMessage = "";
    state.adminUsers = [];
    state.adminLoading = false;
    state.adminLoaded = false;
    state.adminConfirmDelete = null;
    state.adminResult = "";
    state.draftCorrupted = false;
    state.draftCorruptionAcknowledged = false;
    state.sessionExpiredUser = "";
    bumpAuthEpoch();
    // 以下内容直接写在 DOM 中、不随 renderAll 重建，需要单独清空。
    if ($("importInput")) $("importInput").value = "";
    if ($("ruleValue")) $("ruleValue").value = "";
    if ($("ruleTarget")) $("ruleTarget").value = "";
    var dialerList = $("dialerNodeList");
    if (dialerList && dialerList.parentNode) dialerList.parentNode.removeChild(dialerList);
    if ($("importMessages")) { clearElement($("importMessages")); $("importMessages").hidden = true; }
    if ($("nodeSearch")) $("nodeSearch").value = "";
    if ($("nodeRawEditor")) $("nodeRawEditor").value = "";
    clearElement($("nodeSchemaFields"));
    renderValidation(null);
    setText("validationStatus", "尚未校验");
    setText("importSummary", "尚未导入节点");
    renderAll();
    updateDraftStatus();
  }

  async function logout() {
    closeUserDropdown();
    if (hasUnsavedChanges()) {
      try {
        await flushDraftSave();
      } catch (saveError) {
        var message = saveError && saveError.message ? saveError.message : "保存失败";
        if (!window.confirm("草稿保存失败：" + message + "\n\n仍要退出登录吗？未保存的修改将丢失。")) return;
      }
    }
    // 空闲超过 CSRF 有效期后旧 token 会让退出一直 403：先刷新会话取得新的 api token；
    // 若会话已失效则直接按已退出处理。
    var current = null;
    try {
      current = await refreshSession();
    } catch (_) {}
    if (!current || current.authenticated) {
      try {
        await apiRequest("/api/auth/logout", {
          method: "POST",
          skipSessionRefresh: true
        });
      } catch (error) {
        // 401 表示会话已失效，视同已退出；其它错误保持登录状态并提示。
        if (!error || error.status !== 401) {
          displayApiError(error, "退出登录失败");
          return;
        }
      }
    }
    state.user = null;
    state.authenticated = false;
    state.csrfToken = "";
    resetUserState();
    renderUserPanel(null);
    var session = null;
    try {
      // 退出后立即换取 auth 用途的 csrf_token，否则再次登录首个请求会因 token 用途不符被 403。
      session = await refreshSession();
    } catch (_) {}
    showAuthOverlay(session || { csrf_token: "" });
    showToast("已退出登录", "info");
  }

  // 登录/注册成功后的统一收尾：处理会话过期期间换账号、保留未保存修改等情况。
  async function completeAuthentication(payload) {
    // 登录成功后清空登录表单，避免退出后登录层仍预填用户名与明文密码。
    if ($("loginForm")) $("loginForm").reset();
    bumpAuthEpoch();
    var expiredUser = state.sessionExpiredUser;
    state.sessionExpiredUser = "";
    var nextUser = payload.user || null;
    var sameUser = Boolean(expiredUser) && Boolean(nextUser) && String(nextUser.username) === expiredUser;
    // 会话过期后换了账号登录：先清空上一用户的全部本地数据，避免串号。
    if (expiredUser && !sameUser) resetUserState();
    state.authenticated = true;
    state.user = nextUser;
    state.csrfToken = payload.csrf_token || state.csrfToken;
    renderUserPanel(state.user);
    hideAuthOverlay();
    if (sameUser && hasUnsavedChanges() && window.confirm("登录过期前有尚未保存的修改。\n\n确定：保留这些修改并保存到服务器。\n取消：放弃这些修改，重新加载服务器上的草稿。")) {
      state.saveError = null;
      updateDraftStatus();
      try {
        await flushDraftSave();
        showToast("已重新登录，未保存的修改已保存", "info");
      } catch (saveError) {
        displayApiError(saveError, "草稿保存失败");
      }
      return;
    }
    await loadBootstrap();
  }

  async function login(event) {
    event.preventDefault();
    var form = event.currentTarget;
    var button = form.querySelector("button[type=submit]");
    if (button) button.disabled = true;
    try {
      var payload = await apiRequest("/api/auth/login", {
        method: "POST",
        body: {
          username: form.elements.username.value,
          password: form.elements.password.value,
          remember: Boolean(form.elements.remember && form.elements.remember.checked)
        },
        csrfField: "csrf_token"
      });
      await completeAuthentication(payload);
    } catch (error) {
      displayApiError(error, "登录失败");
    } finally {
      if (button) button.disabled = false;
    }
  }

  async function register(event) {
    event.preventDefault();
    var form = event.currentTarget;
    if (form.elements.password.value !== form.elements.passwordConfirm.value) {
      showToast("两次输入的密码不一致", "error");
      return;
    }
    var button = form.querySelector("button[type=submit]");
    if (button) button.disabled = true;
    try {
      var payload = await apiRequest("/api/auth/register", {
        method: "POST",
        body: {
          username: form.elements.username.value,
          password: form.elements.password.value,
          password_confirm: form.elements.passwordConfirm.value
        },
        csrfField: "csrf_token"
      });
      form.reset();
      await completeAuthentication(payload);
      showToast("注册成功，已加载你的草稿", "info");
    } catch (error) {
      displayApiError(error, "注册失败");
    } finally {
      if (button) button.disabled = false;
    }
  }

  async function loadBootstrap() {
    var epoch = state.authEpoch;
    state.loading = true;
    updateDraftStatus();
    try {
      var payload = await apiRequest("/api/config");
      if (isStale(epoch)) return;
      state.authenticated = true;
      applyBootstrap(payload, true);
      hideAuthOverlay();
      if (state.user && state.user.is_admin === true) await loadAdminUsers();
    } catch (error) {
      if (isStale(epoch) || (error && error.accountChanged)) return;
      if (error && (error.status === 401 || error.status === 403)) {
        var nextSession = await refreshSession();
        if (isStale(epoch)) return;
        showAuthOverlay(nextSession);
      } else {
        state.loading = false;
        state.saveError = error && error.message ? error.message : "配置加载失败";
        updateDraftStatus();
        displayApiError(error, "获取配置失败");
      }
    }
  }

  function showStep(step) {
    var value = Math.max(1, Math.min(4, Number(step) || 1));
    document.querySelectorAll("#workspaceNav .wnav-item").forEach(function (button) {
      var active = Number(button.dataset.step) === value;
      button.classList.toggle("active", active);
      button.setAttribute("aria-selected", active ? "true" : "false");
      if (active) button.setAttribute("tabindex", "0");
      else button.setAttribute("tabindex", "-1");
    });
    document.querySelectorAll(".step-section").forEach(function (panel) {
      var active = panel.id === "step" + value;
      panel.classList.toggle("active", active);
      panel.setAttribute("aria-hidden", active ? "false" : "true");
    });
  }

  function initNavigation() {
    var nav = $("workspaceNav");
    if (!nav) return;
    nav.addEventListener("click", function (event) {
      var button = event.target.closest(".wnav-item");
      if (button) showStep(button.dataset.step);
    });
    nav.addEventListener("keydown", function (event) {
      var buttons = Array.prototype.slice.call(nav.querySelectorAll(".wnav-item"));
      var current = buttons.indexOf(document.activeElement);
      if (current < 0) return;
      var next = current;
      if (event.key === "ArrowRight" || event.key === "ArrowDown") next = (current + 1) % buttons.length;
      if (event.key === "ArrowLeft" || event.key === "ArrowUp") next = (current - 1 + buttons.length) % buttons.length;
      if (event.key === "Home") next = 0;
      if (event.key === "End") next = buttons.length - 1;
      if (next !== current) {
        event.preventDefault();
        buttons[next].focus();
        showStep(buttons[next].dataset.step);
      }
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        showStep(document.activeElement.dataset.step);
      }
    });
    showStep(1);
  }

  function renderStats() {
    var counts = state.counts || {};
    var ready = !state.loading && state.authenticated;
    var nodeCount = ready && Array.isArray(state.config.proxies) ? state.config.proxies.length : undefined;
    setText("nodeCount", nodeCount, "—");
    setText("ruleCountStat", ready ? counts.rules : undefined, "—");
    setText("groupCount", ready ? counts.groups : undefined, "—");
    var subscription = state.subscription || {};
    setText("subscriptionStatus", subscription.status === "published" ? "已发布" : (subscription.status === "draft" ? "草稿" : "—"));
    setText("subscriptionMeta", subscription.published_at || (subscription.status === "draft" ? "尚未发布" : "—"));
    setText("nodeSummary", ready ? String(nodeCount) + " 个节点" : "正在加载");
    setText("ruleCount", ready ? state.config.custom_rules.length : undefined, "—");
    setText("footerNodeCount", nodeCount, "—");
    setText("footerRuleCount", ready ? counts.rules : undefined, "—");
    if (counts.mihomo) setText("runtimeMihomo", counts.mihomo);
  }

  function renderSubscription() {
    var subscription = state.subscription || {};
    var url = typeof subscription.url === "string" ? subscription.url : "";
    setText("subUrl", url, "尚未发布订阅");
    var title = $("subscriptionCardStatus");
    if (title) {
      title.textContent = subscription.status === "published" ? "● 已发布" : (subscription.status === "draft" ? "● 草稿" : "● 未发布");
      title.style.color = subscription.status === "published" ? "var(--success)" : "var(--warn)";
    }
    var copy = $("subCopyBtn");
    if (copy) copy.disabled = !url;
  }

  function renderImport() {
    var input = $("importInput");
    if (!input) return;
    var placeholders = {
      yaml: "粘贴完整 config.yaml、proxies 片段或节点列表",
      url: "输入订阅 URL",
      share: "每行一条 ss://、vless://、vmess://、trojan://、hysteria2://、tuic:// 或 anytls://"
    };
    input.placeholder = placeholders[state.importMethod] || placeholders.yaml;
    input.setAttribute("aria-label", state.importMethod === "url" ? "订阅 URL" : "导入内容");
    document.querySelectorAll(".method-card").forEach(function (card) {
      var active = card.dataset.method === state.importMethod;
      card.classList.toggle("active", active);
      card.setAttribute("aria-selected", active ? "true" : "false");
    });
    setText("importSummary", state.loading ? "正在加载后端草稿…" : (state.config.proxies.length ? "当前草稿已有 " + state.config.proxies.length + " 个节点" : "尚未导入节点"));
  }

  function renderRuleSource() {
    var select = $("ruleSource");
    if (!select) return;
    var options = [
      ["dustinwin规则", "DustinWin 规则源"],
      ["lhie1规则", "lhie1 规则源"],
      ["none", "无基础规则（仅使用自定义规则）"]
    ];
    clearElement(select);
    options.forEach(function (item) {
      var option = document.createElement("option");
      option.value = item[0];
      option.textContent = item[1];
      select.appendChild(option);
    });
    if (state.config.selected_rule_type) {
      select.value = state.config.selected_rule_type === "自定义规则" ? "none" : state.config.selected_rule_type;
    }
    if (!select.value) select.value = options[0][0];
    setText("ruleSourceStatus", "当前规则源：" + select.options[select.selectedIndex].textContent);
    renderProviderTargets();
  }

  function selectedProviderSource() {
    if (state.config.selected_rule_type === "dustinwin规则") return "dustinwin";
    if (state.config.selected_rule_type === "lhie1规则") return "lhie1";
    return "";
  }

  function renderProviderTargets() {
    var panel = $("providerTargetsPanel");
    if (!panel) return;
    clearElement(panel);
    var sourceKey = selectedProviderSource();
    panel.hidden = !sourceKey;
    if (!sourceKey) return;
    var defaults = isObject(state.providerDefaults[sourceKey]) ? state.providerDefaults[sourceKey] : {};
    var overrideKey = sourceKey + "_provider_targets";
    var overrides = isObject(state.config.global_config[overrideKey]) ? state.config.global_config[overrideKey] : {};
    var head = document.createElement("div");
    head.className = "panel-head";
    var title = document.createElement("div");
    title.className = "panel-title";
    title.textContent = sourceKey === "dustinwin" ? "DustinWin 规则目标" : "lhie1 规则目标";
    head.appendChild(title);
    var restore = makeButton("恢复当前源默认", "btn btn-ghost", function () {
      state.config.global_config[overrideKey] = {};
      if (!markDirty()) return;
      renderProviderTargets();
      showToast("已恢复当前规则源默认目标，正在排队保存", "info");
    });
    restore.setAttribute("aria-label", "恢复当前规则源默认目标");
    head.appendChild(restore);
    panel.appendChild(head);
    var hint = document.createElement("div");
    hint.className = "status-note";
    hint.textContent = "仅修改当前规则源；切换到另一源不会覆盖其独立覆盖表。";
    panel.appendChild(hint);
    var editor = document.createElement("div");
    editor.className = "target-editor";
    var providerNames = Object.keys(defaults);
    if (!providerNames.length) {
      var empty = document.createElement("div");
      empty.className = "phase2-empty";
      empty.textContent = "服务端尚未提供该规则源的默认目标策略。";
      editor.appendChild(empty);
    }
    providerNames.forEach(function (providerName, index) {
      var defaultTarget = String(defaults[providerName] === undefined ? "" : defaults[providerName]);
      var selected = String(Object.prototype.hasOwnProperty.call(overrides, providerName) ? overrides[providerName] : defaultTarget);
      if (selected === "no-resolve") selected = "Proxy";
      var row = document.createElement("div");
      row.className = "target-row";
      var text = document.createElement("span");
      var name = document.createElement("span");
      name.className = "target-name";
      name.textContent = providerName;
      var note = document.createElement("span");
      note.className = "target-default";
      note.textContent = "默认：" + defaultTarget;
      text.appendChild(name);
      text.appendChild(note);
      row.appendChild(text);
      var select = document.createElement("select");
      select.id = "provider-target-" + sourceKey + "-" + index;
      select.setAttribute("aria-label", providerName + " 目标策略");
      var options = Array.isArray(state.allTargets) ? state.allTargets.map(String).filter(function (value) { return value !== "no-resolve"; }) : [];
      if (options.indexOf(selected) < 0) options.unshift(selected);
      if (!options.length) options = [selected];
      options.filter(function (value, optionIndex, list) { return value && list.indexOf(value) === optionIndex; }).forEach(function (value) {
        var option = document.createElement("option");
        option.value = value;
        option.textContent = value;
        select.appendChild(option);
      });
      select.value = selected;
      select.addEventListener("change", function () {
        var next = isObject(state.config.global_config[overrideKey]) ? clone(state.config.global_config[overrideKey]) : {};
        if (select.value === defaultTarget) delete next[providerName];
        else next[providerName] = select.value;
        state.config.global_config[overrideKey] = next;
        markDirty();
      });
      row.appendChild(select);
      editor.appendChild(row);
    });
    panel.appendChild(editor);
  }

  function renderRules() {
    var target = $("ruleTarget");
    var targets = Array.isArray(state.allTargets) ? state.allTargets : [];
    if (target) {
      // 目标策略支持从列表选择与手动输入（对齐 V1 双模式），datalist 提供候选。
      var datalist = $("ruleTargetOptions");
      var fillTarget = function (element) {
        if (!element) return;
        clearElement(element);
        targets.filter(function (value) { return String(value) !== "no-resolve"; }).forEach(function (value) {
          var option = document.createElement("option");
          option.value = String(value);
          element.appendChild(option);
        });
      };
      fillTarget(datalist);
      if (!target.value) {
        var preferred = targets.find(function (value) { return String(value) === "Proxy"; }) || targets[0];
        if (preferred !== undefined) target.value = String(preferred);
      }
      target.placeholder = targets.length ? "选择或输入策略组名称" : "输入策略组名称";
    }
    var list = $("ruleList");
    if (!list) return;
    clearElement(list);
    var rules = Array.isArray(state.config.custom_rules) ? state.config.custom_rules : [];
    if (!rules.length) {
      var empty = document.createElement("div");
      empty.className = "check-empty";
      empty.textContent = "暂无自定义规则";
      list.appendChild(empty);
      return;
    }
    rules.forEach(function (raw, index) {
      var parts = String(raw).split(",");
      var item = document.createElement("div");
      item.className = "rule-item";
      appendText(item, String(index + 1).padStart(2, "0"), "rule-idx");
      appendText(item, parts[0] || "", "rule-type");
      appendText(item, parts[1] || "", "rule-value");
      var route = document.createElement("span");
      route.className = "rule-target";
      route.textContent = "→ " + (parts.slice(2).join(",") || "");
      item.appendChild(route);
      var moveUp = makeButton("上移", "chip-btn", function () { moveRule(index, -1); });
      moveUp.disabled = index === 0;
      var moveDown = makeButton("下移", "chip-btn", function () { moveRule(index, 1); });
      moveDown.disabled = index === rules.length - 1;
      item.appendChild(moveUp);
      item.appendChild(moveDown);
      var remove = makeButton("删除", "rule-del", function () {
        state.config.custom_rules.splice(index, 1);
        if (!markDirty()) return;
        renderRules();
        renderStats();
      });
      item.appendChild(remove);
      list.appendChild(item);
    });
  }

  function moveRule(index, direction) {
    var rules = state.config.custom_rules;
    var next = index + direction;
    if (!Array.isArray(rules) || next < 0 || next >= rules.length) return;
    var current = rules[index];
    rules[index] = rules[next];
    rules[next] = current;
    if (!markDirty()) return;
    renderRules();
    renderStats();
  }

  function rulesetField(parent, id, labelText, type, value, options) {
    var field = document.createElement("div");
    field.className = "field";
    var label = document.createElement("label");
    label.htmlFor = id;
    label.textContent = labelText;
    field.appendChild(label);
    var control = document.createElement(type === "select" ? "select" : "input");
    control.id = id;
    control.name = id;
    if (type !== "select") control.type = type;
    if (type === "select") {
      (options || []).forEach(function (optionValue) {
        var option = document.createElement("option");
        option.value = String(optionValue);
        option.textContent = String(optionValue);
        control.appendChild(option);
      });
    }
    if (type === "file") control.className = "ruleset-file";
    if (type !== "file") control.value = value === undefined || value === null ? "" : String(value);
    field.appendChild(control);
    parent.appendChild(field);
    return control;
  }

  function rulesetTargetOptions(current) {
    var options = Array.isArray(state.allTargets) ? state.allTargets.map(String).filter(function (value) { return value !== "no-resolve"; }) : [];
    var selected = String(current || "Proxy");
    if (selected === "no-resolve") selected = "Proxy";
    if (options.indexOf(selected) < 0) options.unshift(selected);
    if (!options.length) options = [selected];
    return options.filter(function (value, index, list) { return value && list.indexOf(value) === index; });
  }

  function renderRulesets() {
    var panel = $("rulesetPanel");
    if (!panel) return;
    clearElement(panel);
    var providers = isObject(state.config.custom_rule_providers) ? state.config.custom_rule_providers : {};
    var head = document.createElement("div");
    head.className = "panel-head";
    var title = document.createElement("div");
    title.className = "panel-title";
    title.textContent = "自定义规则集";
    head.appendChild(title);
    var hint = document.createElement("span");
    hint.className = "panel-hint";
    hint.textContent = Object.keys(providers).length + " 个规则集";
    head.appendChild(hint);
    panel.appendChild(head);
    var listSection = document.createElement("div");
    listSection.className = "phase2-section";
    var listHead = document.createElement("div");
    listHead.className = "phase2-section-head";
    var listTitle = document.createElement("div");
    listTitle.className = "phase2-section-title";
    listTitle.textContent = "当前规则集";
    listHead.appendChild(listTitle);
    var listHint = document.createElement("div");
    listHint.className = "phase2-section-hint";
    listHint.textContent = "生成时按各规则集的“匹配顺序”排列";
    listHead.appendChild(listHint);
    listSection.appendChild(listHead);
    var list = document.createElement("div");
    list.className = "ruleset-list";
    var names = Object.keys(providers);
    if (!names.length) {
      var empty = document.createElement("div");
      empty.className = "empty-state";
      empty.textContent = "暂无自定义规则集，可在下方添加 HTTP 或本地文件规则集。";
      list.appendChild(empty);
    }
    names.forEach(function (name) {
      var provider = isObject(providers[name]) ? providers[name] : {};
      var row = document.createElement("div");
      row.className = "ruleset-row";
      var main = document.createElement("div");
      main.className = "ruleset-row-main";
      var nameNode = document.createElement("div");
      nameNode.className = "ruleset-name";
      nameNode.textContent = name;
      main.appendChild(nameNode);
      var meta = document.createElement("div");
      meta.className = "ruleset-meta";
      var source = provider.type === "http" ? (provider.url || "HTTP") : (provider.path || "本地文件");
      meta.textContent = String(provider.type || "file") + " · " + String(provider.behavior || "classical") + " · " + String(provider.format || "") + " · " + String(provider.order || "追加") + " · 目标：" + String(provider.target || "Proxy") + " · " + String(source);
      main.appendChild(meta);
      row.appendChild(main);
      var actions = document.createElement("div");
      actions.className = "ruleset-row-actions";
      var remove = makeButton("移除", "chip-btn danger", function () { removeRuleset(name); });
      remove.setAttribute("aria-label", "移除规则集 " + name);
      actions.appendChild(remove);
      row.appendChild(actions);
      list.appendChild(row);
    });
    listSection.appendChild(list);
    panel.appendChild(listSection);

    var formSection = document.createElement("div");
    formSection.className = "phase2-section";
    var formHead = document.createElement("div");
    formHead.className = "phase2-section-head";
    var formTitle = document.createElement("div");
    formTitle.className = "phase2-section-title";
    formTitle.textContent = "添加规则集";
    formHead.appendChild(formTitle);
    var formHint = document.createElement("div");
    formHint.className = "phase2-section-hint";
    formHint.textContent = "保存前会校验必填字段；URL 可单独测试";
    formHead.appendChild(formHint);
    formSection.appendChild(formHead);
    var mode = document.createElement("div");
    mode.className = "ruleset-mode";
    var httpMode = makeButton("HTTP 规则集", "btn btn-ghost" + (state.rulesetMode === "http" ? " active" : ""), function () {
      state.rulesetMode = "http";
      renderRulesets();
    });
    httpMode.id = "rulesetHttpModeBtn";
    httpMode.setAttribute("aria-pressed", state.rulesetMode === "http" ? "true" : "false");
    var fileMode = makeButton("本地文件规则集", "btn btn-ghost" + (state.rulesetMode === "file" ? " active" : ""), function () {
      state.rulesetMode = "file";
      renderRulesets();
    });
    fileMode.id = "rulesetFileModeBtn";
    fileMode.setAttribute("aria-pressed", state.rulesetMode === "file" ? "true" : "false");
    mode.appendChild(httpMode);
    mode.appendChild(fileMode);
    formSection.appendChild(mode);
    var form = document.createElement("div");
    form.className = "ruleset-form";
    rulesetField(form, "rulesetAlias", "规则集别名", "text", "");
    if (state.rulesetMode === "http") {
      rulesetField(form, "rulesetUrl", "规则集 URL", "url", "");
    } else {
      var fileField = rulesetField(form, "rulesetFile", "规则集文件", "file", "");
      fileField.accept = ".yaml,.yml,.txt,.list,.mrs";
    }
    rulesetField(form, "rulesetBehavior", "behavior", "select", "domain", ["classical", "domain", "ipcidr"]);
    rulesetField(form, "rulesetFormat", "format", "select", "yaml", ["text", "yaml", "mrs"]);
    var interval = rulesetField(form, "rulesetInterval", "更新间隔（秒）", "number", "86400");
    interval.min = "1";
    interval.max = "31536000";
    var order = rulesetField(form, "rulesetOrder", "匹配顺序", "select", "追加", ["优先 (覆盖)", "默认 (追加)", "追加"]);
    order.setAttribute("aria-describedby", "rulesetOrderHelp");
    var target = rulesetField(form, "rulesetTarget", "目标策略", "select", "Proxy", rulesetTargetOptions("Proxy"));
    target.setAttribute("aria-label", "规则集目标策略");
    formSection.appendChild(form);
    var orderHelp = document.createElement("div");
    orderHelp.id = "rulesetOrderHelp";
    orderHelp.className = "schema-note";
    orderHelp.textContent = "优先 (覆盖) 会把规则集放在基础规则之前；追加会放在基础规则之后。";
    formSection.appendChild(orderHelp);
    var actions = document.createElement("div");
    actions.className = "ruleset-actions";
    if (state.rulesetMode === "http") {
      var test = makeButton("测试 URL", "btn btn-ghost", testRulesetUrl);
      test.id = "rulesetTestUrlBtn";
      actions.appendChild(test);
    }
    var save = makeButton(state.rulesetMode === "http" ? "保存 HTTP 规则集" : "上传并保存文件规则集", "btn btn-primary", state.rulesetMode === "http" ? saveHttpRuleset : uploadFileRuleset);
    save.id = state.rulesetMode === "http" ? "rulesetSaveBtn" : "rulesetUploadBtn";
    actions.appendChild(save);
    formSection.appendChild(actions);
    var message = document.createElement("div");
    message.id = "rulesetMessage";
    message.className = "ruleset-message status-note";
    message.textContent = state.rulesetMessage || "";
    formSection.appendChild(message);
    panel.appendChild(formSection);
  }

  function rulesetFormValues() {
    function value(id, fallback) {
      var control = $(id);
      return control ? String(control.value || "").trim() : fallback;
    }
    return {
      alias: value("rulesetAlias", ""),
      url: value("rulesetUrl", ""),
      behavior: value("rulesetBehavior", "domain"),
      format: value("rulesetFormat", "yaml"),
      interval: value("rulesetInterval", "86400"),
      order: value("rulesetOrder", "追加"),
      target: value("rulesetTarget", "Proxy")
    };
  }

  function validateRulesetValues(values, requireUrl) {
    if (!values.alias || !/^[A-Za-z0-9._-]+$/.test(values.alias)) throw new ApiError("规则集别名只能使用字母、数字、点、下划线或短横线", 400);
    var interval = Number(values.interval);
    if (!Number.isInteger(interval) || interval < 1 || interval > 31536000) throw new ApiError("更新间隔必须是 1 到 31536000 秒之间的整数", 400);
    if (!values.target) throw new ApiError("请选择规则集目标策略", 400);
    if (values.target === "no-resolve") throw new ApiError("no-resolve 只能作为规则修饰符，不能作为目标策略", 400);
    if (requireUrl) {
      if (!values.url) throw new ApiError("请输入规则集 URL", 400);
      try {
        var parsed = new URL(values.url, window.location.origin);
        if (parsed.protocol !== "http:" && parsed.protocol !== "https:") throw new Error("protocol");
      } catch (_) {
        throw new ApiError("规则集 URL 必须是 http 或 https 地址", 400);
      }
    }
    return interval;
  }

  async function testRulesetUrl() {
    var epoch = state.authEpoch;
    var values = rulesetFormValues();
    try {
      validateRulesetValues(values, true);
      var button = $("rulesetTestUrlBtn");
      if (button) button.disabled = true;
      var payload = await apiRequest("/api/ruleset/test-url", { method: "POST", body: { url: values.url } });
      if (isStale(epoch)) return;
      state.rulesetUrlTest = { url: values.url, ok: true };
      state.rulesetMessage = "URL 检查通过：" + String(payload.content_type || "可访问") + "，" + String(payload.size || 0) + " bytes";
      var message = $("rulesetMessage");
      if (message) message.textContent = state.rulesetMessage;
    } catch (error) {
      if (isStale(epoch)) return;
      state.rulesetUrlTest = { url: values.url, ok: false };
      state.rulesetMessage = error && error.message ? error.message : "URL 检查失败";
      var errorMessage = $("rulesetMessage");
      if (errorMessage) errorMessage.textContent = state.rulesetMessage;
      displayApiError(error, "规则集 URL 检查失败");
    } finally {
      var testButton = $("rulesetTestUrlBtn");
      if (testButton) testButton.disabled = false;
    }
  }

  async function saveHttpRuleset() {
    var epoch = state.authEpoch;
    var values = rulesetFormValues();
    var button = $("rulesetSaveBtn");
    if (button) button.disabled = true;
    try {
      var interval = validateRulesetValues(values, true);
      var provider = {
        type: "http",
        behavior: values.behavior,
        format: values.format,
        url: values.url,
        interval: interval,
        order: values.order,
        target: values.target
      };
      state.config.custom_rule_providers[values.alias] = provider;
      if (!markDirty()) return;
      await flushDraftSave();
      if (isStale(epoch)) return;
      state.rulesetMessage = "HTTP 规则集已保存到草稿。";
      renderAll();
      showToast("HTTP 规则集已保存", "info");
    } catch (error) {
      if (isStale(epoch)) return;
      displayApiError(error, "HTTP 规则集保存失败");
    } finally {
      var saveButton = $("rulesetSaveBtn");
      if (saveButton) saveButton.disabled = false;
    }
  }

  async function uploadFileRuleset() {
    var epoch = state.authEpoch;
    var values = rulesetFormValues();
    var fileInput = $("rulesetFile");
    var file = fileInput && fileInput.files && fileInput.files[0];
    var button = $("rulesetUploadBtn");
    if (button) button.disabled = true;
    try {
      var interval = validateRulesetValues(values, false);
      if (!file) throw new ApiError("请选择规则集文件", 400);
      var form = new FormData();
      form.append("file", file);
      form.append("alias", values.alias);
      form.append("behavior", values.behavior);
      form.append("format", values.format);
      form.append("interval", String(interval));
      form.append("order", values.order);
      form.append("target", values.target);
      var payload = await apiRequest("/api/ruleset/upload", { method: "POST", body: form });
      if (isStale(epoch)) return;
      var incoming = isObject(payload.custom_rule_providers) ? payload.custom_rule_providers : {};
      if (!Object.keys(incoming).length && isObject(payload.custom_rule_provider)) incoming = payload.custom_rule_provider;
      if (!Object.keys(incoming).length && isObject(payload.provider)) incoming[values.alias] = payload.provider;
      if (!Object.keys(incoming).length) throw new ApiError("服务端未返回可保存的规则集", 502);
      state.config.custom_rule_providers = Object.assign({}, state.config.custom_rule_providers, clone(incoming));
      if (!markDirty()) return;
      await flushDraftSave();
      if (isStale(epoch)) return;
      var serverWarnings = Array.isArray(payload.warnings) ? payload.warnings : [];
      state.rulesetMessage = serverWarnings.length ? "文件已保存；服务端提示：" + serverWarnings.join("；") : "文件规则集已保存到草稿。";
      renderAll();
      if (serverWarnings.length) showToast("文件规则集已保存，但有服务端提示", "info");
      else showToast("文件规则集已保存", "info");
    } catch (error) {
      if (isStale(epoch)) return;
      displayApiError(error, "文件规则集保存失败");
    } finally {
      var uploadButton = $("rulesetUploadBtn");
      if (uploadButton) uploadButton.disabled = false;
    }
  }

  async function restoreRemovedRuleset(name, provider, reason) {
    var epoch = state.authEpoch;
    state.config.custom_rule_providers[name] = provider;
    if (!markDirty()) return;
    renderAll();
    // 会话已过期（登录层已弹出）：只在本地恢复，不保存也不提示“草稿已恢复”。
    if (!state.authenticated) return;
    try {
      await flushDraftSave();
      if (isStale(epoch)) return;
      displayApiError(new ApiError(reason + "，草稿已恢复"), "规则集移除失败");
    } catch (restoreError) {
      if (isStale(epoch)) return;
      displayApiError(new ApiError(reason + "，且草稿恢复失败，请刷新页面确认"), "规则集移除失败");
    }
  }

  async function removeRuleset(name) {
    var providers = isObject(state.config.custom_rule_providers) ? state.config.custom_rule_providers : {};
    if (!Object.prototype.hasOwnProperty.call(providers, name)) return;
    var previousProvider = clone(providers[name]);
    var isPrivateVersion = /^\.\/ruleset\/users\/\d+\//.test(String(previousProvider && previousProvider.path || ""));
    var epoch = state.authEpoch;
    delete state.config.custom_rule_providers[name];
    if (!markDirty()) return;
    try {
      // 只先保存草稿移除；当前 published YAML 可能仍引用旧版本，物理
      // 文件必须等发布成功后的 draft ∪ published 引用清理再处理。
      await flushDraftSave();
      if (isStale(epoch)) return;
      state.rulesetMessage = isPrivateVersion ? "规则集已从草稿移除；发布后清理旧版本。" : "规则集已从草稿移除。";
      renderAll();
      showToast(state.rulesetMessage, "info");
    } catch (error) {
      if (isStale(epoch)) return;
      await restoreRemovedRuleset(name, previousProvider, "规则集移除保存失败");
    }
  }

  function conditionMatches(condition, values) {
    if (!condition || typeof condition !== "object") return true;
    var actual = values[condition.key];
    if (Object.prototype.hasOwnProperty.call(condition, "equals")) return actual === condition.equals;
    if (Object.prototype.hasOwnProperty.call(condition, "not_equals")) return actual !== condition.not_equals;
    return true;
  }

  function controlValues(root) {
    var values = {};
    if (!root) return values;
    root.querySelectorAll("[data-field-key]").forEach(function (control) {
      var key = control.dataset.fieldKey;
      values[key] = control.type === "checkbox" ? control.checked : control.value;
    });
    return values;
  }

  function updateSchemaVisibility(root) {
    if (!root) return;
    var values = controlValues(root);
    root.querySelectorAll("[data-condition]").forEach(function (field) {
      var condition;
      try { condition = JSON.parse(field.dataset.condition); } catch (_) { condition = null; }
      field.classList.toggle("schema-field-hidden", !conditionMatches(condition, values));
    });
  }

  function valueForField(field, values, fallback) {
    var key = field.key;
    if (Object.prototype.hasOwnProperty.call(values, key) && values[key] !== undefined && values[key] !== null) return values[key];
    if (Object.prototype.hasOwnProperty.call(field, "default")) return field.default;
    return fallback;
  }

  function addSchemaControl(parent, field, values, onChange) {
    var wrapper = document.createElement("div");
    wrapper.className = "field schema-field";
    var condition = field.visible_condition || field.visible;
    if (condition && typeof condition === "object") wrapper.dataset.condition = JSON.stringify(condition);
    var label = document.createElement("label");
    label.textContent = (field.label || field.key || "") + (field.required ? " *" : "");
    wrapper.appendChild(label);
    var type = field.type || "input";
    var control;
    var value = valueForField(field, values, type === "checkbox" ? false : "");
    if (type === "select") {
      control = document.createElement("select");
      var optionValues = Array.isArray(field.options) ? field.options : [];
      var selectValue = value === undefined || value === null ? "" : String(value);
      // 编辑既有节点时，字段值可能不在后端枚举里（如订阅带来的旧 flow 值）。
      // 保留原值为首个选项，避免 select 回填为空导致保存时被误判缺字段。
      if (selectValue !== "" && !optionValues.some(function (optionValue) { return String(optionValue) === selectValue; })) {
        var currentOption = document.createElement("option");
        currentOption.value = selectValue;
        currentOption.textContent = selectValue + "（当前值）";
        control.appendChild(currentOption);
      }
      optionValues.forEach(function (optionValue) {
        var option = document.createElement("option");
        option.value = String(optionValue);
        option.textContent = String(optionValue);
        control.appendChild(option);
      });
      control.value = selectValue;
    } else if (type === "textarea") {
      control = document.createElement("textarea");
      control.rows = 3;
      control.value = isObject(value) ? JSON.stringify(value, null, 2) : (value === undefined || value === null ? "" : String(value));
    } else {
      control = document.createElement("input");
      control.type = type === "checkbox" ? "checkbox" : (field.input_type || "text");
      if (control.type === "checkbox") control.checked = Boolean(value);
      else {
        control.value = value === undefined || value === null ? "" : String(value);
        if (field.min !== undefined) control.min = String(field.min);
        if (field.max !== undefined) control.max = String(field.max);
      }
    }
    control.dataset.fieldKey = field.key;
    if (field.required && type !== "checkbox") control.required = true;
    control.id = (field._idPrefix || "schema") + "-" + String(field.key || "field").replace(/[^a-zA-Z0-9_-]/g, "-");
    label.htmlFor = control.id;
    control.addEventListener("change", function () {
      onChange(field, control);
      updateSchemaVisibility(parent);
    });
    if (control.type !== "checkbox") {
      control.addEventListener("input", function () { updateSchemaVisibility(parent); });
    }
    wrapper.appendChild(control);
    if (field.help) {
      var help = document.createElement("div");
      help.className = "schema-note";
      help.textContent = field.help;
      wrapper.appendChild(help);
    }
    parent.appendChild(wrapper);
  }

  function serializeTextValue(control, field) {
    if (control.type === "checkbox") return Boolean(control.checked);
    if ((field.input_type || control.type) === "number") {
      var number = Number(control.value);
      return Number.isFinite(number) ? number : control.value;
    }
    if (field.type === "textarea" && (field.key === "lhie1_provider_targets" || field.key === "dustinwin_provider_targets")) {
      var raw = control.value.trim();
      if (!raw) return {};
      try { return JSON.parse(raw); } catch (_) { return raw; }
    }
    return control.value;
  }

  function renderGlobalConfig() {
    var container = $("globalSchemaPanel");
    if (!container) return;
    clearElement(container);
    var schema = state.globalConfigSchema || {};
    var values = state.config.global_config || {};
    var keys = Object.keys(schema);
    if (!keys.length) {
      var empty = document.createElement("div");
      empty.className = "phase2-empty";
      empty.textContent = "服务端尚未提供全局设置字段定义，暂无可编辑的设置。";
      container.appendChild(empty);
      return;
    }
    var groups = [
      { id: "basic", label: "基础与模式", keys: ["optional_globals_v2", "generation_profile", "is_desktop", "include_inbound_ports", "include_global_compat", "include_router_options", "enable_core_options", "port", "socks_port", "mixed_port", "allow_lan", "bind_address", "mode", "log_level", "ipv6_support", "openclash_preset"] },
      { id: "controller", label: "控制器", keys: ["include_controller", "external_controller", "secret", "external_ui", "external_ui_name", "external_ui_url"] },
      { id: "speed", label: "测速与性能", keys: ["find_process_mode", "url_test_url", "url_test_interval", "url_test_tolerance", "tcp_concurrent", "unified_delay", "geodata_mode", "geodata_loader", "keep_alive_interval", "keep_alive_idle"] },
      { id: "tun", label: "TUN 与路由", keys: ["enable_tun", "tun_stack", "tun_device", "tun_auto_route", "tun_auto_detect_interface", "tun_dns_hijack", "tun_dns_hijack_value", "tun_endpoint_independent_nat", "tun_auto_redirect", "tun_strict_route", "redir_port", "tproxy_port", "interface_name"] },
      { id: "dns", label: "DNS", keys: ["enable_dns", "dns_listen", "dns_ipv6", "enhanced_mode", "fake_ip_range", "fake_ip_range6", "fake_ip_filter_mode", "dns_respect_rules", "direct_nameserver", "proxy_server_nameserver", "default_nameserver", "nameserver", "fallback", "nameserver_policy"] },
      { id: "sniffer", label: "嗅探", keys: ["enable_sniffer", "sniff_override_dest", "sniffer_parse_pure_ip", "sniffer_force_dns_mapping"] },
      { id: "profile", label: "配置与其他", keys: ["profile_store_selected", "profile_store_fake_ip", "ntp_enable", "ntp_server", "ntp_port", "ntp_interval", "ntp_write_to_system", "authentication"] }
    ];
    var assigned = {};
    groups.forEach(function (group) { group.keys.forEach(function (key) { assigned[key] = true; }); });
    var remaining = keys.filter(function (key) { return !assigned[key] && key !== "lhie1_provider_targets" && key !== "dustinwin_provider_targets"; });
    if (remaining.length) groups[groups.length - 1].keys = groups[groups.length - 1].keys.concat(remaining);
    groups.forEach(function (group, groupIndex) {
      var groupKeys = group.keys.filter(function (key) { return Object.prototype.hasOwnProperty.call(schema, key) && key !== "lhie1_provider_targets" && key !== "dustinwin_provider_targets"; });
      if (!groupKeys.length) return;
      var details = document.createElement("details");
      details.className = "schema-group";
      details.open = groupIndex === 0 || group.id === "dns";
      var summary = document.createElement("summary");
      summary.textContent = group.label;
      details.appendChild(summary);
      var grid = document.createElement("div");
      grid.className = "schema-grid schema-group-grid";
      groupKeys.forEach(function (key) {
        var field = schema[key] || {};
        addSchemaControl(grid, Object.assign({ key: key, label: key, _idPrefix: "global" }, field), values, function (field, control) {
          state.config.global_config[field.key] = serializeTextValue(control, field);
          markDirty();
        });
      });
      details.appendChild(grid);
      container.appendChild(details);
    });
    updateSchemaVisibility(container);
  }

  function renderProtocolPills() {
    var container = $("protocolPills");
    if (!container) return;
    clearElement(container);
    var protocols = Object.keys(state.nodeFormSchema || {});
    if (!protocols.length) {
      protocols = state.config.proxies.map(function (node) { return String(node.type || ""); }).filter(Boolean).filter(function (item, index, list) { return list.indexOf(item) === index; });
    }
    var all = makeButton("全部", "pill" + (!state.nodeProtocol ? " active" : ""), function () {
      state.nodeProtocol = "";
      renderProtocolPills();
      renderNodes();
    });
    all.dataset.protocol = "";
    container.appendChild(all);
    protocols.forEach(function (protocol) {
      var pill = makeButton(protocol, "pill" + (state.nodeProtocol === protocol ? " active" : ""), function () {
        state.nodeProtocol = protocol;
        renderProtocolPills();
        renderNodes();
      });
      pill.dataset.protocol = protocol;
      container.appendChild(pill);
    });
  }

  function nodeToFields(node) {
    // 新增节点（空对象）时不回填任何字段值，让 schema default 决定初始状态，
    // 避免显式 false 覆盖后端声明的默认开关（如 anytls 跳过证书验证、端口跳跃）。
    if (!node || !Object.keys(node).length) return {};
    var value = node;
    var ws = isObject(value["ws-opts"]) ? value["ws-opts"] : {};
    var h2 = isObject(value["h2-opts"]) ? value["h2-opts"] : {};
    var grpc = isObject(value["grpc-opts"]) ? value["grpc-opts"] : {};
    var quic = isObject(value["quic-params"]) ? value["quic-params"] : {};
    var fields = {
      node_name: value.name || "",
      node_server: value.server || "",
      node_port: value.port || 443,
      node_udp: value.udp !== false,
      node_password: value.password || ""
    };
    var type = String(value.type || "").toLowerCase();
    if (type === "ss") Object.assign(fields, {
      ss_encryption: value.cipher || "aes-128-gcm",
      ss_udp_over_tcp: Boolean(value["udp-over-tcp"]),
      ss_tfo: Boolean(value.tfo),
      ss_ip_version: value["ip-version"] || "默认",
      ss_mux: Boolean(value.mux)
    });
    if (type === "ssr") Object.assign(fields, {
      ssr_encryption: value.cipher || "",
      ssr_protocol: value.protocol || "",
      ssr_protocol_param: value["protocol-param"] || "",
      ssr_obfs: value.obfs || "",
      ssr_obfs_param: value["obfs-param"] || ""
    });
    if (type === "vless") Object.assign(fields, {
      node_uuid: value.uuid || "",
      vless_tls: Boolean(value.tls),
      vless_flow: value.flow || "none",
      vless_servername: value.servername || "",
      vless_network: value.network || "tcp",
      vless_packet_encoding: value["packet-encoding"] || "",
      vless_tfo: Boolean(value.tfo),
      vless_fp: value["client-fingerprint"] || "chrome",
      vless_ip_version: value["ip-version"] || "默认",
      vless_ws_path: ws.path || "/vless",
      vless_ws_host: ws.headers && ws.headers.Host || "",
      vless_h2_path: h2.path || "/",
      vless_h2_host: Array.isArray(h2.host) ? h2.host[0] : (h2.host || ""),
      vless_grpc_service_name: grpc["grpc-service-name"] || "",
      vless_public_key: value["reality-opts"] && value["reality-opts"]["public-key"] || "",
      vless_short_id: value["reality-opts"] && value["reality-opts"]["short-id"] || "",
      vless_skip_cert_verify: Boolean(value["skip-cert-verify"])
    });
    if (type === "vmess") Object.assign(fields, {
      node_uuid: value.uuid || "",
      node_alterid: value.alterId || 0,
      vmess_encryption: value.cipher || "auto",
      node_tls: Boolean(value.tls),
      node_skip_cert: Boolean(value["skip-cert-verify"]),
      node_tfo: Boolean(value.tfo),
      network_type: value.network || "tcp",
      ip_version: value["ip-version"] || "默认",
      ws_path: ws.path || "/",
      ws_host: ws.headers && ws.headers.Host || "",
      h2_path: h2.path || "/",
      h2_host: Array.isArray(h2.host) ? h2.host[0] : (h2.host || ""),
      grpc_service_name: value["grpc-service-name"] || grpc["grpc-service-name"] || ""
    });
    if (type === "trojan") Object.assign(fields, {
      trojan_udp_over_tcp: Boolean(value["udp-over-tcp"]),
      trojan_tfo: Boolean(value.tfo),
      trojan_network: value.network || "tcp",
      trojan_ip_version: value["ip-version"] || "默认",
      ws_path: ws.path || "/",
      ws_host: ws.headers && ws.headers.Host || "",
      grpc_service_name: grpc["grpc-service-name"] || ""
    });
    if (type === "anytls") Object.assign(fields, {
      anytls_password: value.password || "",
      anytls_sni: value.sni || "",
      anytls_fp: value["client-fingerprint"] || "chrome",
      anytls_skip_cert_verify: Boolean(value["skip-cert-verify"]),
      anytls_alpn: Array.isArray(value.alpn) ? value.alpn.join(",") : (value.alpn || "h2,http/1.1"),
      anytls_ip_version: value["ip-version"] || "默认",
      anytls_idle_session_check_interval: value["idle-session-check-interval"] || 30,
      anytls_idle_session_timeout: value["idle-session-timeout"] || 180,
      anytls_min_idle_session: value["min-idle-session"] || 2,
      anytls_ech_enabled: Boolean(value["ech-opts"] && value["ech-opts"].enable),
      anytls_ech_config: value["ech-opts"] && value["ech-opts"].config || "",
      anytls_ech_query_server_name: value["ech-opts"] && value["ech-opts"]["query-server-name"] || ""
    });
    if (type === "tuic") Object.assign(fields, {
      tuic_uuid: value.uuid || "",
      tuic_password: value.password || "",
      tuic_server_ip: value.ip || "",
      tuic_congestion: value["congestion-controller"] || "bbr",
      tuic_alpn: Array.isArray(value.alpn) ? value.alpn.join(",") : (value.alpn || "h3"),
      tuic_sni: value.sni || "",
      tuic_udp_relay_mode: value["udp-relay-mode"] || "native",
      tuic_heartbeat_interval: value["heartbeat-interval"] || 10000,
      tuic_close_sni: Boolean(value["disable-sni"]),
      tuic_reduce_rtt: value["reduce-rtt"] !== false,
      tuic_skip_cert_verify: value["skip-cert-verify"] !== false,
      tuic_fast_open: value["fast-open"] !== false,
      tuic_ip_version: value["ip-version"] || "默认"
    });
    if (type === "hysteria2") Object.assign(fields, {
      node_password: value.password || "",
      hy2_sni: value.sni || "",
      hy2_obfs_type: value.obfs || "none",
      hy2_obfs_password: value["obfs-password"] || "",
      hy2_up_mbps: Number(String(value.up || "").split(" ")[0]) || 50,
      hy2_down_mbps: Number(String(value.down || "").split(" ")[0]) || 100,
      hy2_skip_cert: value["skip-cert-verify"] !== false,
      hy2_alpn: Array.isArray(value.alpn) ? value.alpn.join(",") : (value.alpn || "h3"),
      enable_port_hopping: Boolean(value.ports),
      port_hopping_range: value.ports || "",
      hy2_hop_interval: value["hop-interval"] || "30",
      hy2_fingerprint: value["client-fingerprint"] || "chrome",
      hy2_ip_version: value["ip-version"] || "默认",
      enable_quic_params: Boolean(value["quic-params"]),
      initial_stream_receive_window: quic["initial-stream-receive-window"] || 8388608,
      max_stream_receive_window: quic["max-stream-receive-window"] || 8388608,
      initial_connection_receive_window: quic["initial-connection-receive-window"] || 20971520,
      max_connection_receive_window: quic["max-connection-receive-window"] || 20971520
    });
    return fields;
  }

  function stripImportMetadata(node) {
    var clean = clone(node) || {};
    delete clean._source_id;
    delete clean._source_name;
    delete clean._origin_name;
    return clean;
  }

  function yamlScalar(value) {
    if (typeof value === "number" || typeof value === "boolean" || value === null) return String(value);
    var text = String(value);
    // 首字符为 YAML 特殊符号、含冒号+空格、井号注释、换行或首尾空白时用双引号包裹。
    if (text === "" || /[:#{}\[\],&*!|>'"%@`\n]/.test(text) || /^[-?:]/.test(text) || text.trim() !== text) {
      return JSON.stringify(text);
    }
    return text;
  }

  function yamlDumpValue(value, indent) {
    if (Array.isArray(value)) {
      if (!value.length) return "[]";
      return value.map(function (item) {
        return "\n" + " ".repeat(indent) + "- " + yamlDumpValue(item, indent + 2);
      }).join("");
    }
    if (isObject(value)) {
      var keys = Object.keys(value);
      if (!keys.length) return "{}";
      return keys.map(function (key) {
        return "\n" + " ".repeat(indent) + key + ": " + yamlDumpValue(value[key], indent + 2);
      }).join("");
    }
    return yamlScalar(value);
  }

  function rawYaml(value) {
    return yamlDumpValue(stripImportMetadata(value || {}), 0).replace(/^\n/, "");
  }

  function wrapRawNodeYaml(rawValue) {
    var trimmed = String(rawValue || "").trim();
    if (trimmed.charAt(0) === "{" && trimmed.charAt(trimmed.length - 1) === "}") {
      try {
        var parsedJson = JSON.parse(trimmed);
        if (isObject(parsedJson)) return "proxies:\n  - " + JSON.stringify(parsedJson);
      } catch (_) {}
    }
    var rawLines = trimmed.split("\n");
    return "proxies:\n  - " + rawLines[0] + (rawLines.length > 1 ? "\n" + rawLines.slice(1).map(function (line) { return "    " + line; }).join("\n") : "");
  }

  // 键序无关的稳定序列化，用于在 state.config 被整体替换后按内容比对节点。
  function stableStringify(value) {
    if (Array.isArray(value)) return "[" + value.map(stableStringify).join(",") + "]";
    if (isObject(value)) {
      return "{" + Object.keys(value).sort().map(function (key) {
        return JSON.stringify(key) + ":" + stableStringify(value[key]);
      }).join(",") + "}";
    }
    return JSON.stringify(value === undefined ? null : value);
  }

  // 节点表单打开期间，自动保存回包会整体替换 state.config（对象引用失效），排序也会改变索引。
  // 按“打开时的对象引用 → 最近快照内容比对 → 唯一同名同协议”的顺序重新定位原节点；
  // 定位失败返回 -1，由调用方提示冲突，绝不按旧索引改写其它节点。
  function locateFormNode(form) {
    var target = form || state.nodeForm;
    if (!target || !target.open || target.index === null) return -1;
    var proxies = Array.isArray(state.config.proxies) ? state.config.proxies : [];
    if (target.ref) {
      var byRef = proxies.indexOf(target.ref);
      if (byRef >= 0) return byRef;
    }
    var snapshot = target.snapshot || {};
    var snapshotKey = stableStringify(snapshot);
    var matches = [];
    proxies.forEach(function (node, itemIndex) {
      if (stableStringify(node) === snapshotKey) matches.push(itemIndex);
    });
    if (matches.length === 1) return matches[0];
    var name = String(snapshot.name || "").trim();
    var type = String(snapshot.type || "");
    if (!name) return -1;
    matches = [];
    proxies.forEach(function (node, itemIndex) {
      if (String(node && node.name || "").trim() === name && String(node && node.type || "") === type) matches.push(itemIndex);
    });
    return matches.length === 1 ? matches[0] : -1;
  }

  // 重新定位表单对应的节点并刷新引用/快照/索引；返回当前索引，定位失败返回 -1。
  function syncNodeFormTarget() {
    var form = state.nodeForm;
    if (!form.open || form.index === null) return -1;
    var current = locateFormNode(form);
    if (current >= 0) {
      form.ref = state.config.proxies[current];
      form.snapshot = clone(form.ref);
      form.lost = false;
    } else {
      form.lost = true;
    }
    form.index = current;
    var note = $("nodeFormConflict");
    if (note) {
      note.hidden = !form.lost;
      note.textContent = form.lost ? "正在编辑的节点已被删除或替换，无法定位原节点。保存不会写入草稿，请取消后重新编辑。" : "";
    }
    return current;
  }

  // 表单当前编辑的节点索引（新增或未打开时为 -1）。
  function editingNodeIndex() {
    if (!state.nodeForm.open || state.nodeForm.index === null) return -1;
    return state.nodeForm.index;
  }

  function renderNodeFormMode() {
    var rawMode = $("nodeRawMode");
    if (rawMode) rawMode.hidden = !state.nodeForm.raw;
    var schemaMode = $("nodeSchemaMode");
    if (schemaMode) schemaMode.hidden = state.nodeForm.raw;
    var toggle = $("toggleRawNodeBtn");
    if (toggle) toggle.textContent = state.nodeForm.raw ? "使用字段表单" : "编辑原始 YAML";
  }

  // rebuild 为 true 时按原节点重建字段；否则（如 renderAll 被保存回包触发）只同步定位与显示，
  // 不重建表单，避免用户正在输入的内容被覆盖。
  function renderNodeForm(rebuild) {
    var panel = $("nodeFormPanel");
    if (!panel) return;
    panel.hidden = !state.nodeForm.open;
    if (!state.nodeForm.open) return;
    var adding = state.nodeForm.index === null;
    var current = adding ? -1 : syncNodeFormTarget();
    if (!rebuild && state.nodeForm.built) {
      renderNodeFormMode();
      return;
    }
    var original = adding ? {} : (current >= 0 ? state.config.proxies[current] : (state.nodeForm.snapshot || {}));
    var type = state.nodeForm.protocol || original.type || state.nodeProtocol;
    setText("nodeFormTitle", adding ? "添加节点 · " + type : "编辑节点 · " + type);
    var schemaRoot = $("nodeSchemaFields");
    if (schemaRoot) {
      clearElement(schemaRoot);
      var fields = (state.nodeFormSchema && state.nodeFormSchema[type]) || [];
      var values = nodeToFields(original);
      if (!fields.length) {
        var empty = document.createElement("div");
        empty.className = "phase2-empty";
        empty.textContent = "服务端尚未提供该协议的字段表单，请改用原始 YAML 编辑。";
        schemaRoot.appendChild(empty);
      } else {
        fields.forEach(function (field) {
          addSchemaControl(schemaRoot, field, values, function () {});
        });
        updateSchemaVisibility(schemaRoot);
        attachDialerSuggestions(schemaRoot);
        attachQuicAdvisor(schemaRoot);
      }
    }
    var raw = $("nodeRawEditor");
    if (raw) raw.value = rawYaml(original);
    state.nodeForm.built = true;
    renderNodeFormMode();
  }

  // Hysteria2 QUIC 窗口推荐（BDP 模型，对齐 V1）：带宽 × RTT 推算四项窗口值。
  function attachQuicAdvisor(schemaRoot) {
    if (state.nodeForm.protocol !== "hysteria2") return;
    var quicToggle = schemaRoot.querySelector('[data-field-key="enable_quic_params"]');
    if (!quicToggle) return;
    var wrapper = quicToggle.closest(".schema-field");
    if (!wrapper || schemaRoot.querySelector("#quicBdpTool")) return;
    var tool = document.createElement("div");
    tool.id = "quicBdpTool";
    tool.className = "schema-note";
    tool.style.cssText = "display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:6px";
    var bw = document.createElement("input");
    bw.type = "number"; bw.min = "1"; bw.value = "1000"; bw.title = "带宽 (Mbps)";
    bw.style.width = "90px"; bw.setAttribute("aria-label", "带宽 Mbps");
    var rtt = document.createElement("input");
    rtt.type = "number"; rtt.min = "1"; rtt.value = "50"; rtt.title = "延迟 RTT (ms)";
    rtt.style.width = "90px"; rtt.setAttribute("aria-label", "延迟 RTT ms");
    var calc = makeButton("按 BDP 推荐窗口", "btn btn-ghost", function () {
      var bandwidth = Number(bw.value) || 0;
      var latency = Number(rtt.value) || 0;
      if (bandwidth < 1 || latency < 1) { showToast("请填写有效的带宽与 RTT", "error"); return; }
      var bdp = Math.round(bandwidth * latency * 125);
      var stream = Math.max(2097152, bdp);
      var values = {
        initial_stream_receive_window: stream,
        max_stream_receive_window: Math.round(stream * 1.5),
        initial_connection_receive_window: Math.round(stream * 2.5),
        max_connection_receive_window: Math.round(stream * 4),
      };
      Object.keys(values).forEach(function (key) {
        var control = schemaRoot.querySelector('[data-field-key="' + key + '"]');
        if (control) control.value = String(values[key]);
      });
      if (!quicToggle.checked) quicToggle.click();
      showToast("已按 " + bandwidth + "Mbps / " + latency + "ms 推荐窗口（BDP " + (bdp / 1048576).toFixed(2) + " MB）", "info");
    });
    calc.style.padding = "5px 10px"; calc.style.fontSize = "12px";
    var label = document.createElement("span");
    label.textContent = "BDP 推荐：";
    tool.appendChild(label); tool.appendChild(bw); tool.appendChild(rtt); tool.appendChild(calc);
    wrapper.appendChild(tool);
  }

  function attachDialerSuggestions(schemaRoot) {
    var input = schemaRoot.querySelector('[data-field-key="dialer_proxy_name"]');
    if (!input || input.tagName !== "INPUT") return;
    var datalist = document.getElementById("dialerNodeList");
    if (!datalist) {
      datalist = document.createElement("datalist");
      datalist.id = "dialerNodeList";
      document.body.appendChild(datalist);
    }
    clearElement(datalist);
    (state.config.proxies || []).forEach(function (node) {
      var name = String(node && node.name || "").trim();
      if (!name) return;
      var option = document.createElement("option");
      option.value = name;
      datalist.appendChild(option);
    });
    input.setAttribute("list", "dialerNodeList");
  }

  function openNodeForm(index, protocol) {
    var original = index === null ? {} : (state.config.proxies[index] || {});
    state.nodeForm = {
      open: true,
      index: index,
      protocol: protocol || original.type || state.nodeProtocol || Object.keys(state.nodeFormSchema || {})[0] || "",
      raw: false,
      // 稳定定位依据：打开时的对象引用与内容快照（节点本身没有稳定 id）。
      ref: index === null ? null : state.config.proxies[index] || null,
      snapshot: index === null ? null : clone(original),
      lost: false,
      built: false,
      saving: false
    };
    renderNodeForm(true);
    // 刷新卡片，锁定正在编辑节点的排序/删除按钮。
    renderNodes();
    var panel = $("nodeFormPanel");
    if (panel) panel.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  function closeNodeForm() {
    state.nodeForm.open = false;
    state.nodeForm.raw = false;
    state.nodeForm.built = false;
    var note = $("nodeFormConflict");
    if (note) { note.hidden = true; note.textContent = ""; }
    renderNodeForm();
    renderNodes();
  }

  function deepMergeNodeFields(base, updates) {
    var result = isObject(base) ? clone(base) : {};
    Object.keys(updates || {}).forEach(function (key) {
      var incoming = updates[key];
      if (isObject(incoming) && isObject(result[key])) {
        result[key] = deepMergeNodeFields(result[key], incoming);
      } else {
        result[key] = clone(incoming);
      }
    });
    return result;
  }

  function mergeEditedNode(original, parsed, formFields) {
    var source = original || {};
    var next = parsed || {};
    var merged = deepMergeNodeFields(source, next);
    var changedType = String(source.type || "") !== String(next.type || "");
    var changedNetwork = String(source.network || "") !== String(next.network || "");
    if (changedType || changedNetwork) {
      // These are known transport containers.  When the user explicitly
      // switches transport, remove stale containers absent from the new
      // builder output; unknown top-level keys remain intact.
      ["ws-opts", "h2-opts", "grpc-opts", "grpc-service-name"].forEach(function (key) {
        if (!Object.prototype.hasOwnProperty.call(next, key)) delete merged[key];
      });
    }
    if (formFields && String(next.type || "") === "hysteria2" && !formFields.enable_quic_params) {
      delete merged["quic-params"];
    }
    if (formFields && String(next.type || "") === "anytls" && !formFields.anytls_ech_enabled) {
      delete merged["ech-opts"];
    }
    if (formFields && String(next.type || "") === "vless") {
      // `flow: none` is not an instruction to discard Reality credentials.
      // Some valid subscriptions carry reality-opts without a flow value, and
      // the field form must round-trip them.  Only an explicit clear of both
      // visible Reality values is treated as the user's request to remove the
      // nested object.
      var realityWasPresent = isObject(source["reality-opts"]);
      var realityExplicitlyCleared = Object.prototype.hasOwnProperty.call(formFields, "vless_public_key") &&
        Object.prototype.hasOwnProperty.call(formFields, "vless_short_id") &&
        String(formFields.vless_public_key || "").trim() === "" &&
        String(formFields.vless_short_id || "").trim() === "";
      if (realityWasPresent && realityExplicitlyCleared) delete merged["reality-opts"];
    }
    return merged;
  }

  async function saveNodeForm() {
    var form = state.nodeForm;
    if (!form.open || form.saving) return;
    var adding = form.index === null;
    var startIndex = adding ? -1 : syncNodeFormTarget();
    if (!adding && startIndex < 0) {
      showToast("无法定位正在编辑的节点（可能已被删除或替换），未写入草稿；请取消后重新编辑", "error");
      return;
    }
    var original = adding ? {} : state.config.proxies[startIndex];
    var type = form.protocol || original.type;
    var others = state.config.proxies.filter(function (_, itemIndex) { return itemIndex !== startIndex; });
    var parsed;
    var formFields = null;
    var saveButton = $("saveNodeBtn");
    var epoch = state.authEpoch;
    form.saving = true;
    if (saveButton) saveButton.disabled = true;
    try {
      if (form.raw) {
        var rawValue = ($("nodeRawEditor") && $("nodeRawEditor").value || "").trim();
        if (!rawValue) throw new ApiError("原始 YAML 不能为空", 400);
        var wrapped = wrapRawNodeYaml(rawValue);
        var imported = await apiRequest("/api/import", {
          method: "POST",
          body: {
            mode: "yaml",
            content: wrapped,
            name: "raw-edit",
            existing_proxies: others
          }
        });
        if (isStale(epoch)) return;
        if (!Array.isArray(imported.proxies) || !imported.proxies.length) throw new ApiError("原始 YAML 未解析出节点", 400);
        parsed = stripImportMetadata(imported.proxies[0]);
        type = parsed.type || type;
        // raw YAML 经 /api/import 权威解析后直接使用，不再走 node/build 严格表单校验：
        // 订阅导入的合法节点（如 reality 无 short-id、旧 flow 值）不满足表单必填约束，
        // 二次构建会把可编辑保存误判为失败。
      } else {
        var root = $("nodeSchemaFields");
        var fields = {};
        formFields = fields;
        if (root) {
          root.querySelectorAll("[data-field-key]").forEach(function (control) {
            var field = (state.nodeFormSchema[type] || []).find(function (item) { return item.key === control.dataset.fieldKey; }) || {};
            fields[control.dataset.fieldKey] = serializeTextValue(control, field);
          });
        }
        var built = await apiRequest("/api/node/build", {
          method: "POST",
          body: { type: type, fields: fields, existing_proxies: others }
        });
        if (isStale(epoch)) return;
        parsed = built.node;
      }
      // await 期间用户可能已取消或改开了别的节点表单：不再写入，避免改错节点。
      if (state.nodeForm !== form || !form.open) {
        showToast("节点表单已关闭，本次修改未写入草稿", "info");
        return;
      }
      // await 期间 state.config 可能被保存回包整体替换、或列表被重排：重新定位原节点，
      // 无法定位时提示冲突，绝不追加重复节点或按旧索引覆盖其它节点。
      var currentIndex = adding ? -1 : syncNodeFormTarget();
      if (!adding && currentIndex < 0) {
        throw new ApiError("原节点已被删除或替换，无法定位，本次修改未写入草稿；请取消后重新编辑", 409);
      }
      var base = adding ? {} : state.config.proxies[currentIndex];
      var merged = mergeEditedNode(base, parsed, formFields);
      var name = String(merged.name || "").trim();
      if (!name) throw new ApiError("节点名称不能为空", 400);
      var latestOthers = state.config.proxies.filter(function (_, itemIndex) { return itemIndex !== currentIndex; });
      var duplicate = latestOthers.some(function (node) { return String(node.name || "").trim() === name; });
      if (duplicate) throw new ApiError("节点名称已存在，请使用不同名称", 409);
      if (adding) {
        // 手动添加的节点与导入节点一样携带来源元数据，供来源列展示与统计。
        if (!merged._source_id) {
          merged._source_id = "manual-" + Date.now();
          merged._source_name = "手动添加";
          merged._origin_name = name;
        }
        state.config.proxies.push(merged);
      } else {
        state.config.proxies[currentIndex] = merged;
      }
      if (!markDirty()) return;
      closeNodeForm();
      renderStats();
      showToast(adding ? "节点已加入草稿" : "节点草稿已更新", "info");
    } catch (error) {
      if (isStale(epoch)) return;
      displayApiError(error, "节点保存失败");
    } finally {
      form.saving = false;
      if (saveButton) saveButton.disabled = false;
    }
  }

  function renderNodes() {
    var grid = $("nodeGrid");
    if (!grid) return;
    clearElement(grid);
    var proxies = Array.isArray(state.config.proxies) ? state.config.proxies : [];
    var query = String(state.nodeQuery || "").trim().toLowerCase();
    var visible = 0;
    // 表单编辑中的节点禁止排序、拖拽与删除；先按稳定依据重新定位它的当前索引。
    if (state.nodeForm.open && state.nodeForm.index !== null) syncNodeFormTarget();
    var editingIndex = editingNodeIndex();
    if (!proxies.length) {
      var empty = document.createElement("div");
      empty.className = "empty-state";
      empty.textContent = state.loading ? "正在加载节点…" : "暂无节点，请使用导入或手动添加";
      grid.appendChild(empty);
    }
    proxies.forEach(function (proxy, index) {
      var name = String(proxy.name || ("节点 " + (index + 1)));
      var type = String(proxy.type || "");
      var server = String(proxy.server || proxy.ip || "");
      var port = proxy.port === undefined || proxy.port === null ? "" : String(proxy.port);
      var source = String(proxy._source_name || "");
      var haystack = (name + " " + type + " " + server + " " + port + " " + source).toLowerCase();
      if (state.nodeProtocol && type !== state.nodeProtocol) return;
      if (query && haystack.indexOf(query) < 0) return;
      visible += 1;
      var card = document.createElement("div");
      card.className = "node-card";
      card.dataset.index = String(index);
      var editing = index === editingIndex;
      if (editing) card.classList.add("editing");
      // 拖拽排序（对齐 V1）：基于真实索引交换，筛选状态下也可用；正在编辑的节点不可拖动。
      card.draggable = !editing;
      card.addEventListener("dragstart", function (event) {
        if (editing) {
          event.preventDefault();
          return;
        }
        dragState.fromIndex = index;
        card.classList.add("dragging");
        if (event.dataTransfer) {
          event.dataTransfer.effectAllowed = "move";
          event.dataTransfer.setData("text/plain", String(index));
        }
      });
      card.addEventListener("dragend", function () {
        card.classList.remove("dragging");
        grid.querySelectorAll(".node-card.drop-target").forEach(function (item) { item.classList.remove("drop-target"); });
        dragState.fromIndex = null;
      });
      card.addEventListener("dragover", function (event) {
        if (dragState.fromIndex === null || dragState.fromIndex === index) return;
        event.preventDefault();
        if (event.dataTransfer) event.dataTransfer.dropEffect = "move";
        card.classList.add("drop-target");
      });
      card.addEventListener("dragleave", function () { card.classList.remove("drop-target"); });
      card.addEventListener("drop", function (event) {
        event.preventDefault();
        card.classList.remove("drop-target");
        if (dragState.fromIndex === null || dragState.fromIndex === index) return;
        moveNodeTo(dragState.fromIndex, index);
      });
      var top = document.createElement("div");
      top.className = "node-top";
      appendText(top, name, "node-name");
      appendText(top, type || "未指定协议", "badge b-" + type.replace(/[^a-z0-9_-]/gi, ""));
      card.appendChild(top);
      var serverLine = document.createElement("div");
      serverLine.className = "node-server";
      serverLine.textContent = server + (port ? ":" + port : "");
      card.appendChild(serverLine);
      var meta = document.createElement("div");
      meta.className = "node-meta";
      meta.textContent = source ? "来源：" + source : "运行时延迟：后端未提供";
      card.appendChild(meta);
      var actions = document.createElement("div");
      actions.className = "node-actions";
      [
        ["up", "上移", "chip-btn"],
        ["down", "下移", "chip-btn"],
        ["edit", "编辑", "chip-btn"],
        ["delete", "删除", "chip-btn danger"]
      ].forEach(function (item) {
        var button = makeButton(item[1], item[2], null);
        button.dataset.nodeAction = item[0];
        button.dataset.index = String(index);
        if (editing && item[0] !== "edit") {
          button.disabled = true;
          button.title = "该节点正在编辑，保存或取消后才能排序或删除";
        }
        actions.appendChild(button);
      });
      card.appendChild(actions);
      grid.appendChild(card);
    });
    if (proxies.length && !visible) {
      var noMatch = document.createElement("div");
      noMatch.className = "empty-state";
      noMatch.textContent = "没有匹配当前筛选条件的节点";
      grid.appendChild(noMatch);
    }
    setText("nodeSummary", String(proxies.length) + " 个节点" + (query || state.nodeProtocol ? " · 当前显示 " + visible : ""));
  }

  // 正在表单中编辑的节点不允许排序/删除（按钮已禁用，这里再兜底一次）。
  function rejectIfEditing(index) {
    if (index !== editingNodeIndex() || index < 0) return false;
    showToast("该节点正在编辑，请先保存或取消表单", "error");
    return true;
  }

  function changeNodeOrder(index, direction) {
    var next = index + direction;
    if (next < 0 || next >= state.config.proxies.length) return;
    if (rejectIfEditing(index)) return;
    var list = state.config.proxies;
    var current = list[index];
    list[index] = list[next];
    list[next] = current;
    if (!markDirty()) return;
    renderNodes();
  }

  // 拖拽排序：把 from 移动到 to（跨任意距离），保持其余节点相对顺序。
  var dragState = { fromIndex: null };
  function moveNodeTo(from, to) {
    var list = state.config.proxies;
    if (from === to || from < 0 || to < 0 || from >= list.length || to >= list.length) return;
    if (rejectIfEditing(from)) return;
    var moved = list.splice(from, 1)[0];
    list.splice(to, 0, moved);
    if (!markDirty()) return;
    renderNodes();
    showToast("节点顺序已更新", "info");
  }

  function deleteNode(index) {
    var node = state.config.proxies[index];
    if (!node) return;
    if (rejectIfEditing(index)) return;
    if (!window.confirm("确定删除节点“" + String(node.name || "") + "”？")) return;
    state.config.proxies.splice(index, 1);
    if (!markDirty()) return;
    renderNodes();
    renderStats();
    showToast("节点已从草稿移除", "info");
  }

  async function importNodes() {
    var input = $("importInput");
    var value = input ? input.value.trim() : "";
    if (!value) {
      showToast("请输入要导入的内容", "error");
      return;
    }
    var button = $("importBtn");
    var epoch = state.authEpoch;
    if (button) button.disabled = true;
    try {
      var body = {
        mode: state.importMethod,
        content: state.importMethod === "url" ? "" : value,
        url: state.importMethod === "url" ? value : "",
        name: state.importMethod === "url" ? "远程订阅" : (state.importMethod === "share" ? "分享链接" : "YAML 导入"),
        existing_proxies: clone(state.config.proxies)
      };
      var result = await apiRequest("/api/import", { method: "POST", body: body });
      if (isStale(epoch)) return;
      var incoming = Array.isArray(result.proxies) ? result.proxies : [];
      state.config.proxies = state.config.proxies.concat(incoming);
      if (result.source && isObject(result.source)) {
        var sources = Array.isArray(state.config.import_sources) ? state.config.import_sources : [];
        var existing = sources.findIndex(function (source) { return source.id === result.source.id; });
        if (existing >= 0) sources[existing] = clone(result.source);
        else sources.push(clone(result.source));
        state.config.import_sources = sources;
      }
      if (!markDirty()) return;
      await flushDraftSave();
      if (isStale(epoch)) return;
      if (input) input.value = "";
      renderAll();
      var skipped = Array.isArray(result.skipped) ? result.skipped.length : 0;
      var warnings = Array.isArray(result.warnings) ? result.warnings.length : 0;
      setText("importSummary", "本次导入 " + incoming.length + " 个节点；跳过 " + skipped + " 个；警告 " + warnings + " 条");
      if (warnings) showToast("导入完成，存在 " + warnings + " 条警告", "info");
      else showToast("导入完成，新增 " + incoming.length + " 个节点", "info");
      renderImportMessages(result);
    } catch (error) {
      if (isStale(epoch)) return;
      displayApiError(error, "导入失败");
    } finally {
      if (button) button.disabled = false;
    }
  }

  function renderImportMessages(result) {
    var box = $("importMessages");
    if (!box) return;
    clearElement(box);
    var skipped = Array.isArray(result && result.skipped) ? result.skipped : [];
    var warnings = Array.isArray(result && result.warnings) ? result.warnings : [];
    if (!skipped.length && !warnings.length) {
      box.hidden = true;
      return;
    }
    box.hidden = false;
    if (skipped.length) appendText(box, "跳过重复节点：" + skipped.join("、"), "status-note");
    if (warnings.length) appendText(box, "导入警告：" + warnings.join("；"), "status-note");
  }

  function addRule() {
    var type = $("ruleType");
    var value = $("ruleValue");
    var target = $("ruleTarget");
    if (!type || !target) return;
    var targetValue = String(target.value || "").trim();
    if (!targetValue) {
      showToast("请填写目标策略", "error");
      return;
    }
    // MATCH 是兜底规则，固定两段 MATCH,target，没有也不需要规则值。
    if (type.value === "MATCH") {
      state.config.custom_rules.push("MATCH," + targetValue);
    } else {
      if (!value || !value.value.trim()) {
        showToast("请填写规则值", "error");
        return;
      }
      state.config.custom_rules.push(type.value + "," + value.value.trim() + "," + targetValue);
    }
    if (!markDirty()) return;
    if (value) value.value = "";
    renderRules();
    renderStats();
  }

  function changeRuleSource(value) {
    state.config.selected_rule_type = value;
    if (!markDirty()) return;
    renderRuleSource();
  }

  function updateGlobalActionButtons() {
    ["modeDesktopBtn", "modeRouterBtn", "presetDesktopBtn", "presetRouterBtn"].forEach(function (id) {
      var button = $(id);
      if (button) button.disabled = state.globalSaving || state.saveInFlight;
    });
  }

  async function setMode(router) {
    if (state.globalSaving || state.saveInFlight) return;
    var epoch = state.authEpoch;
    state.globalSaving = true;
    updateGlobalActionButtons();
    var config = state.config.global_config;
    config.generation_profile = router ? "openclash-router" : "desktop-full";
    config.is_desktop = !router;
    if (!markDirty()) {
      state.globalSaving = false;
      updateGlobalActionButtons();
      return;
    }
    renderGlobalConfig();
    updateModeView();
    try {
      await flushDraftSave();
      if (!isStale(epoch)) showToast("生成模式已保存", "info");
    } catch (error) {
      if (!isStale(epoch)) displayApiError(error, "生成模式保存失败");
    } finally {
      if (!isStale(epoch)) state.globalSaving = false;
      updateGlobalActionButtons();
    }
  }

  function updateModeView() {
    var config = state.config.global_config || {};
    var router = config.generation_profile === "openclash-router" || config.is_desktop === false;
    var modeSwitch = $("modeSwitch");
    if (modeSwitch) modeSwitch.classList.toggle("router", router);
    setText("modeDesc", router ? "由 OpenClash 接管 DNS / TUN，仅输出节点与规则。" : "由 YAML 输出客户端 DNS / TUN 设置。");
  }

  async function applyPreset(key) {
    if (state.globalSaving || state.saveInFlight) return;
    var source = state.dnsPresets && Object.keys(state.dnsPresets).length ? state.dnsPresets : state.presets;
    var preset = source && source[key];
    if (!isObject(preset)) {
      showToast("后端未提供该预设", "error");
      return;
    }
    // 预设必须连同生成模式一起落盘：config_builder 以 is_desktop 反推 profile 并
    // 门控 DNS/TUN 输出，只 merge 预设字段会让跨模式点击后 TUN/DNS 静默失效。
    preset = clone(preset);
    if (key === "full_client") {
      preset.is_desktop = true;
      preset.generation_profile = "desktop-full";
      preset.target_mode_user_selected = true;
    } else if (key === "openclash_router") {
      preset.is_desktop = false;
      preset.generation_profile = "openclash-router";
      preset.target_mode_user_selected = true;
    }
    var epoch = state.authEpoch;
    state.globalSaving = true;
    updateGlobalActionButtons();
    state.config.global_config = Object.assign({}, state.config.global_config, clone(preset));
    if (!markDirty()) {
      state.globalSaving = false;
      updateGlobalActionButtons();
      return;
    }
    renderGlobalConfig();
    updateModeView();
    try {
      await flushDraftSave();
      if (!isStale(epoch)) showToast("DNS 预设已保存", "info");
    } catch (error) {
      if (!isStale(epoch)) displayApiError(error, "DNS 预设保存失败");
    } finally {
      if (!isStale(epoch)) state.globalSaving = false;
      updateGlobalActionButtons();
    }
  }

  function renderChecks(checks) {
    var box = $("checkResults");
    if (!box) return;
    clearElement(box);
    var list = Array.isArray(checks) ? checks : [];
    if (!list.length) {
      var empty = document.createElement("div");
      empty.className = "check-empty";
      empty.textContent = "尚未校验，点击“校验草稿”开始";
      box.appendChild(empty);
      box.classList.add("show");
      return;
    }
    box.classList.add("show");
    list.forEach(function (check) {
      var item = document.createElement("div");
      item.className = "check-item " + (check.status === "ok" ? "ok" : (check.status === "warn" ? "warn" : "error"));
      var icon = document.createElement("span");
      icon.className = "icon-circle";
      icon.textContent = check.status === "ok" ? "✓" : (check.status === "warn" ? "!" : "×");
      item.appendChild(icon);
      appendText(item, check.label || "检查", "");
      appendText(item, check.detail || "", "detail");
      box.appendChild(item);
    });
  }

  function renderValidation(payload) {
    var meta = $("validationStats");
    var warningBox = $("validationWarnings");
    var yamlWrap = $("yamlWrap");
    var yamlCode = $("yamlCode");
    var diff = $("publishDiff");
    if (!payload) {
      renderChecks([]);
      if (meta) clearElement(meta);
      if (warningBox) { clearElement(warningBox); warningBox.hidden = true; }
      if (yamlWrap) yamlWrap.classList.remove("show");
      if (yamlCode) clearElement(yamlCode);
      setText("yamlMeta", "", "");
      if (diff) { diff.textContent = ""; diff.classList.remove("show"); }
      updatePublishButton();
      return;
    }
    renderChecks(payload.checks || []);
    if (meta) {
      clearElement(meta);
      var stats = payload.stats || payload.statistics || {};
      Object.keys(stats).forEach(function (key) {
        var cell = document.createElement("div");
        cell.className = "meta-cell";
        appendText(cell, key, "meta-label");
        appendText(cell, stats[key], "meta-value");
        meta.appendChild(cell);
      });
    }
    if (warningBox) {
      clearElement(warningBox);
      var warnings = Array.isArray(payload.warnings) ? payload.warnings : [];
      warningBox.hidden = !warnings.length;
      warnings.forEach(function (warning) { appendText(warningBox, "提示：" + warning, "status-note"); });
    }
    if (yamlWrap && yamlCode && typeof payload.yaml === "string" && payload.yaml) {
      yamlWrap.classList.add("show");
      clearElement(yamlCode);
      payload.yaml.split("\n").forEach(function (line, index) {
        var row = document.createElement("div");
        row.className = "yaml-line";
        appendText(row, String(index + 1), "ln");
        appendText(row, line, "");
        yamlCode.appendChild(row);
      });
      setText("yamlMeta", String(payload.yaml.length) + " bytes");
    }
    if (diff) {
      var publishDiff = payload.publish_diff || payload.diff;
      var diffText = "";
      if (publishDiff && typeof publishDiff === "object") {
        diffText = publishDiff.unified || (publishDiff.has_changes ? "草稿与已发布配置存在差异。" : "草稿与已发布配置没有差异。");
        var added = Array.isArray(publishDiff.added_proxies) ? publishDiff.added_proxies : [];
        var removed = Array.isArray(publishDiff.removed_proxies) ? publishDiff.removed_proxies : [];
        if (added.length) diffText = "新增节点：" + added.join("、") + "\n移除节点：" + (removed.length ? removed.join("、") : "无") + "\n\n" + diffText;
        else if (removed.length) diffText = "移除节点：" + removed.join("、") + "\n\n" + diffText;
      } else if (publishDiff) diffText = String(publishDiff);
      diff.textContent = diffText;
      diff.classList.toggle("show", Boolean(diffText));
    }
    setText("validationStatus", payload.ok ? "校验通过，可选择发布" : "校验未通过，请查看检查项", payload.ok ? "" : "—");
    updatePublishButton();
  }

  function currentValidation() {
    return Boolean(
      state.validation &&
      state.validation.ok === true &&
      state.validatedGeneration === state.dirtyGeneration &&
      state.validatedSignature
    );
  }

  function updatePublishButton() {
    var button = $("publishBtn");
    if (!button) return;
    button.disabled = state.publishInFlight || !currentValidation();
    setText("publishGuard", currentValidation() ? "当前草稿与最近一次校验一致。" : "发布需要先校验当前未修改草稿。");
  }

  async function validateDraft() {
    if (state.validateInFlight) return;
    state.validateInFlight = true;
    var epoch = state.authEpoch;
    var button = $("validateBtn");
    if (button) { button.disabled = true; button.classList.add("loading"); }
    try {
      await flushDraftSave();
      if (isStale(epoch)) return;
      var generation = state.dirtyGeneration;
      var payload = await apiRequest("/api/validate", {
        method: "POST",
        body: draftPayload(),
        allowNotOk: true
      });
      if (isStale(epoch)) return;
      if (generation !== state.dirtyGeneration) {
        state.validation = null;
        state.validatedGeneration = -1;
        state.validatedSignature = "";
        renderValidation(null);
        showToast("校验响应对应旧草稿，请重新校验", "error");
        return;
      }
      state.validation = payload;
      state.validatedGeneration = payload.ok === true ? generation : -1;
      state.validatedSignature = payload.ok === true ? (payload.draft_signature || "") : "";
      if (payload.config) state.config = canonicalDraft(payload.config);
      updateServerFields(payload);
      renderAll();
      renderValidation(payload);
      showToast(payload.ok ? "校验完成，可单独发布" : "校验未通过，请查看检查项", payload.ok ? "info" : "error");
    } catch (error) {
      if (isStale(epoch)) return;
      var details = error && error.details;
      if (details && Array.isArray(details.checks)) {
        state.validation = details.validation || { ok: false, checks: details.checks };
        renderValidation(state.validation);
      }
      displayApiError(error, "校验失败");
    } finally {
      if (!isStale(epoch)) state.validateInFlight = false;
      if (button) { button.disabled = false; button.classList.remove("loading"); }
      updatePublishButton();
    }
  }

  async function publishDraft() {
    // 先置位并禁用按钮再 await 保存，防止重复点击在 flush 期间并发发布。
    if (state.publishInFlight) return;
    state.publishInFlight = true;
    var epoch = state.authEpoch;
    updatePublishButton();
    try {
      await flushDraftSave();
      if (isStale(epoch)) return;
      if (!currentValidation()) {
        showToast("请先校验当前未修改草稿", "error");
        return;
      }
      var generation = state.dirtyGeneration;
      var payload = await apiRequest("/api/publish", {
        method: "POST",
        body: draftPayload()
      });
      if (isStale(epoch)) return;
      if (generation !== state.dirtyGeneration) {
        showToast("发布完成，但本地已有更新草稿；请再次保存和校验", "info");
        scheduleDraftSave();
        return;
      }
      state.validation = payload;
      state.validatedGeneration = generation;
      state.validatedSignature = payload.draft_signature || state.validatedSignature;
      applyServerResponse(payload, generation);
      renderValidation(payload);
      showToast("发布完成，订阅状态已刷新", "info");
    } catch (error) {
      if (isStale(epoch)) return;
      var details = error && error.details;
      if (details && details.validation) renderValidation(details.validation);
      else if (details && details.checks) renderChecks(details.checks);
      displayApiError(error, "发布失败");
    } finally {
      if (!isStale(epoch)) state.publishInFlight = false;
      updatePublishButton();
    }
  }

  function downloadYaml() {
    if (!state.validation || typeof state.validation.yaml !== "string" || !state.validation.yaml) {
      showToast("暂无已校验 YAML", "error");
      return;
    }
    var blob = new Blob([state.validation.yaml], { type: "text/yaml;charset=utf-8" });
    var url = URL.createObjectURL(blob);
    var link = document.createElement("a");
    link.href = url;
    link.download = "config.yaml";
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  async function copySubscription() {
    var url = state.subscription && state.subscription.url;
    if (!url) {
      showToast("暂无已发布订阅链接", "error");
      return;
    }
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) await navigator.clipboard.writeText(url);
      else {
        var input = document.createElement("textarea");
        input.value = url;
        document.body.appendChild(input);
        input.select();
        document.execCommand("copy");
        input.remove();
      }
      showToast("订阅链接已复制", "info");
    } catch (error) {
      showToast("复制失败，请手动复制链接", "error");
    }
  }

  async function resetToken() {
    if (!window.confirm("确定重置订阅 Token 吗？旧链接会失效。")) return;
    var button = $("resetTokenBtn");
    var epoch = state.authEpoch;
    if (button) button.disabled = true;
    try {
      var payload = await apiRequest("/api/token/reset", { method: "POST" });
      if (isStale(epoch)) return;
      state.subscription = clone(payload.subscription || {});
      renderSubscription();
      renderStats();
      showToast("订阅 Token 已重置", "info");
    } catch (error) {
      if (isStale(epoch)) return;
      displayApiError(error, "Token 重置失败");
    } finally {
      if (button) button.disabled = false;
    }
  }

  async function loadAdminUsers() {
    if (!state.user || state.user.is_admin !== true) return;
    if (state.adminLoading) return;
    var epoch = state.authEpoch;
    state.adminLoading = true;
    renderAdminPanel();
    try {
      var payload = await apiRequest("/api/users");
      if (isStale(epoch)) return;
      state.adminUsers = Array.isArray(payload.users) ? clone(payload.users) : [];
      state.adminLoaded = true;
    } catch (error) {
      if (isStale(epoch)) return;
      state.adminResult = error && error.message ? error.message : "用户列表加载失败";
      displayApiError(error, "用户列表加载失败");
    } finally {
      if (!isStale(epoch)) {
        state.adminLoading = false;
        renderAdminPanel();
      }
    }
  }

  async function createAdminUser(event) {
    event.preventDefault();
    var form = event.currentTarget;
    var username = String(form.elements.username.value || "").trim();
    var password = String(form.elements.password.value || "");
    var isAdmin = Boolean(form.elements.is_admin.checked);
    if (!username || !password) {
      showToast("请输入用户名和密码", "error");
      return;
    }
    var epoch = state.authEpoch;
    state.adminLoading = true;
    renderAdminPanel();
    try {
      await apiRequest("/api/users/" + encodeURIComponent(username), {
        method: "POST",
        body: { password: password, is_admin: isAdmin }
      });
      if (isStale(epoch)) return;
      state.adminResult = "用户已创建：" + username;
      form.reset();
    } catch (error) {
      if (isStale(epoch)) return;
      state.adminResult = error && error.message ? error.message : "创建用户失败";
      displayApiError(error, "创建用户失败");
    } finally {
      if (!isStale(epoch)) {
        state.adminLoading = false;
        await loadAdminUsers();
      }
    }
  }

  async function toggleAdminUser(userId) {
    if (state.adminLoading) return;
    var epoch = state.authEpoch;
    state.adminLoading = true;
    renderAdminPanel();
    try {
      var payload = await apiRequest("/api/users/" + encodeURIComponent(String(userId)) + "/toggle", { method: "POST" });
      if (isStale(epoch)) return;
      state.adminResult = "用户状态已更新：" + (payload.is_enabled ? "启用" : "停用");
    } catch (error) {
      if (isStale(epoch)) return;
      state.adminResult = error && error.message ? error.message : "更新用户状态失败";
      displayApiError(error, "更新用户状态失败");
    } finally {
      if (!isStale(epoch)) {
        state.adminLoading = false;
        await loadAdminUsers();
      }
    }
  }

  async function resetAdminUserToken(userId) {
    if (state.adminLoading) return;
    var epoch = state.authEpoch;
    state.adminLoading = true;
    renderAdminPanel();
    try {
      var payload = await apiRequest("/api/users/" + encodeURIComponent(String(userId)) + "/reset-token", { method: "POST" });
      if (isStale(epoch)) return;
      state.adminResult = "临时订阅 URL：" + String(payload.subscription_url || (payload.subscription && payload.subscription.url) || "未返回") + "\nToken：" + String(payload.token || "未返回");
    } catch (error) {
      if (isStale(epoch)) return;
      state.adminResult = error && error.message ? error.message : "重置用户 Token 失败";
      displayApiError(error, "重置用户 Token 失败");
    } finally {
      if (!isStale(epoch)) {
        state.adminLoading = false;
        await loadAdminUsers();
      }
    }
  }

  async function deleteAdminUser(userId) {
    if (state.adminLoading || state.adminConfirmDelete === null) return;
    var epoch = state.authEpoch;
    state.adminLoading = true;
    renderAdminPanel();
    try {
      await apiRequest("/api/users/" + encodeURIComponent(String(userId)) + "/delete", { method: "POST" });
      if (isStale(epoch)) return;
      state.adminResult = "用户已删除";
      state.adminConfirmDelete = null;
    } catch (error) {
      if (isStale(epoch)) return;
      state.adminResult = error && error.message ? error.message : "删除用户失败";
      displayApiError(error, "删除用户失败");
    } finally {
      if (!isStale(epoch)) {
        state.adminLoading = false;
        await loadAdminUsers();
      }
    }
  }

  function renderAdminPanel() {
    var host = $("adminPanelHost");
    if (!host) return;
    clearElement(host);
    var isAdmin = Boolean(state.user && state.user.is_admin === true);
    host.hidden = !isAdmin;
    if (!isAdmin) return;
    var card = document.createElement("div");
    card.className = "sp-card";
    var head = document.createElement("div");
    head.className = "sp-title";
    head.textContent = "管理员用户";
    var refresh = makeButton(state.adminLoading ? "加载中…" : "刷新用户", "btn btn-ghost", loadAdminUsers);
    refresh.disabled = state.adminLoading;
    head.appendChild(refresh);
    card.appendChild(head);
    var form = document.createElement("form");
    form.id = "adminCreateForm";
    form.className = "admin-form";
    var username = rulesetField(form, "adminUsername", "用户名", "text", "");
    username.name = "username";
    var password = rulesetField(form, "adminPassword", "初始密码", "password", "");
    password.name = "password";
    var adminField = document.createElement("div");
    adminField.className = "field field-wide";
    var adminLabel = document.createElement("label");
    adminLabel.className = "f-check";
    var adminCheckbox = document.createElement("input");
    adminCheckbox.id = "adminIsAdmin";
    adminCheckbox.name = "is_admin";
    adminCheckbox.type = "checkbox";
    adminLabel.htmlFor = "adminIsAdmin";
    adminLabel.appendChild(adminCheckbox);
    appendText(adminLabel, " 创建为管理员", "");
    adminField.appendChild(adminLabel);
    form.appendChild(adminField);
    var actions = document.createElement("div");
    actions.className = "admin-actions field-wide";
    var create = makeButton("创建用户", "btn btn-primary", null);
    create.type = "submit";
    create.disabled = state.adminLoading;
    actions.appendChild(create);
    form.appendChild(actions);
    form.addEventListener("submit", createAdminUser);
    card.appendChild(form);
    var list = document.createElement("div");
    list.className = "admin-list phase2-section";
    if (!state.adminLoaded && !state.adminLoading) {
      var prompt = document.createElement("div");
      prompt.className = "phase2-empty";
      prompt.textContent = "点击刷新用户读取管理员列表。";
      list.appendChild(prompt);
    } else if (!state.adminUsers.length && !state.adminLoading) {
      var empty = document.createElement("div");
      empty.className = "empty-state";
      empty.textContent = "暂无用户记录。";
      list.appendChild(empty);
    }
    state.adminUsers.forEach(function (user) {
      var row = document.createElement("div");
      row.className = "admin-row";
      var main = document.createElement("div");
      main.className = "admin-row-main";
      var name = document.createElement("div");
      name.className = "admin-name";
      name.textContent = String(user.username || "");
      main.appendChild(name);
      var meta = document.createElement("div");
      meta.className = "admin-meta";
      meta.textContent = (user.is_admin ? "管理员" : "普通用户") + " · " + (user.is_enabled ? "已启用" : "已停用");
      main.appendChild(meta);
      row.appendChild(main);
      var rowActions = document.createElement("div");
      rowActions.className = "admin-row-actions";
      var toggle = makeButton(user.is_enabled ? "停用" : "启用", "chip-btn", function () { toggleAdminUser(user.id); });
      toggle.disabled = state.adminLoading;
      rowActions.appendChild(toggle);
      var reset = makeButton("重置 Token", "chip-btn", function () { resetAdminUserToken(user.id); });
      reset.disabled = state.adminLoading;
      rowActions.appendChild(reset);
      var remove = makeButton("删除", "chip-btn danger", function () {
        state.adminConfirmDelete = user.id;
        renderAdminPanel();
      });
      remove.disabled = state.adminLoading;
      rowActions.appendChild(remove);
      row.appendChild(rowActions);
      list.appendChild(row);
      if (state.adminConfirmDelete === user.id) {
        var confirm = document.createElement("div");
        confirm.className = "admin-confirm";
        confirm.textContent = "确认删除用户“" + String(user.username || "") + "”？此操作不可恢复。";
        var confirmActions = document.createElement("div");
        confirmActions.className = "admin-actions";
        confirmActions.appendChild(makeButton("确认删除", "btn btn-ghost danger", function () { deleteAdminUser(user.id); }));
        confirmActions.appendChild(makeButton("取消", "btn btn-ghost", function () { state.adminConfirmDelete = null; renderAdminPanel(); }));
        confirm.appendChild(confirmActions);
        list.appendChild(confirm);
      }
    });
    card.appendChild(list);
    if (state.adminResult) {
      var result = document.createElement("div");
      result.className = "admin-result";
      result.textContent = state.adminResult;
      card.appendChild(result);
    }
    host.appendChild(card);
  }

  function renderAll() {
    renderStats();
    renderSubscription();
    renderImport();
    renderNodes();
    renderProtocolPills();
    renderRules();
    renderRuleSource();
    renderRulesets();
    renderGlobalConfig();
    // 表单打开时不重建（renderNodeForm 只同步定位），保护用户正在输入的内容。
    renderNodeForm(false);
    renderAdminPanel();
    updateModeView();
    updateGlobalActionButtons();
    updatePublishButton();
  }

  function initializeEvents() {
    initNavigation();
    var themeToggle = $("themeToggle");
    if (themeToggle) themeToggle.addEventListener("click", function () {
      var root = document.documentElement;
      var dark = !root.classList.contains("dark");
      root.classList.toggle("dark", dark);
      try { localStorage.setItem("v2-theme", dark ? "dark" : "light"); } catch (_) {}
    });
    try {
      document.documentElement.classList.toggle("dark", localStorage.getItem("v2-theme") === "dark");
    } catch (_) {}
    var sidebar = $("sidebarToggle");
    if (sidebar) sidebar.addEventListener("click", function () {
      var layout = $("layout");
      if (layout) layout.classList.toggle("side-hidden");
    });
    var avatar = $("userAvatar");
    if (avatar) avatar.addEventListener("click", function (event) {
      event.stopPropagation();
      toggleUserDropdown();
    });
    document.addEventListener("click", function (event) {
      var dropdown = $("userDropdown");
      if (dropdown && dropdown.classList.contains("open") && !dropdown.contains(event.target) && event.target !== avatar) closeUserDropdown();
    });
    $("userMenu") && $("userMenu").addEventListener("keydown", function (event) {
      var dropdown = $("userDropdown");
      if (event.key !== "Escape" || !dropdown || !dropdown.classList.contains("open")) return;
      closeUserDropdown();
      if (avatar) avatar.focus();
    });
    document.addEventListener("keydown", trapLoginFocus);
    // 有未落盘修改（含去抖窗口内待保存、保存中）时离开页面给出浏览器原生确认。
    window.addEventListener("beforeunload", function (event) {
      if (!hasUnsavedChanges()) return;
      event.preventDefault();
      event.returnValue = "";
      return "";
    });
    $("loginTabBtn") && $("loginTabBtn").addEventListener("click", function () { showAuthPane("login"); });
    $("registerTabBtn") && $("registerTabBtn").addEventListener("click", function () { showAuthPane("register"); });
    $("loginForm") && $("loginForm").addEventListener("submit", login);
    $("registerForm") && $("registerForm").addEventListener("submit", register);
    document.querySelectorAll(".method-card").forEach(function (card) {
      card.addEventListener("click", function () {
        state.importMethod = card.dataset.method || "yaml";
        renderImport();
      });
      card.addEventListener("keydown", function (event) {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          state.importMethod = card.dataset.method || "yaml";
          renderImport();
        }
      });
    });
    $("importBtn") && $("importBtn").addEventListener("click", importNodes);
    $("clearImportBtn") && $("clearImportBtn").addEventListener("click", function () {
      if ($("importInput")) $("importInput").value = "";
      if ($("importMessages")) $("importMessages").hidden = true;
      setText("importSummary", "输入已清空");
    });
    // 上传本工具导出的旧配置文件：读入后填入 YAML 导入框，复用 YAML 导入管线（对齐 V1 恢复入口）。
    // 按钮与 change 监听各只注册一次，避免同一文件触发两次导入。
    $("uploadConfigBtn") && $("uploadConfigBtn").addEventListener("click", function () {
      var input = $("uploadConfigInput");
      if (input) input.click();
    });
    $("uploadConfigInput") && $("uploadConfigInput").addEventListener("change", async function (event) {
      var file = event.target.files && event.target.files[0];
      // 先清空 value，允许再次选择同一文件时仍能触发 change。
      event.target.value = "";
      if (!file) return;
      var fileEpoch = state.authEpoch;
      if (file.size > 5 * 1024 * 1024) {
        showToast("配置文件超过 5MB，请检查是否选择了正确文件", "error");
        return;
      }
      try {
        var text = await file.text();
        if (isStale(fileEpoch)) return;
        if (!text.trim()) {
          showToast("配置文件为空", "error");
          return;
        }
        state.importMethod = "yaml";
        renderImport();
        var area = $("importInput");
        if (area) area.value = text;
        await importNodes();
      } catch (error) {
        displayApiError(error, "配置文件读取失败");
      }
    });
    $("nodeSearch") && $("nodeSearch").addEventListener("input", function (event) {
      state.nodeQuery = event.target.value;
      renderNodes();
    });
    $("protocolPills") && $("protocolPills").addEventListener("click", function (event) {
      var pill = event.target.closest("[data-protocol]");
      if (!pill) return;
      state.nodeProtocol = pill.dataset.protocol;
      renderProtocolPills();
      renderNodes();
    });
    $("nodeGrid") && $("nodeGrid").addEventListener("click", function (event) {
      var button = event.target.closest("[data-node-action]");
      if (!button) return;
      var index = Number(button.dataset.index);
      var action = button.dataset.nodeAction;
      if (action === "up") changeNodeOrder(index, -1);
      if (action === "down") changeNodeOrder(index, 1);
      if (action === "edit") openNodeForm(index);
      if (action === "delete") deleteNode(index);
    });
    $("addNodeBtn") && $("addNodeBtn").addEventListener("click", function () {
      openNodeForm(null, state.nodeProtocol);
    });
    $("toggleRawNodeBtn") && $("toggleRawNodeBtn").addEventListener("click", function () {
      state.nodeForm.raw = !state.nodeForm.raw;
      // 只切换显示模式，不重建表单，两种模式下已输入的内容都保留。
      renderNodeFormMode();
    });
    $("saveNodeBtn") && $("saveNodeBtn").addEventListener("click", saveNodeForm);
    $("cancelNodeBtn") && $("cancelNodeBtn").addEventListener("click", closeNodeForm);
    $("addRuleBtn") && $("addRuleBtn").addEventListener("click", addRule);
    $("ruleType") && $("ruleType").addEventListener("change", function (event) {
      var ruleValue = $("ruleValue");
      if (!ruleValue) return;
      var isMatch = event.target.value === "MATCH";
      ruleValue.disabled = isMatch;
      ruleValue.placeholder = isMatch ? "MATCH 为兜底规则，无需填写值" : "example.com / 192.168.0.0/16";
    });
    $("ruleSource") && $("ruleSource").addEventListener("change", function (event) { changeRuleSource(event.target.value); });
    $("validateBtn") && $("validateBtn").addEventListener("click", validateDraft);
    $("publishBtn") && $("publishBtn").addEventListener("click", publishDraft);
    $("downloadYamlBtn") && $("downloadYamlBtn").addEventListener("click", downloadYaml);
    $("copySubBtn") && $("copySubBtn").addEventListener("click", copySubscription);
    $("subCopyBtn") && $("subCopyBtn").addEventListener("click", copySubscription);
    $("resetTokenBtn") && $("resetTokenBtn").addEventListener("click", resetToken);
    $("saveDraftBtn") && $("saveDraftBtn").addEventListener("click", async function () {
      try {
        await flushDraftSave();
        showToast("草稿已保存", "info");
      } catch (error) {
        displayApiError(error, "草稿保存失败");
      }
    });
    $("modeDesktopBtn") && $("modeDesktopBtn").addEventListener("click", function () { setMode(false); });
    $("modeRouterBtn") && $("modeRouterBtn").addEventListener("click", function () { setMode(true); });
    $("presetDesktopBtn") && $("presetDesktopBtn").addEventListener("click", function () { applyPreset("full_client"); });
    $("presetRouterBtn") && $("presetRouterBtn").addEventListener("click", function () { applyPreset("openclash_router"); });
  }

  async function init() {
    initializeEvents();
    renderAll();
    try {
      var session = await apiRequest("/api/session", { skipSessionRefresh: true });
      if (!session.authenticated) {
        showAuthOverlay(session);
        return;
      }
      state.authenticated = true;
      state.user = session.user || null;
      state.csrfToken = session.csrf_token || "";
      renderUserPanel(state.user);
      await loadBootstrap();
    } catch (error) {
      state.loading = false;
      showAuthOverlay({ csrf_token: state.authCsrf });
      displayApiError(error, "会话加载失败");
    }
  }

  init();
})();
