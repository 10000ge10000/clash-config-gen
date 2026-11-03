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
    ruleCatalog: {},
    ruleFilter: "",
    ruleEditIndex: null,
    allTargets: [],
    counts: {},
    warnings: [],
    importMethod: "yaml",
    nodeProtocol: "",
    nodeQuery: "",
    nodeForm: { open: false, index: null, protocol: "", raw: false },
    // 当前显示的步骤；非当前步骤的区块变化只标记待渲染，切换或空闲时再渲染。
    activeStep: 1,
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
    if (typeof element.replaceChildren === "function") element.replaceChildren();
    else element.textContent = "";
  }

  // 为对象分配稳定的短 id，用于区块签名里比较“是否还是同一个对象”（不比较内容）。
  var objectIds = new WeakMap();
  var objectIdSeq = 0;
  function objectId(value) {
    if (!value || typeof value !== "object") return String(value);
    var id = objectIds.get(value);
    if (!id) {
      objectIdSeq += 1;
      id = objectIdSeq;
      objectIds.set(value, id);
    }
    return "#" + id;
  }

  // 单次渲染最多给多少个新元素播放入场动画；一次性出现大量卡片（首屏、换号）时只动画前若干个，
  // 避免上百个动画同时合成。
  var ENTER_ANIMATION_LIMIT = 40;

  // 入场动画只在元素首次出现/新增时播放：加 is-entering，animationend 后移除（400ms 兜底，
  // 处理元素在 display:none 区域内动画不运行的情况）。重建、重排、筛选都不应调用它。
  function markEntering(element) {
    if (!element) return;
    var finished = false;
    var timer = null;
    function finish(event) {
      if (event && event.target !== element) return;
      if (finished) return;
      finished = true;
      if (timer !== null) window.clearTimeout(timer);
      element.classList.remove("is-entering");
      element.removeEventListener("animationend", finish);
      element.removeEventListener("animationcancel", finish);
    }
    element.classList.add("is-entering");
    element.addEventListener("animationend", finish);
    element.addEventListener("animationcancel", finish);
    timer = window.setTimeout(function () { finish(); }, 400);
  }

  function focusInside(hosts) {
    var active = document.activeElement;
    if (!active || active === document.body) return false;
    return hosts.some(function (host) { return Boolean(host) && host.contains(active); });
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

  // 服务端派生字段的 JSON 缓存：内容未变时保留原对象引用，区块签名据此跳过重渲染。
  // 缓存按对象引用失效（这些字段只会被整体替换，不会被原地修改）。
  var serverJsonCache = {};
  function stateJson(key) {
    var entry = serverJsonCache[key];
    if (entry && entry.ref === state[key]) return entry.json;
    var json = JSON.stringify(state[key]);
    serverJsonCache[key] = { ref: state[key], json: json };
    return json;
  }

  // 内容变化时才替换 state[key]；返回是否发生替换。
  function replaceServerField(key, value) {
    var json = JSON.stringify(value);
    if (json === stateJson(key)) return false;
    state[key] = clone(value);
    serverJsonCache[key] = { ref: state[key], json: json };
    return true;
  }

  // 返回本次实际变化的派生字段，供调用方只刷新受影响的区域。
  function updateServerFields(payload) {
    var changed = {};
    if (!payload || !isObject(payload)) return changed;
    if (payload.subscription) changed.subscription = replaceServerField("subscription", payload.subscription);
    if (payload.counts || payload.statistics) changed.counts = replaceServerField("counts", payload.counts || payload.statistics);
    if (Array.isArray(payload.all_targets)) changed.targets = replaceServerField("allTargets", payload.all_targets);
    if (Array.isArray(payload.warnings)) replaceServerField("warnings", payload.warnings);
    if (Array.isArray(payload.warnings) && payload.warnings.some(function (warning) {
      return String(warning).indexOf("历史草稿字段损坏") >= 0;
    })) {
      state.draftCorrupted = true;
    } else if (payload.config || payload.proxies) {
      state.draftCorrupted = false;
      state.draftCorruptionAcknowledged = false;
    }
    if (isObject(payload.provider_defaults)) changed.providerDefaults = replaceServerField("providerDefaults", payload.provider_defaults);
    if (isObject(payload.presets)) replaceServerField("presets", payload.presets);
    if (isObject(payload.dns_presets)) replaceServerField("dnsPresets", payload.dns_presets);
    if (payload.user) {
      state.user = clone(payload.user);
      state.authenticated = true;
      renderUserPanel(state.user);
    }
    return changed;
  }

  // 节点表单 / 全局设置 schema：内容不变时保留引用，避免每次保存回包都重建表单与协议按钮。
  function updateSchemas(payload) {
    var changed = {};
    if (!payload) return changed;
    if (isObject(payload.node_form_schema)) changed.nodeFormSchema = replaceServerField("nodeFormSchema", payload.node_form_schema);
    if (isObject(payload.global_config_schema)) changed.globalConfigSchema = replaceServerField("globalConfigSchema", payload.global_config_schema);
    return changed;
  }

  // 把服务端回包中的草稿与本地草稿逐项比对：内容一致的部分沿用本地对象引用（节点卡片复用、
  // 节点表单定位都依赖引用），只有服务端规范化后确实不同的部分才替换。返回发生替换的草稿键。
  function reconcileDraft(incoming) {
    var changed = {};
    var local = state.config;
    var localProxies = Array.isArray(local.proxies) ? local.proxies : [];
    var nextProxies = Array.isArray(incoming.proxies) ? incoming.proxies : [];
    var pool = new Map();
    localProxies.forEach(function (node) {
      var key = stableStringify(node);
      if (!pool.has(key)) pool.set(key, []);
      pool.get(key).push(node);
    });
    var proxiesSame = nextProxies.length === localProxies.length && Array.isArray(local.proxies);
    var mergedProxies = nextProxies.map(function (node, index) {
      var bucket = pool.get(stableStringify(node));
      var reuse = bucket && bucket.length ? bucket.shift() : null;
      if (!reuse || reuse !== localProxies[index]) proxiesSame = false;
      return reuse || node;
    });
    if (!proxiesSame) {
      local.proxies = mergedProxies;
      changed.proxies = true;
    }
    ["global_config", "custom_rules", "custom_rule_providers", "import_sources"].forEach(function (key) {
      if (stableStringify(local[key]) === stableStringify(incoming[key])) return;
      local[key] = incoming[key];
      changed[key] = true;
    });
    if (local.selected_rule_type !== incoming.selected_rule_type) {
      local.selected_rule_type = incoming.selected_rule_type;
      changed.selected_rule_type = true;
    }
    return changed;
  }

  function applyBootstrap(payload, resetGeneration) {
    if (!payload) return;
    state.config = canonicalDraft(payload);
    state.serverConfig = clone(state.config);
    updateServerFields(payload);
    replaceServerField("nodeFormSchema", isObject(payload.node_form_schema) ? payload.node_form_schema : {});
    replaceServerField("globalConfigSchema", isObject(payload.global_config_schema) ? payload.global_config_schema : {});
    replaceServerField("presets", isObject(payload.presets) ? payload.presets : {});
    if (isObject(payload.dns_presets)) replaceServerField("dnsPresets", payload.dns_presets);
    else state.dnsPresets = state.presets;
    replaceServerField("providerDefaults", isObject(payload.provider_defaults) ? payload.provider_defaults : {});
    replaceServerField("ruleCatalog", isObject(payload.rule_catalog) ? payload.rule_catalog : {});
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

  // 保存/发布回包：本地代数与回包一致（期间没有更新的修改）时才落地。
  // 不整页重建：用户编辑的数据按内容比对保留本地引用，只刷新服务端派生信息（统计、订阅、
  // 状态栏、目标列表）以及服务端规范化后确实变化的区块。
  function applyServerResponse(payload, generation) {
    if (!payload || generation !== state.dirtyGeneration) return false;
    var incoming = canonicalDraft(payload);
    state.serverConfig = clone(incoming);
    var changedKeys = reconcileDraft(incoming);
    var derived = updateServerFields(payload);
    var schemas = updateSchemas(payload);
    if (isObject(payload.presets) && !isObject(payload.dns_presets)) state.dnsPresets = state.presets;
    state.savedGeneration = generation;
    state.saveError = null;
    refreshDerivedViews(changedKeys, derived, schemas);
    updateDraftStatus();
    return true;
  }

  // 只刷新受变化影响的区域；各区块仍经 renderBlock 做签名比对与“非当前步骤延后渲染”。
  function refreshDerivedViews(changedKeys, derived, schemas) {
    var keys = changedKeys || {};
    var server = derived || {};
    var schema = schemas || {};
    renderStats();
    renderSubscription();
    renderImport();
    if (keys.proxies || schema.nodeFormSchema) {
      renderBlock("nodes");
      renderBlock("pills");
      renderNodeForm(false);
    }
    if (keys.custom_rules || server.targets) renderBlock("rules");
    if (keys.selected_rule_type || keys.global_config || server.providerDefaults || server.targets) renderBlock("ruleSource");
    if (keys.custom_rule_providers) renderBlock("rulesets");
    if (server.targets) refreshRulesetTargetSelect();
    if (keys.global_config || schema.globalConfigSchema) {
      renderBlock("global");
      updateModeView();
    }
    updateGlobalActionButtons();
    updatePublishButton();
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
    renderAll(true);
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
    writeAuthHint(false);
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

  function setSubMenuOpen(open) {
    var popover = $("subPopover");
    var trigger = $("subMenuBtn");
    if (popover) popover.classList.toggle("open", open);
    if (trigger) trigger.setAttribute("aria-expanded", open ? "true" : "false");
    if (open) closeUserDropdown();
  }

  function setUserDropdownOpen(open) {
    var dropdown = $("userDropdown");
    var avatar = $("userAvatar");
    if (open) setSubMenuOpen(false);
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
    if (nodeSearchTimer !== null) {
      window.clearTimeout(nodeSearchTimer);
      nodeSearchTimer = null;
    }
    setSubMenuOpen(false);
    state.config = emptyDraft();
    state.serverConfig = emptyDraft();
    state.subscription = {};
    state.counts = {};
    state.warnings = [];
    state.allTargets = [];
    state.nodeQuery = "";
    state.nodeProtocol = "";
    state.nodeForm = { open: false, index: null, protocol: "", raw: false };
    state.ruleFilter = "";
    state.ruleEditIndex = null;
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
    if ($("ruleNoResolve")) $("ruleNoResolve").checked = false;
    updateRuleForm();
    var dialerList = $("dialerNodeList");
    if (dialerList && dialerList.parentNode) dialerList.parentNode.removeChild(dialerList);
    if ($("importMessages")) { clearElement($("importMessages")); $("importMessages").hidden = true; }
    if ($("nodeSearch")) $("nodeSearch").value = "";
    if ($("nodeRawEditor")) $("nodeRawEditor").value = "";
    clearElement($("nodeSchemaFields"));
    renderValidation(null);
    setText("validationStatus", "尚未校验");
    setText("importSummary", "尚未导入节点");
    // 强制立即重绘所有区块（含非当前步骤），确保上一用户的数据不会残留在 DOM 中。
    renderAll(true);
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
    writeAuthHint(false);
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
    writeAuthHint(true);
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

  // 首屏并行预取：只有本浏览器上次处于登录状态（本地提示位）时才与 /api/session 并行请求
  // /api/config，避免未登录访问时多出一个 401。提示位只是便利缓存，读写失败一律按未登录处理。
  var AUTH_HINT_KEY = "ccg-auth-hint";
  function readAuthHint() {
    try { return window.localStorage.getItem(AUTH_HINT_KEY) === "1"; } catch (_) { return false; }
  }

  function writeAuthHint(on) {
    try {
      if (on) window.localStorage.setItem(AUTH_HINT_KEY, "1");
      else window.localStorage.removeItem(AUTH_HINT_KEY);
    } catch (_) {}
  }

  // 用原生 fetch 预取，不走 apiRequest：失败（含 401）时不触发会话刷新与提示，由 loadBootstrap 正常重试。
  function prefetchConfig() {
    return fetch("/api/config", { credentials: "include", headers: { Accept: "application/json" } })
      .then(function (response) {
        return parseResponse(response).then(function (data) {
          return { ok: response.ok && !(data && data.ok === false), data: data };
        });
      })
      .catch(function () { return null; });
  }

  async function loadBootstrap(prefetched) {
    var epoch = state.authEpoch;
    state.loading = true;
    updateDraftStatus();
    try {
      var payload = null;
      if (prefetched) {
        var early = await prefetched;
        if (isStale(epoch)) return;
        if (early && early.ok) payload = early.data;
      }
      if (!payload) payload = await apiRequest("/api/config");
      if (isStale(epoch)) return;
      state.authenticated = true;
      writeAuthHint(true);
      applyBootstrap(payload, true);
      hideAuthOverlay();
      // 管理员用户列表不阻塞首屏：后台加载，面板自行显示加载状态。
      if (state.user && state.user.is_admin === true) loadAdminUsers().catch(function () {});
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
    state.activeStep = value;
    // 切换到某步骤时补渲染该步骤下被延后的区块。
    flushDirtyBlocks(value);
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
    setText("nodeSummary", ready ? String(nodeCount) + " 个节点" : "正在加载");
    setText("ruleCount", ready ? state.config.custom_rules.filter(function (raw) { return !isMatchRule(raw); }).length : undefined, "—");
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
      var trigger = $("subMenuBtn");
      if (trigger) trigger.title = "订阅链接：" + title.textContent.replace("● ", "");
    }
    var dot = $("subDot");
    if (dot) dot.dataset.status = String(subscription.status || "");
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
      ["dustinwin规则", "DustinWin"],
      ["lhie1规则", "lhie1"],
      ["none", "无基础规则（完全自己写）"]
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
    renderProviderTargets();
    renderRuleFallback();
    renumberRuleFlow();
  }

  function selectedProviderSource() {
    if (state.config.selected_rule_type === "dustinwin规则") return "dustinwin";
    if (state.config.selected_rule_type === "lhie1规则") return "lhie1";
    return "";
  }

  // 当前规则源的基础规则（来自服务端 build_rule_catalog，顺序与生成结果一致）。
  function selectedRuleCatalog() {
    var catalog = isObject(state.ruleCatalog) ? state.ruleCatalog[state.config.selected_rule_type] : null;
    return isObject(catalog) ? catalog : { key: "", label: "", rules: [], fallback: null };
  }

  function isMatchRule(raw) {
    return String(raw).split(",", 1)[0].trim().toUpperCase() === "MATCH";
  }

  // 规则格式：类型,值,目标[,no-resolve]；MATCH 没有值；AND/OR 这类规则的值里本身带逗号，取中间全部。
  function parseRule(raw) {
    var parts = String(raw).split(",");
    var noResolve = parts.length > 2 && parts[parts.length - 1].trim() === "no-resolve";
    if (noResolve) parts.pop();
    if (isMatchRule(raw)) return { type: "MATCH", value: "", target: parts.slice(1).join(","), noResolve: false };
    return { type: parts[0] || "", value: parts.slice(1, -1).join(","), target: parts.length > 1 ? parts[parts.length - 1] : "", noResolve: noResolve };
  }

  var BUILTIN_RULE_TARGETS = ["DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL"];
  function isKnownTarget(target) {
    var list = targetOptions().list;
    return !list.length || list.indexOf(target) >= 0 || BUILTIN_RULE_TARGETS.indexOf(target) >= 0;
  }

  // 各分区独立渲染，序号统一在这里按 DOM 顺序重排，保证与实际匹配顺序连续一致。
  function renumberRuleFlow() {
    var rows = document.querySelectorAll("#ruleFlow [data-rule-seq]");
    rows.forEach(function (row, index) {
      var seq = row.querySelector(".rule-idx");
      if (seq) seq.textContent = String(index + 1).padStart(2, "0");
    });
    setText("ruleSourceStatus", "共 " + rows.length + " 条规则");
  }

  function flowHead(parent, titleText, hintText) {
    var head = document.createElement("div");
    head.className = "flow-head";
    appendText(head, titleText, "flow-title");
    if (hintText) appendText(head, hintText, "flow-hint");
    parent.appendChild(head);
    return head;
  }

  // 规则目标候选（去掉 no-resolve、空值并去重）：按 allTargets 引用缓存，每次变化只用 Set 计算一次，
  // 规则目标 datalist、规则源目标下拉、规则集目标下拉共用同一份结果。
  var targetOptionsCache = { source: null, list: [], key: "" };
  function targetOptions() {
    var source = Array.isArray(state.allTargets) ? state.allTargets : [];
    if (targetOptionsCache.source !== source) {
      var seen = new Set();
      var list = [];
      source.forEach(function (value) {
        var text = String(value);
        if (!text || text === "no-resolve" || seen.has(text)) return;
        seen.add(text);
        list.push(text);
      });
      targetOptionsCache = { source: source, list: list, key: list.join("\u0001") };
    }
    return targetOptionsCache;
  }

  function appendOptions(select, values) {
    var fragment = document.createDocumentFragment();
    values.forEach(function (value) {
      var option = document.createElement("option");
      option.value = value;
      option.textContent = value;
      fragment.appendChild(option);
    });
    select.appendChild(fragment);
  }

  // 目标候选按“策略组 / 节点”分组；当前值已不在候选里时单独保留，避免下拉把它吞掉。
  function appendTargetOptions(select, selected) {
    var list = targetOptions().list;
    if (selected && list.indexOf(selected) < 0) appendOptions(select, [selected]);
    var nodeNames = new Set((Array.isArray(state.config.proxies) ? state.config.proxies : []).map(function (node) { return String(node && node.name || ""); }));
    var nodes = list.filter(function (value) { return nodeNames.has(value); });
    var groups = list.filter(function (value) { return !nodeNames.has(value); });
    if (!nodes.length) {
      appendOptions(select, groups);
      return;
    }
    [["策略组", groups], ["节点", nodes]].forEach(function (item) {
      if (!item[1].length) return;
      var group = document.createElement("optgroup");
      group.label = item[0];
      appendOptions(group, item[1]);
      select.appendChild(group);
    });
  }

  // 规则源目标下拉懒填充：初始只放当前值，首次获得焦点/按下鼠标/按键时才填入全部候选，
  // 填充后保持原选中值不变；选项变化（allTargets 更新）由区块重建处理。
  function fillProviderTargetSelect(select) {
    if (!select || select.dataset.filled === "true") return;
    var selected = select.value || select.dataset.selected || "";
    clearElement(select);
    appendTargetOptions(select, selected);
    select.value = selected;
    select.dataset.filled = "true";
  }

  function applyRuleFilter() {
    var panel = $("providerTargetsPanel");
    if (!panel) return;
    var query = String(state.ruleFilter || "").trim().toLowerCase();
    var rows = panel.querySelectorAll(".target-row");
    var shown = 0;
    rows.forEach(function (row) {
      var match = !query || row.dataset.search.indexOf(query) >= 0 || String(row.dataset.target || "").toLowerCase().indexOf(query) >= 0;
      row.hidden = !match;
      if (match) shown += 1;
    });
    setText("ruleFilterCount", query ? "匹配 " + shown + " / " + rows.length + " 条" : "", "");
  }

  function renderProviderTargets() {
    var panel = $("providerTargetsPanel");
    if (!panel) return;
    clearElement(panel);
    var sourceKey = selectedProviderSource();
    panel.hidden = !sourceKey;
    if (!sourceKey) {
      renumberRuleFlow();
      blockRendered("ruleSource");
      return;
    }
    var catalog = selectedRuleCatalog();
    var rules = Array.isArray(catalog.rules) ? catalog.rules : [];
    var overrideKey = sourceKey + "_provider_targets";
    var overrides = isObject(state.config.global_config[overrideKey]) ? state.config.global_config[overrideKey] : {};
    var head = flowHead(panel, (catalog.label || sourceKey) + " 基础规则", "实际匹配顺序，可修改每条的目标");
    var restore = makeButton("恢复默认目标", "btn btn-ghost", function () {
      state.config.global_config[overrideKey] = {};
      if (!markDirty()) return;
      renderProviderTargets();
      showToast("已恢复当前规则源默认目标，正在排队保存", "info");
    });
    restore.setAttribute("aria-label", "恢复当前规则源默认目标");
    head.appendChild(restore);
    var filter = document.createElement("input");
    filter.type = "search";
    filter.className = "flow-filter";
    filter.placeholder = "按规则名、说明或目标筛选，如 Proxy、netflix";
    filter.setAttribute("aria-label", "筛选基础规则");
    filter.value = state.ruleFilter || "";
    filter.addEventListener("input", function () {
      state.ruleFilter = filter.value;
      applyRuleFilter();
    });
    panel.appendChild(filter);
    var count = document.createElement("div");
    count.id = "ruleFilterCount";
    count.className = "status-note";
    panel.appendChild(count);
    var editor = document.createElement("div");
    editor.className = "target-editor flow-scroll";
    if (!rules.length) {
      var empty = document.createElement("div");
      empty.className = "phase2-empty";
      empty.textContent = "服务端尚未提供该规则源的规则列表。";
      editor.appendChild(empty);
    }
    var fragment = document.createDocumentFragment();
    rules.forEach(function (rule, index) {
      var defaultTarget = String(rule.target || "");
      var overridden = rule.overridable && Object.prototype.hasOwnProperty.call(overrides, rule.value);
      var selected = String(overridden ? overrides[rule.value] : defaultTarget);
      if (selected === "no-resolve") selected = "Proxy";
      var row = document.createElement("div");
      row.className = "target-row" + (overridden ? " is-overridden" : "");
      row.dataset.ruleSeq = "";
      row.dataset.target = selected;
      row.dataset.search = [rule.type, rule.value, rule.label].join(" ").toLowerCase();
      appendText(row, "", "rule-idx");
      appendText(row, rule.type, "rule-type");
      var text = document.createElement("span");
      text.className = "target-text";
      var name = document.createElement("span");
      name.className = "target-name";
      name.textContent = rule.value;
      text.appendChild(name);
      if (rule.no_resolve) appendText(text, "no-resolve", "rule-tag");
      var noteText = [rule.label];
      if (rule.overridable) noteText.push("默认 " + defaultTarget);
      var note = document.createElement("span");
      note.className = "target-default";
      note.textContent = noteText.filter(Boolean).join(" · ");
      text.appendChild(note);
      var warn = document.createElement("span");
      warn.className = "rule-warn";
      warn.hidden = isKnownTarget(selected);
      warn.textContent = "目标不存在，请重新选择";
      text.appendChild(warn);
      row.appendChild(text);
      if (!rule.overridable) {
        appendText(row, "→ " + defaultTarget, "rule-target");
        fragment.appendChild(row);
        return;
      }
      var select = document.createElement("select");
      select.id = "provider-target-" + sourceKey + "-" + index;
      select.setAttribute("aria-label", rule.value + " 目标策略");
      // 初始只放当前值；全部候选在交互时由 fillProviderTargetSelect 懒填充（见 initializeEvents 的委托）。
      select.dataset.lazyTargets = "true";
      select.dataset.selected = selected;
      if (selected) appendOptions(select, [selected]);
      select.value = selected;
      select.addEventListener("change", function () {
        var next = isObject(state.config.global_config[overrideKey]) ? clone(state.config.global_config[overrideKey]) : {};
        if (select.value === defaultTarget) delete next[rule.value];
        else next[rule.value] = select.value;
        select.dataset.selected = select.value;
        row.dataset.target = select.value;
        row.classList.toggle("is-overridden", select.value !== defaultTarget);
        warn.hidden = true;
        state.config.global_config[overrideKey] = next;
        if (!markDirty()) return;
        // DOM 已反映最新选择，同步区块签名，保存回包后不再重建这一面板。
        blockRendered("ruleSource");
      });
      row.appendChild(select);
      fragment.appendChild(row);
    });
    editor.appendChild(fragment);
    panel.appendChild(editor);
    applyRuleFilter();
    renumberRuleFlow();
    blockRendered("ruleSource");
  }

  // 兜底规则始终是列表最后一条：自定义 MATCH 覆盖规则源默认，生成时也固定排在最后。
  function renderRuleFallback() {
    var box = $("ruleFallback");
    if (!box) return;
    var hadFocus = Boolean(document.activeElement) && document.activeElement.id === "ruleFallbackTarget";
    clearElement(box);
    var defaultTarget = String(selectedRuleCatalog().fallback || "");
    var rules = Array.isArray(state.config.custom_rules) ? state.config.custom_rules : [];
    var custom = rules.find(isMatchRule);
    var current = custom !== undefined ? parseRule(custom).target : defaultTarget;
    flowHead(box, "兜底规则", "前面都没命中时走这里");
    var row = document.createElement("div");
    row.className = "target-row";
    row.dataset.ruleSeq = "";
    appendText(row, "", "rule-idx");
    appendText(row, "MATCH", "rule-type");
    var text = document.createElement("span");
    text.className = "target-text";
    var name = document.createElement("span");
    name.className = "target-name";
    name.textContent = "其余全部流量";
    text.appendChild(name);
    var note = document.createElement("span");
    note.className = "target-default";
    note.textContent = defaultTarget ? "默认 " + defaultTarget : "当前规则源没有默认兜底";
    text.appendChild(note);
    if (!current) appendText(text, "未设置兜底时，没命中规则的流量会直连", "rule-warn");
    else if (!isKnownTarget(current)) appendText(text, "目标不存在，请重新选择", "rule-warn");
    row.appendChild(text);
    var select = document.createElement("select");
    select.id = "ruleFallbackTarget";
    select.setAttribute("aria-label", "兜底规则目标策略");
    if (!defaultTarget) {
      var unset = document.createElement("option");
      unset.value = "";
      unset.textContent = "未设置（直连）";
      select.appendChild(unset);
    }
    appendTargetOptions(select, current);
    select.value = current;
    select.addEventListener("change", function () {
      var next = state.config.custom_rules.filter(function (raw) { return !isMatchRule(raw); });
      if (select.value && select.value !== defaultTarget) next.push("MATCH," + select.value);
      state.config.custom_rules = next;
      if (!markDirty()) return;
      renderRuleFallback();
      renumberRuleFlow();
      renderStats();
      blockRendered("rules");
    });
    row.appendChild(select);
    box.appendChild(row);
    if (hadFocus) {
      try { select.focus({ preventScroll: true }); } catch (_) { select.focus(); }
    }
  }

  // 规则目标 datalist：只在候选列表变化时重建。
  var ruleTargetListKey = null;
  function refreshRuleTargetDatalist() {
    var datalist = $("ruleTargetOptions");
    if (!datalist) return;
    var options = targetOptions();
    if (ruleTargetListKey === options.key && datalist.childNodes.length === options.list.length) return;
    clearElement(datalist);
    var fragment = document.createDocumentFragment();
    options.list.forEach(function (value) {
      var option = document.createElement("option");
      option.value = value;
      fragment.appendChild(option);
    });
    datalist.appendChild(fragment);
    ruleTargetListKey = options.key;
  }

  // 上次渲染的规则字符串（多重集比对），用于只给新增的规则项播放入场动画。
  var renderedRuleList = null;

  function renderRules() {
    var target = $("ruleTarget");
    var targets = Array.isArray(state.allTargets) ? state.allTargets : [];
    if (target) {
      // 目标策略支持从列表选择与手动输入（对齐 V1 双模式），datalist 提供候选。
      refreshRuleTargetDatalist();
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
    // MATCH 单独显示在兜底分区；这里保留在 custom_rules 中的原下标，移动和删除都按原下标操作。
    var entries = [];
    rules.forEach(function (raw, index) {
      if (!isMatchRule(raw)) entries.push({ raw: String(raw), index: index });
    });
    var previousCounts = new Map();
    (renderedRuleList || []).forEach(function (raw) { previousCounts.set(raw, (previousCounts.get(raw) || 0) + 1); });
    renderedRuleList = entries.map(function (entry) { return entry.raw; });
    var entering = 0;
    if (!entries.length) {
      var empty = document.createElement("div");
      empty.className = "check-empty";
      empty.textContent = "暂无自定义规则";
      list.appendChild(empty);
    }
    var fragment = document.createDocumentFragment();
    entries.forEach(function (entry, position) {
      var parsed = parseRule(entry.raw);
      var item = document.createElement("div");
      item.className = "rule-item" + (state.ruleEditIndex === entry.index ? " is-editing" : "");
      item.dataset.ruleSeq = "";
      var seen = previousCounts.get(entry.raw) || 0;
      if (seen > 0) previousCounts.set(entry.raw, seen - 1);
      else if (entering < ENTER_ANIMATION_LIMIT) {
        markEntering(item);
        entering += 1;
      }
      appendText(item, "", "rule-idx");
      appendText(item, parsed.type, "rule-type");
      var value = appendText(item, parsed.value, "rule-value");
      if (parsed.noResolve && value) appendText(value, "no-resolve", "rule-tag");
      appendText(item, "→ " + parsed.target, "rule-target");
      if (!isKnownTarget(parsed.target)) appendText(item, "目标不存在", "rule-warn");
      item.appendChild(makeButton("编辑", "chip-btn", function () { beginRuleEdit(entry.index); }));
      var moveUp = makeButton("上移", "chip-btn", function () { moveRule(position, -1); });
      moveUp.disabled = position === 0;
      var moveDown = makeButton("下移", "chip-btn", function () { moveRule(position, 1); });
      moveDown.disabled = position === entries.length - 1;
      item.appendChild(moveUp);
      item.appendChild(moveDown);
      var remove = makeButton("删除", "rule-del", function () {
        state.config.custom_rules.splice(entry.index, 1);
        clearRuleEdit();
        if (!markDirty()) return;
        renderRules();
        renderStats();
      });
      item.appendChild(remove);
      fragment.appendChild(item);
    });
    list.appendChild(fragment);
    renderRuleFallback();
    renumberRuleFlow();
    blockRendered("rules");
  }

  // position 是在“非 MATCH 规则”列表中的位置，交换时换回 custom_rules 的原下标。
  function moveRule(position, direction) {
    var rules = state.config.custom_rules;
    if (!Array.isArray(rules)) return;
    var indices = [];
    rules.forEach(function (raw, index) { if (!isMatchRule(raw)) indices.push(index); });
    var from = indices[position];
    var to = indices[position + direction];
    if (from === undefined || to === undefined) return;
    var current = rules[from];
    rules[from] = rules[to];
    rules[to] = current;
    clearRuleEdit();
    if (!markDirty()) return;
    renderRules();
    renderStats();
  }

  var RULE_PLACEHOLDERS = {
    "DOMAIN-SUFFIX": "example.com",
    "DOMAIN": "www.example.com",
    "DOMAIN-KEYWORD": "example",
    "DOMAIN-REGEX": "^.*\\.example\\.com$",
    "GEOSITE": "category-ads-all",
    "IP-CIDR": "192.168.0.0/16",
    "IP-CIDR6": "2001:db8::/32",
    "GEOIP": "CN",
    "DST-PORT": "443",
    "PROCESS-NAME": "chrome.exe",
    "MATCH": "MATCH 为兜底规则，无需填写值"
  };
  var NO_RESOLVE_RULE_TYPES = ["IP-CIDR", "IP-CIDR6", "GEOIP"];

  function updateRuleForm() {
    var type = $("ruleType");
    if (!type) return;
    var isMatch = type.value === "MATCH";
    var value = $("ruleValue");
    if (value) {
      value.disabled = isMatch;
      value.placeholder = RULE_PLACEHOLDERS[type.value] || "";
    }
    var supportsNoResolve = NO_RESOLVE_RULE_TYPES.indexOf(type.value) >= 0;
    if ($("ruleNoResolveWrap")) $("ruleNoResolveWrap").hidden = !supportsNoResolve;
    if (!supportsNoResolve && $("ruleNoResolve")) $("ruleNoResolve").checked = false;
    var editing = state.ruleEditIndex !== null;
    setText("addRuleBtn", editing ? "保存修改" : (isMatch ? "设为兜底" : "添加规则"));
    if ($("cancelRuleEditBtn")) $("cancelRuleEditBtn").hidden = !editing;
  }

  function clearRuleEdit() {
    if (state.ruleEditIndex === null) return;
    state.ruleEditIndex = null;
    if ($("ruleValue")) $("ruleValue").value = "";
    if ($("ruleNoResolve")) $("ruleNoResolve").checked = false;
    updateRuleForm();
  }

  function beginRuleEdit(index) {
    var raw = state.config.custom_rules[index];
    if (raw === undefined) return;
    var parsed = parseRule(raw);
    var type = $("ruleType");
    // 导入来的规则可能是表单未列出的类型（如 AND、IP-ASN），补一个选项以便原样编辑。
    if (!Array.prototype.some.call(type.options, function (option) { return option.value === parsed.type; })) {
      appendOptions(type, [parsed.type]);
    }
    type.value = parsed.type;
    $("ruleValue").value = parsed.value;
    $("ruleTarget").value = parsed.target;
    if ($("ruleNoResolve")) $("ruleNoResolve").checked = parsed.noResolve;
    state.ruleEditIndex = index;
    updateRuleForm();
    if ($("ruleNoResolveWrap") && parsed.noResolve) $("ruleNoResolveWrap").hidden = false;
    if ($("ruleNoResolve")) $("ruleNoResolve").checked = parsed.noResolve;
    renderRules();
    $("ruleValue").focus();
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
      // 选项可写成 [值, 显示文本]，值与展示不同时使用。
      (options || []).forEach(function (optionValue) {
        var pair = Array.isArray(optionValue) ? optionValue : [optionValue, optionValue];
        var option = document.createElement("option");
        option.value = String(pair[0]);
        option.textContent = String(pair[1]);
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
    var options = targetOptions().list;
    var selected = String(current || "Proxy");
    if (selected === "no-resolve") selected = "Proxy";
    return options.indexOf(selected) < 0 ? [selected].concat(options) : options.slice();
  }

  // 目标候选变化时只刷新规则集表单里的目标下拉（保留当前选择），不重建整个规则集面板。
  function refreshRulesetTargetSelect() {
    var select = $("rulesetTarget");
    if (!select || document.activeElement === select) return;
    var key = targetOptions().key;
    if (select.dataset.targetsKey === key) return;
    var current = select.value || "Proxy";
    clearElement(select);
    appendOptions(select, rulesetTargetOptions(current));
    select.value = current;
    select.dataset.targetsKey = key;
  }

  var RULESET_FIRST_ORDER = "优先 (覆盖)";

  // 规则集在分流列表中的只读展示；增删在下方“自定义规则集”面板。
  function renderRulesetFlow() {
    var providers = isObject(state.config.custom_rule_providers) ? state.config.custom_rule_providers : {};
    var names = Object.keys(providers);
    function fill(id, title, hint, sectionNames) {
      var section = $(id);
      if (!section) return;
      clearElement(section);
      section.hidden = !sectionNames.length;
      if (!sectionNames.length) return;
      flowHead(section, title, hint);
      var rows = document.createElement("div");
      rows.className = "target-editor";
      sectionNames.forEach(function (name) {
        var provider = isObject(providers[name]) ? providers[name] : {};
        var row = document.createElement("div");
        row.className = "target-row";
        row.dataset.ruleSeq = "";
        appendText(row, "", "rule-idx");
        appendText(row, "RULE-SET", "rule-type");
        var text = document.createElement("span");
        text.className = "target-text";
        appendText(text, name, "target-name");
        row.appendChild(text);
        appendText(row, "→ " + String(provider.target || "Proxy"), "rule-target");
        rows.appendChild(row);
      });
      section.appendChild(rows);
    }
    function isFirst(name) { return isObject(providers[name]) && providers[name].order === RULESET_FIRST_ORDER; }
    fill("rulesetFirstFlow", "优先规则集", "排在基础规则之前", names.filter(isFirst));
    fill("rulesetLastFlow", "追加规则集", "排在基础规则之后", names.filter(function (name) { return !isFirst(name); }));
    renumberRuleFlow();
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
    listHint.textContent = "在上方分流规则中的位置由“匹配顺序”决定";
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
      meta.textContent = String(provider.type || "file") + " · " + String(provider.behavior || "classical") + " · " + String(provider.format || "") + " · " + (provider.order === RULESET_FIRST_ORDER ? "优先" : "追加") + " · 目标：" + String(provider.target || "Proxy") + " · " + String(source);
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
    var order = rulesetField(form, "rulesetOrder", "匹配顺序", "select", "追加", [[RULESET_FIRST_ORDER, "优先：排在基础规则之前"], ["追加", "追加：排在基础规则之后"]]);
    order.setAttribute("aria-describedby", "rulesetOrderHelp");
    var target = rulesetField(form, "rulesetTarget", "目标策略", "select", "Proxy", rulesetTargetOptions("Proxy"));
    target.setAttribute("aria-label", "规则集目标策略");
    target.dataset.targetsKey = targetOptions().key;
    formSection.appendChild(form);
    var orderHelp = document.createElement("div");
    orderHelp.id = "rulesetOrderHelp";
    orderHelp.className = "schema-note";
    orderHelp.textContent = "想让规则集抢在基础规则前生效选“优先”，只补充基础规则没覆盖的内容选“追加”。";
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
    renderRulesetFlow();
    blockRendered("rulesets");
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
      // 保存回包已刷新派生信息；这里只重绘规则集面板（清空表单并显示提示）。
      renderRulesets();
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
      renderRulesets();
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
    renderRulesets();
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
      renderRulesets();
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
    var isGlobal = root.id === "globalSchemaPanel";
    // 全局设置的部分条件字段（is_desktop）没有控件，由生成模式开关写入草稿，需要从草稿取值。
    var values = isGlobal ? Object.assign({}, state.config.global_config, controlValues(root)) : controlValues(root);
    var conditional = [];
    root.querySelectorAll("[data-condition]").forEach(function (field) {
      var condition;
      try { condition = JSON.parse(field.dataset.condition); } catch (_) { condition = null; }
      var hidden = !conditionMatches(condition, values);
      field.classList.toggle("schema-field-hidden", hidden);
      conditional.push({ field: field, key: condition && condition.key, hidden: hidden });
    });
    if (!isGlobal) return;
    // 条件依赖的开关自身被隐藏时，子字段也隐藏（软路由模式下“启用 DNS”隐藏，DNS 子项不能留着）。
    var hiddenKeys = {};
    var changed = true;
    while (changed) {
      changed = false;
      conditional.forEach(function (item) {
        if (!item.hidden && hiddenKeys[item.key]) {
          item.hidden = true;
          item.field.classList.add("schema-field-hidden");
        }
        var control = item.field.querySelector("[data-field-key]");
        if (item.hidden && control && !hiddenKeys[control.dataset.fieldKey]) {
          hiddenKeys[control.dataset.fieldKey] = true;
          changed = true;
        }
      });
    }
    root.querySelectorAll("details[data-group]").forEach(function (details) {
      details.hidden = !details.querySelector(".schema-field:not(.schema-field-hidden)");
    });
  }

  function valueForField(field, values, fallback) {
    var key = field.key;
    if (Object.prototype.hasOwnProperty.call(values, key) && values[key] !== undefined && values[key] !== null) return values[key];
    if (Object.prototype.hasOwnProperty.call(field, "default")) return field.default;
    return fallback;
  }

  // 字段可见条件引用到的 key 集合：只有这些字段变化时才需要重算可见性。
  function conditionKeysOf(fields) {
    var keys = {};
    (fields || []).forEach(function (field) {
      var condition = field && (field.visible_condition || field.visible);
      if (condition && typeof condition === "object" && condition.key) keys[condition.key] = true;
    });
    return keys;
  }

  // 控件显示值，与 addSchemaControl 的初始回填规则一致（就地刷新全局设置时复用）。
  function schemaDisplayValue(field, values) {
    var type = field.type || "input";
    var value = valueForField(field, values, type === "checkbox" ? false : "");
    if (type === "checkbox") return Boolean(value);
    if (type === "textarea") return isObject(value) ? JSON.stringify(value, null, 2) : (value === undefined || value === null ? "" : String(value));
    return value === undefined || value === null ? "" : String(value);
  }

  // visibility：{ root, keys }。root 为可见性计算范围（全局设置是整个面板，跨分组条件才能取到值），
  // keys 为被条件引用的字段；未提供时按旧行为以 parent 为范围、任意变化都重算。
  function addSchemaControl(parent, field, values, onChange, visibility) {
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
    var visibilityRoot = visibility && visibility.root ? visibility.root : parent;
    var affectsVisibility = !visibility || !visibility.keys || Boolean(visibility.keys[field.key]);
    control.addEventListener("change", function () {
      onChange(field, control);
      if (affectsVisibility) updateSchemaVisibility(visibilityRoot);
    });
    if (control.type !== "checkbox" && affectsVisibility) {
      control.addEventListener("input", function () { updateSchemaVisibility(visibilityRoot); });
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
      // 留空要原样传回，Number("") 是 0，会被当成填了 0
      if (String(control.value).trim() === "") return "";
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

  var GLOBAL_GROUPS = [
    { id: "basic", label: "基础与端口", keys: ["include_inbound_ports", "include_global_compat", "include_router_options", "enable_core_options", "port", "socks_port", "mixed_port", "allow_lan", "bind_address", "mode", "log_level", "ipv6_support"] },
    { id: "controller", label: "控制器", keys: ["include_controller", "external_controller", "secret", "external_ui", "external_ui_name", "external_ui_url"] },
    { id: "speed", label: "测速与性能", keys: ["find_process_mode", "url_test_url", "url_test_interval", "url_test_tolerance", "tcp_concurrent", "unified_delay", "geodata_mode", "geodata_loader", "keep_alive_interval", "keep_alive_idle"] },
    { id: "tun", label: "TUN 与路由", keys: ["enable_tun", "tun_stack", "tun_device", "tun_auto_route", "tun_auto_detect_interface", "tun_dns_hijack", "tun_dns_hijack_value", "tun_endpoint_independent_nat", "tun_auto_redirect", "tun_strict_route", "redir_port", "tproxy_port", "interface_name"] },
    { id: "dns", label: "DNS", keys: ["enable_dns", "dns_listen", "dns_ipv6", "enhanced_mode", "fake_ip_range", "fake_ip_range6", "fake_ip_filter_mode", "dns_respect_rules", "direct_nameserver", "proxy_server_nameserver", "default_nameserver", "nameserver", "fallback", "nameserver_policy"] },
    { id: "sniffer", label: "嗅探", keys: ["enable_sniffer", "sniff_override_dest", "sniffer_parse_pure_ip", "sniffer_force_dns_mapping"] },
    { id: "profile", label: "配置与其他", keys: ["profile_store_selected", "profile_store_fake_ip", "ntp_enable", "ntp_server", "ntp_port", "ntp_interval", "ntp_write_to_system", "authentication"] }
  ];

  // 全局设置面板的渲染状态：schema 引用不变时只就地刷新控件值，不重建（保留展开状态、焦点与未提交输入）。
  // values 记录每个字段最近一次写入控件的值（稳定序列化），用于判断哪些控件需要刷新。
  var globalRender = { schema: null, built: false, values: {}, pendingRebuild: false };

  // 不作为普通字段展示：目标覆盖在分流规则中编辑；模式由生成模式开关写入；
  // optional_globals_v2 被后端强制为 true；openclash_preset 由推荐配置写入。
  var GLOBAL_HIDDEN_KEYS = { lhie1_provider_targets: true, dustinwin_provider_targets: true, generation_profile: true, is_desktop: true, optional_globals_v2: true, openclash_preset: true };
  function isProviderTargetKey(key) {
    return GLOBAL_HIDDEN_KEYS[key] === true;
  }

  function globalFieldFor(schema, key) {
    return Object.assign({ key: key, label: key, _idPrefix: "global" }, schema[key] || {});
  }

  function renderGlobalConfig(forceRebuild) {
    var container = $("globalSchemaPanel");
    if (!container) return;
    var schema = state.globalConfigSchema || {};
    var values = state.config.global_config || {};
    var canPatch = !forceRebuild && !globalRender.pendingRebuild && globalRender.built && globalRender.schema === schema;
    if (canPatch && patchGlobalConfigValues(container, schema, values)) {
      blockRendered("global");
      return;
    }
    // 必须重建，但用户正在面板内输入：先不重建，等焦点离开面板后再刷新。
    if (!forceRebuild && focusInside([container])) {
      globalRender.pendingRebuild = true;
      renderWhenFocusLeaves("global", [container]);
      return;
    }
    rebuildGlobalConfig(container, schema, values);
    blockRendered("global");
  }

  // 就地刷新：只改动值发生变化且当前未聚焦的控件；返回 false 表示需要整体重建（如下拉缺少新值的选项）。
  function patchGlobalConfigValues(container, schema, values) {
    var active = document.activeElement;
    var needRebuild = false;
    container.querySelectorAll("[data-field-key]").forEach(function (control) {
      if (needRebuild) return;
      var key = control.dataset.fieldKey;
      var stamp = stableStringify(values[key]);
      if (globalRender.values[key] === stamp) return;
      // 正在编辑的控件保留用户输入，记录保持旧值，下一次刷新再同步。
      if (control === active) return;
      var display = schemaDisplayValue(globalFieldFor(schema, key), values);
      if (control.type === "checkbox") {
        control.checked = display;
      } else if (control.tagName === "SELECT") {
        var hasOption = Array.prototype.some.call(control.options, function (option) { return option.value === display; });
        if (!hasOption && display !== "") {
          needRebuild = true;
          return;
        }
        control.value = display;
      } else if (control.value !== display) {
        control.value = display;
      }
      globalRender.values[key] = stamp;
    });
    if (needRebuild) return false;
    // 生成模式没有对应控件，上面的循环感知不到，所以每次都重算可见性。
    updateSchemaVisibility(container);
    return true;
  }

  function rebuildGlobalConfig(container, schema, values) {
    // 记录重建前的界面状态：分组展开、焦点与光标位置、页面滚动位置。
    var openState = {};
    container.querySelectorAll("details[data-group]").forEach(function (details) { openState[details.dataset.group] = details.open; });
    var active = document.activeElement;
    var focusId = active && container.contains(active) && active.id ? active.id : "";
    var selectionStart = null;
    var selectionEnd = null;
    if (focusId) {
      try {
        selectionStart = active.selectionStart;
        selectionEnd = active.selectionEnd;
      } catch (_) {}
    }
    var scrollX = window.scrollX;
    var scrollY = window.scrollY;
    globalRender = { schema: schema, built: false, values: {}, pendingRebuild: false };
    var keys = Object.keys(schema);
    if (!keys.length) {
      clearElement(container);
      var empty = document.createElement("div");
      empty.className = "phase2-empty";
      empty.textContent = "服务端尚未提供全局设置字段定义，暂无可编辑的设置。";
      container.appendChild(empty);
      return;
    }
    var groups = GLOBAL_GROUPS.map(function (group) { return { id: group.id, label: group.label, keys: group.keys.slice() }; });
    var assigned = {};
    groups.forEach(function (group) { group.keys.forEach(function (key) { assigned[key] = true; }); });
    var remaining = keys.filter(function (key) { return !assigned[key] && !isProviderTargetKey(key); });
    if (remaining.length) groups[groups.length - 1].keys = groups[groups.length - 1].keys.concat(remaining);
    var visibility = {
      root: container,
      keys: conditionKeysOf(keys.map(function (key) { return schema[key]; }))
    };
    var fragment = document.createDocumentFragment();
    groups.forEach(function (group, groupIndex) {
      var groupKeys = group.keys.filter(function (key) { return Object.prototype.hasOwnProperty.call(schema, key) && !isProviderTargetKey(key); });
      if (!groupKeys.length) return;
      var details = document.createElement("details");
      details.className = "schema-group";
      details.dataset.group = group.id;
      details.open = Object.prototype.hasOwnProperty.call(openState, group.id) ? openState[group.id] : (groupIndex === 0 || group.id === "dns");
      var summary = document.createElement("summary");
      summary.textContent = group.label;
      details.appendChild(summary);
      var grid = document.createElement("div");
      grid.className = "schema-grid schema-group-grid";
      groupKeys.forEach(function (key) {
        addSchemaControl(grid, globalFieldFor(schema, key), values, function (field, control) {
          state.config.global_config[field.key] = serializeTextValue(control, field);
          // 控件已显示该值，记录下来，保存回包后无需再刷新此控件。
          globalRender.values[field.key] = stableStringify(state.config.global_config[field.key]);
          markDirty();
        }, visibility);
        globalRender.values[key] = stableStringify(values[key]);
      });
      details.appendChild(grid);
      fragment.appendChild(details);
    });
    clearElement(container);
    container.appendChild(fragment);
    updateSchemaVisibility(container);
    globalRender.built = true;
    if (focusId) {
      var target = document.getElementById(focusId);
      if (target && container.contains(target)) {
        try { target.focus({ preventScroll: true }); } catch (_) { target.focus(); }
        try {
          if (selectionStart !== null && selectionStart !== undefined) target.setSelectionRange(selectionStart, selectionEnd);
        } catch (_) {}
      }
    }
    if (window.scrollX !== scrollX || window.scrollY !== scrollY) window.scrollTo(scrollX, scrollY);
  }

  function protocolList() {
    var protocols = Object.keys(state.nodeFormSchema || {});
    if (protocols.length) return protocols;
    var seen = new Set();
    (Array.isArray(state.config.proxies) ? state.config.proxies : []).forEach(function (node) {
      var type = String(node && node.type || "");
      if (type) seen.add(type);
    });
    return Array.from(seen);
  }

  // 协议筛选按钮只负责渲染；点击统一由 initializeEvents 中 #protocolPills 的事件委托处理。
  function renderProtocolPills() {
    var container = $("protocolPills");
    if (!container) return;
    clearElement(container);
    var fragment = document.createDocumentFragment();
    var all = makeButton("全部", "pill" + (!state.nodeProtocol ? " active" : ""), null);
    all.dataset.protocol = "";
    fragment.appendChild(all);
    protocolList().forEach(function (protocol) {
      var pill = makeButton(protocol, "pill" + (state.nodeProtocol === protocol ? " active" : ""), null);
      pill.dataset.protocol = protocol;
      fragment.appendChild(pill);
    });
    container.appendChild(fragment);
    blockRendered("pills");
  }

  function nodeToFields(node) {
    // 新增节点（空对象）时不回填任何字段值，让 schema default 决定初始状态，
    // 避免显式 false 覆盖后端声明的默认开关（如 anytls 跳过证书验证、端口跳跃）。
    if (!node || !Object.keys(node).length) return {};
    var value = node;
    var ws = isObject(value["ws-opts"]) ? value["ws-opts"] : {};
    var h2 = isObject(value["h2-opts"]) ? value["h2-opts"] : {};
    var grpc = isObject(value["grpc-opts"]) ? value["grpc-opts"] : {};
    var xhttp = isObject(value["xhttp-opts"]) ? value["xhttp-opts"] : {};
    var quic = isObject(value["quic-params"]) ? value["quic-params"] : {};
    var fields = {
      node_name: value.name || "",
      node_server: value.server || "",
      node_port: value.port || 443,
      node_udp: value.udp !== false,
      node_password: value.password || ""
    };
    var type = String(value.type || "").toLowerCase();
    if (type === "ss" || type === "vless" || type === "vmess") {
      var smux = isObject(value.smux) ? value.smux : {};
      var brutal = isObject(smux["brutal-opts"]) ? smux["brutal-opts"] : {};
      Object.assign(fields, {
        enable_smux: isObject(value.smux),
        smux_enabled: smux.enabled !== false,
        smux_protocol: smux.protocol || "h2mux",
        smux_max_connections: smux["max-connections"] || 4,
        smux_brutal_enabled: Boolean(brutal.enabled),
        smux_brutal_up: Number(String(brutal.up || "").split(" ")[0]) || 100,
        smux_brutal_down: Number(String(brutal.down || "").split(" ")[0]) || 100
      });
    }
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
      vless_xhttp_path: xhttp.path || "/",
      vless_xhttp_host: xhttp.host || "",
      vless_xhttp_mode: xhttp.mode || "stream-one",
      vless_encryption: value.encryption || "",
      vless_alpn: Array.isArray(value.alpn) ? value.alpn.join(",") : "",
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
      anytls_tfo: Boolean(value.tfo),
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
      // 节点没写带宽时留空，保存时不能凭空写入默认值，否则客户端会被限速
      hy2_up_mbps: Number(String(value.up || "").split(" ")[0]) || "",
      hy2_down_mbps: Number(String(value.down || "").split(" ")[0]) || "",
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
        var visibility = { root: schemaRoot, keys: conditionKeysOf(fields) };
        fields.forEach(function (field) {
          addSchemaControl(schemaRoot, field, values, function () {}, visibility);
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
      ["ws-opts", "h2-opts", "grpc-opts", "grpc-service-name", "xhttp-opts"].forEach(function (key) {
        if (!Object.prototype.hasOwnProperty.call(next, key)) delete merged[key];
      });
    }
    if (formFields && String(next.type || "") === "hysteria2" && !formFields.enable_quic_params) {
      delete merged["quic-params"];
    }
    if (formFields && Object.prototype.hasOwnProperty.call(formFields, "enable_smux")) {
      // 表单取消勾选表示关闭，合并时不能保留原值
      if (!formFields.enable_smux) delete merged.smux;
      else if (!formFields.smux_brutal_enabled && isObject(merged.smux)) delete merged.smux["brutal-opts"];
    }
    if (formFields && String(next.type || "") === "hysteria2") {
      if (!Object.prototype.hasOwnProperty.call(next, "up")) delete merged.up;
      if (!Object.prototype.hasOwnProperty.call(next, "down")) delete merged.down;
    }
    if (formFields && String(next.type || "") === "anytls" && !formFields.anytls_ech_enabled) {
      delete merged["ech-opts"];
    }
    if (formFields && String(next.type || "") === "vless") {
      // 表单清空这两项表示关闭，合并时不能保留原值。
      if (!Object.prototype.hasOwnProperty.call(next, "encryption")) delete merged.encryption;
      if (!Object.prototype.hasOwnProperty.call(next, "alpn")) delete merged.alpn;
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

  // 节点卡片复用：按节点对象引用缓存卡片 DOM；排序/删除只移动或移除对应卡片，筛选只切换隐藏，
  // 只有新出现的节点才新建卡片并播放入场动画。
  var nodeCards = new WeakMap();
  // 卡片 → { key: 内容签名, buttons: 操作按钮 }
  var nodeCardParts = new WeakMap();
  // 最近一次渲染的节点与卡片顺序：节点对象被替换（编辑保存、服务端规范化）时按位置沿用原卡片。
  var nodeGridView = { nodes: [], cards: [] };
  var nodeGridStatus = null;
  // 节点筛选输入的去抖定时器（退出/换号时需清除，避免把上一用户的筛选词写回）。
  var nodeSearchTimer = null;

  function nodeCardInfo(proxy, index) {
    var node = proxy || {};
    var name = String(node.name || ("节点 " + (index + 1)));
    var type = String(node.type || "");
    var server = String(node.server || node.ip || "");
    var port = node.port === undefined || node.port === null ? "" : String(node.port);
    var source = String(node._source_name || "");
    return {
      name: name,
      type: type,
      server: server,
      port: port,
      source: source,
      key: [name, type, server, port, source].join("\u0001"),
      haystack: (name + " " + type + " " + server + " " + port + " " + source).toLowerCase()
    };
  }

  function fillNodeCard(card, info) {
    var fragment = document.createDocumentFragment();
    var top = document.createElement("div");
    top.className = "node-top";
    appendText(top, info.name, "node-name");
    appendText(top, info.type || "未指定协议", "badge b-" + info.type.replace(/[^a-z0-9_-]/gi, ""));
    fragment.appendChild(top);
    var serverLine = document.createElement("div");
    serverLine.className = "node-server";
    serverLine.textContent = info.server + (info.port ? ":" + info.port : "");
    fragment.appendChild(serverLine);
    var meta = document.createElement("div");
    meta.className = "node-meta";
    meta.textContent = info.source ? "来源：" + info.source : "运行时延迟：后端未提供";
    fragment.appendChild(meta);
    var actions = document.createElement("div");
    actions.className = "node-actions";
    var buttons = [
      ["up", "上移", "chip-btn"],
      ["down", "下移", "chip-btn"],
      ["edit", "编辑", "chip-btn"],
      ["delete", "删除", "chip-btn danger"]
    ].map(function (item) {
      var button = makeButton(item[1], item[2], null);
      button.dataset.nodeAction = item[0];
      actions.appendChild(button);
      return button;
    });
    fragment.appendChild(actions);
    clearElement(card);
    card.appendChild(fragment);
    nodeCardParts.set(card, { key: info.key, buttons: buttons, index: null, editing: null });
  }

  // 每次渲染都要同步的动态状态：真实索引、编辑锁定、筛选隐藏。只在值变化时写 DOM。
  function syncNodeCardState(card, index, editing, filteredOut) {
    var parts = nodeCardParts.get(card);
    var indexText = String(index);
    if (card.dataset.index !== indexText) card.dataset.index = indexText;
    if (filteredOut) {
      if (card.dataset.hidden !== "true") {
        card.dataset.hidden = "true";
        card.hidden = true;
      }
    } else if (card.dataset.hidden) {
      delete card.dataset.hidden;
      card.hidden = false;
    }
    if (parts.index === indexText && parts.editing === editing) return;
    card.classList.toggle("editing", editing);
    card.draggable = !editing;
    parts.buttons.forEach(function (button) {
      button.dataset.index = indexText;
      var locked = editing && button.dataset.nodeAction !== "edit";
      button.disabled = locked;
      if (locked) button.title = "该节点正在编辑，保存或取消后才能排序或删除";
      else button.removeAttribute("title");
    });
    parts.index = indexText;
    parts.editing = editing;
  }

  function renderNodes() {
    var grid = $("nodeGrid");
    if (!grid) return;
    var proxies = Array.isArray(state.config.proxies) ? state.config.proxies : [];
    var query = String(state.nodeQuery || "").trim().toLowerCase();
    var visible = 0;
    // 表单编辑中的节点禁止排序、拖拽与删除；先按稳定依据重新定位它的当前索引。
    if (state.nodeForm.open && state.nodeForm.index !== null) syncNodeFormTarget();
    var editingIndex = editingNodeIndex();
    var present = new Set(proxies);
    var previous = nodeGridView;
    var used = new Set();
    var cards = [];
    var entering = 0;
    proxies.forEach(function (proxy, index) {
      var info = nodeCardInfo(proxy, index);
      var matched = (!state.nodeProtocol || info.type === state.nodeProtocol) && (!query || info.haystack.indexOf(query) >= 0);
      if (matched) visible += 1;
      var cacheable = proxy !== null && typeof proxy === "object";
      var card = cacheable ? nodeCards.get(proxy) : null;
      if (card && used.has(card)) card = null;
      if (!card) {
        // 同一位置上的旧节点已不在列表中：视为被替换，沿用其卡片并更新内容，不重播入场动画。
        var oldCard = previous.cards[index];
        var oldNode = previous.nodes[index];
        if (oldCard && !used.has(oldCard) && !present.has(oldNode)) card = oldCard;
      }
      if (!card) {
        card = document.createElement("div");
        card.className = "node-card";
        fillNodeCard(card, info);
        if (entering < ENTER_ANIMATION_LIMIT) {
          markEntering(card);
          entering += 1;
        }
      } else if (nodeCardParts.get(card).key !== info.key) {
        fillNodeCard(card, info);
      }
      if (cacheable) nodeCards.set(proxy, card);
      used.add(card);
      syncNodeCardState(card, index, index === editingIndex, !matched);
      cards.push(card);
    });
    var statusText = "";
    if (!proxies.length) statusText = state.loading ? "正在加载节点…" : "暂无节点，请使用导入或手动添加";
    else if (!visible) statusText = "没有匹配当前筛选条件的节点";
    var desired = cards.slice();
    if (statusText) {
      if (!nodeGridStatus) {
        nodeGridStatus = document.createElement("div");
        nodeGridStatus.className = "empty-state";
      }
      nodeGridStatus.textContent = statusText;
      desired.push(nodeGridStatus);
    }
    if (!grid.querySelector(".node-card") && desired.length > 1) {
      // 首次批量出现：一次性插入，避免逐个插入。
      var fragment = document.createDocumentFragment();
      desired.forEach(function (node) { fragment.appendChild(node); });
      clearElement(grid);
      grid.appendChild(fragment);
    } else {
      // 按目标顺序就地调整：位置正确的卡片不动，只移动错位的、移除多余的。
      var cursor = grid.firstChild;
      desired.forEach(function (node) {
        if (node === cursor) {
          cursor = cursor.nextSibling;
          return;
        }
        grid.insertBefore(node, cursor);
      });
      while (cursor) {
        var next = cursor.nextSibling;
        grid.removeChild(cursor);
        cursor = next;
      }
    }
    nodeGridView = { nodes: proxies.slice(), cards: cards };
    setText("nodeSummary", String(proxies.length) + " 个节点" + (query || state.nodeProtocol ? " · 当前显示 " + visible : ""));
    blockRendered("nodes");
  }

  // 拖拽排序（对齐 V1）：事件委托在 #nodeGrid 上，基于卡片 data-index 的真实索引交换，
  // 筛选状态下也可用；正在编辑的节点不可拖动。
  function nodeCardFromEvent(event) {
    var target = event.target;
    var card = target && target.closest ? target.closest(".node-card") : null;
    var grid = $("nodeGrid");
    return card && grid && grid.contains(card) ? card : null;
  }

  function initNodeDragEvents() {
    var grid = $("nodeGrid");
    if (!grid) return;
    grid.addEventListener("dragstart", function (event) {
      var card = nodeCardFromEvent(event);
      if (!card) return;
      var index = Number(card.dataset.index);
      if (card.classList.contains("editing") || index === editingNodeIndex()) {
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
    grid.addEventListener("dragend", function (event) {
      var card = nodeCardFromEvent(event);
      if (card) card.classList.remove("dragging");
      grid.querySelectorAll(".node-card.drop-target, .node-card.dragging").forEach(function (item) {
        item.classList.remove("drop-target");
        item.classList.remove("dragging");
      });
      dragState.fromIndex = null;
    });
    grid.addEventListener("dragover", function (event) {
      var card = nodeCardFromEvent(event);
      if (!card) return;
      var index = Number(card.dataset.index);
      if (dragState.fromIndex === null || dragState.fromIndex === index) return;
      event.preventDefault();
      if (event.dataTransfer) event.dataTransfer.dropEffect = "move";
      card.classList.add("drop-target");
    });
    grid.addEventListener("dragleave", function (event) {
      var card = nodeCardFromEvent(event);
      if (card) card.classList.remove("drop-target");
    });
    grid.addEventListener("drop", function (event) {
      var card = nodeCardFromEvent(event);
      if (!card) return;
      event.preventDefault();
      card.classList.remove("drop-target");
      var index = Number(card.dataset.index);
      if (dragState.fromIndex === null || dragState.fromIndex === index) return;
      moveNodeTo(dragState.fromIndex, index);
    });
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
        existing_proxies: clone(state.config.proxies),
        on_conflict: importReplaceChecked() ? "replace" : "skip"
      };
      var result = await apiRequest("/api/import", { method: "POST", body: body });
      if (isStale(epoch)) return;
      var incoming = Array.isArray(result.proxies) ? result.proxies : [];
      var replacing = Array.isArray(result.replaced_proxies) ? result.replaced_proxies : [];
      var emptiedSourceIds = applyReplacedProxies(replacing);
      state.config.proxies = state.config.proxies.concat(incoming);
      if (result.source && isObject(result.source)) {
        var sources = Array.isArray(state.config.import_sources) ? state.config.import_sources : [];
        sources = sources.filter(function (source) { return emptiedSourceIds.indexOf(source.id) < 0; });
        var existing = sources.findIndex(function (source) { return source.id === result.source.id; });
        if (existing >= 0) sources[existing] = clone(result.source);
        else sources.push(clone(result.source));
        state.config.import_sources = sources;
      }
      if (!markDirty()) return;
      await flushDraftSave();
      if (isStale(epoch)) return;
      if (input) input.value = "";
      resetImportReplace();
      // 保存回包已刷新派生信息；这里只渲染节点相关区域（新卡片才播放入场动画）。
      renderBlock("nodes");
      renderBlock("pills");
      renderStats();
      renderImport();
      var skipped = Array.isArray(result.skipped) ? result.skipped.length : 0;
      var warnings = Array.isArray(result.warnings) ? result.warnings.length : 0;
      setText("importSummary", "本次导入 " + incoming.length + " 个节点；覆盖 " + replacing.length + " 个；跳过 " + skipped + " 个；警告 " + warnings + " 条");
      if (warnings) showToast("导入完成，存在 " + warnings + " 条警告", "info");
      else showToast("导入完成，新增 " + incoming.length + " 个，覆盖 " + replacing.length + " 个节点", "info");
      renderImportMessages(result);
    } catch (error) {
      if (isStale(epoch)) return;
      displayApiError(error, "导入失败");
    } finally {
      if (button) button.disabled = false;
    }
  }

  function importReplaceChecked() {
    var box = $("importReplace");
    return Boolean(box && box.checked);
  }

  // 就地替换同名节点，顺序不变，策略组按名称引用也就不会失效。
  // 返回替换后不再有节点的旧来源 id，这些来源要从列表里去掉。
  function applyReplacedProxies(replacing) {
    var byName = {};
    replacing.forEach(function (node) { byName[String(node.name)] = node; });
    var oldSourceIds = [];
    state.config.proxies = state.config.proxies.map(function (node) {
      var replacement = byName[String(node.name)];
      if (!replacement) return node;
      if (node._source_id) oldSourceIds.push(node._source_id);
      return replacement;
    });
    return oldSourceIds.filter(function (id, index) {
      return oldSourceIds.indexOf(id) === index && !state.config.proxies.some(function (node) { return node._source_id === id; });
    });
  }

  // onekey `x export` 的内容首行带标记：同一台 VPS 重新导出后默认覆盖更新。
  // 用户手动改过勾选后不再自动改动。
  function syncImportReplaceDefault() {
    var input = $("importInput");
    var box = $("importReplace");
    if (!input || !box || box.dataset.userSet === "true") return;
    box.checked = input.value.indexOf("# onekey-export") >= 0;
  }

  function resetImportReplace() {
    var box = $("importReplace");
    if (!box) return;
    box.checked = false;
    delete box.dataset.userSet;
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
    if (targetValue.indexOf(",") >= 0) {
      showToast("目标策略不能包含逗号", "error");
      return;
    }
    var editing = state.ruleEditIndex;
    var rules = state.config.custom_rules;
    // MATCH 是兜底规则，固定两段 MATCH,target，没有也不需要规则值；只保留一条，由新值替换旧值。
    if (type.value === "MATCH") {
      var kept = rules.filter(function (raw, index) { return index !== editing && !isMatchRule(raw); });
      kept.push("MATCH," + targetValue);
      state.config.custom_rules = kept;
    } else {
      var ruleValue = value ? value.value.trim() : "";
      if (!ruleValue) {
        showToast("请填写规则值", "error");
        return;
      }
      // AND/OR/NOT 这类逻辑规则的值本身带逗号，其余类型出现逗号会被拆错字段。
      if (ruleValue.indexOf(",") >= 0 && !/^(AND|OR|NOT|SUB-RULE)$/.test(type.value)) {
        showToast("规则值不能包含逗号", "error");
        return;
      }
      var noResolve = $("ruleNoResolve");
      var raw = type.value + "," + ruleValue + "," + targetValue + (noResolve && noResolve.checked ? ",no-resolve" : "");
      if (rules.some(function (item, index) { return index !== editing && String(item) === raw; })) {
        showToast("这条规则已经存在", "error");
        return;
      }
      if (editing !== null) rules[editing] = raw;
      else rules.push(raw);
    }
    state.ruleEditIndex = null;
    if (!markDirty()) return;
    if (value) value.value = "";
    if ($("ruleNoResolve")) $("ruleNoResolve").checked = false;
    updateRuleForm();
    renderRules();
    renderStats();
  }

  function changeRuleSource(value) {
    state.config.selected_rule_type = value;
    state.ruleFilter = "";
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
    setText("modeDesc", router ? "DNS、TUN、嗅探由 OpenClash 接管，YAML 只输出节点、策略组和规则，相关设置已隐藏。" : "YAML 自带 DNS、TUN、嗅探等完整设置，导入客户端即可使用。");
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
      if (!isStale(epoch)) showToast("推荐配置已应用", "info");
    } catch (error) {
      if (!isStale(epoch)) displayApiError(error, "推荐配置保存失败");
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

  // 最近一次写入 #yamlCode 的 YAML 文本；相同内容不重复构建。
  var renderedYamlText = null;

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
      renderedYamlText = null;
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
      // YAML 内容不变时不重建；变化时只生成“行号列 + 正文列”两个文本节点，而不是每行一组元素。
      if (renderedYamlText !== payload.yaml || !yamlCode.firstChild) {
        var lineCount = payload.yaml.split("\n").length;
        var numbers = new Array(lineCount);
        for (var lineIndex = 0; lineIndex < lineCount; lineIndex += 1) numbers[lineIndex] = String(lineIndex + 1);
        var block = document.createElement("div");
        block.className = "yaml-block";
        // 复用 .yaml-line 的排版（flex + pre），但不挂 .yaml-line 类，避免整块触发逐行悬停高亮。
        block.style.cssText = "display:flex;padding:0 18px;white-space:pre";
        appendText(block, numbers.join("\n"), "ln");
        appendText(block, payload.yaml, "yaml-text");
        clearElement(yamlCode);
        yamlCode.appendChild(block);
        renderedYamlText = payload.yaml;
      }
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
      // 校验回包按内容比对合并草稿（保留未变化部分的对象引用），只刷新受影响区域。
      var changedKeys = payload.config ? reconcileDraft(canonicalDraft(payload.config)) : {};
      var derived = updateServerFields(payload);
      refreshDerivedViews(changedKeys, derived, {});
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
    // 侧栏现在只放管理员面板：普通用户没有侧栏，主内容占满整行。
    if ($("layout")) $("layout").classList.toggle("no-sidebar", !isAdmin);
    if ($("sidebarToggle")) $("sidebarToggle").hidden = !isAdmin;
    if (!isAdmin) {
      blockRendered("admin");
      return;
    }
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
    blockRendered("admin");
  }

  // ============ 区块级脏检查 ============
  // 每个区块有签名（决定它渲染结果的输入）；签名未变则跳过。step 非 0 的区块只在其步骤可见时渲染，
  // 否则标记待渲染，切换到该步骤或浏览器空闲时再补。containers 内有焦点时延后到焦点离开再重建，
  // 避免打断输入。各 render 函数结束时调用 blockRendered 记录签名，因此直接调用 render 函数
  // （用户操作后的局部刷新）也会同步签名。
  var BLOCKS = {
    nodes: {
      step: 2,
      signature: function () {
        var proxies = Array.isArray(state.config.proxies) ? state.config.proxies : [];
        var form = state.nodeForm || {};
        return [
          objectId(proxies),
          proxies.map(objectId).join(","),
          state.nodeQuery,
          state.nodeProtocol,
          form.open ? String(form.index) + objectId(form.ref) : "-",
          state.loading
        ].join("|");
      },
      render: function () { renderNodes(); }
    },
    pills: {
      step: 2,
      signature: function () { return protocolList().join(",") + "|" + state.nodeProtocol; },
      render: function () { renderProtocolPills(); }
    },
    rules: {
      step: 3,
      signature: function () {
        var rules = Array.isArray(state.config.custom_rules) ? state.config.custom_rules : [];
        return rules.join("\u0002") + "|" + targetOptions().key;
      },
      render: function () { renderRules(); }
    },
    ruleSource: {
      step: 3,
      containers: ["providerTargetsPanel", "ruleSource", "ruleFallback"],
      signature: function () {
        var sourceKey = selectedProviderSource();
        var overrides = sourceKey ? state.config.global_config[sourceKey + "_provider_targets"] : null;
        return [
          state.config.selected_rule_type,
          objectId(state.ruleCatalog),
          JSON.stringify(overrides === undefined ? null : overrides),
          targetOptions().key
        ].join("|");
      },
      render: function () { renderRuleSource(); }
    },
    rulesets: {
      step: 3,
      containers: ["rulesetPanel"],
      signature: function () { return JSON.stringify(state.config.custom_rule_providers || {}) + "|" + state.rulesetMode; },
      render: function () { renderRulesets(); }
    },
    global: {
      step: 3,
      // 无签名：schema 不变时 renderGlobalConfig 只就地刷新变化的控件，开销很小。
      signature: null,
      render: function (force) { renderGlobalConfig(Boolean(force)); }
    },
    admin: {
      step: 0,
      containers: ["adminPanelHost"],
      signature: function () {
        return [
          Boolean(state.user && state.user.is_admin === true),
          objectId(state.adminUsers),
          state.adminLoading,
          state.adminLoaded,
          state.adminConfirmDelete,
          state.adminResult
        ].join("|");
      },
      render: function () { renderAdminPanel(); }
    }
  };
  var blockMeta = {};
  Object.keys(BLOCKS).forEach(function (name) { blockMeta[name] = { sig: undefined, dirty: false }; });

  function blockRendered(name) {
    var block = BLOCKS[name];
    var meta = blockMeta[name];
    if (!block || !meta) return;
    meta.sig = block.signature ? block.signature() : null;
    meta.dirty = false;
  }

  // options.force：无视签名/步骤/焦点立即渲染；options.allowHidden：允许渲染非当前步骤（空闲补渲染用）。
  function renderBlock(name, options) {
    var opts = options || {};
    var block = BLOCKS[name];
    var meta = blockMeta[name];
    if (!block || !meta) return false;
    if (!opts.force) {
      if (block.signature && !meta.dirty && meta.sig === block.signature()) return false;
      if (!opts.allowHidden && block.step && block.step !== state.activeStep) {
        meta.dirty = true;
        scheduleIdleBlocks();
        return false;
      }
      if (block.containers) {
        var hosts = block.containers.map($).filter(Boolean);
        if (focusInside(hosts)) {
          meta.dirty = true;
          renderWhenFocusLeaves(name, hosts);
          return false;
        }
      }
    }
    block.render(Boolean(opts.force));
    return true;
  }

  // 补渲染被延后的区块；传入 step 时只处理该步骤（及常驻区块）。
  function flushDirtyBlocks(step) {
    Object.keys(BLOCKS).forEach(function (name) {
      var meta = blockMeta[name];
      if (!meta || !meta.dirty) return;
      if (step !== undefined && BLOCKS[name].step && BLOCKS[name].step !== step) return;
      renderBlock(name, { allowHidden: step === undefined });
    });
  }

  var idleBlocksScheduled = false;
  function scheduleIdleBlocks() {
    if (idleBlocksScheduled) return;
    idleBlocksScheduled = true;
    var run = function () {
      idleBlocksScheduled = false;
      flushDirtyBlocks();
    };
    if (typeof window.requestIdleCallback === "function") window.requestIdleCallback(run, { timeout: 800 });
    else window.setTimeout(run, 150);
  }

  // 容器内有焦点时延后重建：焦点离开所有容器后再渲染一次（监听只挂一次）。
  var focusWaiters = {};
  function renderWhenFocusLeaves(name, hosts) {
    if (focusWaiters[name]) return;
    focusWaiters[name] = true;
    var onFocusOut = function () {
      window.setTimeout(function () {
        if (!focusWaiters[name] || focusInside(hosts)) return;
        hosts.forEach(function (host) { host.removeEventListener("focusout", onFocusOut); });
        focusWaiters[name] = false;
        if (name === "global") renderGlobalConfig(false);
        else renderBlock(name, { allowHidden: true });
      }, 0);
    };
    hosts.forEach(function (host) { host.addEventListener("focusout", onFocusOut); });
  }

  // force 为 true 时立即重绘全部区块（换号/退出/回滚等需要彻底刷新的场景）。
  function renderAll(force) {
    var options = force ? { force: true } : undefined;
    renderStats();
    renderSubscription();
    renderImport();
    Object.keys(BLOCKS).forEach(function (name) { renderBlock(name, options); });
    // 表单打开时不重建（renderNodeForm 只同步定位），保护用户正在输入的内容。
    renderNodeForm(false);
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
      var subMenu = $("subMenu");
      if (subMenu && !subMenu.contains(event.target)) setSubMenuOpen(false);
    });
    var subTrigger = $("subMenuBtn");
    if (subTrigger) subTrigger.addEventListener("click", function () {
      setSubMenuOpen(subTrigger.getAttribute("aria-expanded") !== "true");
    });
    $("subMenu") && $("subMenu").addEventListener("keydown", function (event) {
      if (event.key !== "Escape" || !subTrigger || subTrigger.getAttribute("aria-expanded") !== "true") return;
      setSubMenuOpen(false);
      subTrigger.focus();
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
    $("importInput") && $("importInput").addEventListener("input", syncImportReplaceDefault);
    $("importReplace") && $("importReplace").addEventListener("change", function (event) {
      event.target.dataset.userSet = "true";
    });
    $("clearImportBtn") && $("clearImportBtn").addEventListener("click", function () {
      if ($("importInput")) $("importInput").value = "";
      resetImportReplace();
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
    // 节点筛选 120ms 去抖；renderNodes 复用卡片，只切换不匹配卡片的隐藏状态。
    $("nodeSearch") && $("nodeSearch").addEventListener("input", function (event) {
      var value = event.target.value;
      if (nodeSearchTimer !== null) window.clearTimeout(nodeSearchTimer);
      nodeSearchTimer = window.setTimeout(function () {
        nodeSearchTimer = null;
        state.nodeQuery = value;
        renderNodes();
      }, 120);
    });
    initNodeDragEvents();
    // 规则源目标下拉在首次交互时懒填充全部候选（委托在常驻容器上，面板重建后仍有效）。
    var providerPanel = $("providerTargetsPanel");
    if (providerPanel) {
      var fillLazyTarget = function (event) {
        var select = event.target && event.target.closest ? event.target.closest("select[data-lazy-targets]") : null;
        if (select) fillProviderTargetSelect(select);
      };
      providerPanel.addEventListener("focusin", fillLazyTarget);
      providerPanel.addEventListener("mousedown", fillLazyTarget);
      providerPanel.addEventListener("keydown", fillLazyTarget);
      providerPanel.addEventListener("touchstart", fillLazyTarget, { passive: true });
    }
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
    $("ruleType") && $("ruleType").addEventListener("change", updateRuleForm);
    $("cancelRuleEditBtn") && $("cancelRuleEditBtn").addEventListener("click", function () {
      clearRuleEdit();
      renderRules();
    });
    updateRuleForm();
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
    // 上次处于登录状态时与 /api/session 并行预取草稿；未登录则丢弃预取结果。
    var prefetched = readAuthHint() ? prefetchConfig() : null;
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
      await loadBootstrap(prefetched);
    } catch (error) {
      state.loading = false;
      showAuthOverlay({ csrf_token: state.authCsrf });
      displayApiError(error, "会话加载失败");
    }
  }

  init();
})();
