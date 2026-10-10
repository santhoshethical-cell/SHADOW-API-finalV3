/* Advanced scan options — guided forms for every CLI option.
 *
 * A tiny data-driven form engine renders each section from a schema and can
 * read it back into a plain object. collectAdvancedOptions() assembles the
 * `options` payload the backend's scan_options.materialize() expects.
 *
 * Credential fields are ordinary inputs here; the value is sent once over the
 * authenticated POST and the backend swaps it for a per-scan env-var name so it
 * never lands on disk.
 */
(function () {
  let uid = 0;
  const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

  function h(tag, attrs, ...kids) {
    const e = document.createElement(tag);
    attrs = attrs || {};
    for (const [k, v] of Object.entries(attrs)) {
      if (v == null) continue;
      if (k === "class") e.className = v;
      else if (k === "html") e.innerHTML = v;
      else if (k.slice(0, 2) === "on") e.addEventListener(k.slice(2), v);
      else e.setAttribute(k, v);
    }
    for (const kid of kids.flat()) {
      if (kid == null || kid === false) continue;
      e.append(kid.nodeType ? kid : document.createTextNode(kid));
    }
    return e;
  }

  function wrap(def, control) {
    return h("label", { class: "field adv-field" },
      h("span", { class: "adv-label" }, def.label,
        def.hint ? h("small", { class: "adv-hint" }, def.hint) : null),
      control);
  }

  // Build one field -> {node, read}
  function field(def) {
    if (def.type === "checkbox") {
      const inp = h("input", { type: "checkbox" });
      if (def.default) inp.checked = true;
      return { node: h("label", { class: "adv-check" }, inp, " " + def.label), read: () => inp.checked };
    }
    if (def.type === "select") {
      const sel = h("select", {}, ...def.opts.map((o) => {
        const val = o.v !== undefined ? o.v : o;
        const lab = o.l !== undefined ? o.l : o;
        return h("option", { value: val }, lab);
      }));
      if (def.default != null) sel.value = def.default;
      return { node: wrap(def, sel), read: () => sel.value };
    }
    if (def.type === "textarea") {
      const ta = h("textarea", { placeholder: def.ph || "", rows: def.rows || 3, spellcheck: "false" });
      return { node: wrap(def, ta), read: () => ta.value };
    }
    if (def.type === "taglist") {
      const inp = h("input", { placeholder: def.ph || "comma separated", spellcheck: "false" });
      return {
        node: wrap(def, inp),
        read: () => inp.value.split(/[,\n]/).map((s) => s.trim()).filter(Boolean),
      };
    }
    if (def.type === "group") {
      const form = buildForm(def.schema);
      return { node: h("fieldset", { class: "adv-group" }, h("legend", {}, def.label), form.node), read: form.read };
    }
    if (def.type === "list") {
      return listField(def);
    }
    // text | password | number
    const t = def.type === "password" ? "password" : def.type === "number" ? "number" : "text";
    const inp = h("input", { type: t, placeholder: def.ph || "", spellcheck: "false",
      autocomplete: t === "password" ? "new-password" : "off" });
    if (def.default != null) inp.value = def.default;
    return {
      node: wrap(def, inp),
      read: () => (def.type === "number" ? (inp.value ? Number(inp.value) : undefined) : inp.value),
    };
  }

  // A repeatable list of sub-forms -> {node, read: ()=>array}
  function listField(def) {
    const items = [];
    const holder = h("div", { class: "adv-list-items" });
    const addRow = () => {
      const id = ++uid;
      const sub = buildForm(def.schema);
      const row = h("div", { class: "adv-list-row" },
        h("div", { class: "adv-list-body" }, sub.node),
        h("button", { type: "button", class: "btn ghost tiny adv-del",
          onclick: () => { row.remove(); const i = items.findIndex((x) => x.id === id); if (i >= 0) items.splice(i, 1); } }, "Remove"));
      items.push({ id, read: sub.read });
      holder.append(row);
    };
    const node = h("div", { class: "adv-list" },
      h("div", { class: "adv-list-head" }, h("span", { class: "adv-label" }, def.label,
        def.hint ? h("small", { class: "adv-hint" }, def.hint) : null),
        h("button", { type: "button", class: "btn ghost tiny", onclick: addRow }, "+ Add " + (def.item || "item"))),
      holder);
    if (def.min) for (let i = 0; i < def.min; i++) addRow();
    return { node, read: () => items.map((it) => it.read()) };
  }

  function buildForm(schema) {
    const fields = schema.map((def) => ({ def, f: field(def) }));
    const node = h("div", { class: "adv-form" }, ...fields.map((x) => x.f.node));
    const read = () => {
      const out = {};
      for (const { def, f } of fields) out[def.k] = f.read();
      return out;
    };
    return { node, read };
  }

  // A collapsible section that can be enabled/disabled -> {node, enabled, read}
  function section(title, subtitle, schema, opts) {
    opts = opts || {};
    const form = buildForm(schema);
    const toggle = h("input", { type: "checkbox", class: "adv-enable" });
    const body = h("div", { class: "adv-section-body", hidden: opts.optional ? "" : null }, form.node);
    if (!opts.optional) body.hidden = false;
    toggle.addEventListener("change", () => { body.hidden = !toggle.checked; });
    const head = opts.optional
      ? h("label", { class: "adv-section-head" }, toggle, h("strong", {}, title),
          subtitle ? h("small", { class: "adv-hint" }, subtitle) : null)
      : h("div", { class: "adv-section-head" }, h("strong", {}, title),
          subtitle ? h("small", { class: "adv-hint" }, subtitle) : null);
    return {
      node: h("div", { class: "adv-section" }, head, body),
      enabled: () => (opts.optional ? toggle.checked : true),
      read: form.read,
    };
  }

  // ------------------------------------------------------------------ schemas
  const methodSel = (dflt) => ({ type: "select", opts: METHODS, default: dflt || "GET" });

  const caseCommon = [
    { k: "name", label: "Case name", type: "text", ph: "descriptive-name" },
    { k: "method", label: "Method", ...methodSel("GET") },
    { k: "url", label: "URL (path or absolute)", type: "text", ph: "/api/orders/1001" },
  ];

  const S = {
    discovery: [
      { k: "no_browser", label: "Skip browser (Phase 2) — static + HTTP only", type: "checkbox" },
      { k: "discovery_only", label: "Discovery only — skip all security validation", type: "checkbox" },
      { k: "concurrency", label: "Discovery concurrency", type: "number", ph: "1–20", hint: "default 10" },
      { k: "openapi_url", label: "OpenAPI spec URL", type: "text", ph: "https://target/openapi.json" },
      { k: "openapi_text", label: "…or paste OpenAPI JSON", type: "textarea", rows: 4 },
      { k: "extra_hosts", label: "Extra authorized hosts", type: "taglist", hint: "only hosts you may test" },
    ],
    login_api: [
      { k: "url", label: "Login URL", type: "text", ph: "http://target/rest/user/login" },
      { k: "method", label: "Method", ...methodSel("POST") },
      { k: "body_type", label: "Body type", type: "select", opts: ["json", "form"], default: "json" },
      { k: "body", label: "Login body fields", type: "list", item: "field", min: 2,
        schema: [
          { k: "key", label: "Field", type: "text", ph: "email" },
          { k: "value", label: "Value", type: "text", ph: "user@site" },
          { k: "secret", label: "Secret (hide + keep off disk)", type: "checkbox" },
        ] },
      { k: "token_from", label: "Token from", type: "select", opts: ["json", "header", "cookie"], default: "json" },
      { k: "token_path", label: "Token path / key", type: "text", ph: "$.authentication.token" },
      { k: "inject_as", label: "Inject as", type: "select", opts: ["header", "cookie"], default: "header" },
      { k: "inject_name", label: "Inject name", type: "text", default: "Authorization" },
      { k: "inject_template", label: "Inject template", type: "text", default: "Bearer {token}" },
    ],
    login_browser: [
      { k: "login_url", label: "Login page URL", type: "text", ph: "http://target/login" },
      { k: "fields", label: "Form fields (CSS selector → value)", type: "list", item: "field", min: 2,
        schema: [
          { k: "selector", label: "CSS selector", type: "text", ph: "input[name=username]" },
          { k: "value", label: "Value", type: "text", ph: "wiener" },
          { k: "secret", label: "Secret", type: "checkbox" },
        ] },
      { k: "submit", label: "Submit selector (optional)", type: "text", ph: "button[type=submit]" },
      { k: "wait_for", label: "Wait for", type: "text", default: "networkidle" },
    ],
    headers: [
      { k: "headers", label: "Custom headers", type: "list", item: "header",
        schema: [
          { k: "name", label: "Header", type: "text", ph: "X-API-Key" },
          { k: "value", label: "Value", type: "text" },
        ] },
    ],
    evidence: [
      { k: "har_text", label: "Paste HAR JSON", type: "textarea", rows: 3, hint: "observed traffic" },
      { k: "traffic_log_text", label: "Paste gateway/access log", type: "textarea", rows: 3 },
      { k: "api_inventory_text", label: "Paste approved API inventory (JSON/CSV)", type: "textarea", rows: 3 },
      { k: "no_auto_evidence", label: "Disable automatic local evidence discovery", type: "checkbox" },
      { k: "no_history", label: "Disable per-target inventory history", type: "checkbox" },
    ],
    bola: [
      { k: "header_name", label: "Auth header", type: "text", default: "Authorization" },
      { k: "user_a_value", label: "User A credential", type: "password", ph: "Bearer …A" },
      { k: "user_b_value", label: "User B credential", type: "password", ph: "Bearer …B" },
      { k: "cases", label: "BOLA cases", type: "list", item: "case", min: 1,
        schema: [
          ...caseCommon,
          { k: "object_location", label: "Object in", type: "select", opts: ["path", "query", "body"], default: "path" },
          { k: "object_name", label: "Object name", type: "text", ph: "orderId" },
          { k: "object_value", label: "Object value (User A's)", type: "text", ph: "1001" },
          { k: "json_body_text", label: "JSON body (if in body)", type: "textarea", rows: 2 },
          { k: "evidence_paths", label: "Evidence paths", type: "taglist", ph: "id, ownerId" },
        ] },
    ],
    auth: [
      { k: "header_name", label: "Auth header", type: "text", default: "Authorization" },
      { k: "valid_value", label: "Valid token", type: "password", ph: "Bearer valid…" },
      { k: "invalid_value", label: "Invalid token (optional)", type: "password" },
      { k: "expired_value", label: "Expired token (optional)", type: "password" },
      { k: "cases", label: "Protected-endpoint cases", type: "list", item: "case", min: 1,
        schema: [
          ...caseCommon,
          { k: "evidence_paths", label: "Evidence paths (proves it's protected)", type: "taglist" },
          { k: "json_body_text", label: "JSON body (optional)", type: "textarea", rows: 2 },
          { k: "allow_state_change", label: "Allow state change (needs active testing)", type: "checkbox" },
        ] },
    ],
    parameter: [
      { k: "cases", label: "Mass-assignment cases", type: "list", item: "case", min: 1,
        schema: [
          { k: "name", label: "Case name", type: "text" },
          { k: "method", label: "Method", ...methodSel("PATCH") },
          { k: "url", label: "URL", type: "text", ph: "/api/products/1/price" },
          { k: "parameter", label: "Injected parameter", type: "text", ph: "price" },
          { k: "mutation_body_text", label: "Mutation body (JSON)", type: "textarea", rows: 2, ph: '{"price": 0}' },
          { k: "verify", label: "Verification", type: "group", schema: [
            { k: "method", label: "Method", ...methodSel("GET") },
            { k: "url", label: "URL", type: "text", ph: "/api/products/1/price" },
            { k: "json_path", label: "JSON path", type: "text", ph: "$.price" },
            { k: "original_value", label: "Original value", type: "text" },
            { k: "mutated_value", label: "Expected mutated value", type: "text" },
          ] },
          { k: "cleanup", label: "Cleanup (revert)", type: "group", schema: [
            { k: "method", label: "Method", ...methodSel("PATCH") },
            { k: "url", label: "URL", type: "text" },
            { k: "json_body_text", label: "Restore body (JSON)", type: "textarea", rows: 2 },
          ] },
        ] },
    ],
    injection: [
      { k: "cases", label: "Injection cases", type: "list", item: "case", min: 1,
        schema: [
          ...caseCommon,
          { k: "parameter", label: "Parameter", type: "text" },
          { k: "baseline_value", label: "Baseline (benign) value", type: "text" },
          { k: "categories", label: "Categories", type: "taglist", ph: "sql, nosql, command, template" },
        ] },
    ],
    access: [
      { k: "identities", label: "Identities", type: "list", item: "identity", min: 2,
        schema: [
          { k: "name", label: "Name", type: "text", ph: "member" },
          { k: "header_name", label: "Header", type: "text", default: "Authorization" },
          { k: "value", label: "Credential", type: "password" },
        ] },
      { k: "cases", label: "Access-control cases", type: "list", item: "case", min: 1,
        schema: [
          { k: "name", label: "Case name", type: "text" },
          { k: "type", label: "Type", type: "select", opts: ["object", "function", "session"], default: "object" },
          { k: "method", label: "Method", ...methodSel("GET") },
          { k: "url", label: "URL", type: "text" },
          { k: "allowed_identity", label: "Allowed identity", type: "text", ph: "owner" },
          { k: "denied_identities", label: "Denied identities", type: "taglist", ph: "other" },
          { k: "evidence_paths", label: "Evidence paths", type: "taglist" },
        ] },
    ],
  };

  // ------------------------------------------------------------------ render
  const sections = {};
  function mount() {
    const host = document.getElementById("adv-body");
    if (!host) return;

    sections.discovery = section("Discovery", "Phase 1/2 controls", S.discovery);

    const authTokenForm = buildForm([
      { k: "token", label: "Auth token", type: "password", ph: "Bearer …" },
      { k: "token_header", label: "Auth header", type: "text", default: "Authorization" },
      { k: "cookie", label: "Cookie header", type: "password", ph: "session=…" },
    ]);
    sections._authToken = authTokenForm;
    sections.headers = section("Custom headers", "sent with every request", S.headers, { optional: true });

    const loginMode = h("select", {}, h("option", { value: "api" }, "Mode A · API login"),
      h("option", { value: "browser" }, "Mode B · Browser login"));
    const apiForm = buildForm(S.login_api);
    const browserForm = buildForm(S.login_browser);
    const browserWrap = h("div", { hidden: "" }, browserForm.node);
    const apiWrap = h("div", {}, apiForm.node);
    loginMode.addEventListener("change", () => {
      const api = loginMode.value === "api";
      apiWrap.hidden = !api; browserWrap.hidden = api;
    });
    const loginToggle = h("input", { type: "checkbox", class: "adv-enable" });
    const loginBody = h("div", { class: "adv-section-body", hidden: "" },
      wrap({ label: "Login mode" }, loginMode), apiWrap, browserWrap);
    loginToggle.addEventListener("change", () => { loginBody.hidden = !loginToggle.checked; });
    const loginSection = h("div", { class: "adv-section" },
      h("label", { class: "adv-section-head" }, loginToggle, h("strong", {}, "Authenticated login"),
        h("small", { class: "adv-hint" }, "acquire a session before scanning")), loginBody);
    sections._login = { enabled: () => loginToggle.checked, mode: () => loginMode.value,
      readApi: apiForm.read, readBrowser: browserForm.read };

    sections.evidence = section("Evidence & imports", "traffic / inventory", S.evidence, { optional: true });

    sections.active = (() => {
      const inp = h("input", { type: "checkbox", class: "adv-enable" });
      const node = h("div", { class: "adv-section adv-danger" },
        h("label", { class: "adv-section-head" }, inp, h("strong", {}, "⚠ Active testing"),
          h("small", { class: "adv-hint" }, "allows authorized state-changing exploit validation")));
      return { node, enabled: () => inp.checked };
    })();

    sections.bola = section("BOLA / IDOR (API1)", "two identities", S.bola, { optional: true });
    sections.auth = section("Broken authentication (API2)", "valid vs invalid tokens", S.auth, { optional: true });
    sections.parameter = section("Mass assignment (API3)", "mutates state — active, reversible", S.parameter, { optional: true });
    sections.injection = section("Safe injection indicators", "bounded probes", S.injection, { optional: true });
    sections.access = section("Access control (API1/2/5)", "multi-identity", S.access, { optional: true });

    host.append(
      sections.discovery.node,
      groupCard("Authentication", authTokenForm.node, sections.headers.node, loginSection),
      sections.evidence.node,
      sections.active.node,
      groupCard("Security validators", sections.bola.node, sections.auth.node,
        sections.parameter.node, sections.injection.node, sections.access.node),
    );
  }

  function groupCard(title, ...nodes) {
    return h("div", { class: "adv-card" }, h("h4", { class: "adv-card-title" }, title), ...nodes);
  }

  // ------------------------------------------------------------------ collect
  function nonEmpty(obj) {
    // strip undefined / empty-string / empty-array leaves so the payload is lean
    if (Array.isArray(obj)) {
      const arr = obj.map(nonEmpty).filter((v) => v !== undefined);
      return arr.length ? arr : undefined;
    }
    if (obj && typeof obj === "object") {
      const out = {};
      for (const [k, v] of Object.entries(obj)) {
        const c = nonEmpty(v);
        if (c !== undefined) out[k] = c;
      }
      return Object.keys(out).length ? out : undefined;
    }
    if (obj === "" || obj === undefined || obj === null || obj === false) return undefined;
    return obj;
  }

  window.collectAdvancedOptions = function () {
    if (!sections.discovery) return {};
    const opts = {};
    opts.discovery = sections.discovery.read();

    const auth = {};
    Object.assign(auth, sections._authToken.read());
    const headers = sections.headers.enabled() ? sections.headers.read().headers : null;
    if (headers && headers.length) auth.headers = headers;
    if (sections._login.enabled()) {
      auth.login = sections._login.mode() === "api"
        ? Object.assign({ mode: "api" }, sections._login.readApi())
        : Object.assign({ mode: "browser" }, sections._login.readBrowser());
    }
    opts.auth = auth;

    if (sections.active.enabled()) opts.active_testing = true;
    if (sections.evidence.enabled()) opts.evidence = sections.evidence.read();

    const validators = {};
    if (sections.bola.enabled()) {
      const m = sections.bola.read();
      validators.bola = {
        header_name: m.header_name,
        identities: { user_a: { auth_value: m.user_a_value }, user_b: { auth_value: m.user_b_value } },
        cases: m.cases,
      };
    }
    if (sections.auth.enabled()) validators.auth = sections.auth.read();
    if (sections.parameter.enabled()) validators.parameter = sections.parameter.read();
    if (sections.injection.enabled()) validators.injection = sections.injection.read();
    if (sections.access.enabled()) validators.access = sections.access.read();
    if (Object.keys(validators).length) opts.validators = validators;

    return nonEmpty(opts) || {};
  };

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", mount);
  else mount();
})();
