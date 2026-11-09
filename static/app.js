"use strict";
// All dynamic text is inserted with textContent (never innerHTML), and CSP forbids inline script.
let token = sessionStorage.getItem("tv_token");
let me = null;
const app = document.getElementById("app");

function h(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (k === "class") e.className = v;
    else e.setAttribute(k, v);
  }
  for (const c of kids.flat()) if (c != null && c !== false) e.append(c.nodeType ? c : document.createTextNode(String(c)));
  return e;
}
function toast(msg) {
  const t = document.getElementById("toast");
  t.textContent = msg; t.className = "show";
  setTimeout(() => (t.className = ""), 3500);
}
async function api(path, { method = "GET", body, form } = {}) {
  const opts = { method, headers: {} };
  if (token) opts.headers.Authorization = "Bearer " + token;
  if (form) opts.body = form;
  else if (body) { opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(body); }
  const r = await fetch("/api" + path, opts);
  if (r.status === 401 && token) { clear(); showLogin(); throw new Error("Please sign in again"); }
  if (!r.ok) {
    let m = r.statusText;
    try { const j = await r.json(); m = typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail); } catch (_) {}
    throw new Error(m);
  }
  return r;
}
const j = async (p, o) => (await api(p, o)).json();
const run = (fn) => async (...a) => { try { await fn(...a); } catch (e) { toast(e.message); } };
function clear() { token = null; me = null; sessionStorage.removeItem("tv_token"); }

function nav() {
  const n = document.getElementById("nav");
  n.replaceChildren();
  if (!me) return;
  n.append(h("span", { class: "muted" }, `${me.display_name} (${me.role})`),
    h("button", { class: "secondary", onclick: showDocs }, "Documents"));
  if (me.role === "admin") {
    n.append(h("button", { class: "secondary", onclick: showAudit }, "Activity"),
      h("button", { class: "secondary", onclick: showUsers }, "Users"));
  }
  n.append(h("button", { class: "secondary", onclick: run(async () => { await api("/auth/logout", { method: "POST" }); clear(); nav(); showLogin(); }) }, "Sign out"));
}

function showLogin() {
  nav();
  const u = h("input", { id: "u", autocomplete: "username", required: "" });
  const p = h("input", { id: "p", type: "password", autocomplete: "current-password", required: "" });
  const go = run(async () => {
    const r = await (await api("/auth/login", { method: "POST", body: { username: u.value, password: p.value } })).json();
    token = r.token; me = r.user; sessionStorage.setItem("tv_token", token); nav(); showDocs();
  });
  app.replaceChildren(h("div", { class: "card" }, h("h2", {}, "Sign in"),
    h("div", { class: "row" }, h("label", { for: "u" }, "Username"), u),
    h("div", { class: "row" }, h("label", { for: "p" }, "Password"), p),
    h("button", { onclick: go }, "Sign in")));
  p.addEventListener("keydown", (e) => e.key === "Enter" && go());
}

async function download(id, name, version) {
  const r = await api(`/documents/${id}/download` + (version ? `?version=${version}` : ""));
  const url = URL.createObjectURL(await r.blob());
  const a = h("a", { href: url, download: name }); document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

async function showDocs() {
  nav();
  const f = { q: h("input", { placeholder: "Name contains" }), owner: h("input", { placeholder: "Owner username" }),
    category: h("input", { placeholder: "Category" }), from: h("input", { type: "date", "aria-label": "Created from" }),
    to: h("input", { type: "date", "aria-label": "Created to" }), trash: h("input", { type: "checkbox", id: "trash" }) };
  const results = h("div");
  const search = run(async () => {
    const p = new URLSearchParams();
    if (f.q.value) p.set("q", f.q.value); if (f.owner.value) p.set("owner", f.owner.value);
    if (f.category.value) p.set("category", f.category.value);
    if (f.from.value) p.set("created_from", f.from.value); if (f.to.value) p.set("created_to", f.to.value);
    if (f.trash.checked) p.set("trash", "true");
    const docs = await j("/documents?" + p);
    results.replaceChildren(docs.length ? h("table", {}, h("tr", {}, ...["Name", "Category", "Owner", "Your access", "Updated"].map((x) => h("th", {}, x))),
      ...docs.map((d) => h("tr", {}, h("td", {}, h("a", { class: "link", href: "#", onclick: (e) => { e.preventDefault(); showDoc(d.id); } }, d.name)),
        h("td", {}, d.category), h("td", {}, d.owner), h("td", {}, h("span", { class: "tag" }, d.my_level)), h("td", {}, d.updated_at.replace("T", " ").replace("+00:00", " UTC")))))
      : h("p", { class: "muted" }, "No documents match. Documents appear here only when you own them or someone shared them with you."));
  });
  const kids = [h("div", { class: "card" }, h("h2", {}, "Find documents"),
    h("div", { class: "row" }, f.q, f.owner, f.category, f.from, f.to,
      h("label", { for: "trash" }, f.trash, " Deleted"), h("button", { onclick: search }, "Search")))];
  if (me.role === "owner") {
    const file = h("input", { type: "file" }), name = h("input", { placeholder: "Display name (optional)" }),
      cat = h("input", { placeholder: "Category", value: "general" });
    kids.push(h("div", { class: "card" }, h("h2", {}, "Upload a document"),
      h("div", { class: "row" }, file, name, cat, h("button", { onclick: run(async () => {
        if (!file.files[0]) throw new Error("Choose a file first");
        const fd = new FormData(); fd.append("file", file.files[0]); fd.append("category", cat.value);
        if (name.value) fd.append("name", name.value);
        await api("/documents", { method: "POST", form: fd }); toast("Uploaded"); showDocs();
      }) }, "Upload")),
      h("p", { class: "muted" }, "Allowed: pdf, png, jpg, txt, csv, docx, xlsx. Max 10 MB.")));
  }
  kids.push(results);
  app.replaceChildren(...kids); search();
}

async function showDoc(id) {
  const d = await j(`/documents/${id}`);
  const isEdit = d.my_level === "edit" || d.my_level === "owner", isOwner = d.my_level === "owner";
  const kids = [h("button", { class: "secondary", onclick: showDocs }, "Back"),
    h("div", { class: "card" }, h("h2", {}, d.name),
      h("p", { class: "muted" }, `Category ${d.category}. Owner ${d.owner}. Your access: ${d.my_level}. Version ${d.current_version}.`),
      h("div", { class: "row" }, h("button", { onclick: run(() => download(id, d.name)) }, "Download latest"),
        isOwner && h("button", { class: "danger", onclick: run(async () => { if (confirm("Delete this document? You can restore it from Deleted.")) { await api(`/documents/${id}`, { method: "DELETE" }); showDocs(); } }) }, "Delete")))];
  if (isEdit) {
    const nm = h("input", { value: d.name }), ct = h("input", { value: d.category }), nf = h("input", { type: "file" });
    kids.push(h("div", { class: "card" }, h("h2", {}, "Edit"),
      h("div", { class: "row" }, nm, ct, h("button", { onclick: run(async () => { await api(`/documents/${id}`, { method: "PATCH", body: { name: nm.value, category: ct.value } }); toast("Saved"); showDoc(id); }) }, "Save details")),
      h("div", { class: "row" }, nf, h("button", { onclick: run(async () => { if (!nf.files[0]) throw new Error("Choose a file first"); const fd = new FormData(); fd.append("file", nf.files[0]); await api(`/documents/${id}/versions`, { method: "POST", form: fd }); toast("New version uploaded"); showDoc(id); }) }, "Upload new version"))));
  }
  kids.push(h("div", { class: "card" }, h("h2", {}, "Versions"), h("table", {}, h("tr", {}, ...["Version", "File", "Size", "Uploaded by", "When", ""].map((x) => h("th", {}, x))),
    ...d.versions.map((v) => h("tr", {}, h("td", {}, v.version), h("td", {}, v.original_filename), h("td", {}, v.size + " B"), h("td", {}, v.uploaded_by), h("td", {}, v.created_at),
      h("td", {}, h("a", { class: "link", href: "#", onclick: (e) => { e.preventDefault(); run(() => download(id, v.original_filename, v.version))(); } }, "Download")))))));
  if (isOwner) {
    const dir = await j("/users/directory");
    const who = h("select", {}, ...dir.map((u) => h("option", { value: u.id }, `${u.display_name} (${u.username}, ${u.role})`)));
    const lvl = h("select", {}, h("option", { value: "read" }, "Read"), h("option", { value: "edit" }, "Edit (owners only)"));
    kids.push(h("div", { class: "card" }, h("h2", {}, "Who has access"),
      d.grants.length ? h("table", {}, ...d.grants.map((g) => h("tr", {}, h("td", {}, `${g.display_name} (${g.username})`), h("td", {}, h("span", { class: "tag" }, g.level)),
        h("td", {}, h("button", { class: "danger", onclick: run(async () => { await api(`/documents/${id}/grants/${g.user_id}`, { method: "DELETE" }); toast("Access removed"); showDoc(id); }) }, "Remove access")))))
        : h("p", { class: "muted" }, "Only you can open this document."),
      h("div", { class: "row" }, who, lvl, h("button", { onclick: run(async () => { await api(`/documents/${id}/grants/${who.value}`, { method: "PUT", body: { level: lvl.value } }); toast("Access updated"); showDoc(id); }) }, "Give access"))));
    const hist = await j(`/documents/${id}/history`);
    kids.push(auditTable("Who has touched this document", hist));
  }
  app.replaceChildren(...kids);
}

function auditTable(title, rows) {
  return h("div", { class: "card" }, h("h2", {}, title), rows.length ? h("table", {}, h("tr", {}, ...["#", "When", "Who", "Action", "Result", "IP", "Detail"].map((x) => h("th", {}, x))),
    ...rows.map((r) => h("tr", {}, h("td", {}, r.seq), h("td", {}, r.ts), h("td", {}, r.actor_name || "-"), h("td", {}, r.action),
      h("td", {}, h("span", { class: "tag " + r.outcome }, r.outcome)), h("td", {}, r.ip || ""), h("td", { class: "wrap" }, r.detail)))) : h("p", { class: "muted" }, "Nothing recorded yet."));
}

async function showAudit() {
  nav();
  const [alerts, ver] = await Promise.all([j("/admin/alerts"), j("/admin/audit/verify")]);
  const action = h("input", { placeholder: "Action (e.g. download)" }), outcome = h("select", {}, ...["", "success", "denied", "failure"].map((o) => h("option", { value: o }, o || "Any result")));
  const out = h("div");
  const load = run(async () => {
    const p = new URLSearchParams(); if (action.value) p.set("action", action.value); if (outcome.value) p.set("outcome", outcome.value);
    out.replaceChildren(auditTable("Activity and permission changes", await j("/admin/audit?" + p)));
  });
  app.replaceChildren(
    h("div", { class: "card" }, h("h2", {}, "Needs attention (last hour)"), alerts.length ? h("ul", {}, ...alerts.map((a) => h("li", { class: "bad" }, a.message))) : h("p", { class: "muted" }, "Nothing unusual.")),
    h("div", { class: "card" }, h("h2", {}, "Audit log integrity"), h("p", { class: ver.ok ? "" : "bad" }, ver.ok ? `Chain verified: ${ver.entries_checked} entries. Head: ${ver.head}` : `TAMPERING DETECTED at entry ${ver.broken_at_seq}`)),
    h("div", { class: "card" }, h("div", { class: "row" }, action, outcome, h("button", { onclick: load }, "Filter"))), out);
  load();
}

async function showUsers() {
  nav();
  const users = await j("/admin/users");
  const f = { username: h("input", { placeholder: "username" }), display_name: h("input", { placeholder: "Display name" }), password: h("input", { type: "password", placeholder: "Password (10+ chars)" }),
    role: h("select", {}, ...["viewer", "owner", "admin"].map((r) => h("option", { value: r }, r))) };
  app.replaceChildren(h("div", { class: "card" }, h("h2", {}, "Users"), h("table", {}, h("tr", {}, ...["User", "Role", "Active", ""].map((x) => h("th", {}, x))),
    ...users.map((u) => h("tr", {}, h("td", {}, `${u.display_name} (${u.username})`), h("td", {}, u.role), h("td", {}, u.active ? "yes" : "no"),
      h("td", {}, h("button", { class: u.active ? "danger" : "secondary", onclick: run(async () => { await api(`/admin/users/${u.id}`, { method: "PATCH", body: { active: !u.active } }); showUsers(); }) }, u.active ? "Deactivate" : "Reactivate")))))),
    h("div", { class: "card" }, h("h2", {}, "Add a user"), h("div", { class: "row" }, f.username, f.display_name, f.password, f.role,
      h("button", { onclick: run(async () => { await api("/admin/users", { method: "POST", body: Object.fromEntries(Object.entries(f).map(([k, v]) => [k, v.value])) }); toast("User created"); showUsers(); }) }, "Create user"))));
}

(async () => {
  if (token) { try { me = await j("/me"); nav(); return showDocs(); } catch (_) { clear(); } }
  showLogin();
})();
