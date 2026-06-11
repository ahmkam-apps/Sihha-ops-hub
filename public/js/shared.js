// Sihha Ops Hub — shared frontend helpers. Loaded via <script src="/js/shared.js"></script>
// BEFORE each page's inline script.

// ── Escaping helpers (XSS) ────────────────────────────────────────────────────
function esc(s){return s==null?'':String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');}
// For values placed inside single-quoted JS string args within onclick="" attributes
function escJs(s){return esc(String(s==null?'':s).replace(/\\/g,'\\\\').replace(/'/g,"\\'"));}

// ── API wrapper factory ───────────────────────────────────────────────────────
// getToken:          () => current bearer token (or null/undefined)
// sendBodyIfDefined: true  → body is sent whenever it is !== undefined
//                            (portal.html legacy behavior)
//                    false → body is sent only when truthy
//                            (index.html legacy behavior)
// Kept as a parameter to preserve exact pre-refactor semantics per page.
function makeApi(getToken, sendBodyIfDefined) {
  return async function api(method, path, body) {
    const opts = { method, headers: { 'Content-Type': 'application/json' } };
    const token = getToken();
    if (token) opts.headers['Authorization'] = 'Bearer ' + token;
    if (sendBodyIfDefined ? body !== undefined : body) opts.body = JSON.stringify(body);
    const res = await fetch('/api' + path, opts);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || 'Request failed');
    return data;
  };
}
