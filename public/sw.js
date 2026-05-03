// SIHAA Service Worker — v3
const CACHE = 'sihaa-v3';
const PAGES = ['/order', '/portal', '/intake', '/volunteer'];

// ── Install: pre-cache public pages ──────────────────────────────────────────
self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE)
      .then(c => Promise.allSettled(PAGES.map(p => c.add(p))))
      .then(() => self.skipWaiting())
  );
});

// ── Activate: clear old caches ────────────────────────────────────────────────
self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

// ── Fetch strategy ────────────────────────────────────────────────────────────
self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);

  // API calls: always network, never cache
  if (url.pathname.startsWith('/api/')) {
    e.respondWith(fetch(e.request));
    return;
  }

  // Icons/manifests: cache-first
  if (url.pathname.startsWith('/icons/') || url.pathname.includes('manifest')) {
    e.respondWith(
      caches.match(e.request)
        .then(cached => cached || fetch(e.request).then(r => {
          caches.open(CACHE).then(c => c.put(e.request, r.clone()));
          return r;
        }))
    );
    return;
  }

  // HTML pages: network-first, fall back to cache, then offline message
  if (e.request.mode === 'navigate' || e.request.headers.get('accept')?.includes('text/html')) {
    e.respondWith(
      fetch(e.request)
        .then(r => {
          caches.open(CACHE).then(c => c.put(e.request, r.clone()));
          return r;
        })
        .catch(() => caches.match(e.request).then(cached => cached || offlinePage()))
    );
    return;
  }

  // Everything else: network-first
  e.respondWith(fetch(e.request).catch(() => caches.match(e.request)));
});

function offlinePage() {
  return new Response(`<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Offline — SIHAA</title>
<style>
  body{font-family:Helvetica,Arial,sans-serif;background:#111;color:#fff;
    display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;text-align:center;padding:24px}
  h1{font-size:28px;font-weight:800;letter-spacing:-0.04em;margin-bottom:12px}
  p{font-size:15px;opacity:0.6;line-height:1.6}
</style></head>
<body>
  <div>
    <h1>You're offline</h1>
    <p>SIHAA needs an internet connection to submit requests.<br>Please reconnect and try again.</p>
  </div>
</body></html>`, {
    status: 503,
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  });
}
