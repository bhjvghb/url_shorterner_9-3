const CACHE = 'linksnap-v1';

// 需要缓存的静态资源
const PRECACHE = [
  '/',
  '/static/style.css',
  '/static/icon-192.png',
  '/static/icon-512.png',
  '/static/manifest.json'
];

// 安装时预缓存
self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE).then(cache => cache.addAll(PRECACHE))
  );
  self.skipWaiting();
});

// 激活时清理旧缓存
self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

// 网络优先策略（动态页面不缓存，仅回退离线页）
self.addEventListener('fetch', e => {
  // 跳过非 GET 请求和 API 调用
  if (e.request.method !== 'GET') return;
  if (e.request.url.includes('/shorten') || e.request.url.includes('/set-lang')) return;

  e.respondWith(
    fetch(e.request)
      .then(response => {
        // 仅缓存静态资源
        if (e.request.url.includes('/static/')) {
          const clone = response.clone();
          caches.open(CACHE).then(cache => cache.put(e.request, clone));
        }
        return response;
      })
      .catch(() => caches.match(e.request))
  );
});
