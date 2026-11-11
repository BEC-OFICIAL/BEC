/* Job Search · sw.js (versión de limpieza)
   Borra las copias guardadas por versiones anteriores, se desinstala
   y recarga las pestañas abiertas para que carguen la versión actual. */
self.addEventListener('install', () => self.skipWaiting());

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    try {
      const keys = await caches.keys();
      await Promise.all(keys.map((k) => caches.delete(k)));
    } catch (e) {}
    try { await self.registration.unregister(); } catch (e) {}
    try {
      const clients = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
      clients.forEach((c) => { try { c.navigate(c.url); } catch (e) {} });
    } catch (e) {}
  })());
});

/* Sin interceptar nada: todo va directo a la red. */
self.addEventListener('fetch', () => {});
