self.addEventListener('push', (event) => {
  const data = event.data ? event.data.text() : '';
  event.waitUntil(
    self.registration.showNotification('PrivateLine', { body: data })
  );
});
