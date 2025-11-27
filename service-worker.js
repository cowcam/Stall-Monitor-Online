self.addEventListener('push', function(event) {
  let data = {};
  if (event.data) {
    data = event.data.json();
  }

  const options = {
    body: data.body || 'New activity detected!',
    icon: data.icon || '/assets/stallmonitor.png',
    badge: '/assets/stallmonitor.png', // Small icon for status bar
    vibrate: [200, 100, 200],
    data: {
        url: data.url || '/' 
    }
  };

  event.waitUntil(
    self.registration.showNotification(data.title || 'Stall Monitor', options)
  );
});

self.addEventListener('notificationclick', function(event) {
  event.notification.close();
  // Open the dashboard when clicked
  event.waitUntil(
    clients.openWindow(event.notification.data.url)
  );
});