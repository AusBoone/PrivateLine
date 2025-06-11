import api from '../api';
import { urlB64ToUint8Array } from './encoding';
/**
 * Attempt to register the browser for push notifications and send the
 * resulting subscription to the backend. When unsupported or denied, the
 * function exits silently.
 */

export async function setupWebPush() {
  if (typeof window === 'undefined' || !('serviceWorker' in navigator)) return;
  if (typeof Notification === 'undefined' || !('PushManager' in window)) return;
  try {
    const perm = await Notification.requestPermission();
    if (perm !== 'granted') return;
    let reg = await navigator.serviceWorker.getRegistration();
    if (!reg) {
      reg = await navigator.serviceWorker.register('/sw.js');
    }
    const key = process.env.REACT_APP_VAPID_PUBLIC_KEY || '';
    const sub = await reg.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: urlB64ToUint8Array(key),
    });
    await api.post('/api/push-token', { token: JSON.stringify(sub), platform: 'web' });
  } catch (e) {
    console.error('Failed to setup push', e);
  }
}

/**
 * Unregister the current push subscription and remove it from the backend.
 * When unsupported or no subscription exists, the function exits silently.
 */
export async function removeWebPush() {
  if (typeof window === 'undefined' || !('serviceWorker' in navigator)) return;
  try {
    const reg = await navigator.serviceWorker.getRegistration();
    if (!reg) return;
    const sub = await reg.pushManager.getSubscription();
    if (!sub) return;
    await api.delete('/api/push-token', { data: { token: JSON.stringify(sub) } });
    if (typeof sub.unsubscribe === 'function') {
      await sub.unsubscribe();
    }
  } catch (e) {
    console.error('Failed to remove push', e);
  }
}
