import api from '../api';
import { urlB64ToUint8Array } from './encoding';

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
