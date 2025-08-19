/**
 * Utilities for managing Web Push subscriptions.
 *
 * This module exposes helpers to register and unregister the browser with the
 * backend's push service. It assumes the presence of Service Worker support
 * and the Web Push API.
 *
 * Modification summary:
 * - ``setupWebPush`` now validates the backend response when registering a
 *   token. If the backend returns a non-2xx status or a network error occurs,
 *   the function retries once before surfacing the failure via the catch
 *   block. This helps diagnose push registration issues that would otherwise
 *   be silently ignored.
 */

import api from '../api';
import { urlB64ToUint8Array } from './encoding';

/**
 * Attempt to register the browser for push notifications and send the
 * resulting subscription to the backend. When unsupported or denied, the
 * function exits silently.
 */
export async function setupWebPush() {
  // Abort early in environments that lack Service Worker or Push API support.
  if (typeof window === 'undefined' || !('serviceWorker' in navigator)) return;
  if (typeof Notification === 'undefined' || !('PushManager' in window)) return;

  try {
    const perm = await Notification.requestPermission();
    if (perm !== 'granted') return; // User declined notifications.

    // Either retrieve an existing worker registration or create one so we can
    // obtain a push subscription from it.
    let reg = await navigator.serviceWorker.getRegistration();
    if (!reg) {
      reg = await navigator.serviceWorker.register('/sw.js');
    }

    // Subscribe the client to push notifications using the VAPID public key
    // provided at build time. ``userVisibleOnly`` ensures each push results in
    // a notification, satisfying browser requirements.
    const key = process.env.REACT_APP_VAPID_PUBLIC_KEY || '';
    const sub = await reg.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: urlB64ToUint8Array(key),
    });

    const payload = { token: JSON.stringify(sub), platform: 'web' };

    // Attempt to persist the subscription with the backend. We retry once on a
    // network failure or non-2xx HTTP status so transient issues do not
    // permanently disable push notifications.
    let attempt = 0;
    let lastError;
    while (attempt < 2) {
      try {
        // ``api.post`` resolves with the full Axios response object. We inspect
        // the HTTP status to ensure the backend accepted the subscription.
        // Axios ordinarily rejects non-2xx statuses, but explicitly checking
        // makes the intent clear and protects against custom ``validateStatus``
        // configurations.
        const res = await api.post('/api/push-token', payload);
        if (res.status >= 200 && res.status < 300) {
          return; // Successfully registered the push token.
        }

        // Treat an unexpected status as an error to trigger a retry.
        lastError = new Error(`Unexpected status code ${res.status}`);
      } catch (err) {
        // Capture the error so it can be surfaced if all retries fail.
        lastError = err;
      }
      attempt += 1;
    }

    // If both attempts failed, surface the error via the catch block below to
    // aid troubleshooting.
    throw lastError;
  } catch (e) {
    // Logging the error is important for visibility because callers typically
    // fire-and-forget this function during application startup.
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
