/**
 * Tests for the Web Push registration helper.
 *
 * ``setupWebPush`` should post the push subscription to the backend and retry
 * once when the backend responds with a non-2xx status. After two failures the
 * error must be surfaced so callers are aware that push registration did not
 * complete successfully.
 */
import api from '../../api';
import { setupWebPush } from '../push';

// Provide a minimal environment implementing the pieces of the Web Push API
// used by ``setupWebPush``.
beforeEach(() => {
  // Mock permission prompt to grant notification access.
  global.Notification = {
    requestPermission: jest.fn().mockResolvedValue('granted'),
  };

  // Dummy subscription returned by the PushManager.
  const fakeSub = { endpoint: 'test' };

  const subscribe = jest.fn().mockResolvedValue(fakeSub);

  // Service worker registration with a push manager capable of subscribing.
  const registration = {
    pushManager: { subscribe },
  };

  // Ensure navigator exists and expose the mocked service worker helpers.
  global.navigator = global.navigator || {};
  global.navigator.serviceWorker = {
    getRegistration: jest.fn().mockResolvedValue(registration),
    register: jest.fn().mockResolvedValue(registration),
  };

  // ``setupWebPush`` checks for the presence of ``PushManager`` on ``window``;
  // augment the existing window object rather than replacing it so utilities
  // like ``atob`` remain available.
  global.window = global.window || {};
  global.window.PushManager = function PushManager() {};
});

afterEach(() => {
  // Reset spies and mocks so each test has a pristine environment.
  jest.clearAllMocks();
  jest.restoreAllMocks();
});

/**
 * The happy path should send the subscription to the backend a single time.
 */
test('sends subscription to backend when registration succeeds', async () => {
  const postMock = jest.spyOn(api, 'post').mockResolvedValue({ status: 201 });

  await setupWebPush();

  expect(postMock).toHaveBeenCalledTimes(1);
});

/**
 * A failed attempt should be retried once and eventually succeed without
 * logging an error.
 */
test('retries once on non-2xx response before succeeding', async () => {
  const postMock = jest
    .spyOn(api, 'post')
    .mockRejectedValueOnce({ response: { status: 500 } })
    .mockResolvedValueOnce({ status: 201 });

  const errSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

  await setupWebPush();

  expect(postMock).toHaveBeenCalledTimes(2);
  expect(errSpy).not.toHaveBeenCalled();

  errSpy.mockRestore();
});

/**
 * When both attempts fail, the function should surface the error via
 * ``console.error`` so callers can diagnose the issue.
 */
test('logs error after repeated failures', async () => {
  jest
    .spyOn(api, 'post')
    .mockRejectedValue({ response: { status: 500 } });

  const errSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

  await setupWebPush();

  expect(api.post).toHaveBeenCalledTimes(2);
  expect(errSpy).toHaveBeenCalled();

  errSpy.mockRestore();
});
