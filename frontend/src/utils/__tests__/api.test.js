/**
 * Tests for the API request interceptor that injects the CSRF token.
 *
 * The interceptor must gracefully handle request configurations that omit a
 * `headers` object. These tests verify that the guard initializes the headers
 * and attaches the token correctly.
 */
import Cookies from 'js-cookie';
import api from '../../api';

describe('API request interceptor', () => {
  afterEach(() => {
    // Clean up the CSRF cookie to avoid cross-test contamination.
    Cookies.remove('csrf_access_token');
  });

  test('adds CSRF token when request has no headers object', () => {
    // Simulate the backend having issued a CSRF token cookie after login.
    Cookies.set('csrf_access_token', 'abc123');

    // Request configuration lacking headers should be expanded to include them.
    const config = {};
    const interceptor = api.interceptors.request.handlers[0].fulfilled;
    const updated = interceptor(config);

    expect(updated.headers['X-CSRF-TOKEN']).toBe('abc123');
  });

  test('creates empty headers when no CSRF cookie exists', () => {
    // A request without headers and without a CSRF cookie should still result
    // in an initialized headers object so downstream code can rely on it.
    const config = {};
    const interceptor = api.interceptors.request.handlers[0].fulfilled;
    const updated = interceptor(config);

    expect(updated.headers).toEqual({});
  });
});
