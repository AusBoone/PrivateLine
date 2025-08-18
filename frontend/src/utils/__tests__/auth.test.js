/**
 * Tests for authentication utility functions.
 *
 * Focuses on verifying that `getUserId` correctly handles various states of the
 * `user_id` cookie including valid numbers, absence of the cookie, and malformed
 * values.
 */
import Cookies from 'js-cookie';
import { getUserId } from '../auth';

describe('getUserId', () => {
  afterEach(() => {
    // Ensure cookies from one test do not affect another.
    Cookies.remove('user_id');
  });

  test('returns numeric ID when cookie contains a valid number', () => {
    // The cookie holds a simple numeric string; should be parsed to a number.
    Cookies.set('user_id', '42');
    expect(getUserId()).toBe(42);
  });

  test('returns null when cookie is missing', () => {
    // With no cookie present, the function should gracefully return null.
    expect(getUserId()).toBeNull();
  });

  test('returns null when cookie value is non-numeric', () => {
    // A non-numeric string should not be converted and instead yield null.
    Cookies.set('user_id', 'abc');
    expect(getUserId()).toBeNull();
  });
});
