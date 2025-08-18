/**
 * Authentication utility helpers.
 *
 * Provides functions for retrieving authentication-related data from browser
 * cookies. `getUserId` exposes the numeric identifier for the currently
 * authenticated user if available.
 *
 * This module was updated to make cookie parsing more robust by relying on
 * `Number.parseInt` and explicitly returning `null` when the stored value
 * cannot be interpreted as a valid integer.
 */
import Cookies from 'js-cookie';

/**
 * Retrieve the current user's identifier from the `user_id` cookie.
 *
 * @returns {number|null} The numeric user identifier when the cookie exists
 * and contains a valid base-10 integer; otherwise `null` when the cookie is
 * missing or the value is malformed.
 */
export function getUserId() {
  // Read the raw cookie value; `undefined` signifies that the cookie is absent.
  const id = Cookies.get('user_id');

  // Parse the cookie using `Number.parseInt` to avoid implicit base guessing.
  const numericId = Number.parseInt(id, 10);

  // `Number.parseInt` yields `NaN` when the value is missing or non-numeric.
  // Return `null` in these cases to signal that a valid ID is unavailable.
  return Number.isNaN(numericId) ? null : numericId;
}
