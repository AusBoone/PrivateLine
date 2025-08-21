import axios from 'axios';
import Cookies from 'js-cookie';

/**
 * API helper configured for PrivateLine backend.
 *
 * All requests include credentials so authentication cookies are sent.
 * For state-changing operations the backend expects the CSRF token stored in
 * the ``csrf_access_token`` cookie to be provided via the ``X-CSRF-TOKEN``
 * header. An interceptor automatically attaches this header when present.
 *
 * Modification summary:
 * - The request interceptor now defensively initializes ``config.headers``
 *   so that requests lacking a headers object do not throw when the CSRF
 *   token is attached.
 * - ``REACT_APP_API_URL`` now defaults to ``https://localhost:5000`` with a
 *   visible warning when omitted.
 * - Production builds enforce HTTPS and abort if an insecure base URL is
 *   supplied.
 */

// Read relevant environment variables once so testing and runtime logic share
// a single source of truth.
const { REACT_APP_API_URL, NODE_ENV } = process.env;

// Determine the API base URL. When the application is launched without an
// explicit ``REACT_APP_API_URL`` environment variable the developer almost
// certainly intends to target a locally running backend. To make that scenario
// safe-by-default we point to a local HTTPS server and emit a warning so the
// oversight is obvious.
let baseURL = REACT_APP_API_URL;
if (!baseURL) {
  // eslint-disable-next-line no-console
  console.warn(
    'REACT_APP_API_URL is not set; defaulting to https://localhost:5000',
  );
  baseURL = 'https://localhost:5000';
}

// In production builds plaintext HTTP requests are disallowed to prevent
// accidental leakage of authentication cookies or other sensitive information.
// Failing fast here avoids subtle runtime errors later.
if (NODE_ENV === 'production' && !baseURL.startsWith('https://')) {
  throw new Error(
    `Insecure API URL "${baseURL}" rejected: HTTPS is required in production.`,
  );
}

// Axios instance used throughout the React app. ``withCredentials`` ensures
// the JWT cookies issued by the backend are sent with each request.
const api = axios.create({
  baseURL,
  withCredentials: true,
});

// Attach the ``X-CSRF-TOKEN`` header when the corresponding cookie exists. This
// satisfies Flask-JWT-Extended's CSRF double submit check.
api.interceptors.request.use((config) => {
  const csrf = Cookies.get('csrf_access_token');

  // Axios may supply a config without a ``headers`` object (e.g., simple GET
  // requests). Initialize it so setting the CSRF header does not attempt to
  // assign to ``undefined`` which would raise a TypeError.
  // eslint-disable-next-line no-param-reassign
  config.headers = config.headers || {};

  if (csrf) {
    // eslint-disable-next-line no-param-reassign
    config.headers['X-CSRF-TOKEN'] = csrf;
  }
  return config;
});


export default api;

