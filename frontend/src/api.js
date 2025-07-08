import axios from 'axios';
import Cookies from 'js-cookie';

/**
 * API helper configured for PrivateLine backend.
 *
 * All requests include credentials so authentication cookies are sent.
 * For state-changing operations the backend expects the CSRF token stored in
 * the ``csrf_access_token`` cookie to be provided via the ``X-CSRF-TOKEN``
 * header. An interceptor automatically attaches this header when present.
 */

// Axios instance used throughout the React app. ``withCredentials`` ensures
// the JWT cookies issued by the backend are sent with each request.
const api = axios.create({
  baseURL: process.env.REACT_APP_API_URL || 'http://localhost:5000',
  withCredentials: true,
});

// Attach the ``X-CSRF-TOKEN`` header when the corresponding cookie exists. This
// satisfies Flask-JWT-Extended's CSRF double submit check.
api.interceptors.request.use((config) => {
  const csrf = Cookies.get('csrf_access_token');
  if (csrf) {
    // eslint-disable-next-line no-param-reassign
    config.headers['X-CSRF-TOKEN'] = csrf;
  }
  return config;
});


export default api;

