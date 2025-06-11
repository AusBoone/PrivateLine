import axios from 'axios';

/**
 * Axios instance pre-configured with the API base URL. Requests include
 * credentials so the backend can read the authentication cookie.
 */
const api = axios.create({
  baseURL: process.env.REACT_APP_API_URL || 'http://localhost:5000',
  withCredentials: true,
});


export default api;

