export function getUserIdFromToken() {
  const token = localStorage.getItem('access_token');
  if (!token) return null;
  try {
    const payload = JSON.parse(atob(token.split('.')[1]));
    return payload.sub ? parseInt(payload.sub, 10) : null;
  } catch (e) {
    console.error('Failed to decode token', e);
    return null;
  }
}
