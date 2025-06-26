import Cookies from 'js-cookie';

export function getUserId() {
  const id = Cookies.get('user_id');
  return id ? parseInt(id, 10) : null;
}
