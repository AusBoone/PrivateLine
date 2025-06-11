export function getUserId() {
  const id = sessionStorage.getItem('user_id');
  return id ? parseInt(id, 10) : null;
}
