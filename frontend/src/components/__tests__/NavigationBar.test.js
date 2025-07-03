// Tests for the navigation bar ensuring token revocation and redirects work
// correctly when the user logs out.
import { render, fireEvent, waitFor } from '@testing-library/react';
import { Router } from 'react-router-dom';
import { createMemoryHistory } from 'history';
import NavigationBar from '../NavigationBar';
import api from '../../api';
import { removeWebPush } from '../../utils/push';
import { clearAll as clearPersistedGroupKeys } from '../../utils/groupKeyStore';
import Cookies from 'js-cookie';

jest.mock('../../api');
jest.mock('../../utils/push', () => ({ removeWebPush: jest.fn().mockResolvedValue() }));
jest.mock('../../utils/groupKeyStore', () => ({ clearAll: jest.fn().mockResolvedValue() }));

afterEach(() => {
  jest.clearAllMocks();
  document.cookie = 'pinned_keys=; expires=Thu, 01 Jan 1970 00:00:00 GMT';
  document.cookie = 'private_key_pem=; expires=Thu, 01 Jan 1970 00:00:00 GMT';
  document.cookie = 'user_id=; expires=Thu, 01 Jan 1970 00:00:00 GMT';
});

test('logout revokes token and redirects to login', async () => {
  api.post.mockResolvedValueOnce({ status: 200 });
  const history = createMemoryHistory({ initialEntries: ['/chat'] });
  Cookies.set('pinned_keys', '[]');
  Cookies.set('private_key_pem', 'pk');
  Cookies.set('user_id', '1');

  const { getByRole } = render(
    <Router history={history}>
      <NavigationBar onToggleTheme={() => {}} currentTheme="light" />
    </Router>
  );

  fireEvent.click(getByRole('button', { name: /logout/i }));

  await waitFor(() => expect(api.post).toHaveBeenCalledWith('/api/revoke'));
  await waitFor(() => expect(removeWebPush).toHaveBeenCalled());
  await waitFor(() => expect(clearPersistedGroupKeys).toHaveBeenCalled());
  await waitFor(() => expect(Cookies.get('pinned_keys')).toBeUndefined());
  await waitFor(() => expect(history.location.pathname).toBe('/login'));
});
