// Tests for the navigation bar ensuring token revocation and redirects work
// correctly when the user logs out.
import { render, fireEvent, waitFor } from '@testing-library/react';
import { Router } from 'react-router-dom';
import { createMemoryHistory } from 'history';
import NavigationBar from '../NavigationBar';
import api from '../../api';

jest.mock('../../api');

afterEach(() => {
  jest.clearAllMocks();
  localStorage.clear();
  sessionStorage.clear();
});

test('logout revokes token and redirects to login', async () => {
  api.post.mockResolvedValueOnce({ status: 200 });
  const history = createMemoryHistory({ initialEntries: ['/chat'] });
  localStorage.setItem('access_token', 'abc');
  localStorage.setItem('pinned_keys', '[]');
  sessionStorage.setItem('private_key_pem', 'pk');

  const { getByRole } = render(
    <Router history={history}>
      <NavigationBar onToggleTheme={() => {}} currentTheme="light" />
    </Router>
  );

  fireEvent.click(getByRole('button', { name: /logout/i }));

  await waitFor(() => expect(api.post).toHaveBeenCalledWith('/api/revoke'));
  await waitFor(() => expect(localStorage.getItem('access_token')).toBeNull());
  await waitFor(() => expect(history.location.pathname).toBe('/login'));
});
