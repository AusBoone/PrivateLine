// Tests for the login form covering success and error flows. The API layer and
// secure store helpers are mocked to avoid side effects.
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { Router } from 'react-router-dom';
import { createMemoryHistory } from 'history';
import LoginForm from '../LoginForm';
import api from '../../api';
import { loadKeyMaterial } from '../../utils/secureStore';
import Cookies from 'js-cookie';

jest.mock('../../api');
jest.mock('../../utils/secureStore', () => ({
  loadKeyMaterial: jest.fn(),
}));

beforeAll(() => {
  global.crypto = {
    subtle: {
      importKey: jest.fn().mockResolvedValue('key'),
      deriveKey: jest.fn().mockResolvedValue('derived'),
      decrypt: jest.fn().mockResolvedValue(new ArrayBuffer(1)),
    },
  };
  if (!global.TextEncoder) {
    global.TextEncoder = require('util').TextEncoder;
  }
});

afterEach(() => {
  jest.clearAllMocks();
  document.cookie = 'user_id=; expires=Thu, 01 Jan 1970 00:00:00 GMT';
  document.cookie = 'private_key_pem=; expires=Thu, 01 Jan 1970 00:00:00 GMT';
  document.cookie = 'pinned_keys=; expires=Thu, 01 Jan 1970 00:00:00 GMT';
});

test('successful login redirects to chat', async () => {
  api.post.mockResolvedValueOnce({ status: 200, data: { access_token: 'abc' } });
  api.get.mockResolvedValueOnce({ status: 200, data: { pinned_keys: [] } });
  loadKeyMaterial.mockResolvedValue({ encrypted_private_key: 'enc', salt: 's', nonce: 'n' });

  const history = createMemoryHistory({ initialEntries: ['/login'] });
  render(
    <Router history={history}>
      <LoginForm />
    </Router>
  );

  fireEvent.change(screen.getByLabelText(/username/i), { target: { value: 'alice' } });
  fireEvent.change(screen.getByLabelText(/password/i), { target: { value: 'secret' } });
  fireEvent.click(screen.getByRole('button', { name: /login/i }));

  await waitFor(() => expect(api.post).toHaveBeenCalledWith('/api/login', { username: 'alice', password: 'secret' }));
  await waitFor(() => expect(history.location.pathname).toBe('/chat'));
});

test('shows error on failed login', async () => {
  api.post.mockRejectedValueOnce({ response: { data: { message: 'Invalid' } } });

  const history = createMemoryHistory({ initialEntries: ['/login'] });
  render(
    <Router history={history}>
      <LoginForm />
    </Router>
  );

  fireEvent.change(screen.getByLabelText(/username/i), { target: { value: 'bob' } });
  fireEvent.change(screen.getByLabelText(/password/i), { target: { value: 'bad' } });
  fireEvent.click(screen.getByRole('button', { name: /login/i }));

  await screen.findByText('Invalid');
});
