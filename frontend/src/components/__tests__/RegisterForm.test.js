import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { Router } from 'react-router-dom';
import { createMemoryHistory } from 'history';
import RegisterForm from '../RegisterForm';
import api from '../../api';
import { saveKeyMaterial } from '../../utils/secureStore';

jest.mock('../../api');
jest.mock('../../utils/secureStore', () => ({
  saveKeyMaterial: jest.fn(),
}));

afterEach(() => {
  jest.clearAllMocks();
});

test('successful registration saves key material and redirects to login', async () => {
  api.post.mockResolvedValueOnce({ status: 201, data: { encrypted_private_key: 'enc', salt: 's', nonce: 'n', fingerprint: 'fp' } });

  const history = createMemoryHistory({ initialEntries: ['/register'] });
  render(
    <Router history={history}>
      <RegisterForm />
    </Router>
  );

  fireEvent.change(screen.getByLabelText(/username/i), { target: { value: 'alice' } });
  fireEvent.change(screen.getByLabelText(/email/i), { target: { value: 'a@example.com' } });
  fireEvent.change(screen.getByLabelText(/password/i), { target: { value: 'secret' } });
  fireEvent.click(screen.getByRole('button', { name: /register/i }));

  await waitFor(() => expect(saveKeyMaterial).toHaveBeenCalled());
  await waitFor(() => expect(history.location.pathname).toBe('/login'));
});

test('shows error on registration failure', async () => {
  api.post.mockRejectedValueOnce({ response: { data: { message: 'Taken' } } });

  const history = createMemoryHistory({ initialEntries: ['/register'] });
  render(
    <Router history={history}>
      <RegisterForm />
    </Router>
  );

  fireEvent.change(screen.getByLabelText(/username/i), { target: { value: 'bob' } });
  fireEvent.change(screen.getByLabelText(/email/i), { target: { value: 'b@example.com' } });
  fireEvent.change(screen.getByLabelText(/password/i), { target: { value: 'bad' } });
  fireEvent.click(screen.getByRole('button', { name: /register/i }));

  await screen.findByText('Taken');
});
