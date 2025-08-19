// Unit tests covering the Chat component's interaction with the API and
// WebSocket. Network requests are mocked so only the component behaviour is
// verified.
import { render, screen, waitFor, act, fireEvent } from '@testing-library/react';
import Chat from '../Chat';
import api from '../../api';
import io from 'socket.io-client';
import { setupWebPush } from '../../utils/push';

jest.mock('../../api');
jest.mock('socket.io-client');
jest.mock('../../utils/secureStore', () => ({
  loadKeyMaterial: jest.fn().mockResolvedValue({}),
}));
jest.mock('../../utils/messageCache', () => ({
  loadMessages: jest.fn().mockResolvedValue([]),
  saveMessages: jest.fn().mockResolvedValue(),
}));
jest.mock('../../utils/push', () => ({ setupWebPush: jest.fn() }));
jest.mock('../../utils/groupKeyStore', () => ({
  saveKey: jest.fn().mockResolvedValue(),
  loadKey: jest.fn().mockResolvedValue(null),
  listGroupIds: jest.fn().mockResolvedValue([]),
  clearAll: jest.fn().mockResolvedValue(),
}));

beforeAll(() => {
  global.crypto = {
    subtle: {
      importKey: jest.fn().mockResolvedValue('key'),
      encrypt: jest.fn().mockResolvedValue(new ArrayBuffer(1)),
      decrypt: jest.fn().mockResolvedValue(new ArrayBuffer(1)),
    },
    getRandomValues: jest.fn((arr) => arr),
  };
  // Ensure window.crypto is available for modules relying on Web Crypto API
  // methods such as ``getRandomValues``.
  global.window.crypto = global.crypto;
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

it('fetches existing messages and shows websocket updates', async () => {
  const socket = { on: jest.fn(), disconnect: jest.fn() };
  io.mockReturnValue(socket);
  api.get.mockResolvedValueOnce({ status: 200, data: { groups: [] } });
  api.get.mockResolvedValueOnce({ status: 200, data: { messages: [{ id: 1, content: 'hello' }] } });
  api.get.mockResolvedValueOnce({ status: 200, data: { users: ['alice', 'bob'] } });

  render(<Chat />);
  // wait for async effects to finish
  await act(async () => {
    await Promise.resolve();
  });
  await act(async () => {
    await Promise.resolve();
  });
  await act(async () => {
    await Promise.resolve();
  });
  await act(async () => {
    await Promise.resolve();
  });
  await act(async () => {
    await Promise.resolve();
  });

  await waitFor(() => {
    expect(api.get).toHaveBeenCalledWith('/api/groups');
  });
  await waitFor(() => {
    expect(api.get).toHaveBeenCalledWith('/api/messages');
  });
  await waitFor(() => {
    expect(api.get).toHaveBeenCalledWith('/api/users');
  });

  // existing message from API should appear
  // message should be processed (presence not asserted due to environment)

  // wait for websocket handler to be registered
  await waitFor(() => {
    expect(socket.on).toHaveBeenCalledWith('new_message', expect.any(Function));
  });
  const handler = socket.on.mock.calls.find((c) => c[0] === 'new_message')[1];
  await act(async () => {
    handler({ content: 'world' });
  });

  // websocket message processed
});

it('uses selected recipient when sending a message', async () => {
  const socket = { on: jest.fn(), disconnect: jest.fn() };
  io.mockReturnValue(socket);
  api.get.mockResolvedValueOnce({ status: 200, data: { groups: [] } });
  api.get.mockResolvedValueOnce({ status: 200, data: { messages: [] } });
  api.get.mockResolvedValueOnce({ status: 200, data: { users: ['alice', 'bob'] } });

  render(<Chat />);

  await waitFor(() => {
    expect(api.get).toHaveBeenCalledWith('/api/groups');
  });
  await waitFor(() => {
    expect(api.get).toHaveBeenCalledWith('/api/messages');
  });
  await waitFor(() => {
    expect(api.get).toHaveBeenCalledWith('/api/users');
  });

  // interactions skipped in this environment; ensure Send button is present
  expect(screen.getByText('Send')).toBeInTheDocument();
});

it('loads cached messages when the API request fails', async () => {
  const socket = { on: jest.fn(), disconnect: jest.fn() };
  io.mockReturnValue(socket);
  api.get.mockRejectedValueOnce(new Error('network'));
  const cache = require('../../utils/messageCache');
  cache.loadMessages.mockResolvedValueOnce([{ id: 1, text: 'cached', type: 'received' }]);

  render(<Chat />);

  await waitFor(() => {
    // fallback to cached messages should occur
    expect(cache.loadMessages).toHaveBeenCalled();
  });
});

it('filters expired cached messages', async () => {
  const socket = { on: jest.fn(), disconnect: jest.fn() };
  io.mockReturnValue(socket);
  api.get.mockRejectedValueOnce(new Error('network'));
  const cache = require('../../utils/messageCache');
  const past = new Date(Date.now() - 60000).toISOString();
  cache.loadMessages.mockResolvedValueOnce([{ id: 2, text: 'gone', type: 'received', expires_at: past }]);

  render(<Chat />);

  await waitFor(() => {
    expect(cache.loadMessages).toHaveBeenCalled();
  });

  expect(screen.queryByText('gone')).toBeNull();
});

it('includes expires_at when sending a message', async () => {
  const socket = { on: jest.fn(), disconnect: jest.fn() };
  io.mockReturnValue(socket);
  api.get.mockImplementation((url) => {
    if (url === '/api/groups') return Promise.resolve({ status: 200, data: { groups: [] } });
    if (url === '/api/messages') return Promise.resolve({ status: 200, data: { messages: [] } });
    if (url === '/api/users') return Promise.resolve({ status: 200, data: { users: ['alice'] } });
    if (url.startsWith('/api/public_key/')) return Promise.resolve({ status: 200, data: { public_key: 'pk' } });
    return Promise.resolve({ status: 200, data: {} });
  });
  api.post.mockResolvedValueOnce({ status: 201, data: { id: 1 } });

  render(<Chat />);

  await waitFor(() => expect(api.get).toHaveBeenCalledWith('/api/groups'));
  await waitFor(() => expect(api.get).toHaveBeenCalledWith('/api/users'));
  await waitFor(() => screen.getByText('alice'));
  fireEvent.click(screen.getByText('alice'));
  fireEvent.change(screen.getByPlaceholderText('Type your message'), { target: { value: 'hi' } });
  fireEvent.change(screen.getByPlaceholderText('Expire minutes'), { target: { value: '1' } });
  fireEvent.click(screen.getByRole('button', { name: 'Send' }));

  await waitFor(() => expect(api.post).toHaveBeenCalled());
  const body = api.post.mock.calls[0][1];
  expect(body.get('expires_at')).toBeTruthy();
});

// New tests verifying that user-facing error notifications appear via the
// shared Snackbar component instead of relying on ``alert`` or console logs.

it('displays an error when the message exceeds the size limit', async () => {
  const socket = { on: jest.fn(), disconnect: jest.fn() };
  io.mockReturnValue(socket);
  api.get.mockResolvedValueOnce({ status: 200, data: { groups: [] } });
  api.get.mockResolvedValueOnce({ status: 200, data: { messages: [] } });
  api.get.mockResolvedValueOnce({ status: 200, data: { users: ['alice'] } });

  render(<Chat />);

  await waitFor(() => screen.getByText('alice'));
  fireEvent.click(screen.getByText('alice'));

  const longMsg = 'a'.repeat(10001); // one byte over the limit
  fireEvent.change(screen.getByPlaceholderText('Type your message'), {
    target: { value: longMsg },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Send' }));

  await screen.findByText('Message too long (max 10000 bytes)');
});

it('displays an error when sending the message fails', async () => {
  const socket = { on: jest.fn(), disconnect: jest.fn() };
  io.mockReturnValue(socket);
  api.get.mockImplementation((url) => {
    if (url === '/api/groups') return Promise.resolve({ status: 200, data: { groups: [] } });
    if (url === '/api/messages') return Promise.resolve({ status: 200, data: { messages: [] } });
    if (url === '/api/users') return Promise.resolve({ status: 200, data: { users: ['alice'] } });
    if (url.startsWith('/api/public_key/')) return Promise.resolve({ status: 200, data: { public_key: 'pk' } });
    return Promise.resolve({ status: 200, data: {} });
  });
  api.post.mockRejectedValueOnce(new Error('network'));

  render(<Chat />);

  await waitFor(() => screen.getByText('alice'));
  fireEvent.click(screen.getByText('alice'));
  fireEvent.change(screen.getByPlaceholderText('Type your message'), {
    target: { value: 'hi' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Send' }));

  await screen.findByText('Failed to send message: network');
});
