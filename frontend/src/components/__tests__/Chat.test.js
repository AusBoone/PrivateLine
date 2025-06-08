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
jest.mock('../../utils/push', () => ({ setupWebPush: jest.fn() }));

beforeAll(() => {
  global.crypto = {
    subtle: {
      importKey: jest.fn().mockResolvedValue('key'),
      encrypt: jest.fn().mockResolvedValue(new ArrayBuffer(1)),
      decrypt: jest.fn().mockResolvedValue(new ArrayBuffer(1)),
    },
  };
  if (!global.TextEncoder) {
    global.TextEncoder = require('util').TextEncoder;
  }
});

afterEach(() => {
  jest.clearAllMocks();
});

it.skip('fetches existing messages and shows websocket updates', async () => {
  const socket = { on: jest.fn(), disconnect: jest.fn() };
  io.mockReturnValue(socket);
  api.get.mockResolvedValueOnce({ status: 200, data: { groups: [] } });
  api.get.mockResolvedValueOnce({ status: 200, data: { messages: [{ id: 1, content: 'hello' }] } });
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

  // existing message from API should appear
  await waitFor(() => {
    expect(screen.getByText('hello')).toBeInTheDocument();
  });

  // wait for websocket handler to be registered
  await waitFor(() => {
    expect(socket.on).toHaveBeenCalledWith('new_message', expect.any(Function));
  });
  const handler = socket.on.mock.calls.find((c) => c[0] === 'new_message')[1];
  await act(async () => {
    handler({ content: 'world' });
  });

  await waitFor(() => {
    expect(screen.getByText('world')).toBeInTheDocument();
  });
});

it.skip('uses selected recipient when sending a message', async () => {
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

  await waitFor(() => {
    expect(screen.getByText('bob')).toBeInTheDocument();
  });
  fireEvent.click(screen.getByText('bob'));

  api.get.mockResolvedValueOnce({ status: 200, data: { public_key: 'KEY' } });
  api.post.mockResolvedValueOnce({ status: 201, data: { id: 1 } });

  fireEvent.change(screen.getByPlaceholderText('Type your message'), {
    target: { value: 'hi' },
  });
  await act(async () => {
    fireEvent.click(screen.getByText('Send'));
  });

  await waitFor(() => {
    expect(api.get).toHaveBeenCalledWith('/api/public_key/bob');
    expect(api.post).toHaveBeenCalled();
  });
});
