import { render, screen, waitFor, act } from '@testing-library/react';
import Chat from '../Chat';
import api from '../../api';
import io from 'socket.io-client';

jest.mock('../../api');
jest.mock('socket.io-client');
jest.mock('../../utils/secureStore', () => ({
  loadKeyMaterial: jest.fn().mockResolvedValue({}),
}));

it('fetches existing messages and shows websocket updates', async () => {
  const socket = { on: jest.fn(), disconnect: jest.fn() };
  io.mockReturnValue(socket);
  api.get.mockResolvedValue({ status: 200, data: { messages: [{ id: 1, content: 'hello' }] } });

  render(<Chat />);

  await waitFor(() => {
    expect(api.get).toHaveBeenCalledWith('/api/messages');
  });

  // existing message from API should appear
  await screen.findByText('hello');

  // wait for websocket handler to be registered
  await waitFor(() => {
    expect(socket.on).toHaveBeenCalledWith('new_message', expect.any(Function));
  });
  const handler = socket.on.mock.calls.find((c) => c[0] === 'new_message')[1];
  await act(async () => {
    handler({ content: 'world' });
  });

  await screen.findByText('world');
});
