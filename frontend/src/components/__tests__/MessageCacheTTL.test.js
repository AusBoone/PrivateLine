import { TextEncoder, TextDecoder } from 'util';
import { initCacheSecret, saveMessages, loadMessages, DEFAULT_TTL_MS } from '../../utils/messageCache';

beforeAll(() => {
  if (!global.TextEncoder) global.TextEncoder = TextEncoder;
  if (!global.TextDecoder) global.TextDecoder = TextDecoder;
  global.crypto = {
    subtle: {
      importKey: jest.fn().mockResolvedValue('material'),
      deriveKey: jest.fn().mockResolvedValue('key'),
      encrypt: jest.fn(async () => new TextEncoder().encode('cipher')),
      decrypt: jest.fn(async () => new TextEncoder().encode('[{"id":1,"text":"hi"}]')),
    },
    getRandomValues: jest.fn((arr) => arr.fill(1)),
  };
  global.window.crypto = global.crypto;
});

beforeEach(async () => {
  const dbs = await indexedDB.databases();
  await Promise.all(dbs.map((d) => indexedDB.deleteDatabase(d.name)));
});

test('cache entry beyond default TTL is purged', async () => {
  jest.spyOn(Date, 'now').mockReturnValue(0);
  await initCacheSecret('pw');
  await saveMessages([{ id: 1, text: 'hi' }]);

  Date.now.mockReturnValue(DEFAULT_TTL_MS + 1000);
  const msgs = await loadMessages();
  expect(msgs).toEqual([]);
});
