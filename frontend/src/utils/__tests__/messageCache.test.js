import { TextEncoder, TextDecoder } from 'util';
import { initCacheSecret, saveMessages, loadMessages } from '../messageCache';

beforeAll(() => {
  global.crypto = {
    subtle: {
      importKey: jest.fn().mockResolvedValue('material'),
      deriveKey: jest.fn().mockResolvedValue('key'),
      encrypt: jest.fn(async () => new TextEncoder().encode('cipher')),
      decrypt: jest.fn(async () => new TextEncoder().encode('[{"id":1,"text":"hi"}]')),
    },
    getRandomValues: jest.fn((arr) => arr.fill(1)),
  };
  if (!global.TextEncoder) global.TextEncoder = TextEncoder;
  if (!global.TextDecoder) global.TextDecoder = TextDecoder;
});

beforeEach(async () => {
  const dbs = await indexedDB.databases();
  await Promise.all(dbs.map((d) => indexedDB.deleteDatabase(d.name)));
});

test('encrypts and decrypts messages', async () => {
  await initCacheSecret('pw');
  await saveMessages([{ id: 1, text: 'hi' }]);
  const msgs = await loadMessages();
  expect(msgs).toEqual([{ id: 1, text: 'hi' }]);
});

test('purges messages beyond ttl', async () => {
  const now = Date.now();
  jest.spyOn(Date, 'now').mockReturnValue(now);
  await initCacheSecret('pw');
  await saveMessages([{ id: 1, text: 'hi' }]);
  Date.now.mockReturnValue(now + 5000);
  const msgs = await loadMessages({ ttlMs: 1000 });
  expect(msgs).toEqual([]);
});
