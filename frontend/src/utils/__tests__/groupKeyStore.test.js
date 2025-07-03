import { saveKey, loadKey, listGroupIds, clearAll } from '../groupKeyStore';

beforeEach(() => {
  return clearAll();
});

test('saves and loads a key', async () => {
  await saveKey(1, 'abcd');
  const v = await loadKey(1);
  expect(v).toBe('abcd');
});

test('listGroupIds returns stored ids', async () => {
  await saveKey(2, 'x');
  await saveKey(3, 'y');
  const ids = await listGroupIds();
  expect(ids).toEqual(expect.arrayContaining([2, 3]));
});
