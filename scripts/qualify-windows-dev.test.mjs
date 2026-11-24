import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, unlink, writeFile, rmdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { planTransfer, verifyTransfer } from './qualify-windows-dev.mjs';

const map = (checksums, sizes = checksums.map(() => 4)) => ({
  version: '2', files: [{ offset: 0, checksums, sizes }],
});

test('moves cached blocks and includes only changed bytes in the qualified transfer', async () => {
  const plan = planTransfer(map(['one', 'two', 'three']), map(['three', 'new', 'one']), 12, 12);
  assert.deepEqual(plan.map(block => block.previousOffset), [8, undefined, 0]);
  const folder = await mkdtemp(join(tmpdir(), 'artmotife-delta-'));
  const old = join(folder, 'old.exe'), next = join(folder, 'new.exe');
  try {
    await writeFile(old, 'abcd1234defg');
    await writeFile(next, 'defg9999abcd');
    const result = await verifyTransfer(old, next, plan);
    assert.equal(result.fetched, 4);
    assert.equal(result.sha512, createHash('sha512').update('defg9999abcd').digest('base64'));
  } finally {
    await Promise.all([unlink(old), unlink(next)]);
    await rmdir(folder);
  }
});

test('invalid blockmaps fail the qualification and size mismatches need downloads', () => {
  assert.throws(() => planTransfer(map(['a']), map(['a']), 5, 4), /cover the installer/);
  assert.throws(() => planTransfer(map(['a']), map(['a'], [0]), 4, 0));
  assert.equal(planTransfer(map(['a']), map(['a'], [6]), 4, 6)[0].previousOffset, undefined);
});
