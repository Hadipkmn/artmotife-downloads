import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { copyFile, mkdir, open, readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { gunzipSync } from 'node:zlib';

const maximumTransferBytes = 16 * 1024 * 1024;
const hash = async (file, algorithm, output) => {
  const digest = createHash(algorithm);
  for await (const buffer of createReadStream(file)) digest.update(buffer);
  return digest.digest(output);
};
const loadJson = async (folder, name) => JSON.parse(await readFile(join(folder, name), 'utf8'));

function blocks({ version, files }, expectedBytes) {
  assert.equal(version, '2', 'Unexpected blockmap format');
  assert.equal(files.length, 1, 'Expected a single installer blockmap');
  const [file] = files;
  assert.equal(file.offset, 0);
  assert.equal(file.sizes.length, file.checksums.length);
  let offset = 0;
  const result = file.sizes.map((size, index) => {
    assert.ok(Number.isSafeInteger(size) && size > 0 && size <= 1024 * 1024);
    const block = { offset, size, checksum: file.checksums[index] };
    offset += size;
    return block;
  });
  assert.equal(offset, expectedBytes, 'Blockmap does not cover the installer');
  return result;
}

export function planTransfer(previous, next, oldBytes, newBytes) {
  const known = new Map(blocks(previous, oldBytes).map(block => [
    block.checksum + ':' + block.size, block.offset,
  ]));
  return blocks(next, newBytes).map(block => ({
    ...block, previousOffset: known.get(block.checksum + ':' + block.size),
  }));
}

export async function verifyTransfer(previous, next, plan) {
  const oldFile = await open(previous, 'r');
  try {
    const newFile = await open(next, 'r');
    try {
      const integrity = createHash('sha512');
      let fetched = 0;
      const bytes = Buffer.allocUnsafe(1024 * 1024);
      for (const { previousOffset, offset, size } of plan) {
        const fromNew = previousOffset === undefined;
        const { bytesRead } = await (fromNew ? newFile : oldFile).read(bytes, 0, size, fromNew ? offset : previousOffset);
        assert.equal(bytesRead, size, 'The installer block was truncated');
        if (fromNew) fetched += size;
        integrity.update(bytes.subarray(0, size));
      }
      return { fetched, sha512: integrity.digest('base64') };
    } finally {
      await newFile.close();
    }
  } finally {
    await oldFile.close();
  }
}

async function verifiedCandidate(folder, source, tooling) {
  assert.match(source, /^[a-f0-9]{40}$/);
  const receipt = await loadJson(folder, 'candidate-receipt.json');
  const installer = await loadJson(folder, 'windows-installer-qualification.json');
  const component = await loadJson(folder, 'windows-component-qualification.json');
  const packaged = await loadJson(folder, 'windows-final-artifact.json');
  const version = installer.candidate;
  assert.match(version, /^\d+\.\d+\.\d+$/);
  assert.equal(receipt.source, source);
  assert.match(tooling ?? '', /^[a-f0-9]{40}$/);
  assert.equal(receipt.workflowSource, tooling);
  assert.equal(receipt.published, false);
  for (const evidence of [installer, component, packaged]) {
    assert.equal(evidence.source, source);
    assert.equal(evidence.status, 'passed');
  }
  assert.equal(component.platform, 'win32');
  assert.equal(component.arch, 'x64');
  assert.equal(packaged.version, version);
  assert.equal(installer.installedProductVersion, version + '.0');
  assert.ok(installer.installationPathContainsSpaces === true && installer.preservedModel === true &&
    installer.preservedConfiguration === true && installer.preservedHistory === true);
  const filename = 'ArtMotife-Connector-' + version + '-windows-x64.exe';
  const sizes = new Map();
  for (const name of [filename, filename + '.blockmap', 'latest.yml']) {
    const expected = receipt.files.find(entry => entry.name === name);
    assert.ok(Number.isSafeInteger(expected?.bytes) && expected.bytes > 0);
    const handle = await open(join(folder, name), 'r');
    try {
      const { size } = await handle.stat();
      assert.equal(size, expected.bytes);
    } finally {
      await handle.close();
    }
    assert.equal(await hash(join(folder, name), 'sha256', 'hex'), expected.sha256);
    sizes.set(name, expected.bytes);
  }
  const metadata = await readFile(join(folder, 'latest.yml'), 'utf8');
  assert.equal(/^version: ([\d.]+)\r?$/m.exec(metadata)?.[1], version);
  assert.equal(/^path: ([^\r\n]+)\r?$/m.exec(metadata)?.[1], filename);
  assert.equal(/^  - url: ([^\r\n]+)\r?$/m.exec(metadata)?.[1], filename);
  assert.equal(Number(/^    size: (\d+)\r?$/m.exec(metadata)?.[1]), sizes.get(filename));
  const sha512 = await hash(join(folder, filename), 'sha512', 'base64');
  assert.equal(/^sha512: ([a-z0-9+/=]+)\r?$/im.exec(metadata)?.[1], sha512);
  assert.equal(/^    sha512: ([a-z0-9+/=]+)\r?$/im.exec(metadata)?.[1], sha512);
  const map = JSON.parse(gunzipSync(await readFile(join(folder, filename + '.blockmap'))));
  return { filename, folder, map, metadata, sha512, size: sizes.get(filename), mapBytes: sizes.get(filename + '.blockmap'), version };
}

async function qualify([baseline, candidate, destination, baselineSource, candidateSource, iteration]) {
  assert.match(iteration ?? '', /^[1-9][0-9]{0,3}$/);
  const [old, next] = await Promise.all([verifiedCandidate(baseline, baselineSource, process.env.BASELINE_TOOLING), verifiedCandidate(candidate, candidateSource, process.env.CANDIDATE_TOOLING)]);
  const order = next.version.split('.').findIndex((part, index) => Number(part) !== Number(old.version.split('.')[index]));
  assert.ok(order >= 0 && Number(next.version.split('.')[order]) > Number(old.version.split('.')[order]), 'DEV version must advance');
  const plan = planTransfer(old.map, next.map, old.size, next.size);
  const { fetched, sha512 } = await verifyTransfer(join(old.folder, old.filename), join(next.folder, next.filename), plan);
  assert.equal(sha512, next.sha512, 'Reconstructed installer must match the exact qualified bytes');
  const metadataBytes = Buffer.byteLength(next.metadata) + old.mapBytes + next.mapBytes;
  assert.ok(fetched + metadataBytes <= maximumTransferBytes, 'Differential transfer exceeds the Windows DEV budget');
  const report = {
    tag: 'v' + next.version + '-beta.' + iteration,
    source: candidateSource, baseline: old.version, baselineSource,
    version: next.version, changedBlockBytes: fetched, metadataBytes, fallbackBytes: next.size, sha512,
    cachedPreviousInstallerRequired: true, localInstallWritesMeasured: false,
  };
  if (destination !== '-') {
    await mkdir(destination);
    await copyFile(join(next.folder, next.filename), join(destination, next.filename));
    for (const release of [old, next]) {
      const map = release.filename + '.blockmap';
      await copyFile(join(release.folder, map), join(destination, map));
    }
    await writeFile(join(destination, 'beta.yml'), next.metadata, { flag: 'wx' });
    await writeFile(join(destination, 'dev-qualification.json'), JSON.stringify(report, null, 2) + '\n', { flag: 'wx' });
  }
  console.log(JSON.stringify(report));
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  await qualify(process.argv.slice(2));
}
