import { cp, mkdir, readdir, rm } from 'node:fs/promises';
import { join, resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const source = resolve(root, '..', 'web', 'dist');
const destination = resolve(root, 'worker', 'public');

await rm(destination, { recursive: true, force: true });
await mkdir(destination, { recursive: true });
await cp(source, destination, { recursive: true });
const orDir = resolve(destination, 'or');
for (const file of await readdir(orDir)) {
  if (file.endsWith('.jar')) await rm(join(orDir, file), { force: true });
}
