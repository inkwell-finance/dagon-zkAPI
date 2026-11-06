import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';

const [binary, profilePath, mode] = process.argv.slice(2);
if (!binary || !profilePath || !['--check', '--pin', '--hash'].includes(mode)) throw new Error('expected BINARY PROFILE --check|--pin|--hash');
const data = await readFile(binary);
let end = data.length;
while (end > 0 && data[end - 1] === 0) end--;
const hash = createHash('sha256').update(data.subarray(0, end)).digest('hex');
const text = await readFile(profilePath, 'utf8');
const profile = JSON.parse(text);
if (mode === '--pin') {
  const old = `"executable_sha256": "${profile.program.executable_sha256}"`;
  if (!text.includes(old)) throw new Error('profile executable hash field is not canonical');
  await writeFile(profilePath, text.replace(old, `"executable_sha256": "${hash}"`));
} else if (mode === '--check' && hash !== profile.program.executable_sha256) {
  throw new Error(`executable hash ${hash} differs from profile ${profile.program.executable_sha256}; rebuild and repin with bash scripts/build-verifiable-program.sh --pin`);
}
console.log(hash);
