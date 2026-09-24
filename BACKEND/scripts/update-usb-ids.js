const fs = require('node:fs/promises');
const path = require('node:path');

const source = 'https://usb-ids.gowdy.us/usb.ids';
const target = path.join(__dirname, '..', 'usb.ids');
const chunkSize = 64 * 1024;

async function main() {
  const head = await fetch(source, { method: 'HEAD' });
  if (!head.ok) throw new Error(`USB ID source returned HTTP ${head.status}`);
  const length = Number(head.headers.get('content-length'));
  if (!Number.isSafeInteger(length) || length < 1000) throw new Error('USB ID source did not provide a valid content length.');

  const chunks = [];
  for (let start = 0; start < length; start += chunkSize) {
    const end = Math.min(start + chunkSize, length) - 1;
    const response = await fetch(source, { headers: { Range: `bytes=${start}-${end}` } });
    const expectedRange = `bytes ${start}-${end}/${length}`;
    if (response.status !== 206 || response.headers.get('content-range') !== expectedRange) {
      throw new Error(`Unexpected range response for ${expectedRange}.`);
    }
    const chunk = Buffer.from(await response.arrayBuffer());
    if (chunk.length !== end - start + 1) throw new Error(`Incomplete USB ID data at byte ${start}.`);
    chunks.push(chunk);
  }

  const data = Buffer.concat(chunks);
  const text = data.toString('utf8');
  if (data.length !== length || !text.startsWith('#') || !text.includes('# Version:') || !text.endsWith('\n')) {
    throw new Error('Downloaded USB ID snapshot failed integrity checks.');
  }
  const temporary = `${target}.tmp`;
  await fs.writeFile(temporary, data);
  await fs.rename(temporary, target);
  console.log(`Updated ${path.basename(target)} (${length} bytes; ${text.match(/^# Version:.*$/m)?.[0] || 'version unknown'}).`);
}

main().catch((error) => {
  console.error(`USB ID update failed: ${error.message}`);
  process.exitCode = 1;
});
