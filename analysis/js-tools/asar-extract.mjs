#!/opt/node/bin/node
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { getRawHeader, extractFile } from '@electron/asar';

const usage = 'Usage: asar-extract ARCHIVE NEW_DIRECTORY\nExtract packed regular files with size/hash verification; JSON manifest on stdout.';
const args = process.argv.slice(2);
let staging;
try {
  if (args.length === 1 && args[0] === '--help') {
    console.log(usage);
  } else {
    if (args.length !== 2) throw new Error(usage);
    const [archive, destination] = args.map(p => path.resolve(p));
    const stat = fs.statSync(archive);
    if (!stat.isFile() || stat.size > 512 * 1024 * 1024) throw new Error('Archive must be a regular file of at most 512 MiB');
    if (fs.existsSync(destination)) throw new Error('Destination must not already exist');
    const { header, headerSize } = getRawHeader(archive);
    const files = [];
    const skipped = [];
    let total = 0;
    let entries = 0;
    function visit(directory, prefix = '', depth = 0) {
      if (depth > 64) throw new Error('Archive nesting exceeds 64 directories');
      for (const [name, entry] of Object.entries(directory.files)) {
        if (++entries > 10000) throw new Error('Archive exceeds 10000 entries');
        if (!name || name === '.' || name === '..' || /[/\\\0]/.test(name)) throw new Error('Invalid archive path');
        const member = prefix ? `${prefix}/${name}` : name;
        if ('link' in entry || entry.unpacked) {
          skipped.push({ path: member, reason: 'link' in entry ? 'symlink' : 'external_unpacked_entry' });
        } else if ('files' in entry) {
          visit(entry, member, depth + 1);
        } else {
          const offset = Number(entry.offset);
          total += entry.size;
          if (!Number.isSafeInteger(entry.size) || entry.size < 0 || entry.size > 64 * 1024 * 1024 || total > 512 * 1024 * 1024) throw new Error(`Extraction size limit: ${member}`);
          if (!Number.isSafeInteger(offset) || offset < 0 || 8 + headerSize + offset + entry.size > stat.size) throw new Error(`Truncated or invalid member: ${member}`);
          files.push({ path: member, entry });
        }
      }
    }
    visit(header);
    staging = fs.mkdtempSync(path.join(path.dirname(destination), '.jaq-asar-'));
    const manifest = [];
    for (const { path: member, entry } of files) {
      const content = extractFile(archive, member);
      if (content.length !== entry.size) throw new Error(`Size mismatch: ${member}`);
      const sha256 = createHash('sha256').update(content).digest('hex');
      const integrity = entry.integrity;
      if (integrity && (integrity.algorithm !== 'SHA256' || integrity.hash?.toLowerCase() !== sha256)) throw new Error(`Integrity mismatch or unsupported algorithm: ${member}`);
      const target = path.join(staging, member);
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, content, { flag: 'wx', mode: 0o600 });
      manifest.push({ path: member, size: content.length, sha256, integrity: integrity ? 'verified' : 'not_available' });
    }
    fs.renameSync(staging, destination);
    staging = undefined;
    console.log(JSON.stringify({ status: skipped.length ? 'partial' : 'complete', archive, destination, files: manifest, skipped }, null, 2));
  }
} catch (error) {
  if (staging) fs.rmSync(staging, { recursive: true, force: true });
  console.error(`asar-extract: ${error.message}`);
  process.exitCode = 1;
}
