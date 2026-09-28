#!/opt/node/bin/node
import fs from 'node:fs';
import { format } from 'prettier';

const args = process.argv.slice(2);
if (args.length === 1 && args[0] === '--help') {
  console.log('Usage: js-format INPUT.js > /work/readable.js\nParse and format inert JavaScript; never loads project configuration or executes input.');
} else {
  try {
    if (args.length !== 1) throw new Error('Usage: js-format INPUT.js > /work/readable.js');
    const stat = fs.statSync(args[0]);
    if (!stat.isFile() || stat.size > 16 * 1024 * 1024) throw new Error('Input must be a regular file of at most 16 MiB');
    // Explicit parser, no resolveConfig, project plugins, imports, or evaluation.
    process.stdout.write(await format(fs.readFileSync(args[0], 'utf8'), {
      parser: 'babel', embeddedLanguageFormatting: 'off',
    }));
  } catch (error) {
    console.error(`js-format: ${error.message}`);
    process.exitCode = 1;
  }
}
