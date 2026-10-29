import { readFileSync } from 'node:fs';

const contents = readFileSync('/input/notes.txt', 'utf8');
const items = contents.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);

if (items.length === 0) {
  throw new Error('The selected notes file has no nonempty lines.');
}

const wordCount = items.reduce((count, line) => count + line.split(/\s+/).length, 0);

console.log(JSON.stringify({
  title: 'Protection pilot notes',
  lineCount: items.length,
  wordCount,
  items,
}));
