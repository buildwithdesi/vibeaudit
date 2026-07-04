/**
 * "Second fifty" additions: the checklist gaps surfaced by mapping vibe-audit against
 * the extended vibe-coding threat list — command injection, unsafe deserialization, and
 * the missing-error-monitoring nudge. Each locks fire + zero-false-positive directions.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { commandInjection } from '../../src/rules/command-injection.js';
import { unsafeDeserialization } from '../../src/rules/unsafe-deserialization.js';
import { noErrorMonitoring } from '../../src/rules/no-error-monitoring.js';
import { unpinnedDependencies } from '../../src/rules/unpinned-dependencies.js';
import { missingSri } from '../../src/rules/missing-sri.js';
import { templateInjection } from '../../src/rules/template-injection.js';

function mk(relativePath, content) {
  return { path: `/project/${relativePath}`, relativePath, content, lines: content.split('\n') };
}
const fires = (rule, path, src) => rule.check(mk(path, src)).length > 0;
const clean = (rule, path, src) => rule.check(mk(path, src)).length === 0;

// ─── command-injection ────────────────────────────────────────────────────────
describe('command-injection', () => {
  it('flags exec/spawn commands built from interpolation or concatenation', () => {
    assert.ok(fires(commandInjection, 'api/run.js', 'exec(`git clone ${repo}`);'));
    assert.ok(fires(commandInjection, 'api/run.js', "execSync('rm -rf ' + userPath);"));
    assert.ok(fires(commandInjection, 'api/run.js', 'spawn(`node ${scriptName}`);'));
  });
  it('does NOT flag a static command, an arg array, or a bare variable', () => {
    assert.ok(clean(commandInjection, 'api/run.js', "exec('ls -la');"));
    assert.ok(clean(commandInjection, 'api/run.js', "execFile('git', ['clone', repo]);"));
    assert.ok(clean(commandInjection, 'api/run.js', "spawn('ls', [dir]);"));
    assert.ok(clean(commandInjection, 'api/run.js', 'execSync(cmd);')); // bare var — conservative, no FP
  });
});

// ─── unsafe-deserialization ───────────────────────────────────────────────────
describe('unsafe-deserialization', () => {
  it('flags node-serialize unserialize() and vm.runIn*', () => {
    assert.ok(fires(unsafeDeserialization, 'api/x.js', 'const obj = unserialize(payload);'));
    assert.ok(fires(unsafeDeserialization, 'api/x.js', 'vm.runInNewContext(userCode);'));
  });
  it('does NOT flag JSON.parse or yaml.load', () => {
    assert.ok(clean(unsafeDeserialization, 'api/x.js', 'const data = JSON.parse(body);'));
    assert.ok(clean(unsafeDeserialization, 'api/x.js', 'const cfg = yaml.load(fileContents);'));
  });
});

// ─── no-error-monitoring ──────────────────────────────────────────────────────
describe('no-error-monitoring', () => {
  it('flags a web app package.json with no monitoring dependency', () => {
    assert.ok(fires(noErrorMonitoring, 'package.json',
      JSON.stringify({ dependencies: { next: '14.0.0', react: '18.0.0' } })));
  });
  it('does NOT flag when a monitor is present', () => {
    assert.ok(clean(noErrorMonitoring, 'package.json',
      JSON.stringify({ dependencies: { next: '14.0.0', '@sentry/nextjs': '7.0.0' } })));
  });
  it('does NOT flag CLIs/libraries (no web framework) or non-package.json files', () => {
    assert.ok(clean(noErrorMonitoring, 'package.json',
      JSON.stringify({ dependencies: { acorn: '8.0.0' } })));
    assert.ok(clean(noErrorMonitoring, 'src/app.js', 'export const x = 1;'));
  });
});

// ─── unpinned-dependencies ────────────────────────────────────────────────────
describe('unpinned-dependencies', () => {
  it('flags deps pinned to * / latest', () => {
    assert.ok(fires(unpinnedDependencies, 'package.json',
      JSON.stringify({ dependencies: { react: 'latest' } }, null, 2)));
    assert.ok(fires(unpinnedDependencies, 'package.json',
      JSON.stringify({ dependencies: { lodash: '*' } }, null, 2)));
  });
  it('does NOT flag caret/tilde/exact pins or non-package.json', () => {
    assert.ok(clean(unpinnedDependencies, 'package.json',
      JSON.stringify({ dependencies: { react: '^18.0.0', lodash: '~4.17.0', next: '14.0.0' } }, null, 2)));
    assert.ok(clean(unpinnedDependencies, 'src/app.js', 'const react = "latest";'));
  });
});

// ─── missing-sri ──────────────────────────────────────────────────────────────
describe('missing-sri', () => {
  it('flags external CDN script/stylesheet with no integrity', () => {
    assert.ok(fires(missingSri, 'public/index.html', '<script src="https://cdn.jsdelivr.net/npm/lib.js"></script>'));
    assert.ok(fires(missingSri, 'public/index.html', '<link rel="stylesheet" href="https://cdn.example.com/s.css">'));
  });
  it('does NOT flag SRI-protected, relative, or non-stylesheet links', () => {
    assert.ok(clean(missingSri, 'public/index.html',
      '<script src="https://cdn/lib.js" integrity="sha384-abc" crossorigin="anonymous"></script>'));
    assert.ok(clean(missingSri, 'public/index.html', '<script src="/local/app.js"></script>'));
    assert.ok(clean(missingSri, 'public/index.html', '<link rel="preconnect" href="https://fonts.gstatic.com">'));
  });
});

// ─── template-injection ───────────────────────────────────────────────────────
describe('template-injection', () => {
  it('flags a template compiled from dynamic input', () => {
    assert.ok(fires(templateInjection, 'api/mail.js', 'Handlebars.compile(`<h1>${userInput}</h1>`);'));
    assert.ok(fires(templateInjection, 'api/mail.js', "ejs.render('Hello ' + name);"));
  });
  it('does NOT flag a static template or a non-engine .compile()', () => {
    assert.ok(clean(templateInjection, 'api/mail.js', "Handlebars.compile('<h1>{{name}}</h1>');"));
    assert.ok(clean(templateInjection, 'api/mail.js', 'myThing.compile(userInput);'));
  });
});
