/**
 * Accessibility / WCAG rule pack (v1.2).
 *
 * Two directions, both enforced per rule:
 *   - MUST flag: the Level A violation an automated legal scanner would catch.
 *   - MUST NOT flag: accessible markup — including the JSX shapes that break naive
 *     /<tag[^>]*>/ regexes (arrow handlers with '>' before the labelling attribute).
 *
 * These are the zero-false-positive guards. If any "MUST NOT flag" case trips, the
 * rule is too aggressive to ship.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { a11yImgNoAlt } from '../../src/rules/a11y-img-no-alt.js';
import { a11yPositiveTabindex } from '../../src/rules/a11y-positive-tabindex.js';
import { a11yNoLang } from '../../src/rules/a11y-no-lang.js';
import { a11yButtonNoName } from '../../src/rules/a11y-button-no-name.js';
import { a11yFormNoLabel } from '../../src/rules/a11y-form-no-label.js';
import { a11yClickNoKeyboard } from '../../src/rules/a11y-click-no-keyboard.js';

function mk(relativePath, content) {
  return { path: `/project/${relativePath}`, relativePath, content, lines: content.split('\n') };
}
const fires = (rule, path, src) => rule.check(mk(path, src)).length > 0;
const clean = (rule, path, src) => rule.check(mk(path, src)).length === 0;

// ─── a11y-img-no-alt ──────────────────────────────────────────────────────────
describe('a11y-img-no-alt', () => {
  it('flags <img>/<Image> with no alt', () => {
    assert.ok(fires(a11yImgNoAlt, 'src/Hero.jsx', '<img src="/logo.png" />'));
    assert.ok(fires(a11yImgNoAlt, 'src/Hero.tsx', '<Image src="/hero.png" width={800} height={600} />'));
  });
  it('does NOT flag images with alt (including decorative alt="")', () => {
    assert.ok(clean(a11yImgNoAlt, 'src/Hero.jsx', '<img src="/logo.png" alt="Company logo" />'));
    assert.ok(clean(a11yImgNoAlt, 'src/Hero.jsx', '<img src="/x.png" alt="" />'));
    assert.ok(clean(a11yImgNoAlt, 'src/Hero.jsx', '<img src="/x.png" aria-hidden="true" />'));
    assert.ok(clean(a11yImgNoAlt, 'src/Hero.jsx', '<img {...imgProps} />'));
  });
  it('does NOT flag alt that comes AFTER an arrow handler with > (openingTag robustness)', () => {
    assert.ok(clean(a11yImgNoAlt, 'src/A.tsx', '<img src="/a.png" onError={() => setBroken(true)} alt="Avatar" />'));
  });
  it('does NOT flag non-markup files or SVG <image>', () => {
    assert.ok(clean(a11yImgNoAlt, 'src/util.js', 'const s = "<img src=x>";'));
    assert.ok(clean(a11yImgNoAlt, 'src/Icon.jsx', '<image href="/x.png" />'));
  });
});

// ─── a11y-positive-tabindex ───────────────────────────────────────────────────
describe('a11y-positive-tabindex', () => {
  it('flags positive tabindex', () => {
    assert.ok(fires(a11yPositiveTabindex, 'src/A.tsx', '<div tabIndex={5}>x</div>'));
    assert.ok(fires(a11yPositiveTabindex, 'src/B.html', '<button tabindex="3">Go</button>'));
  });
  it('does NOT flag tabindex 0 or -1', () => {
    assert.ok(clean(a11yPositiveTabindex, 'src/A.tsx', '<div tabIndex={0}>x</div>'));
    assert.ok(clean(a11yPositiveTabindex, 'src/A.tsx', '<div tabIndex={-1}>x</div>'));
    assert.ok(clean(a11yPositiveTabindex, 'src/B.html', '<div tabindex="0">x</div>'));
  });
});

// ─── a11y-no-lang ─────────────────────────────────────────────────────────────
describe('a11y-no-lang', () => {
  it('flags <html> with no lang', () => {
    assert.ok(fires(a11yNoLang, 'index.html', '<!doctype html><html><head></head><body></body></html>'));
  });
  it('does NOT flag <html lang> or spread', () => {
    assert.ok(clean(a11yNoLang, 'index.html', '<html lang="en"><head></head></html>'));
    assert.ok(clean(a11yNoLang, 'app/layout.tsx', '<html {...htmlProps}><body>{children}</body></html>'));
    assert.ok(clean(a11yNoLang, 'src/util.js', 'const s = "<html>"'));
  });
});

// ─── a11y-button-no-name ──────────────────────────────────────────────────────
describe('a11y-button-no-name', () => {
  it('flags buttons with no accessible name (empty / icon-only)', () => {
    assert.ok(fires(a11yButtonNoName, 'src/A.tsx', '<button></button>'));
    assert.ok(fires(a11yButtonNoName, 'src/A.tsx', '<button className="close"><XIcon /></button>'));
    assert.ok(fires(a11yButtonNoName, 'src/A.tsx', '<button><svg viewBox="0 0 24 24"><path d="M0 0" /></svg></button>'));
  });
  it('does NOT flag named buttons', () => {
    assert.ok(clean(a11yButtonNoName, 'src/A.tsx', '<button>Save</button>'));
    assert.ok(clean(a11yButtonNoName, 'src/A.tsx', '<button>{label}</button>'));
    assert.ok(clean(a11yButtonNoName, 'src/A.tsx', '<button aria-label="Close"><XIcon /></button>'));
    assert.ok(clean(a11yButtonNoName, 'src/A.tsx', '<button title="Menu"><MenuIcon /></button>'));
  });
  it('does NOT flag aria-label that comes AFTER an arrow onClick with > (openingTag robustness)', () => {
    assert.ok(clean(a11yButtonNoName, 'src/A.tsx', '<button onClick={() => go()} aria-label="Next"><Arrow /></button>'));
  });
});

// ─── a11y-form-no-label ───────────────────────────────────────────────────────
describe('a11y-form-no-label', () => {
  it('flags controls with no labelling signal (placeholder is not a label)', () => {
    assert.ok(fires(a11yFormNoLabel, 'src/A.tsx', '<input type="text" placeholder="Search" />'));
    assert.ok(fires(a11yFormNoLabel, 'src/A.tsx', '<textarea placeholder="Message" />'));
  });
  it('does NOT flag labelled / exempt controls', () => {
    assert.ok(clean(a11yFormNoLabel, 'src/A.tsx', '<input type="text" id="email" />'));
    assert.ok(clean(a11yFormNoLabel, 'src/A.tsx', '<input type="text" aria-label="Search" />'));
    assert.ok(clean(a11yFormNoLabel, 'src/A.tsx', '<input type="hidden" value="x" />'));
    assert.ok(clean(a11yFormNoLabel, 'src/A.tsx', '<input type="submit" value="Go" />'));
    assert.ok(clean(a11yFormNoLabel, 'src/A.tsx', '<label>Email <input type="email" /></label>'));
    assert.ok(clean(a11yFormNoLabel, 'src/A.tsx', "<input {...register('email')} />"));
  });
  it('does NOT flag id that comes AFTER an arrow onChange with > (openingTag robustness)', () => {
    assert.ok(clean(a11yFormNoLabel, 'src/A.tsx', '<input onChange={() => set(qty > 0)} id="qty" />'));
  });
});

// ─── a11y-click-no-keyboard ───────────────────────────────────────────────────
describe('a11y-click-no-keyboard', () => {
  it('flags onClick on a non-interactive element', () => {
    assert.ok(fires(a11yClickNoKeyboard, 'src/A.tsx', '<div onClick={() => open()}>Menu</div>'));
    assert.ok(fires(a11yClickNoKeyboard, 'src/A.tsx', '<span onClick={handleClick}>Click</span>'));
  });
  it('does NOT flag a real <button>, or a div with role + keyboard support', () => {
    assert.ok(clean(a11yClickNoKeyboard, 'src/A.tsx', '<button onClick={() => open()}>Menu</button>'));
    assert.ok(clean(a11yClickNoKeyboard, 'src/A.tsx', '<div className="card">no handler</div>'));
    assert.ok(clean(a11yClickNoKeyboard, 'src/A.tsx', '<div {...clickProps}>x</div>'));
  });
  it('does NOT flag role/onKeyDown that come AFTER an arrow onClick with > (openingTag robustness)', () => {
    assert.ok(clean(a11yClickNoKeyboard, 'src/A.tsx', '<div onClick={() => go(a > b)} role="button" tabIndex={0} onKeyDown={onKey}>X</div>'));
  });
});

// ─── Whole-component zero-FP guard ────────────────────────────────────────────
describe('a11y pack: accessible component produces zero findings', () => {
  const rules = [a11yImgNoAlt, a11yPositiveTabindex, a11yNoLang, a11yButtonNoName, a11yFormNoLabel, a11yClickNoKeyboard];
  const accessible = mk(
    'src/SignupCard.tsx',
    `export function SignupCard({ onSubmit }) {
  return (
    <form onSubmit={onSubmit}>
      <img src="/logo.svg" alt="Digital Alchemy" />
      <label htmlFor="email">Email</label>
      <input id="email" type="email" onChange={(e) => set(e.target.value)} />
      <button type="submit" aria-label="Create account"><SpinnerIcon /></button>
      <div role="button" tabIndex={0} onClick={next} onKeyDown={onKey}>Skip</div>
    </form>
  );
}`,
  );
  it('flags nothing across all six rules', () => {
    for (const rule of rules) {
      assert.equal(rule.check(accessible).length, 0, `${rule.id} should not flag accessible markup`);
    }
  });
});
