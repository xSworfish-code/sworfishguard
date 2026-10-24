/*
 * Security regression tests: they read the project's own source code and fail
 * if a dangerous pattern ever sneaks in (HTML injection sinks, eval, inline
 * scripts, third-party resources, a weakened Content Security Policy...).
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const html = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
const jsDir = path.join(root, 'js');
const jsFiles = fs.readdirSync(jsDir).filter((f) => f.endsWith('.js'));
const strip = (src) => src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1'); // remove comments

test('no JavaScript file uses HTML injection sinks or eval', () => {
  const banned = [/\.innerHTML\s*=/, /\.outerHTML\s*=/, /insertAdjacentHTML/, /document\.write/,
                  /\beval\s*\(/, /new\s+Function\s*\(/, /setTimeout\s*\(\s*['"`]/, /setInterval\s*\(\s*['"`]/];
  for (const file of jsFiles) {
    const src = strip(fs.readFileSync(path.join(jsDir, file), 'utf8'));
    for (const re of banned) assert.ok(!re.test(src), `${file} matches ${re}`);
  }
});

test('Math.random is never used for security (only crypto.getRandomValues)', () => {
  for (const file of jsFiles) {
    const src = strip(fs.readFileSync(path.join(jsDir, file), 'utf8'));
    assert.ok(!/Math\.random/.test(src), file);
  }
});

test('index.html has a strict Content Security Policy', () => {
  const m = html.match(/http-equiv="Content-Security-Policy" content="([^"]+)"/);
  assert.ok(m, 'CSP meta tag present');
  const csp = m[1];
  for (const directive of ["default-src 'none'", "object-src 'none'", "base-uri 'none'", "form-action 'none'",
                           "require-trusted-types-for 'script'", 'connect-src https://api.pwnedpasswords.com']) {
    assert.ok(csp.includes(directive), 'CSP includes ' + directive);
  }
  assert.ok(!/unsafe-inline|unsafe-eval|\*/.test(csp), 'CSP has no unsafe-inline, unsafe-eval or wildcards');
});

test('index.html has no inline scripts, inline styles or inline event handlers', () => {
  const scripts = html.match(/<script\b[^>]*>/g) || [];
  for (const tag of scripts) assert.match(tag, /src="js\/[a-z0-9-]+\.js"/, 'external local script: ' + tag);
  assert.ok(!/<script\b[^>]*>\s*\S/.test(html.replace(/<script\b[^>]*src=[^>]*><\/script>/g, '')), 'no inline <script> content');
  assert.ok(!/\sstyle="/.test(html), 'no style="" attributes');
  assert.ok(!/<style\b/.test(html), 'no <style> blocks');
  assert.ok(!/\son[a-z]+\s*=/.test(html), 'no onclick= / onload= handlers');
});

test('no third-party scripts, styles or fonts are loaded', () => {
  const urls = [...html.matchAll(/(?:src|href)="(https?:\/\/[^"]+)"/g)].map((m) => m[1]);
  for (const u of urls) {
    assert.ok(/^https:\/\/github\.com\/?$/.test(u), 'only the GitHub link may be external, found ' + u);
  }
  const css = fs.readFileSync(path.join(root, 'css', 'styles.css'), 'utf8');
  assert.ok(!/@import|https?:\/\//.test(css.replace(/\/\*[\s\S]*?\*\//g, '')), 'CSS loads nothing external');
});

test('external links never leak the opener or referrer', () => {
  const anchors = html.match(/<a\b[^>]*href="https?:\/\/[^"]*"[^>]*>/g) || [];
  for (const a of anchors) assert.match(a, /rel="[^"]*noopener[^"]*noreferrer|rel="[^"]*noreferrer[^"]*noopener/, a);
});

test('sensitive inputs do not autocomplete and have length limits', () => {
  const inputs = html.match(/<input\b[^>]*data-sensitive[^>]*>/g) || [];
  assert.ok(inputs.length >= 2);
  for (const i of inputs) {
    assert.match(i, /autocomplete="off"/, i);
    assert.match(i, /maxlength="\d+"/, i);
    assert.match(i, /type="password"/, i);
  }
});

test('both languages define exactly the same translation keys', () => {
  const { STRINGS } = require('../js/i18n.js');
  const es = Object.keys(STRINGS.es).sort();
  const en = Object.keys(STRINGS.en).sort();
  assert.deepEqual(es, en);
  // every data-i18n key used in the HTML exists
  const used = [...html.matchAll(/data-i18n(?:-placeholder|-aria)?="([^"]+)"/g)].map((m) => m[1]);
  for (const key of used) assert.ok(key in STRINGS.es, 'missing translation: ' + key);
});

test('glossary terms exist in both languages and both levels', () => {
  const terms = require('../js/glossary.js');
  assert.ok(terms.length >= 12);
  for (const t of terms) for (const lang of ['es', 'en']) for (const k of ['term', 'basic', 'expert']) {
    assert.ok(t[lang][k] && t[lang][k].length > 3, `${t.id}.${lang}.${k}`);
  }
});
