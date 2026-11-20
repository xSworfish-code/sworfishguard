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
const crypto = require('node:crypto');
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
  for (const tag of scripts) assert.match(tag, /src="js\/(vendor\/)?[A-Za-z0-9-]+\.js"/, 'external local script: ' + tag);
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

test('the bundled QR library is exactly the reviewed jsQR 1.4.0 file', () => {
  // If this fails, someone changed the third-party code: review it before updating the hash.
  const buf = fs.readFileSync(path.join(jsDir, 'vendor', 'jsQR.js'));
  assert.equal(crypto.createHash('sha256').update(buf).digest('hex'), 'bc40c8a15196236b2314db0856f72ca0b49980cd5413b8c852a7349f5fee0859');
  const src = buf.toString('utf8');
  for (const re of [/innerHTML/, /\beval\s*\(/, /new\s+Function/, /XMLHttpRequest|fetch\s*\(/, /Math\.random/]) assert.ok(!re.test(src), 'jsQR matches ' + re);
  assert.ok(fs.existsSync(path.join(jsDir, 'vendor', 'jsQR-LICENSE.txt')), 'license kept next to it');
});

test('the service worker is safe and only caches files that exist', () => {
  const sw = fs.readFileSync(path.join(root, 'sw.js'), 'utf8');
  assert.match(sw, /origin !== self\.location\.origin\) return/, 'never touches other sites (breach API)');
  const files = [...sw.matchAll(/'([^']+\.(?:html|css|js|woff2|svg|png|webmanifest))'/g)].map((m) => m[1]);
  assert.ok(files.length > 20);
  for (const f of files) assert.ok(fs.existsSync(path.join(root, f)), 'missing ' + f);
  for (const f of jsFiles) assert.ok(files.includes('js/' + f), 'sw.js does not cache js/' + f);
  const csp = html.match(/http-equiv="Content-Security-Policy" content="([^"]+)"/)[1];
  assert.match(csp, /trusted-types sg-sw;/, 'one Trusted Types policy, only for the service worker');
  const app = fs.readFileSync(path.join(jsDir, 'app.js'), 'utf8');
  assert.match(app, /createScriptURL: function \(u\) \{ if \(u === 'sw\.js'\) return u; throw/);
});

test('links opened from the page never leak the opener', () => {
  for (const a of html.match(/<a\b[^>]*target="_blank"[^>]*>/g) || []) assert.match(a, /rel="noopener noreferrer"/, a);
});
