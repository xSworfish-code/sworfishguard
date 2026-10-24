/*!
 * SworfishGuard — UI wiring
 *
 * Security notes:
 *  - User input is only ever inserted with textContent / setAttribute (never
 *    innerHTML). The page's CSP also enforces Trusted Types, so the browser
 *    would block any accidental HTML injection.
 *  - Password fields are cleared after 5 minutes without activity and when
 *    the page is hidden from history (pagehide), so they are not restored
 *    by the back/forward cache.
 *
 * Author: Asaf Rojas (Sworfish Tech) — MIT License
 */
(function () {
  'use strict';

  var SG = window.SworfishGuard;
  var i18n = SG.i18n;
  var t = i18n.t;
  var $ = function (id) { return document.getElementById(id); };
  var PAGES = ['analyzer', 'breach', 'generator', 'phishing', 'scam', 'hash', 'checkup', 'glossary'];
  var AUTO_CLEAR_MS = 5 * 60 * 1000;

  var state = {
    mode: 'basic', page: 'analyzer',
    analysis: null, breach: null, breachError: null,
    genType: 'passphrase', generated: null,
    phishing: null, scam: null,
    hash: null, hashFile: null, hashError: null, hashBusy: false,
    checkup: {}, remember: false, glQuery: ''
  };

  // ------------------------------------------------------------ helpers
  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }
  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
  function num(n, digits) {
    return Number(n).toLocaleString(i18n.lang, { maximumFractionDigits: digits === undefined ? 1 : digits });
  }
  function bytes(n) {
    if (n < 1024) return num(n, 0) + ' B';
    if (n < 1048576) return num(n / 1024) + ' KB';
    return num(n / 1048576) + ' MB';
  }
  function duration(seconds) {
    var d = SG.password.formatDuration(seconds);
    if (d.value === 1) return t('dur.' + d.unit + '.one');
    return t('dur.' + d.unit, { n: d.value === null ? '' : num(d.value, 0) });
  }
  function setProps(dl, rows) {
    clear(dl);
    rows.forEach(function (r) {
      dl.appendChild(el('dt', '', r[0]));
      dl.appendChild(el('dd', '', r[1]));
    });
  }
  function setTable(table, rows) {
    var body = table.tBodies[0];
    clear(body);
    rows.forEach(function (cells) {
      var tr = el('tr');
      cells.forEach(function (c) { tr.appendChild(el('td', c.cls || '', c.text)); });
      body.appendChild(tr);
    });
  }
  var toastTimer;
  function toast(message) {
    var box = $('toast');
    box.textContent = message;
    box.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { box.hidden = true; }, 4000);
  }
  function store(key, value) { try { localStorage.setItem(key, value); } catch (e) { /* blocked: ignore */ } }
  function read(key) { try { return localStorage.getItem(key); } catch (e) { return null; } }

  // -------------------------------------------------------- translations
  function applyTranslations() {
    document.documentElement.lang = i18n.lang;
    document.title = t('meta.title');
    document.querySelectorAll('[data-i18n]').forEach(function (n) { n.textContent = t(n.dataset.i18n); });
    document.querySelectorAll('[data-i18n-placeholder]').forEach(function (n) { n.placeholder = t(n.dataset.i18nPlaceholder); });
    document.querySelectorAll('[data-i18n-aria]').forEach(function (n) { n.setAttribute('aria-label', t(n.dataset.i18nAria)); });
    document.querySelectorAll('[data-set-lang]').forEach(function (b) {
      b.setAttribute('aria-pressed', String(b.dataset.setLang === i18n.lang));
    });
    $('ph-x-desc').textContent = t('ph.x', { count: SG.data.BRANDS.length });
    renderAll();
  }
  function renderAll() {
    renderAnalysis(); renderBreach(); renderGenerated(); renderPhishing();
    renderScam(); renderHash(); renderCheckup(); renderGlossary();
  }
  document.querySelectorAll('[data-set-lang]').forEach(function (b) {
    b.addEventListener('click', function () { i18n.setLang(b.dataset.setLang); applyTranslations(); });
  });

  // --------------------------------------------------------------- mode
  function setMode(mode) {
    state.mode = mode === 'expert' ? 'expert' : 'basic';
    document.body.dataset.mode = state.mode;
    document.querySelectorAll('[data-set-mode]').forEach(function (b) {
      b.setAttribute('aria-pressed', String(b.dataset.setMode === state.mode));
    });
    document.querySelectorAll('details[data-expert]').forEach(function (d) { d.open = state.mode === 'expert'; });
    store('sg-mode', state.mode);
  }
  document.querySelectorAll('[data-set-mode]').forEach(function (b) {
    b.addEventListener('click', function () { setMode(b.dataset.setMode); });
  });

  // -------------------------------------------------------------- pages
  var navItems = Array.prototype.slice.call(document.querySelectorAll('.nav-item'));

  function showPage(id, opts) {
    if (PAGES.indexOf(id) === -1) id = 'analyzer';
    state.page = id;
    navItems.forEach(function (b) {
      if (b.dataset.page === id) b.setAttribute('aria-current', 'page');
      else b.removeAttribute('aria-current');
    });
    document.querySelectorAll('.page').forEach(function (p) { p.hidden = p.dataset.pageId !== id; });
    if (!(opts && opts.keepHash)) { try { history.replaceState(null, '', '#' + id); } catch (e) { /* ignore */ } }
    if (opts && opts.scroll) $('workspace').scrollIntoView({ block: 'start' });
    if (opts && opts.focus) {
      var first = $('page-' + id).querySelector('input:not(.visually-hidden), textarea, select, button');
      if (first) first.focus({ preventScroll: true });
    }
  }

  navItems.forEach(function (b, idx) {
    b.addEventListener('click', function () { showPage(b.dataset.page); });
    b.addEventListener('keydown', function (e) {
      var next = null;
      if (e.key === 'ArrowDown' || e.key === 'ArrowRight') next = navItems[(idx + 1) % navItems.length];
      if (e.key === 'ArrowUp' || e.key === 'ArrowLeft') next = navItems[(idx - 1 + navItems.length) % navItems.length];
      if (next) { e.preventDefault(); next.focus(); showPage(next.dataset.page); }
    });
  });
  document.querySelectorAll('[data-goto]').forEach(function (a) {
    a.addEventListener('click', function (e) {
      e.preventDefault();
      showPage(a.dataset.goto, { scroll: true, focus: true });
    });
  });

  // Show/hide and clear buttons
  document.querySelectorAll('[data-toggle-visibility]').forEach(function (btn) {
    btn.setAttribute('aria-pressed', 'false');
    btn.addEventListener('click', function () {
      var input = $(btn.dataset.toggleVisibility);
      var show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      btn.setAttribute('aria-pressed', String(show));
    });
  });
  document.querySelectorAll('[data-clear]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var input = $(btn.dataset.clear);
      input.value = '';
      input.dispatchEvent(new Event('input'));
      input.focus();
    });
  });

  // ----------------------------------------------------------- analyzer
  var anInput = $('an-input');
  anInput.addEventListener('input', function () {
    state.analysis = anInput.value ? SG.password.analyzePassword(anInput.value) : null;
    renderAnalysis();
  });

  function renderAnalysis() {
    var r = state.analysis;
    $('an-empty').hidden = !!r;
    $('an-results').hidden = !r;
    $('an-meter').dataset.score = r ? String(r.score) : '-1';
    $('an-score').textContent = r ? t('score.' + r.score) : '';
    if (!r) return;

    $('an-entropy').textContent = num(r.entropy);
    $('an-length').textContent = String(r.length);
    $('an-online').textContent = duration(r.crackTimes.online);
    $('an-offline').textContent = duration(r.crackTimes.offline);

    var classes = $('an-classes');
    clear(classes);
    ['lower', 'upper', 'digit', 'symbol', 'unicode'].forEach(function (k) {
      if (k === 'unicode' && !r.classes.unicode) return;
      classes.appendChild(el('span', 'tag ' + (r.classes[k] ? 'green' : 'off'), t('cls.' + k)));
    });

    var pats = $('an-patterns');
    clear(pats);
    if (!r.patterns.length) pats.appendChild(el('li', 'muted', t('an.noPatterns')));
    r.patterns.forEach(function (p) {
      var li = el('li');
      li.appendChild(el('span', 'tag ' + (p.type === 'common' ? 'red' : 'orange'), t('pat.' + p.type)));
      li.appendChild(el('code', 'row-main', p.token));
      pats.appendChild(li);
    });

    var fb = $('an-feedback');
    clear(fb);
    r.feedback.forEach(function (key) { fb.appendChild(el('li', key === 'excellent' ? 'done' : '', t('fb.' + key))); });

    var b = r.breakdown || {};
    setProps($('an-x-props'), [
      [t('an.x.pool'), String(r.poolSize)],
      [t('an.x.perChar'), num(b.bitsPerChar, 2)],
      [t('an.x.random'), String(b.randomChars) + ' × ' + num(b.bitsPerChar, 2) + ' = ' + num(b.randomBits) + ' bits'],
      [t('an.x.patternBits'), num(b.patternBits) + ' bits'],
      [t('an.entropy'), num(r.entropy) + ' bits'],
      [t('an.x.guesses'), '≈ 10^' + num(b.guessesLog10)]
    ]);
    setTable($('an-x-table'), r.patterns.map(function (p) {
      return [{ text: t('pat.' + p.type) }, { text: p.token, cls: 'mono' }, { text: num(p.bits) + ' bits', cls: 'num' }];
    }));
  }

  $('an-to-breach').addEventListener('click', function () {
    $('br-input').value = anInput.value;
    showPage('breach', { focus: false });
    $('br-form').requestSubmit();
  });

  // ------------------------------------------------------------- breach
  var breachBusy = false;
  $('br-form').addEventListener('submit', function (e) {
    e.preventDefault();
    var pw = $('br-input').value;
    if (!pw || breachBusy) return;
    breachBusy = true;
    var btn = $('br-button');
    btn.disabled = true;
    btn.textContent = t('br.checking');
    state.breach = null;
    state.breachError = null;
    SG.breach.checkPassword(pw)
      .then(function (res) { state.breach = res; })
      .catch(function (err) { state.breachError = err && err.message === 'timeout' ? 'timeout' : 'error'; })
      .then(function () {
        breachBusy = false;
        btn.disabled = false;
        renderBreach();
      });
  });

  function renderBreach() {
    var box = $('br-result');
    var r = state.breach;
    if (!breachBusy) $('br-button').textContent = t('br.button');
    clear(box);
    box.className = 'result';
    $('br-hash').hidden = !r;
    if (state.breachError) {
      box.hidden = false;
      box.classList.add('warn');
      box.appendChild(el('strong', '', t(state.breachError === 'timeout' ? 'br.timeout' : 'br.error')));
      return;
    }
    if (!r) { box.hidden = true; setProps($('br-x-props'), []); return; }
    box.hidden = false;
    box.classList.add(r.found ? 'bad' : 'good');
    box.appendChild(el('strong', '', r.found ? t('br.found', { n: num(r.count, 0) }) : t('br.safe')));
    box.appendChild(el('p', '', t(r.found ? 'br.foundHint' : 'br.safeHint')));
    $('br-prefix').textContent = r.prefix;
    $('br-suffix').textContent = r.suffix;
    setProps($('br-x-props'), [
      [t('br.x.url'), 'GET ' + r.stats.url],
      [t('br.x.lines'), num(r.stats.lines - r.stats.padding, 0)],
      [t('br.x.padding'), num(r.stats.padding, 0) + (r.stats.padded ? '' : ' (no padding)')],
      [t('br.x.bytes'), bytes(r.stats.bytes)],
      [t('br.x.ms'), num(r.stats.ms, 0) + ' ms']
    ]);
  }

  // ---------------------------------------------------------- generator
  function setGenType(type) {
    state.genType = type === 'password' ? 'password' : 'passphrase';
    document.querySelectorAll('[data-gen-type]').forEach(function (b) {
      b.setAttribute('aria-checked', String(b.dataset.genType === state.genType));
    });
    $('gen-pp-opts').hidden = state.genType !== 'passphrase';
    $('gen-pw-opts').hidden = state.genType !== 'password';
    generate();
  }
  document.querySelectorAll('[data-gen-type]').forEach(function (b) {
    b.addEventListener('click', function () { setGenType(b.dataset.genType); });
  });

  function generate() {
    $('gen-length-value').textContent = $('gen-length').value;
    $('gen-words-value').textContent = $('gen-words').value;
    try {
      state.generated = state.genType === 'passphrase'
        ? SG.generator.generatePassphrase({
            words: +$('gen-words').value, separator: $('gen-sep').value,
            capitalize: $('gen-cap').checked, addNumber: $('gen-num').checked, lang: i18n.lang })
        : SG.generator.generatePassword({
            length: +$('gen-length').value, lower: $('gen-lower').checked, upper: $('gen-upper').checked,
            digits: $('gen-digits').checked, symbols: $('gen-symbols').checked,
            excludeAmbiguous: $('gen-ambiguous').checked });
    } catch (err) {
      state.generated = { error: true };
    }
    renderGenerated();
  }

  function renderGenerated() {
    var g = state.generated;
    if (!g) return;
    $('gen-copy').textContent = t('gen.copy');
    $('gen-output').textContent = g.error ? '—' : g.password;
    var score = g.error ? -1 : g.entropy < 40 ? 1 : g.entropy < 60 ? 2 : g.entropy < 80 ? 3 : 4;
    $('gen-meter').dataset.score = String(score);
    $('gen-meta').textContent = g.error ? t('gen.needOne')
      : t('score.' + score) + ', ' + t('gen.strength', { bits: num(g.entropy) });
    if (!g.error) {
      setProps($('gen-x-props'), [
        [t('gen.x.pool'), String(g.poolSize)],
        [t('an.entropy'), num(g.entropy) + ' bits'],
        [t('an.offline'), duration(SG.password.crackTimes(g.entropy).offline)]
      ]);
    }
  }

  ['gen-length', 'gen-lower', 'gen-upper', 'gen-digits', 'gen-symbols', 'gen-ambiguous',
   'gen-words', 'gen-sep', 'gen-cap', 'gen-num'].forEach(function (id) { $(id).addEventListener('input', generate); });
  $('gen-new').addEventListener('click', generate);

  $('gen-copy').addEventListener('click', function () {
    var g = state.generated;
    if (!g || g.error) return;
    var btn = $('gen-copy');
    var done = function () {
      btn.textContent = t('gen.copied');
      setTimeout(function () { btn.textContent = t('gen.copy'); }, 1500);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(g.password).then(done, function () { selectText($('gen-output')); });
    } else {
      selectText($('gen-output'));
    }
  });
  function selectText(node) {
    var range = document.createRange();
    range.selectNodeContents(node);
    var sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
  }
  $('gen-analyze').addEventListener('click', function () {
    var g = state.generated;
    if (!g || g.error) return;
    anInput.value = g.password;
    anInput.dispatchEvent(new Event('input'));
    showPage('analyzer');
  });

  // ----------------------------------------------------------- phishing
  $('ph-form').addEventListener('submit', function (e) {
    e.preventDefault();
    var v = $('ph-input').value;
    state.phishing = v.trim() ? SG.phishing.analyzeUrl(v) : null;
    renderPhishing();
  });

  function renderFindings(list, findings, prefix, emptyKey) {
    clear(list);
    if (!findings.length) list.appendChild(el('li', 'muted', t(emptyKey)));
    findings.forEach(function (f) {
      var li = el('li');
      li.appendChild(el('span', 'tag ' + f.severity, t('sev.' + f.severity)));
      li.appendChild(el('span', 'row-main', t(prefix + f.id, { d: f.detail })));
      list.appendChild(li);
    });
  }

  function renderVerdict(prefix, keyPrefix, r) {
    var level = r.official ? 'official' : r.level;
    $(prefix + '-verdict').dataset.level = level;
    $(prefix + '-level').textContent = t(keyPrefix + '.level.' + level);
    var brand = r.findings && r.findings.filter(function (f) { return f.id === 'officialDomain'; })[0];
    $(prefix + '-hint').textContent = t(keyPrefix + '.levelHint.' + level, { brand: brand ? brand.detail : '' });
    $(prefix + '-score').textContent = r.score + '/100';
  }

  function renderPhishing() {
    var r = state.phishing;
    $('ph-result').hidden = !r;
    if (!r) return;
    if (!r.valid) {
      $('ph-verdict').dataset.level = 'medium';
      $('ph-level').textContent = t(r.error === 'tooLong' ? 'ph.tooLong' : 'ph.invalid');
      $('ph-hint').textContent = '';
      $('ph-score').textContent = '';
      $('ph-real').hidden = true;
      clear($('ph-findings'));
      return;
    }
    renderVerdict('ph', 'ph', r);
    $('ph-real').hidden = !r.registeredDomain;
    $('ph-real-domain').textContent = r.registeredDomain;
    renderFindings($('ph-findings'), r.findings, 'f.', 'ph.noFindings');

    var d = r.details || {};
    var rows = [[t('ph.x.scheme'), r.scheme || '—'], [t('ph.x.host'), r.host || '—']];
    if (r.unicodeHost && r.unicodeHost !== r.host) rows.push([t('ph.x.unicode'), r.unicodeHost]);
    rows.push([t('ph.x.domain'), r.registeredDomain || '—'],
      [t('ph.x.sub'), d.subdomains && d.subdomains.length ? d.subdomains.join(' . ') : '—'],
      [t('ph.x.tld'), d.tld ? '.' + d.tld : '—'], [t('ph.x.port'), d.port || '—'],
      [t('ph.x.path'), r.path || '/']);
    setProps($('ph-x-props'), rows);
    setTable($('ph-x-breakdown'), (r.breakdown || []).map(function (b) {
      return [{ text: b.id, cls: 'mono' }, { text: '+' + b.points, cls: 'num' }];
    }).concat([[{ text: t('common.score') }, { text: r.score + '/100', cls: 'num' }]]));
  }

  // --------------------------------------------------------------- scam
  $('sc-form').addEventListener('submit', function (e) {
    e.preventDefault();
    var v = $('sc-input').value;
    state.scam = v.trim() ? SG.scam.analyzeMessage(v) : null;
    renderScam();
  });

  function renderScam() {
    var r = state.scam;
    $('sc-result').hidden = !r || !r.valid;
    if (!r || !r.valid) return;
    renderVerdict('sc', 'sc', r);
    $('sc-truncated').hidden = !r.truncated;
    renderFindings($('sc-findings'), r.findings, 'sf.', 'sc.noFindings');
    var links = $('sc-links');
    clear(links);
    if (!r.links.length) links.appendChild(el('li', 'muted', t('sc.noLinks')));
    r.links.forEach(function (l) {
      var li = el('li');
      var lvl = l.official ? 'official' : l.level;
      li.appendChild(el('span', 'tag ' + (lvl === 'high' ? 'critical' : lvl === 'medium' ? 'medium' : 'green'), t('ph.level.' + lvl)));
      li.appendChild(el('code', 'row-main', l.url));
      if (l.registeredDomain) li.appendChild(el('span', 'row-side', l.registeredDomain));
      links.appendChild(li);
    });
    setTable($('sc-x-breakdown'), r.breakdown.map(function (b) {
      return [{ text: b.id, cls: 'mono' }, { text: '+' + b.points, cls: 'num' }];
    }).concat([[{ text: t('common.score') }, { text: r.score + '/100', cls: 'num' }]]));
  }

  // Example chips
  document.querySelectorAll('[data-example]').forEach(function (b) {
    b.addEventListener('click', function () {
      if (b.dataset.example === 'ph') {
        $('ph-input').value = b.dataset.value;
        $('ph-form').requestSubmit();
      } else {
        $('sc-input').value = t('sc.ex.' + b.dataset.key + '.text');
        $('sc-form').requestSubmit();
      }
    });
  });

  // ---------------------------------------------------------- file hash
  var drop = $('fh-drop');
  $('fh-file').addEventListener('change', function () {
    if (this.files && this.files[0]) hashFile(this.files[0]);
    this.value = '';
  });
  ['dragenter', 'dragover'].forEach(function (ev) {
    drop.addEventListener(ev, function (e) { e.preventDefault(); drop.classList.add('dragover'); });
  });
  ['dragleave', 'drop'].forEach(function (ev) {
    drop.addEventListener(ev, function () { drop.classList.remove('dragover'); });
  });
  drop.addEventListener('drop', function (e) {
    e.preventDefault();
    var f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
    if (f) hashFile(f);
  });
  // Prevent the browser from opening files dropped anywhere else on the page.
  window.addEventListener('dragover', function (e) { e.preventDefault(); });
  window.addEventListener('drop', function (e) { e.preventDefault(); });
  $('fh-expected').addEventListener('input', renderHash);

  function hashFile(file) {
    state.hashFile = { name: file.name, size: file.size, type: file.type };
    state.hash = null;
    state.hashError = null;
    state.hashBusy = true;
    renderHash();
    SG.fileHash.hashData(file)
      .then(function (res) { state.hash = res; })
      .catch(function (err) { state.hashError = err && err.message === 'tooLarge' ? 'tooLarge' : 'error'; })
      .then(function () { state.hashBusy = false; renderHash(); });
  }

  function renderHash() {
    var status = $('fh-status');
    var cmp = $('fh-compare');
    status.textContent = state.hashBusy ? t('fh.computing') : state.hashError ? t('fh.' + state.hashError) : '';
    $('fh-result').hidden = !state.hash;
    clear(cmp);
    cmp.className = 'result';
    cmp.hidden = true;
    if (!state.hash) return;

    setProps($('fh-props'), [[t('fh.file'), state.hashFile.name], [t('fh.size'), bytes(state.hashFile.size)]]);
    var list = $('fh-hashes');
    clear(list);
    SG.fileHash.ALGORITHMS.forEach(function (alg) {
      var li = el('li', alg === 'SHA-256' ? '' : 'x-only');
      li.appendChild(el('span', 'alg', alg));
      li.appendChild(el('code', '', state.hash.hashes[alg]));
      var copy = el('button', 'btn-ghost', t('fh.copy'));
      copy.type = 'button';
      copy.addEventListener('click', function () {
        if (navigator.clipboard) navigator.clipboard.writeText(state.hash.hashes[alg]).then(function () { toast(t('gen.copied')); }, function () {});
      });
      li.appendChild(copy);
      list.appendChild(li);
    });
    setProps($('fh-x-props'), [[t('fh.x.ms'), num(state.hash.ms, 0) + ' ms'], ['MIME', state.hashFile.type || '—']]);

    var c = SG.fileHash.compare(state.hash.hashes, $('fh-expected').value);
    if (c.status === 'empty') return;
    cmp.hidden = false;
    if (c.status === 'match') { cmp.classList.add('good'); cmp.appendChild(el('strong', '', t('fh.match'))); }
    else if (c.status === 'mismatch') { cmp.classList.add('bad'); cmp.appendChild(el('strong', '', t('fh.mismatch'))); }
    else { cmp.classList.add('warn'); cmp.appendChild(el('strong', '', t('fh.badFormat'))); }
    if (c.algorithm) cmp.appendChild(el('p', 'x-only', c.algorithm));
  }

  // ------------------------------------------------------------ checkup
  function renderCheckup() {
    var list = $('ck-list');
    clear(list);
    SG.checkup.QUESTIONS.forEach(function (q) {
      var li = el('li');
      li.appendChild(el('span', 'q-text', t('q.' + q.id)));
      var group = el('div', 'segmented');
      group.setAttribute('role', 'radiogroup');
      group.setAttribute('aria-label', t('q.' + q.id));
      ['yes', 'no', 'unsure'].forEach(function (v) {
        var b = el('button', '', t('ck.' + v));
        b.type = 'button';
        b.dataset.value = v;
        b.setAttribute('role', 'radio');
        b.setAttribute('aria-checked', String(state.checkup[q.id] === v));
        b.addEventListener('click', function () {
          state.checkup[q.id] = v;
          if (state.remember) SG.checkup.save(state.checkup);
          renderCheckup();
          var again = list.querySelector('[aria-label="' + CSS.escape(t('q.' + q.id)) + '"] [data-value="' + v + '"]');
          if (again) again.focus();
        });
        group.appendChild(b);
      });
      li.appendChild(group);
      list.appendChild(li);
    });

    var s = SG.checkup.score(state.checkup);
    $('ck-summary').dataset.level = s.level;
    $('ck-score').textContent = s.answered ? String(s.score) : '—';
    $('ck-level').textContent = t('ck.level.' + s.level);
    $('ck-bar').style.width = s.answered ? s.score + '%' : '0';
    $('ck-progress').textContent = t('ck.progress', { a: s.answered, t: s.total });

    var plan = $('ck-plan');
    clear(plan);
    if (!s.plan.length) plan.appendChild(el('li', 'muted', s.answered ? t('ck.planEmpty') : t('ck.level.none')));
    s.plan.forEach(function (id) {
      var li = el('li');
      li.appendChild(el('strong', '', t('q.' + id)));
      li.appendChild(el('span', '', t('tip.' + id)));
      plan.appendChild(li);
    });
    $('ck-remember').checked = state.remember;
  }
  $('ck-remember').addEventListener('change', function () {
    state.remember = this.checked;
    if (state.remember) SG.checkup.save(state.checkup); else SG.checkup.clear();
  });
  $('ck-reset').addEventListener('click', function () {
    state.checkup = {};
    SG.checkup.clear();
    if (state.remember) SG.checkup.save(state.checkup);
    renderCheckup();
  });

  // ----------------------------------------------------------- glossary
  function fold(s) { return String(s).toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, ''); }
  $('gl-search').addEventListener('input', function () { state.glQuery = this.value; renderGlossary(); });

  function renderGlossary() {
    var list = $('gl-list');
    clear(list);
    var q = fold(state.glQuery.trim());
    var shown = 0;
    SG.glossary.forEach(function (term) {
      var tr = term[i18n.lang] || term.es;
      if (q && fold(tr.term + ' ' + tr.basic + ' ' + tr.expert).indexOf(q) === -1) return;
      shown++;
      var art = el('article', 'term');
      art.appendChild(el('h3', '', tr.term));
      art.appendChild(el('p', '', tr.basic));
      art.appendChild(el('p', 'expert-text x-only', tr.expert));
      list.appendChild(art);
    });
    $('gl-none').hidden = shown > 0;
  }

  // ------------------------------------------- auto-clear sensitive data
  var idleTimer;
  function wipeSensitive() {
    var had = false;
    document.querySelectorAll('[data-sensitive]').forEach(function (input) {
      if (input.value) had = true;
      input.value = '';
      input.type = 'password';
    });
    document.querySelectorAll('[data-toggle-visibility]').forEach(function (b) { b.setAttribute('aria-pressed', 'false'); });
    state.analysis = null;
    state.breach = null;
    state.breachError = null;
    renderAnalysis();
    renderBreach();
    return had;
  }
  function resetIdle() {
    clearTimeout(idleTimer);
    idleTimer = setTimeout(function () {
      if (wipeSensitive()) { generate(); toast(t('autoclear')); }
    }, AUTO_CLEAR_MS);
  }
  ['keydown', 'pointerdown', 'input'].forEach(function (ev) { document.addEventListener(ev, resetIdle, { passive: true }); });
  window.addEventListener('pagehide', function () { wipeSensitive(); });

  // --------------------------------------------------------------- boot
  // Link to the repo automatically when hosted on GitHub Pages (user.github.io/repo).
  var m = location.hostname.match(/^([a-z0-9-]+)\.github\.io$/i);
  if (m) {
    var repo = location.pathname.split('/').filter(Boolean)[0] || (m[1] + '.github.io');
    document.querySelectorAll('.repo-link').forEach(function (a) { a.href = 'https://github.com/' + m[1] + '/' + repo; });
  }

  state.checkup = SG.checkup.load();
  state.remember = Object.keys(state.checkup).length > 0;
  i18n.setLang(i18n.detect());
  setMode(read('sg-mode') === 'expert' ? 'expert' : 'basic');
  setGenType('passphrase');
  applyTranslations();
  var startHash = (location.hash || '').replace('#', '');
  if (PAGES.indexOf(startHash) !== -1) showPage(startHash, { scroll: true });
  else showPage('analyzer', { keepHash: true });
  resetIdle();
})();
