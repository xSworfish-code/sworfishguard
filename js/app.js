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
  var PAGES = ['analyzer', 'breach', 'generator', 'phishing', 'scam', 'qr', 'email', 'meta', 'hash', 'quiz', 'checkup', 'glossary'];
  var AUTO_CLEAR_MS = 5 * 60 * 1000;

  var state = {
    mode: 'basic', page: 'analyzer',
    analysis: null, breach: null, breachError: null,
    genType: 'passphrase', generated: null,
    phishing: null, scam: null,
    hash: null, hashFile: null, hashError: null, hashBusy: false,
    checkup: {}, remember: false, glQuery: '',
    qr: null, qrError: null, qrBusy: false, qrSource: '',
    email: null, emailError: null,
    meta: null, metaError: null, metaBusy: false,
    quiz: null
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
  /** 1234567 -> "1,2 millones" ; 1e20 -> "10^20" */
  function bigNumber(n) {
    if (!isFinite(n)) return t('num.power', { n: '308+' });
    if (n < 1e3) return num(Math.max(1, Math.round(n)), 0);
    if (n < 1e6) return t('num.thousand', { n: num(n / 1e3, n < 1e4 ? 1 : 0) });
    if (n < 1e9) return t('num.million', { n: num(n / 1e6, n < 1e7 ? 1 : 0) });
    if (n < 1e12) return t('num.billion', { n: num(n / 1e9, n < 1e10 ? 1 : 0) });
    if (n < 1e15 && i18n.lang === 'es') return t('num.trillion', { n: num(n / 1e12, n < 1e13 ? 1 : 0) });
    return t('num.power', { n: Math.round(Math.log10(n)) });
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

  /** Makes a box accept dropped files. */
  function dropTarget(box, onFile) {
    ['dragenter', 'dragover'].forEach(function (ev) {
      box.addEventListener(ev, function (e) { e.preventDefault(); box.classList.add('dragover'); });
    });
    ['dragleave', 'drop'].forEach(function (ev) {
      box.addEventListener(ev, function () { box.classList.remove('dragover'); });
    });
    box.addEventListener('drop', function (e) {
      e.preventDefault();
      var f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
      if (f) onFile(f);
    });
  }

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
    renderQr(); renderEmail(); renderMeta(); renderQuiz();
    updateNavToggle();
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
    if (id !== 'qr') stopCamera();
    setNavOpen(false);
    updateNavToggle();
    if (!(opts && opts.keepHash)) { try { history.replaceState(null, '', '#' + id); } catch (e) { /* ignore */ } }
    if (opts && opts.scroll) $('workspace').scrollIntoView({ block: 'start' });
    if (opts && opts.focus) {
      var first = $('page-' + id).querySelector('input:not(.visually-hidden), textarea, select, button');
      if (first) first.focus({ preventScroll: true });
    }
  }

  // On phones the tool list is folded behind one button that shows the current tool.
  function setNavOpen(open) {
    var btn = $('nav-toggle');
    btn.setAttribute('aria-expanded', String(open));
    btn.parentNode.classList.toggle('nav-open', open);
  }
  function updateNavToggle() {
    var current = navItems.filter(function (b) { return b.dataset.page === state.page; })[0];
    if (!current) return;
    $('nav-toggle-emoji').textContent = current.querySelector('.emoji').textContent;
    $('nav-toggle-label').textContent = t('page.' + state.page);
  }
  $('nav-toggle').addEventListener('click', function () {
    setNavOpen(this.getAttribute('aria-expanded') !== 'true');
  });

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
  var PERSONAL = ['an-p-name', 'an-p-birth', 'an-p-other'];
  function personalInputs() { return PERSONAL.map(function (id) { return $(id).value; }).filter(Boolean); }
  function analyzeNow() {
    state.analysis = anInput.value ? SG.password.analyzePassword(anInput.value, personalInputs()) : null;
    renderAnalysis();
  }
  anInput.addEventListener('input', analyzeNow);
  PERSONAL.forEach(function (id) { $(id).addEventListener('input', function () { if (anInput.value) analyzeNow(); }); });

  // A random passphrase shown as "a stronger example" (made once per page view, never sent anywhere).
  var example = null;
  function exampleFor(lang) {
    if (!example || example.lang !== lang) {
      var g = SG.generator.generatePassphrase({ words: 6, lang: lang });
      example = { lang: lang, password: g.password, analysis: SG.password.analyzePassword(g.password) };
    }
    return example;
  }

  function pieceDetail(p) {
    var key = 'pd.' + p.type + (p.type === 'random' && Array.from(p.token).length === 1 ? 'One' : '');
    var text = t(key, { rank: num(p.rank || 0, 0), turns: p.turns, base: p.base, count: p.count,
      day: p.day, month: p.month, year: p.year, n: Array.from(p.token).length });
    if (p.l33t) text += t('pd.leet', { subs: (p.subs || []).join(', ') });
    if (p.caps === 'start') text += t('pd.capsStart');
    else if (p.caps === 'all') text += t('pd.capsAll');
    else if (p.caps === 'mixed') text += t('pd.capsMixed');
    if (p.reversed) text += t('pd.reversed', { word: p.word });
    return text;
  }

  function renderAnalysis() {
    var r = state.analysis;
    $('an-empty').hidden = !!r;
    $('an-results').hidden = !r;
    $('an-meter').dataset.score = r ? String(r.score) : '-1';
    $('an-score').textContent = r ? t('score.' + r.score) : '';
    if (!r) return;

    $('an-summary').textContent = t('an.summary', { guesses: bigNumber(r.guesses) });
    $('an-online').textContent = duration(r.crackTimes.onlineThrottled);
    $('an-offline').textContent = duration(r.crackTimes.offlineFast);

    // The password split the way an attacker would split it
    var strip = $('an-pieces'), list = $('an-piece-list');
    clear(strip); clear(list);
    r.sequence.forEach(function (p, idx) {
      var chip = el('span', 'piece t-' + p.type);
      chip.appendChild(el('code', '', p.token));
      chip.appendChild(el('small', '', t('piece.' + p.type)));
      strip.appendChild(chip);
      var li = el('li', 't-' + p.type);
      var head = el('div', 'piece-head');
      head.appendChild(el('code', '', p.token));
      head.appendChild(el('span', 'tag', t('piece.' + p.type)));
      head.appendChild(el('span', 'piece-guesses', t('pd.guesses', { n: bigNumber(Math.pow(10, p.guessesLog10)) })));
      li.appendChild(head);
      li.appendChild(el('p', '', pieceDetail(p)));
      list.appendChild(li);
    });
    $('an-total').textContent = r.sequence.length > 1 ? t('an.total', { n: r.sequence.length, guesses: bigNumber(r.guesses) }) : '';

    var warn = $('an-warnings');
    clear(warn);
    if (!r.warnings.length) warn.appendChild(el('li', 'muted', t('an.noWeak')));
    r.warnings.forEach(function (k) {
      var li = el('li');
      li.appendChild(el('span', 'tag ' + (/^(top10|top100|commonPassword|personal|tooShort)$/.test(k) ? 'critical' : 'medium'), '!'));
      li.appendChild(el('span', 'row-main', t('w.' + k)));
      warn.appendChild(li);
    });
    var fb = $('an-feedback');
    clear(fb);
    r.suggestions.forEach(function (key) { fb.appendChild(el('li', key === 'excellent' ? 'done' : '', t('fb.' + key))); });

    var showExample = r.score <= 3;
    $('an-example').hidden = !showExample;
    if (showExample) {
      var ex = exampleFor(i18n.lang);
      $('an-example-pw').textContent = ex.password;
      $('an-example-time').textContent = t('an.exampleTime', { t: duration(ex.analysis.crackTimes.offlineFast) });
    }

    setProps($('an-x-props'), [
      [t('an.x.guesses'), '10^' + num(r.guessesLog10, 2)],
      [t('an.x.real'), num(r.entropy) + ' bits'],
      [t('an.x.naive'), num(r.breakdown.naiveBits) + ' bits'],
      [t('an.x.pool'), String(r.poolSize)],
      [t('an.x.matches'), String(r.breakdown.matchesFound)]
    ]);
    setTable($('an-x-times'), ['onlineThrottled', 'onlineFast', 'offlineSlow', 'offlineFast'].map(function (k) {
      return [{ text: t('an.sc.' + k) }, { text: duration(r.crackTimes[k]), cls: 'num' }];
    }));
    setTable($('an-x-table'), r.sequence.map(function (p) {
      var extra = p.rank ? (p.dict + ' #' + p.rank) : p.type;
      return [{ text: p.token, cls: 'mono' }, { text: extra }, { text: '10^' + num(p.guessesLog10, 1), cls: 'num' }];
    }));
  }

  $('an-to-gen').addEventListener('click', function () {
    setGenType('passphrase');
    showPage('generator', { scroll: true, focus: true });
  });
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
    state.genType = type === 'password' || type === 'pin' ? type : 'passphrase';
    document.querySelectorAll('[data-gen-type]').forEach(function (b) {
      b.setAttribute('aria-checked', String(b.dataset.genType === state.genType));
    });
    $('gen-pp-opts').hidden = state.genType !== 'passphrase';
    $('gen-pw-opts').hidden = state.genType !== 'password';
    $('gen-pin-opts').hidden = state.genType !== 'pin';
    $('gen-analyze').hidden = state.genType === 'pin';
    $('gen-type-hint').textContent = t('gen.typeHint.' + state.genType);
    generate();
  }
  document.querySelectorAll('[data-gen-type]').forEach(function (b) {
    b.addEventListener('click', function () { setGenType(b.dataset.genType); });
  });

  function generate() {
    $('gen-length-value').textContent = $('gen-length').value;
    $('gen-words-value').textContent = $('gen-words').value;
    try {
      state.generated = state.genType === 'pin'
        ? SG.generator.generatePin({ length: +$('gen-pin-len').value })
        : state.genType === 'passphrase'
        ? SG.generator.generatePassphrase({
            words: +$('gen-words').value, separator: $('gen-sep').value,
            capitalize: $('gen-cap').checked, addNumber: $('gen-num').checked, addSymbol: $('gen-sym').checked,
            lang: $('gen-lang').value })
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
    $('gen-type-hint').textContent = t('gen.typeHint.' + state.genType);
    if (g.error) {
      $('gen-meter').dataset.score = '-1';
      $('gen-meta').textContent = t('gen.needOne');
      $('gen-time').textContent = '';
      return;
    }
    if (state.genType === 'pin') {
      // A PIN is never "strong" offline: its safety comes from the lock after a few tries.
      $('gen-meter').dataset.score = '2';
      $('gen-meta').textContent = t('gen.strength', { bits: num(g.entropy) });
      $('gen-time').textContent = t('gen.timePin', { n: num(Math.round(g.poolSize / 3), 0) });
      $('gen-pin-note').textContent = t('gen.pinNote', { n: num(g.rejected, 0), total: num(g.total, 0) });
    } else {
      // Use the most pessimistic of: the generator's exact entropy and the analyzer's attacker view.
      var bits = Math.min(g.entropy, SG.password.analyzePassword(g.password).entropy);
      var times = SG.password.crackTimes(bits);
      var score = SG.password.scoreOf(Math.pow(2, bits));
      $('gen-meter').dataset.score = String(score);
      $('gen-meta').textContent = t('score.' + score) + ', ' + t('gen.strength', { bits: num(bits) });
      $('gen-time').textContent = t('gen.time', { slow: duration(times.offlineSlow), fast: duration(times.offlineFast) });
    }
    setProps($('gen-x-props'), [
      [t('gen.x.pool'), num(g.poolSize, 0)],
      [t('an.entropy'), num(g.entropy) + ' bits']
    ]);
  }

  ['gen-length', 'gen-lower', 'gen-upper', 'gen-digits', 'gen-symbols', 'gen-ambiguous',
   'gen-words', 'gen-sep', 'gen-cap', 'gen-num', 'gen-sym', 'gen-lang', 'gen-pin-len'].forEach(function (id) { $(id).addEventListener('input', generate); });
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
      li.appendChild(el('span', 'row-main', t(prefix + f.id, { d: f.id === 'combo' ? t('sc.type.' + f.detail) : f.detail })));
      list.appendChild(li);
    });
  }

  // Findings where each item already carries its full translation key.
  function renderKeyed(list, findings, emptyKey) {
    clear(list);
    if (!findings.length) list.appendChild(el('li', 'muted', t(emptyKey)));
    findings.forEach(function (f) {
      var li = el('li');
      li.appendChild(el('span', 'tag ' + f.severity, t('sev.' + f.severity)));
      li.appendChild(el('span', 'row-main', t(f.key, { d: f.key === 'sf.combo' ? t('sc.type.' + f.detail) : f.detail })));
      list.appendChild(li);
    });
  }
  function setVerdict(prefix, level, title, hint, score) {
    $(prefix + '-verdict').dataset.level = level;
    $(prefix + '-level').textContent = title;
    $(prefix + '-hint').textContent = hint;
    $(prefix + '-score').textContent = score === null || score === undefined ? '' : score + '/100';
  }
  function copyText(text, message) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { toast(message || t('gen.copied')); }, function () {});
    }
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
    renderAnatomy($('ph-anatomy'), r);
    var lvl = r.official ? 'official' : r.level;
    var brandF = r.findings.filter(function (f) { return f.id === 'officialDomain'; })[0];
    $('ph-advice').textContent = t('ph.advice.' + lvl, { brand: brandF ? brandF.detail : '' });
    $('ph-advice').dataset.level = lvl;

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

  /** Shows the link split in parts: protocol / decoration / REAL DOMAIN / path. */
  function renderAnatomy(box, r) {
    clear(box);
    box.hidden = !r.host || !r.registeredDomain;
    if (box.hidden) return;
    var href = r.href || '';
    var userInfo = (href.match(/^[a-z]+:\/\/([^@/]*)@/i) || [])[1];
    var host = r.unicodeHost && r.unicodeHost !== r.host ? r.unicodeHost : r.host;
    var domain = r.registeredDomain;
    if (r.unicodeHost && r.unicodeHost !== r.host) {
      var labels = r.unicodeHost.split('.');
      domain = labels.slice(-domain.split('.').length).join('.');
    }
    var sub = host.length > domain.length ? host.slice(0, host.length - domain.length) : '';
    var parts = [['scheme', (r.scheme || 'http') + '://']];
    if (userInfo) parts.push(['user', decodeURIComponent(userInfo) + '@']);
    if (sub) parts.push(['sub', sub]);
    parts.push(['domain', domain]);
    if (r.path && r.path !== '/') parts.push(['path', r.path.length > 60 ? r.path.slice(0, 60) + '…' : r.path]);
    var line = el('div', 'anatomy-line');
    parts.forEach(function (p) {
      var seg = el('span', 'seg seg-' + p[0]);
      seg.appendChild(el('code', '', p[1]));
      seg.appendChild(el('small', '', t('ph.part.' + p[0])));
      line.appendChild(seg);
    });
    box.appendChild(line);
    box.appendChild(el('p', 'hint-text', t('ph.anatomyHint')));
  }

  // --------------------------------------------------------------- scam
  $('sc-form').addEventListener('submit', function (e) {
    e.preventDefault();
    var v = $('sc-input').value;
    state.scamText = v.slice(0, SG.scam.MAX_TEXT);
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
    // The original message with the suspicious phrases marked
    var marked = $('sc-marked'), msg = state.scamText || '';
    clear(marked);
    var pos = 0;
    r.highlights.forEach(function (h) {
      if (h.start > pos) marked.appendChild(document.createTextNode(msg.slice(pos, h.start)));
      var mk = el('mark', 'sev-' + (h.severity === 'critical' || h.severity === 'high' ? 'critical' : 'medium'), msg.slice(h.start, h.end));
      mk.title = t('sev.' + h.severity);
      marked.appendChild(mk);
      pos = h.end;
    });
    if (pos < msg.length) marked.appendChild(document.createTextNode(msg.slice(pos)));
    // Type of scam + what to do
    $('sc-type').hidden = !r.type;
    if (r.type) {
      $('sc-type-name').textContent = t('sc.type.' + r.type);
      $('sc-type-how').textContent = t('sc.how.' + r.type);
    }
    $('sc-advice').hidden = !!r.type;
    $('sc-advice').textContent = r.level === 'low' ? t('sc.advice.low') : t('ph.advice.medium');
    var good = $('sc-legit');
    clear(good);
    (r.legitSigns || []).forEach(function (k) {
      var li = el('li');
      li.appendChild(el('span', 'tag green', t('sev.good')));
      li.appendChild(el('span', 'row-main', t('lg.' + k)));
      good.appendChild(li);
    });
    good.hidden = !(r.legitSigns || []).length;
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


  // ------------------------------------------------------------ QR codes
  var SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  var LEVEL_RANK = { low: 0, official: 0, medium: 1, high: 2 };

  /** Turns what the QR contains into a verdict, findings and details. */
  function assessQr(text) {
    var P = SG.qr.classifyPayload(text);
    var out = { payload: P, level: 'low', score: null, findings: [], props: [], url: null, hintKey: 'qr.hint.' + P.type };
    function add(key, severity, detail) { out.findings.push({ key: key, severity: severity, detail: detail || '' }); }
    function raise(level) { if (LEVEL_RANK[level] > LEVEL_RANK[out.level]) out.level = level; }
    function prop(k, v) { if (v) out.props.push([t('qr.p.' + k), String(v)]); }
    function fromScam(message) {
      var r = SG.scam.analyzeMessage(message);
      if (!r.valid) return;
      r.findings.forEach(function (f) { add('sf.' + f.id, f.severity, f.detail); });
      r.links.forEach(function (l) {
        var lvl = l.official ? 'low' : l.level;
        raise(lvl);
        if (lvl !== 'low') add('qf.contactLink', lvl === 'high' ? 'high' : 'medium', l.url);
      });
      raise(r.level);
    }

    switch (P.type) {
      case 'url':
        out.url = SG.phishing.analyzeUrl(P.url);
        if (out.url.valid) {
          out.level = out.url.official ? 'official' : out.url.level;
          out.score = out.url.score;
          out.url.findings.forEach(function (f) { add('f.' + f.id, f.severity, f.detail); });
          if (P.implicit) add('qf.implicit', 'low');
        }
        break;
      case 'dangerous':
        add('qf.dangerous', 'critical', P.scheme); out.level = 'high'; break;
      case 'wifi':
        prop('ssid', P.ssid);
        prop('security', P.security === 'open' ? t('qr.p.noPassword') : P.security);
        prop('password', P.hasPassword ? t('qr.p.passwordValue', { n: P.passwordLength }) : '');
        prop('hidden', P.hidden ? t('common.yes') : '');
        if (P.security === 'open') { add('qf.openWifi', 'medium'); raise('medium'); }
        else if (P.security === 'WEP') { add('qf.wepWifi', 'medium'); raise('medium'); }
        else add('qf.wifiOk', 'info');
        if (P.hidden) add('qf.hiddenWifi', 'low');
        break;
      case 'otp':
        prop('issuer', P.issuer); prop('account', P.account);
        add('qf.otp', 'medium', P.issuer || P.account); raise('medium'); break;
      case 'crypto':
        prop('coin', P.coin); prop('address', P.address); prop('amount', P.amount);
        add('qf.crypto', 'high', P.coin); raise('high'); break;
      case 'sms':
        prop('number', P.number); prop('message', P.body);
        add('qf.sms', 'low', P.number);
        if (P.body) fromScam(P.body);
        break;
      case 'phone':
        prop('number', P.number); add('qf.phone', 'info', P.number); break;
      case 'email':
        prop('to', P.to); prop('subject', P.subject); prop('message', P.body);
        if (P.subject || P.body) fromScam(P.subject + '\n' + P.body);
        break;
      case 'contact':
        prop('name', P.name); prop('org', P.org); prop('phones', P.phones.join(', ')); prop('emails', P.emails.join(', '));
        P.urls.forEach(function (u) {
          var r = SG.phishing.analyzeUrl(u);
          var lvl = r.valid ? (r.official ? 'low' : r.level) : 'medium';
          add('qf.contactLink', lvl === 'high' ? 'high' : lvl === 'medium' ? 'medium' : 'info', u);
          raise(lvl);
        });
        break;
      case 'app':
        if (P.scheme === 'itms-services') { add('qf.appInstall', 'high', P.scheme); raise('high'); }
        else { add('qf.appLink', 'low', P.scheme); }
        break;
      case 'geo':
        prop('location', P.lat + ', ' + P.lon); break;
      case 'other':
        add('qf.other', 'medium', P.scheme); raise('medium'); break;
      default:
        fromScam(P.text || '');
    }
    out.findings.sort(function (a, b) { return SEV_RANK[b.severity] - SEV_RANK[a.severity]; });
    return out;
  }

  function showQrText(text, info) {
    state.qr = { text: text, info: info || {}, assessment: assessQr(text) };
    state.qrError = null;
    renderQr();
    $('qr-result').scrollIntoView({ block: 'nearest' });
  }

  function decodeQrFile(file) {
    if (!file) return;
    stopCamera();
    state.qrBusy = true; state.qrError = null; state.qr = null; state.qrSource = 'image';
    renderQr();
    SG.qr.decodeImageFile(file)
      .then(function (found) {
        if (found) showQrText(found.text, found); else state.qrError = 'none';
      })
      .catch(function (err) {
        var m = err && err.message;
        state.qrError = m === 'notImage' || m === 'tooLarge' ? m : 'error';
      })
      .then(function () { state.qrBusy = false; renderQr(); });
  }

  $('qr-file').addEventListener('change', function () {
    if (this.files && this.files[0]) decodeQrFile(this.files[0]);
    this.value = '';
  });
  dropTarget($('qr-drop'), decodeQrFile);
  document.addEventListener('paste', function (e) {
    if (state.page !== 'qr' && state.page !== 'meta') return;
    var items = (e.clipboardData && e.clipboardData.files) || [];
    for (var i = 0; i < items.length; i++) {
      if (/^image\//.test(items[i].type)) {
        e.preventDefault();
        if (state.page === 'qr') decodeQrFile(items[i]); else readPhoto(items[i]);
        return;
      }
    }
  });

  // Camera: frames are read in memory, nothing is recorded or sent.
  var cam = { stream: null, timer: null, canvas: null };
  function stopCamera() {
    if (cam.timer) { clearTimeout(cam.timer); cam.timer = null; }
    if (cam.stream) { cam.stream.getTracks().forEach(function (tr) { tr.stop(); }); cam.stream = null; }
    var video = $('qr-video');
    if (video) video.srcObject = null;
    if ($('qr-camera')) $('qr-camera').hidden = true;
  }
  function scanFrame() {
    var video = $('qr-video');
    if (!cam.stream) return;
    if (video.readyState >= 2 && video.videoWidth) {
      var size = SG.qr.fitSize(video.videoWidth, video.videoHeight, 720);
      cam.canvas = cam.canvas || document.createElement('canvas');
      cam.canvas.width = size.width; cam.canvas.height = size.height;
      var ctx = cam.canvas.getContext('2d', { willReadFrequently: true });
      ctx.drawImage(video, 0, 0, size.width, size.height);
      var found = SG.qr.decodePixels(ctx.getImageData(0, 0, size.width, size.height));
      if (found) {
        stopCamera();
        state.qrSource = 'camera';
        $('qr-status').textContent = '';
        showQrText(found.text, found);
        return;
      }
    }
    cam.timer = setTimeout(scanFrame, 180);
  }
  $('qr-camera-btn').addEventListener('click', function () {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) { state.qrError = 'camError'; renderQr(); return; }
    state.qr = null; state.qrError = null;
    renderQr();
    navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: 'environment' } }, audio: false })
      .then(function (stream) {
        cam.stream = stream;
        var video = $('qr-video');
        video.srcObject = stream;
        $('qr-camera').hidden = false;
        $('qr-status').textContent = t('qr.scanning');
        return video.play().then(scanFrame);
      })
      .catch(function (err) {
        stopCamera();
        state.qrError = err && (err.name === 'NotAllowedError' || err.name === 'SecurityError') ? 'camDenied' : 'camError';
        renderQr();
      });
  });
  $('qr-stop').addEventListener('click', function () { stopCamera(); $('qr-status').textContent = ''; });
  $('qr-copy').addEventListener('click', function () { if (state.qr) copyText(state.qr.text, t('qr.copied')); });
  $('qr-again').addEventListener('click', function () {
    state.qr = null; renderQr();
    $('qr-drop').scrollIntoView({ block: 'nearest' });
    $('qr-file').click();
  });

  function renderQr() {
    var status = $('qr-status');
    if (state.qrBusy) status.textContent = t('qr.reading');
    else if (state.qrError) status.textContent = t('qr.' + state.qrError);
    else if (!cam.stream) status.textContent = '';
    var q = state.qr;
    $('qr-result').hidden = !q;
    if (!q) return;
    var a = q.assessment, P = a.payload;
    $('qr-type').textContent = t('qr.type.' + P.type);
    $('qr-text').textContent = q.text.length > 600 ? q.text.slice(0, 600) + '…' : q.text;
    if (a.url && a.url.valid) {
      renderVerdict('qr', 'ph', a.url);
    } else {
      setVerdict('qr', a.level, t('qr.level.' + (a.level === 'official' ? 'low' : a.level)), t(a.hintKey), null);
    }
    $('qr-real').hidden = !(a.url && a.url.registeredDomain);
    $('qr-real-domain').textContent = a.url ? a.url.registeredDomain || '' : '';
    setProps($('qr-props'), a.props);
    $('qr-props').hidden = !a.props.length;
    renderKeyed($('qr-findings'), a.findings, 'ph.noFindings');
    setProps($('qr-x-props'), [
      [t('qr.x.source'), t(state.qrSource === 'camera' ? 'qr.x.sourceCamera' : 'qr.x.sourceImage')],
      [t('qr.x.version'), q.info.version ? String(q.info.version) : '—'],
      [t('qr.x.bytes'), q.info.bytes ? String(q.info.bytes) : String(q.text.length)],
      [t('qr.p.scheme'), (q.text.match(/^([a-z][a-z0-9+.-]*):/i) || ['', '—'])[1]]
    ]);
  }

  // -------------------------------------------------------- email headers
  var EMAIL_EXAMPLE = [
    'Received: from vps-2231.hosting-barato.example (unknown [185.220.101.4])',
    '        by mx.google.com with ESMTP id 4fb4; Tue, 11 Nov 2026 03:12:00 -0800 (PST)',
    'Authentication-Results: mx.google.com;',
    '       spf=softfail (google.com: domain of soporte@baccredomatic.com does not designate 185.220.101.4 as permitted sender) smtp.mailfrom=soporte@baccredomatic.com;',
    '       dmarc=fail (p=QUARANTINE sp=QUARANTINE dis=QUARANTINE) header.from=baccredomatic.com',
    'Return-Path: <soporte@baccredomatic.com>',
    'From: "BAC Credomatic" <soporte@baccredomatic.com>',
    'Reply-To: <bac.verificacion.hn@gmail.com>',
    'To: cliente@gmail.com',
    'Subject: =?UTF-8?Q?Su_cuenta_ser=C3=A1_suspendida?=',
    'Message-ID: <a81f@vps-2231.hosting-barato.example>',
    'Date: Tue, 11 Nov 2026 11:11:58 +0000'
  ].join('\n');

  $('em-form').addEventListener('submit', function (e) {
    e.preventDefault();
    var v = $('em-input').value;
    if (!v.trim()) { state.email = null; state.emailError = 'empty'; renderEmail(); return; }
    var r = SG.email.analyzeHeaders(v);
    state.email = r.valid ? r : null;
    state.emailError = r.valid ? null : 'tooShort';
    renderEmail();
  });
  $('em-example').addEventListener('click', function () {
    $('em-input').value = EMAIL_EXAMPLE;
    $('em-form').requestSubmit();
  });

  function renderEmail() {
    $('em-status').textContent = state.emailError ? t('em.' + state.emailError) : '';
    var r = state.email;
    $('em-result').hidden = !r;
    if (!r) return;
    var level = r.official ? 'official' : r.level;
    setVerdict('em', level, t('em.level.' + level), t('em.levelHint.' + level, { brand: r.brand }), r.score);

    var grid = $('em-auth');
    clear(grid);
    ['spf', 'dkim', 'dmarc'].forEach(function (k) {
      var res = r.auth[k];
      var known = ['pass', 'fail', 'softfail', 'none', 'neutral', 'unchecked'].indexOf(res) !== -1;
      var cls = res === 'pass' ? 'green' : res === 'fail' ? 'red' : res === 'softfail' ? 'orange' : 'off';
      var card = el('div', 'auth-card');
      var top = el('div', 'auth-top');
      top.appendChild(el('strong', '', t('em.auth.' + k)));
      top.appendChild(el('span', 'tag ' + cls, known ? t('em.res.' + res) : t('em.res.other', { r: res })));
      card.appendChild(top);
      card.appendChild(el('p', '', t('em.auth.' + k + 'Hint')));
      grid.appendChild(card);
    });

    function addr(a) { return a ? (a.name ? a.name + ' <' + a.address + '>' : a.address) : ''; }
    var rows = [[t('em.p.from'), addr(r.from) || '—']];
    if (r.replyTo) rows.push([t('em.p.replyTo'), addr(r.replyTo)]);
    if (r.returnPath && r.returnPath.address) rows.push([t('em.p.returnPath'), r.returnPath.address]);
    if (r.subject) rows.push([t('em.p.subject'), r.subject]);
    if (r.date) rows.push([t('em.p.date'), r.date]);
    setProps($('em-props'), rows);
    renderFindings($('em-findings'), r.findings, 'ef.', 'em.noFindings');

    var hops = r.hops.map(function (h, i) {
      return [{ text: String(i + 1), cls: 'num' }, { text: h.from || '—', cls: 'mono' }, { text: h.by || '—', cls: 'mono' }, { text: h.ip || '—', cls: 'mono' }];
    });
    hops.unshift([{ text: t('em.hop.n') }, { text: t('em.hop.from') }, { text: t('em.hop.by') }, { text: t('em.hop.ip') }]);
    setTable($('em-hops'), hops);
    setTable($('em-x-breakdown'), r.breakdown.map(function (b) {
      return [{ text: b.id, cls: 'mono' }, { text: '+' + b.points, cls: 'num' }];
    }).concat([[{ text: t('common.score') }, { text: r.score + '/100', cls: 'num' }]]));
  }

  // ------------------------------------------------------ photo metadata
  var metaUrls = [];
  function revokeMeta() { metaUrls.forEach(function (u) { URL.revokeObjectURL(u); }); metaUrls = []; }

  function cleanName(name, ext) {
    var base = String(name || 'foto').replace(/\.[^.]+$/, '').replace(/[^\w\- ]+/g, '').trim().slice(0, 60) || 'foto';
    return base + '-limpia.' + ext;
  }

  function readPhoto(file) {
    if (!file) return;
    revokeMeta();
    state.meta = null; state.metaError = null;
    if (!/^image\//.test(file.type || '')) { state.metaError = 'notImage'; renderMeta(); return; }
    if (file.size > SG.metadata.MAX_BYTES) { state.metaError = 'tooLarge'; renderMeta(); return; }
    state.metaBusy = true;
    renderMeta();
    file.arrayBuffer().then(function (buf) {
      var bytes = new Uint8Array(buf);
      var info = SG.metadata.inspect(bytes);
      var preview = URL.createObjectURL(file);
      metaUrls.push(preview);
      if (info.supported) {
        var cleaned = SG.metadata.clean(bytes);
        var url = URL.createObjectURL(new Blob([cleaned.bytes], { type: file.type || (info.format === 'png' ? 'image/png' : 'image/jpeg') }));
        metaUrls.push(url);
        return { info: info, preview: preview, url: url, name: cleanName(file.name, info.format === 'png' ? 'png' : 'jpg'), removed: cleaned.removedBytes, reencoded: false, size: file.size };
      }
      // HEIC, WebP...: draw it and save a new JPEG (drawing drops every metadata block).
      return createImageBitmap(file).then(function (bmp) {
        var c = document.createElement('canvas');
        c.width = bmp.width; c.height = bmp.height;
        c.getContext('2d').drawImage(bmp, 0, 0);
        if (bmp.close) bmp.close();
        return new Promise(function (res) { c.toBlob(res, 'image/jpeg', 0.92); });
      }).then(function (blob) {
        if (!blob) throw new Error('error');
        var url = URL.createObjectURL(blob);
        metaUrls.push(url);
        return { info: info, preview: preview, url: url, name: cleanName(file.name, 'jpg'), removed: 0, reencoded: true, size: file.size };
      });
    }).then(function (result) { state.meta = result; })
      .catch(function () { state.metaError = 'error'; })
      .then(function () { state.metaBusy = false; renderMeta(); });
  }

  $('md-file').addEventListener('change', function () {
    if (this.files && this.files[0]) readPhoto(this.files[0]);
    this.value = '';
  });
  dropTarget($('md-drop'), readPhoto);

  function renderMeta() {
    $('md-status').textContent = state.metaBusy ? t('md.reading') : state.metaError ? t('md.' + state.metaError) : '';
    var m = state.meta;
    $('md-result').hidden = !m;
    if (!m) return;
    var info = m.info;
    var level = info.risk;
    var vLevel = level === 'high' ? 'high' : level === 'medium' ? 'medium' : 'low';
    setVerdict('md', vLevel, t('md.level.' + level), t('md.hint.' + level), null);
    $('md-preview').src = m.preview;

    $('md-gps').hidden = !info.gps;
    if (info.gps) {
      $('md-gps-coords').textContent = info.gps.lat + ', ' + info.gps.lon + (info.gps.altitude !== null ? ' · ' + num(info.gps.altitude, 0) + ' m' : '');
      $('md-map').href = 'https://www.openstreetmap.org/?mlat=' + encodeURIComponent(info.gps.lat) + '&mlon=' + encodeURIComponent(info.gps.lon) + '#map=16/' + encodeURIComponent(info.gps.lat) + '/' + encodeURIComponent(info.gps.lon);
    }
    var rows = info.fields.map(function (f) { return [t('md.f.' + f.id), f.value]; })
      .concat(info.extras.map(function (x) { return [t('md.extra'), t('md.e.' + x)]; }));
    setProps($('md-props'), rows.length ? rows : [[t('md.found'), t('md.nothing')]]);

    var dl = $('md-download');
    dl.href = m.url;
    dl.setAttribute('download', m.name);
    $('md-clean-note').textContent = m.reencoded ? t('md.cleanReencoded')
      : m.removed ? t('md.cleanLossless', { n: bytes(m.removed) }) : t('md.cleanAlready');
    setProps($('md-x-props'), [
      [t('md.x.format'), info.format.toUpperCase()],
      [t('md.x.size'), bytes(m.size)],
      [t('md.x.orientation'), String(info.orientation)],
      [t('md.x.removed'), m.reencoded ? '—' : num(m.removed, 0) + ' B']
    ]);
  }

  // ----------------------------------------------------------------- quiz
  var QUIZ_ROUND = 10;
  function shuffled(list) {
    var a = list.slice(), r = new Uint32Array(1);
    for (var i = a.length - 1; i > 0; i--) {
      crypto.getRandomValues(r);
      var j = r[0] % (i + 1), tmp = a[i];
      a[i] = a[j]; a[j] = tmp;
    }
    return a;
  }
  function newQuiz() {
    var ids = shuffled(SG.quiz.CASES.map(function (c) { return c.id; })).slice(0, QUIZ_ROUND);
    state.quiz = { ids: ids, i: 0, answers: {}, answered: false, done: false };
  }
  function quizCase(id) { return SG.quiz.CASES.filter(function (c) { return c.id === id; })[0]; }
  function answerQuiz(choice) {
    var q = state.quiz;
    if (!q || q.answered || q.done) return;
    q.answers[q.ids[q.i]] = choice;
    q.answered = true;
    renderQuiz();
    $('qz-next').focus();
  }
  $('qz-real').addEventListener('click', function () { answerQuiz('real'); });
  $('qz-scam').addEventListener('click', function () { answerQuiz('scam'); });
  $('qz-next').addEventListener('click', function () {
    var q = state.quiz;
    if (q.i + 1 >= q.ids.length) q.done = true; else { q.i++; q.answered = false; }
    renderQuiz();
    (q.done ? $('qz-restart') : $('qz-real')).focus();
  });
  $('qz-restart').addEventListener('click', function () { newQuiz(); renderQuiz(); $('qz-real').focus(); });

  function renderQuiz() {
    var q = state.quiz;
    if (!q) return;
    var lang = i18n.lang;
    $('qz-play').hidden = q.done;
    $('qz-end').hidden = !q.done;
    var right = q.ids.filter(function (id) { return q.answers[id] === quizCase(id).answer; }).length;
    if (q.done) {
      var g = SG.quiz.grade(q.answers, q.ids);
      $('qz-score').textContent = g.right + '/' + g.total;
      $('qz-level').textContent = t('qz.level.' + g.level);
      var list = $('qz-review');
      clear(list);
      if (!g.wrong.length) list.appendChild(el('li', 'muted', t('qz.allRight')));
      g.wrong.forEach(function (id) {
        var c = quizCase(id), tr = c[lang] || c.es;
        var li = el('li', 'qz-review-item');
        li.appendChild(el('span', 'tag ' + (c.answer === 'scam' ? 'red' : 'green'), t(c.answer === 'scam' ? 'qz.scam' : 'qz.real')));
        var box = el('div', 'row-main');
        box.appendChild(el('code', '', tr.text));
        box.appendChild(el('p', '', tr.why));
        li.appendChild(box);
        list.appendChild(li);
      });
      return;
    }
    var id = q.ids[q.i], c = quizCase(id), tr = c[lang] || c.es;
    $('qz-progress').textContent = t('qz.progress', { i: q.i + 1, n: q.ids.length });
    $('qz-points').textContent = t('qz.points', { n: right });
    $('qz-bar').style.width = Math.round((q.i + (q.answered ? 1 : 0)) / q.ids.length * 100) + '%';
    $('qz-kind').textContent = t('qz.kind.' + c.kind);
    $('qz-from').textContent = tr.from;
    var text = $('qz-text');
    text.textContent = tr.text;
    text.classList.toggle('mono', c.kind === 'link');
    $('qz-card').dataset.kind = c.kind;
    ['qz-real', 'qz-scam'].forEach(function (bid) {
      $(bid).disabled = q.answered;
      var picked = q.answered && q.answers[id] === (bid === 'qz-real' ? 'real' : 'scam');
      $(bid).classList.toggle('picked', picked);
      $(bid).setAttribute('aria-pressed', String(picked));
    });
    var fb = $('qz-feedback');
    clear(fb);
    fb.hidden = !q.answered;
    $('qz-next').hidden = !q.answered;
    $('qz-next').textContent = t(q.i + 1 >= q.ids.length ? 'qz.finish' : 'qz.next');
    if (q.answered) {
      var ok = q.answers[id] === c.answer;
      fb.className = 'result ' + (ok ? 'good' : 'bad');
      fb.appendChild(el('strong', '', t((ok ? 'qz.right.' : 'qz.wrong.') + c.answer)));
      fb.appendChild(el('p', '', tr.why));
      $('qz-card').dataset.answer = c.answer;
    } else {
      delete $('qz-card').dataset.answer;
    }
  }

  // ---------------------------------------------------------- file hash
  $('fh-file').addEventListener('change', function () {
    if (this.files && this.files[0]) hashFile(this.files[0]);
    this.value = '';
  });
  dropTarget($('fh-drop'), hashFile);
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
    document.querySelectorAll('[data-personal]').forEach(function (input) {
      if (input.value) had = true;
      input.value = '';
    });
    example = null;
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
  window.addEventListener('pagehide', function () { wipeSensitive(); stopCamera(); });
  document.addEventListener('visibilitychange', function () { if (document.hidden) stopCamera(); });

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
  newQuiz();
  applyTranslations();
  // Links like "#qr" (from the footer, a bookmark or the back button) open that tool.
  window.addEventListener('hashchange', function () {
    var h = (location.hash || '').replace('#', '');
    if (PAGES.indexOf(h) !== -1 && h !== state.page) showPage(h, { keepHash: true, scroll: true });
  });
  var startHash = (location.hash || '').replace('#', '');
  if (PAGES.indexOf(startHash) !== -1) showPage(startHash, { scroll: true });
  else showPage('analyzer', { keepHash: true });
  resetIdle();

  // Offline mode (installable app). With Trusted Types on, the service worker
  // URL must go through a policy that only accepts this exact file.
  if ('serviceWorker' in navigator && location.protocol === 'https:') {
    try {
      var swUrl = 'sw.js';
      if (window.trustedTypes && window.trustedTypes.createPolicy) {
        swUrl = window.trustedTypes.createPolicy('sg-sw', {
          createScriptURL: function (u) { if (u === 'sw.js') return u; throw new TypeError('blocked'); }
        }).createScriptURL('sw.js');
      }
      navigator.serviceWorker.register(swUrl).catch(function () { /* offline mode is optional */ });
    } catch (e) { /* ignore */ }
  }
})();
