/*!
 * SworfishGuard — Scam Message Detector (SMS, WhatsApp, email)
 *
 * How it works:
 *   1. CLEAN the text the way a person reads it, undoing the tricks scammers
 *      use to dodge filters: "c0dig0" -> "codigo", "p.i.n." -> "pin",
 *      invisible characters, letters from other alphabets, accents.
 *      A position map is kept so the original phrases can be highlighted.
 *   2. SIGNALS: rules look for what the message ASKS you to do (send a
 *      code, transfer money, pay a fee, install an app, type your data...)
 *      and for the bait (prize, blocked account, parcel, job, investment...).
 *   3. COMBINATIONS: a scam is bait + request. "New number" + "send money"
 *      is the family scam; "parcel" + "pay a fee" is the fake delivery...
 *      Each combination names the type of scam and says what to do.
 *   4. LINKS: every link goes through the link detector. If the message
 *      names a brand but its links go somewhere else, it's impersonation.
 *   5. LEGIT SIGNS lower the score: real one-time codes say "don't share
 *      it", real alerts give no link and tell you to call the number on
 *      your card.
 *
 * Everything runs locally; the message never leaves the browser.
 * Heuristic and educational: it explains signals, it cannot prove intent.
 * Accuracy is measured with tests/benchmark.js.
 *
 * Author: Asaf Rojas (Sworfish Tech) — MIT License
 */
(function (root) {
  'use strict';

  var SG = root.SworfishGuard || {};
  var phishing = SG.phishing || (typeof require === 'function' ? require('./phishing-detector.js') : null);
  var DATA = SG.data || (typeof require === 'function' ? require('./brands.js') : null);

  var MAX_TEXT = 5000;
  var WEIGHT = { critical: 45, high: 30, medium: 12, low: 5, info: 0 };

  // ------------------------------------------------------------- cleaning
  var LEET = { '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a', '$': 's' };
  var INVISIBLE = /[­​-‏⁠-⁤﻿͏᠎]/;

  /**
   * Returns { text, map } where text[k] came from original[map[k]].
   * Lowercase, no accents, no invisible characters, look-alike letters
   * mapped to Latin, leetspeak undone inside words, spaced letters joined.
   */
  function clean(original) {
    var src = Array.from(original);
    var out = [];  // { c, at } at = index in the UTF-16 original
    var at = 0;
    src.forEach(function (ch) {
      var here = at;
      at += ch.length;
      if (INVISIBLE.test(ch)) return;
      var low = ch.toLowerCase();
      var base = low.normalize('NFD').replace(/[̀-ͯ]/g, '');
      if (base.length !== 1) base = low.length === 1 ? low : ' ';
      if (phishing && phishing.skeleton && /[^\x00-\x7F]/.test(base)) base = phishing.skeleton(base) || base;
      out.push({ c: base.length === 1 ? base : ' ', at: here });
    });

    // Leetspeak only inside words that are mostly letters: "c0dig0", "b4nco", "bl0queada".
    var i = 0;
    while (i < out.length) {
      if (!/[a-z0-9@$]/.test(out[i].c)) { i++; continue; }
      var j = i;
      while (j < out.length && /[a-z0-9@$]/.test(out[j].c)) j++;
      var word = out.slice(i, j).map(function (x) { return x.c; }).join('');
      var letters = (word.match(/[a-z]/g) || []).length;
      if (letters >= 2 && letters >= word.length / 2 && /[013457@$]/.test(word) && !/^\d/.test(word)) {
        for (var k = i; k < j; k++) if (LEET[out[k].c]) out[k].c = LEET[out[k].c];
      }
      i = j;
    }

    // Spaced or dotted letters: "c o d i g o", "p.i.n." -> "codigo", "pin"
    var text = out.map(function (x) { return x.c; }).join('');
    var spaced = /(?:^|[^a-z])((?:[a-z][ .\-_*·]){2,}[a-z])(?![a-z])/g;
    var drop = {};
    var m;
    while ((m = spaced.exec(text)) !== null) {
      var start = m.index + m[0].length - m[1].length;
      for (var p = start; p < start + m[1].length; p++) if (!/[a-z]/.test(text[p])) drop[p] = true;
      spaced.lastIndex = start + m[1].length;
    }
    var finalChars = [], map = [];
    out.forEach(function (x, idx) { if (!drop[idx]) { finalChars.push(x.c); map.push(x.at); } });
    return { text: finalChars.join(''), map: map };
  }

  // ---------------------------------------------------------------- signals
  // "group" says what part of the trick it is: bait, request, pressure, context.
  var RULES = [
    // Requests (what they want you to do)
    { id: 'money', group: 'request', severity: 'high',
      re: /(transfier[ae]me|transfiereme|deposit[ae]me|prest[ae]me|me (puedes|podes|podrias|pueden|podria|podra) (transferir|depositar|prestar|ayudar con (dinero|plata|pisto|\d))|me (puedes|podes|podrias|pueden|podria|podra) (mandar|enviar|pasar|depositar) (unos |unas |de )?(dinero|plata|pisto|saldo|lempiras|\d|l\.? ?\d|\$)|necesito que me (deposites|transfieras|mandes|envies|prestes|hagas una transferencia)|hagas una transferencia|mand[ae]me (\d|l\.? ?\d|dinero|plata|pisto|saldo)|envia(me)? (dinero|plata|pisto|saldo)|ocupo (dinero|pisto|un favor|que me)|me prest(as|es|aras) (dinero|plata|pisto|\d)|me (puedes|podes) prestar|send (me )?money|send me \$|can you (send|transfer|lend) me|send (me )?\$\d|lend me)/g },
    { id: 'payFee', group: 'request', severity: 'high',
      re: /((solo|unicamente|solamente) (paga|pague|pagar|pagas|deposita|deposite|depositar|cancela|cancele)|(necesita|necesitas|tiene que|tienes que|debe|debes) (pagar|depositar|cancelar) (l\.? ?\d|\$|una|un|el|la)|pag(a|ue|ar|o|uen) (el |la |los |de |una |un )?(envio|comision|arancel|impuesto|tarifa|cargo|deposito|inscripcion|liberacion|desembolso|seguro|traspaso|gastos)|(comision|arancel|tarifa|cargo|inscripcion) de (l\.?|lps\.?|\$|usd)? ?\d|deposite? l\.? ?\d[\d,.]* (a la cuenta|de comision)|para (liberarl[oa]|reclamarl[oa]|recibirl[oa]|el traspaso|el desembolso)|to claim (it|your)|pay (the |a |only )?(fee|shipping|customs)|(shipping|processing|customs|release) fee)/g },
    { id: 'askCode', group: 'request', severity: 'critical', special: true },
    { id: 'personalData', group: 'request', severity: 'high',
      re: /(numero de (tu |su )?tarjeta|fecha de (vencimiento|expiracion)|\bcvv\b|\bcvc\b|codigo cvv|(tu|su) (numero de )?(dni|identidad|rtn)|numero de identidad|usuario y (clave|contrasena)|(tu|su) (clave|contrasena|pin)( de| del| bancari)|datos (personales|bancarios)|nombre completo y|card number|social security|your (password|pin)\b)/g },
    { id: 'remoteAccess', group: 'request', severity: 'high',
      re: /(anydesk|teamviewer|rustdesk|quicksupport|ultraviewer|supremo|acceso remoto|control remoto|remote access|screen ?share|comparte (tu|la) pantalla)/g },
    { id: 'verifyAccount', group: 'request', severity: 'medium',
      re: /((verifi|valid|confirm)(ca|que|car|ar|e|a|ue) (tu|su|sus|tus) (cuenta|identidad|datos|usuario|informacion)|actuali(za|ce|zar|ze) (tus|sus) (datos|informacion|metodo de pago)|reactiv(a|e|ar)(la)? (tu|su) (cuenta|tarjeta)|(verify|confirm|validate) your (account|identity|information|details)|update your (billing|details|information|payment))/g },
    { id: 'callNumber', group: 'request', severity: 'medium', special: true },
    { id: 'payNow', group: 'request', severity: 'medium',
      re: /((pague|paga|pagar|cancele) (hoy|ya|ahora|aqui|en (el|este|la) (siguiente )?(enlace|link))|(para|a) pagar (tu|su|el|la)|pague con descuento|pay (now|here|today)|(pasame|mandame|enviame|deposita(me)?) el pago|pag(a|o|ue) (por|con|via) tigo ?money)/g },
    { id: 'payMethod', group: 'request', severity: 'low',
      re: /(por tigo ?money|tarjeta(s)? de regalo|gift ?cards?|bitcoin|\busdt\b|criptomonedas?|western union|moneygram|remesa)/g },
    { id: 'replyKeyword', group: 'request', severity: 'low',
      re: /(responde (si|con la palabra|con tu)|responda (si|con la palabra|con su)|envia (si|la palabra)|reply (yes|with))/g },
    { id: 'offPlatform', group: 'request', severity: 'low',
      re: /(escribe(me)? (al|por) (whatsapp|telegram|interno)|contacta(me|nos)? (por|al) (telegram|whatsapp)|por telegram|via telegram|\btelegram\b)/g },
    // Bait (the story)
    { id: 'askNewNumber', group: 'bait', severity: 'high',
      re: /(numero nuevo|nuevo numero|cambie (de|mi) numero|este es mi numero|mi otro numero|guard(a|e|alo) este numero|perdi mi (telefono|cel|celular)|se me (arruino|dano|quebro|perdio|cayo) el (cel|telefono|celular)|escribiendo de este numero|new number|changed my number|broke my phone|lost my phone)/g },
    { id: 'prize', group: 'bait', severity: 'medium',
      re: /(ganaste|has ganado|ha ganado|usted gano|ganador(a)? (de|del)|sido seleccionad[oa]|fue (el )?ganador|premio|sorteo|rifa|ruleta|regalo gratis|bono gratis|you won|you('ve| have) won|winner|prize|lottery|loteria|gift card|free (robux|vbucks|v-bucks|gift))/g },
    { id: 'investment', group: 'bait', severity: 'high',
      re: /(duplica (tu|su) dinero|ganancias? garantizad|inversion segura|invierte (desde|solo|hoy|ya)|\d+ ?% (semanal|diario|mensual)|criptomoneda|forex|trading|rentabilidad|plataforma de inversion|guaranteed (returns|profit)|double your)/g },
    { id: 'job', group: 'bait', severity: 'medium',
      re: /(trabajo (desde casa|facil|de medio tiempo|medio tiempo)|trabaja desde casa|desde (tu|su) casa|gana(r|s)? (dinero|l\.? ?\d|\$\d)|ingresos extra|sin experiencia|oferta (laboral|de empleo)|dando like|dar like|resenas de \d|por cada resena|pago diario|pagos diarios|recursos humanos de|work from home|easy money|earn \$|per day)/g },
    { id: 'package', group: 'bait', severity: 'low',
      re: /(paquete|envio|aduana|retenid[oa]|entrega fallida|no (pudimos|pudo ser) entregad|no pudimos entregar|guia de rastreo|direccion incompleta|parcel|delivery|customs|shipment)/g },
    { id: 'accountThreat', group: 'bait', severity: 'medium',
      re: /((cuenta|tarjeta|usuario|servicio|linea|licencia) (ha sido |fue |sera |esta |quedara )?(bloquead|suspendid|desactivad|cancelad|eliminad|restringid|limitad|vencid)|sera (eliminad|suspendid|desactivad|bloquead|cancelad)|(bloquead|suspendid|eliminad)[oa] (en|por)|movimientos? sospechos|actividad (inusual|sospechosa)|acceso no autorizado|cargo no reconocido|inconsistencias|(account|card) (has been |was |is |will be )?(locked|suspended|limited|disabled|deleted)|unusual activity)/g },
    { id: 'govBenefit', group: 'bait', severity: 'medium',
      re: /(bono (tecnologico|solidario|vida mejor|del gobierno|de ayuda|navideno)|subsidio|beneficio del gobierno|ayuda (economica )?del gobierno|el gobierno (entrega|regala|da)|reembolso de impuestos|devolucion de impuestos|tax refund|government (grant|benefit)|stimulus)/g },
    { id: 'loan', group: 'bait', severity: 'medium',
      re: /(prestamo (inmediato|rapido|facil|sin)|sin buro|sin revisar buro|credito (inmediato|aprobado|sin)|aprobado en \d+ minutos|loan approved)/g },
    { id: 'techVirus', group: 'bait', severity: 'medium',
      re: /(tiene virus|esta infectad|infectado|licencia (de windows )?(vencio|vencida|expiro)|soporte tecnico|tecnico (lo|le) (arregle|ayude)|has a virus|is infected|tech(nical)? support)/g },
    { id: 'tooGood', group: 'bait', severity: 'medium',
      re: /(de por vida|gratis para siempre|cuentas? (premium|de netflix|de spotify|de disney)|a mitad de precio|super barat|regalad[oa]|lifetime (account|access)|90 ?% (de )?descuento)/g },
    { id: 'curiosity', group: 'bait', severity: 'low',
      re: /((eres tu|sos vos|sos tu) (en|el de|la de) (este|el|esta|la) (video|foto)|mira este video|(sales|salis) (vos |tu )?en (este|un) video|is this you|are you in this video)/g },
    // Pressure
    { id: 'urgency', group: 'pressure', severity: 'medium',
      re: /(urgente|urgencia|de inmediato|inmediatamente|ahora mismo|ahorita|hoy mismo|ultimo aviso|ultima oportunidad|(24|48) ?horas|vence hoy|expira|antes de que|cupos limitados|en las proximas|sin falta|apurate|please hurry|urgent|immediately|final notice|last chance|expires|within (24|48)|right now|now at)/g },
    { id: 'threat', group: 'pressure', severity: 'medium',
      re: /(multa|demanda|policia|arresto|embargo|accion legal|denuncia|sera multad|corte (de|del) servicio|evite el corte|fine\b|lawsuit|police|arrest|legal action)/g },
    { id: 'genericGreeting', group: 'context', severity: 'low',
      re: /(estimad[oa] (cliente|usuario|tarjetahabiente)|querid[oa] (cliente|usuario)|senor cliente|dear (customer|user|client|member))/g }
  ];

  var CODE_WORDS = /(codigo|code|\bpin\b|\botp\b|token|clave dinamica|codigo de verificacion|digitos)/g;
  var ASK_WORDS = /(envi(a|e|ame|anos|enos|alo)|reenvi|mand(a|e|ame)(lo|melo)?|pas(a|e|as|ame|amelo)|compart(e|a|elo|irlo)|dict(a|e)|proporcion|brind(a|e)|digit(a|e)|dime|diga|decime|responda|confirm(a|e|ame)|me lo (puedes|podes|podrias)|podrias (mandar|enviar|pasar|reenviar)|send|share|tell me|reply|forward|give me)/;
  var SAFE_OTP = /(no (lo |la |este codigo )?compart|nunca (lo |la )?compart|no se lo (des|de)|no lo (des|de) a nadie|nunca te (lo )?pediremos|do not share|don'?t share|never share|if you did not request|si no (lo )?solicitaste)/;
  var PHONE = /(\+?504[\s-]?)?\b[2-9]\d{3}[\s-]?\d{4}\b|\+?1[\s-]?\(?\d{3}\)?[\s-]?\d{3}[\s-]?\d{4}/g;
  var CALL_WORDS = /(llam(a|e|ar|anos|enos)|comuniquese|comunicate|marca(r)? al|escrib(a|e|enos|eme) al|call|contact us|text us)/;
  // Real alerts tell you to use the number on the back of your card / official channels, and give no link.
  var LEGIT_HINT = /(al reverso de (su|tu) tarjeta|numero (oficial )?que aparece|canales oficiales|nunca te (pediremos|solicitaremos)|we will never ask)/;
  var NOTIFICATION = /(compra aprobada|transferencia recibida|recarga de l\.? ?\d+ fue exitosa|fue exitosa|saldo disponible|tu recibo|your receipt|has been delivered|was delivered|acumulaste|gracias por tu compra)/;

  // Combinations: bait + request = a known type of scam.
  var COMBOS = [
    { type: 'accountTakeover', needs: ['askCode'] },
    { type: 'family', needs: ['askNewNumber', ['money', 'payFee', 'urgency']] },
    { type: 'techSupport', needs: [['remoteAccess', 'techVirus'], ['remoteAccess', 'callNumber']] },
    { type: 'prize', needs: ['prize', ['payFee', 'personalData', 'callNumber', 'badLink', 'money', 'verifyAccount']] },
    { type: 'delivery', needs: ['package', ['payFee', 'badLink', 'verifyAccount']] },
    { type: 'investment', needs: ['investment'] },
    { type: 'job', needs: ['job', ['payFee', 'offPlatform', 'money', 'callNumber', 'replyKeyword', 'payMethod']] },
    { type: 'fine', needs: ['threat', ['payNow', 'payFee', 'badLink', 'unknownLink']] },
    { type: 'shopping', needs: ['tooGood', ['payMethod', 'payNow', 'money', 'payFee', 'badLink']] },
    { type: 'loan', needs: ['loan', ['payFee', 'money']] },
    { type: 'government', needs: ['govBenefit', ['badLink', 'personalData', 'verifyAccount', 'payFee']] },
    { type: 'bankPhishing', needs: [['brandMismatch', 'accountThreat'], ['badLink', 'callNumber', 'verifyAccount', 'personalData', 'brandMismatch']] },
    { type: 'curiosityLink', needs: ['curiosity', ['badLink', 'unknownLink']] },
    { type: 'feeTrap', needs: ['payFee'] }
  ];

  function tokensOf(s) { return s.split(/[^a-z0-9]+/).filter(Boolean); }

  // ---------------------------------------------------------------- analyze
  /**
   * Analyze a message.
   * @param {string} message
   * @returns {object} { valid, score, level, type, findings[], highlights[], links[], truncated, breakdown }
   */
  function analyzeMessage(message) {
    var original = String(message || '').slice(0, MAX_TEXT);
    var cleaned = clean(original);
    var text = cleaned.text;
    var findings = [], spans = [], has = {};
    if (!text.trim()) return { valid: false, findings: [], links: [], highlights: [] };

    function span(start, end, id, severity) {
      var a = cleaned.map[start], b = cleaned.map[Math.min(end, cleaned.map.length) - 1];
      if (a === undefined || b === undefined) return;
      var last = Array.from(original.slice(b, b + 2))[0] || '';
      var end2 = b + last.length;
      // Mark whole words: "bloquead" -> "bloqueada"
      while (end2 < original.length && /[A-Za-zÀ-ÿ]/.test(original[end2])) end2++;
      while (a > 0 && /[A-Za-zÀ-ÿ]/.test(original[a - 1])) a--;
      spans.push({ start: a, end: end2, id: id, severity: severity });
    }
    function add(id, severity, detail) {
      if (has[id]) return;
      has[id] = true;
      findings.push({ id: id, severity: severity, detail: detail || '' });
    }
    function rule(r) {
      r.re.lastIndex = 0;
      var m, first = null;
      while ((m = r.re.exec(text)) !== null) {
        // The detail quotes the ORIGINAL words (with accents), not the cleaned ones.
        if (!first) first = original.slice(cleaned.map[m.index], cleaned.map[m.index + m[0].length - 1] + 1).trim() || m[0].trim();
        span(m.index, m.index + m[0].length, r.id, r.severity);
        if (m[0].length === 0) r.re.lastIndex++;
      }
      if (first) add(r.id, r.severity, first);
    }

    var safeOtp = SAFE_OTP.test(text);
    var notification = NOTIFICATION.test(text);

    // 1) Codes: asking for a code is the #1 account-takeover trick.
    CODE_WORDS.lastIndex = 0;
    var codeHit = CODE_WORDS.exec(text);
    if (codeHit) {
      if (safeOtp && !/(reenvi|me lo (puedes|podes)|pasamelo|forward)/.test(text)) add('otpWarning', 'info', codeHit[0]);
      else if (ASK_WORDS.test(text)) {
        add('askCode', 'critical', codeHit[0]);
        span(codeHit.index, codeHit.index + codeHit[0].length, 'askCode', 'critical');
      }
    }

    // 2) Rules
    RULES.forEach(function (r) {
      if (r.special) return;
      if (r.id === 'personalData' && safeOtp) return;   // "never share your code" is not a request
      rule(r);
    });

    // 3) "Call / write to this number"
    PHONE.lastIndex = 0;
    var ph = PHONE.exec(text);
    if (ph && CALL_WORDS.test(text) && !LEGIT_HINT.test(text)) {
      add('callNumber', 'medium', original.slice(cleaned.map[ph.index], cleaned.map[ph.index + ph[0].length - 1] + 1).trim());
      span(ph.index, ph.index + ph[0].length, 'callNumber', 'medium');
    }

    // 4) Shouting
    var letters = original.replace(/[^A-Za-zÁÉÍÓÚÑáéíóúñ]/g, '');
    var caps = original.replace(/[^A-ZÁÉÍÓÚÑ]/g, '');
    if ((original.match(/!/g) || []).length >= 3 || (letters.length >= 20 && caps.length / letters.length > 0.5)) add('shouting', 'low');

    // 5) Links
    var links = phishing.extractUrls(original).map(function (u) {
      var r = phishing.analyzeUrl(u);
      return { url: u, level: r.valid ? r.level : 'medium', score: r.valid ? r.score : 0,
               registeredDomain: r.registeredDomain || '', official: !!r.official, result: r };
    });
    links.forEach(function (l) {
      var at = original.indexOf(l.url);
      if (at !== -1 && l.level !== 'low' && !l.official) spans.push({ start: at, end: at + l.url.length, id: 'link', severity: l.level === 'high' ? 'critical' : 'high' });
    });
    if (links.some(function (l) { return !l.official; })) has.unknownLink = true;
    var rank = { low: 0, medium: 1, high: 2 };
    var worst = links.reduce(function (w, l) { return !l.official && rank[l.level] > rank[w] ? l.level : w; }, 'low');
    if (worst === 'high') { add('dangerousLink', 'critical', links.filter(function (l) { return l.level === 'high' && !l.official; })[0].url); has.badLink = true; }
    else if (worst === 'medium') { add('suspiciousLink', 'high', links.filter(function (l) { return l.level === 'medium'; })[0].url); has.badLink = true; }

    // 6) A brand is named: do its links go to its official site?
    var tokens = tokensOf(text);
    var brandHit = null;
    DATA.BRANDS.some(function (b) {
      var named = b.keywords.some(function (k) { return k.length >= 6 ? text.indexOf(k) !== -1 : tokens.indexOf(k) !== -1; }) ||
                  tokens.indexOf(b.name.toLowerCase()) !== -1;
      if (named) { brandHit = b; return true; }
      return false;
    });
    if (brandHit) {
      var official = links.some(function (l) { return brandHit.domains.indexOf(l.registeredDomain) !== -1; });
      if (links.length && !official) { add('brandLinkMismatch', 'high', brandHit.name); has.brandMismatch = true; }
      else if (official) add('officialLink', 'info', brandHit.name);
      else if (has.accountThreat || has.callNumber || has.personalData || has.verifyAccount) { add('brandRequest', 'medium', brandHit.name); has.brandMismatch = true; }
      else add('brandMentioned', 'info', brandHit.name);
    }

    // 7) Which kind of scam is it? (first combination that matches)
    var type = null;
    COMBOS.some(function (c) {
      var ok = c.needs.every(function (need) {
        return Array.isArray(need) ? need.some(function (n) { return has[n]; }) : has[need];
      });
      if (ok) { type = c.type; return true; }
      return false;
    });
    if (!type && has.badLink) type = 'phishingLink';
    if (!type && has.unknownLink && (has.payNow || has.payFee || has.personalData || has.verifyAccount)) type = 'phishingLink';
    if (type && type !== 'accountTakeover' && type !== 'feeTrap' && type !== 'phishingLink') add('combo', 'high', type);

    // 8) Legit signs
    var legitSigns = [];
    if (safeOtp && !has.askCode) legitSigns.push('safeOtp');
    if (LEGIT_HINT.test(text) && !has.badLink) legitSigns.push('officialChannel');
    if (notification && !has.badLink && !has.payFee && !has.money) legitSigns.push('notification');
    if (has.officialLink && !has.badLink) legitSigns.push('officialLinkOnly');

    var score = findings.reduce(function (s, f) { return s + WEIGHT[f.severity]; }, 0) - legitSigns.length * 15;
    score = Math.max(0, Math.min(score, 100));
    var hasCritical = findings.some(function (f) { return f.severity === 'critical'; });
    var level = (score >= 40 || hasCritical || (type && type !== 'feeTrap')) ? 'high' : score >= 20 ? 'medium' : 'low';
    if (type === 'feeTrap' && level === 'low') level = 'medium';

    var order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    findings.sort(function (a, b) { return order[a.severity] - order[b.severity]; });
    spans.sort(function (a, b) { return a.start - b.start || b.end - a.end; });
    var highlights = [];
    spans.forEach(function (s) {
      var last = highlights[highlights.length - 1];
      if (last && s.start < last.end) { if (s.end > last.end) last.end = s.end; if (order[s.severity] < order[last.severity]) { last.severity = s.severity; last.id = s.id; } }
      else highlights.push({ start: s.start, end: s.end, id: s.id, severity: s.severity });
    });

    return { valid: true, score: score, level: level, type: level === 'low' ? null : type, findings: findings, highlights: highlights,
             legitSigns: legitSigns, links: links, cleanedText: text,
             truncated: String(message || '').length > MAX_TEXT,
             breakdown: findings.map(function (f) { return { id: f.id, points: WEIGHT[f.severity] }; })
               .concat(legitSigns.map(function (id) { return { id: 'legit:' + id, points: -15 }; })) };
  }

  var api = { analyzeMessage: analyzeMessage, clean: clean, MAX_TEXT: MAX_TEXT };
  root.SworfishGuard = root.SworfishGuard || {};
  root.SworfishGuard.scam = Object.freeze(api);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
