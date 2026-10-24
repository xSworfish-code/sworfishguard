/*!
 * SworfishGuard — Scam Message Detector (SMS, WhatsApp, email)
 *
 * Reads a pasted message and looks for the tricks scammers use: asking for
 * verification codes, urgency, prizes, money requests, "new number" family
 * scams, fake package fees, impersonated brands with foreign links... Every
 * link found inside the message is also checked by the phishing detector.
 *
 * Everything runs locally; the message never leaves the browser.
 * Heuristic and educational: it explains signals, it cannot prove intent.
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

  // Patterns run on lowercase text without accents ("contraseña" -> "contrasena").
  var RULES = [
    { id: 'askNewNumber', severity: 'high', re: /(numero nuevo|nuevo numero|cambie (de|mi) numero|este es mi numero|mi otro numero|new number|changed my number)/ },
    { id: 'money', severity: 'high', re: /(transferencia|transfiere|transferir|deposit[ao]|depositar|enviar dinero|envia(me)? dinero|prest(a|ame) dinero|giro|remesa|recarga|tarjeta de regalo|gift ?card|bitcoin|usdt|send money|wire transfer|\btransfer\b|\bpay\b|payment|pago pendiente|pague|pagar)/ },
    { id: 'prize', severity: 'high', re: /(ganaste|has ganado|ha ganado|ganador|felicidades|felicitaciones|premio|sorteo|seleccionad[oa]|you won|you('ve| have) won|winner|congratulations|prize|lottery|loteria|bono gratis|regalo gratis)/ },
    { id: 'investment', severity: 'high', re: /(duplica tu dinero|ganancias garantizadas|inversion segura|invierte (desde|solo)|criptomoneda|forex|trading|rentabilidad|guaranteed (returns|profit)|double your)/ },
    { id: 'personalData', severity: 'high', re: /(numero de (tu |su )?tarjeta|fecha de (vencimiento|expiracion)|codigo de seguridad|cvv|cvc|tarjeta de identidad|numero de identidad|\bdni\b|datos personales|card number|social security|identity number)/ },
    { id: 'urgency', severity: 'medium', re: /(urgente|urgencia|inmediat|de inmediato|ahora mismo|hoy mismo|ultimo aviso|ultima oportunidad|(24|48) ?horas|expira|vence hoy|suspendid|bloquead|desactivad|cancelad[ao]|restringid|urgent|immediately|final notice|last chance|expires|suspended|locked|within (24|48))/ },
    { id: 'threat', severity: 'medium', re: /(multa|demanda|policia|arresto|embargo|accion legal|denuncia|deuda pendiente|fine\b|lawsuit|police|arrest|legal action)/ },
    { id: 'package', severity: 'medium', re: /(paquete|envio|aduana|retenid[oa]|entrega fallida|no pudimos entregar|guia de rastreo|tracking|parcel|delivery|customs|shipment)/ },
    { id: 'job', severity: 'medium', re: /(trabajo desde casa|trabaja desde casa|gana dinero|ingresos extra|sin experiencia|oferta (laboral|de empleo)|dar like|work from home|easy money|earn \$|per day)/ },
    { id: 'genericGreeting', severity: 'low', re: /(estimad[oa] (cliente|usuario)|querid[oa] (cliente|usuario)|dear (customer|user|client))/ }
  ];

  var CODE_WORDS = /(codigo|code|\bpin\b|\botp\b|token|clave|contrasena|password|cvv)/;
  var ASK_WORDS = /(envi(a|e|ame|anos|enos)|reenvi|compart(e|a|elo)|dict(a|e)|proporcion|brind(a|e)|digit(a|e)|ingres(a|e)|dime|diga|responda|confirm|send|share|tell|reply|forward)/;
  var SAFE_OTP = /(no (lo |la )?compart|nunca compart|no se lo (des|de)|do not share|don'?t share|never share)/;
  var PHONE = /(\+?504[\s-]?)?\b[2-9]\d{3}[\s-]?\d{4}\b/;
  var CALL_WORDS = /(llam|whatsapp|escrib|marca|comunicate|contact|call|text us)/;

  function normalize(text) {
    return String(text || '').slice(0, MAX_TEXT).toLowerCase()
      .normalize('NFD').replace(/[̀-ͯ]/g, '');
  }

  function firstMatch(re, text) {
    var m = text.match(re);
    return m ? m[0].trim() : '';
  }

  function tokensOf(s) { return s.split(/[^a-z0-9]+/).filter(Boolean); }

  /**
   * Analyze a message.
   * @param {string} message
   * @returns {object} { score, level, findings[], links[], truncated }
   */
  function analyzeMessage(message) {
    var original = String(message || '');
    var text = normalize(original);
    var findings = [];
    function add(id, severity, detail) { findings.push({ id: id, severity: severity, detail: detail || '' }); }

    if (!text.trim()) return { valid: false, findings: [], links: [] };

    // 1) Requests for verification codes: the #1 account-takeover trick.
    if (CODE_WORDS.test(text)) {
      if (SAFE_OTP.test(text)) add('otpWarning', 'info', firstMatch(CODE_WORDS, text));
      else if (ASK_WORDS.test(text)) add('askCode', 'critical', firstMatch(CODE_WORDS, text));
    }

    // 2) Keyword rules.
    RULES.forEach(function (r) {
      var hit = firstMatch(r.re, text);
      if (hit) add(r.id, r.severity, hit);
    });

    // 3) "Call / WhatsApp this number".
    if (PHONE.test(text) && CALL_WORDS.test(text)) add('callNumber', 'medium', firstMatch(PHONE, text));

    // 4) Shouting: lots of "!!!" or mostly capital letters.
    var letters = original.replace(/[^A-Za-zÁÉÍÓÚÑáéíóúñ]/g, '');
    var caps = original.replace(/[^A-ZÁÉÍÓÚÑ]/g, '');
    if ((original.match(/!/g) || []).length >= 3 || (letters.length >= 20 && caps.length / letters.length > 0.5)) {
      add('shouting', 'low');
    }

    // 5) Links: every one is analyzed by the phishing detector.
    var links = phishing.extractUrls(original).map(function (u) {
      var r = phishing.analyzeUrl(u);
      return { url: u, level: r.valid ? r.level : 'medium', score: r.valid ? r.score : 0,
               registeredDomain: r.registeredDomain || '', official: !!r.official, result: r };
    });
    var worst = links.reduce(function (w, l) {
      var rank = { low: 0, medium: 1, high: 2 };
      return rank[l.level] > rank[w] ? l.level : w;
    }, 'low');
    if (worst === 'high') add('dangerousLink', 'critical', links.filter(function (l) { return l.level === 'high'; })[0].url);
    else if (worst === 'medium') add('suspiciousLink', 'high', links.filter(function (l) { return l.level === 'medium'; })[0].url);

    // 6) A brand is named but the links do not go to its official domain.
    var tokens = tokensOf(text);
    var brandHit = null;
    DATA.BRANDS.some(function (b) {
      var named = b.keywords.some(function (k) { return k.length >= 6 ? text.indexOf(k) !== -1 : tokens.indexOf(k) !== -1; }) ||
                  text.indexOf(normalize(b.name)) !== -1;
      if (named) { brandHit = b; return true; }
      return false;
    });
    if (brandHit) {
      var official = links.some(function (l) { return brandHit.domains.indexOf(l.registeredDomain) !== -1; });
      if (links.length && !official) {
        add('brandLinkMismatch', 'high', brandHit.name);
      } else if (official) {
        add('officialLink', 'info', brandHit.name);
      } else {
        add('brandMentioned', 'info', brandHit.name);
      }
    }

    var score = Math.min(findings.reduce(function (s, f) { return s + WEIGHT[f.severity]; }, 0), 100);
    var hasCritical = findings.some(function (f) { return f.severity === 'critical'; });
    var level = (score >= 40 || hasCritical) ? 'high' : score >= 20 ? 'medium' : 'low';
    var order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    findings.sort(function (a, b) { return order[a.severity] - order[b.severity]; });

    return { valid: true, score: score, level: level, findings: findings, links: links,
             truncated: original.length > MAX_TEXT,
             breakdown: findings.map(function (f) { return { id: f.id, points: WEIGHT[f.severity] }; }) };
  }

  var api = { analyzeMessage: analyzeMessage, MAX_TEXT: MAX_TEXT };
  root.SworfishGuard = root.SworfishGuard || {};
  root.SworfishGuard.scam = Object.freeze(api);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
