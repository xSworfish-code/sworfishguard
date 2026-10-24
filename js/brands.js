/*!
 * SworfishGuard — Brand & threat data used by the phishing and scam detectors.
 *
 * Every "domains" entry is the brand's REAL official registered domain.
 * Honduran entries were verified in October 2026 against the brands' own
 * websites, Wikipedia infoboxes and app-store listings:
 *   - Banco Atlántida  -> bancatlan.hn            (www.bancatlan.hn, app.bancatlan.hn)
 *   - BAC Credomatic   -> baccredomatic.com       (www.baccredomatic.com/es-hn)
 *   - Ficohsa          -> ficohsa.hn, ficohsa.com (www.ficohsa.hn, ficohsa.com/hn/interbanca)
 *   - Banpaís          -> banpais.hn, corporacionbi.com (www.banpais.hn; owned by Banco Industrial)
 *   - Banco de Occidente -> bancocci.hn           (Wikipedia: Banco de Occidente (Honduras))
 *   - Davivienda Honduras -> davivienda.com.hn    (Wikipedia: Banco Davivienda Honduras)
 *   - Tigo Honduras    -> tigo.com.hn
 *   - Claro Honduras   -> claro.com.hn
 *   - Honducor (Correos de Honduras) -> honducor.gob.hn
 *
 * Risky TLDs combine the Interisle "Phishing Landscape 2025" report (top
 * phishing scores: .xin, .bond, .help, .win, .cfd), Spamhaus domain reputation
 * updates (.top called out as an abuse hotspot) and TLDs long known for free
 * or very cheap abusive registrations.
 *
 * To add a brand: copy an entry, list its keywords (lowercase, no accents)
 * and its official domains. Keywords shorter than 6 characters only match a
 * whole word inside the domain (so "tigo" does not match "contigo").
 *
 * Author: Asaf Rojas (Sworfish Tech) — MIT License
 */
(function (root) {
  'use strict';

  var BRANDS = [
    // --- Honduras: banks ------------------------------------------------------
    { name: 'Banco Atlántida', category: 'bank', country: 'HN', keywords: ['bancatlan', 'atlantida'], domains: ['bancatlan.hn'] },
    { name: 'BAC Credomatic', category: 'bank', country: 'HN', keywords: ['baccredomatic', 'credomatic', 'bachonduras'], domains: ['baccredomatic.com'] },
    { name: 'Ficohsa', category: 'bank', country: 'HN', keywords: ['ficohsa'], domains: ['ficohsa.hn', 'ficohsa.com'] },
    { name: 'Banpaís', category: 'bank', country: 'HN', keywords: ['banpais'], domains: ['banpais.hn', 'corporacionbi.com'] },
    { name: 'Banco de Occidente', category: 'bank', country: 'HN', keywords: ['bancocci', 'bancodeoccidente'], domains: ['bancocci.hn'] },
    { name: 'Davivienda', category: 'bank', country: 'HN', keywords: ['davivienda'], domains: ['davivienda.com.hn', 'davivienda.com'] },
    // --- Honduras: telecom, mail -------------------------------------------
    { name: 'Tigo', category: 'telecom', country: 'HN', keywords: ['tigo', 'tigomoney', 'mitigo'], domains: ['tigo.com.hn', 'tigo.com', 'tigomoney.com'] },
    { name: 'Claro', category: 'telecom', country: 'HN', keywords: ['claro'], domains: ['claro.com.hn', 'claro.com'] },
    { name: 'Honducor', category: 'shipping', country: 'HN', keywords: ['honducor', 'correoshonduras'], domains: ['honducor.gob.hn'] },
    // --- Global: payments & remittances ------------------------------------
    { name: 'PayPal', category: 'payments', keywords: ['paypal'], domains: ['paypal.com', 'paypal.me'] },
    { name: 'Western Union', category: 'payments', keywords: ['westernunion'], domains: ['westernunion.com', 'wu.com'] },
    { name: 'Remitly', category: 'payments', keywords: ['remitly'], domains: ['remitly.com'] },
    { name: 'Binance', category: 'payments', keywords: ['binance'], domains: ['binance.com'] },
    // --- Global: accounts & social ------------------------------------------
    { name: 'Google', category: 'account', keywords: ['google', 'gmail'], domains: ['google.com', 'google.hn', 'gmail.com', 'youtube.com', 'youtu.be', 'goo.gl', 'googleusercontent.com'] },
    { name: 'Microsoft', category: 'account', keywords: ['microsoft', 'outlook', 'hotmail', 'office365'], domains: ['microsoft.com', 'microsoftonline.com', 'live.com', 'office.com', 'outlook.com', 'hotmail.com', 'microsoft365.com'] },
    { name: 'Apple', category: 'account', keywords: ['apple', 'icloud', 'appleid'], domains: ['apple.com', 'icloud.com'] },
    { name: 'Facebook', category: 'social', keywords: ['facebook'], domains: ['facebook.com', 'fb.com', 'fb.me', 'messenger.com', 'meta.com'] },
    { name: 'Instagram', category: 'social', keywords: ['instagram'], domains: ['instagram.com'] },
    { name: 'WhatsApp', category: 'social', keywords: ['whatsapp'], domains: ['whatsapp.com', 'whatsapp.net', 'wa.me'] },
    { name: 'TikTok', category: 'social', keywords: ['tiktok'], domains: ['tiktok.com'] },
    // --- Global: shopping, streaming ----------------------------------------
    { name: 'Amazon', category: 'shopping', keywords: ['amazon'], domains: ['amazon.com', 'amazon.com.mx', 'amazon.es'] },
    { name: 'Netflix', category: 'streaming', keywords: ['netflix'], domains: ['netflix.com'] },
    { name: 'Spotify', category: 'streaming', keywords: ['spotify'], domains: ['spotify.com'] },
    // --- Global: gaming ------------------------------------------------------
    { name: 'Steam', category: 'gaming', keywords: ['steam', 'steampowered', 'steamcommunity'], domains: ['steampowered.com', 'steamcommunity.com'] },
    { name: 'Roblox', category: 'gaming', keywords: ['roblox'], domains: ['roblox.com'] },
    { name: 'Discord', category: 'gaming', keywords: ['discord'], domains: ['discord.com', 'discord.gg', 'discordapp.com'] },
    { name: 'Epic Games', category: 'gaming', keywords: ['epicgames', 'fortnite'], domains: ['epicgames.com', 'fortnite.com'] },
    // --- Global: shipping ----------------------------------------------------
    { name: 'DHL', category: 'shipping', keywords: ['dhl'], domains: ['dhl.com'] },
    { name: 'FedEx', category: 'shipping', keywords: ['fedex'], domains: ['fedex.com'] },
    { name: 'UPS', category: 'shipping', keywords: ['ups'], domains: ['ups.com'] }
  ];

  var RISKY_TLDS = [
    // Interisle Phishing Landscape 2025 (highest phishing scores)
    'xin', 'bond', 'help', 'win', 'cfd',
    // Spamhaus abuse hotspot
    'top',
    // Free / ultra-cheap TLDs with long abuse history
    'tk', 'ml', 'ga', 'cf', 'gq',
    // Frequently abused new gTLDs
    'xyz', 'icu', 'buzz', 'cyou', 'sbs', 'click', 'link', 'rest', 'cam', 'monster',
    'support', 'work', 'fit',
    // Confusing file-extension TLDs
    'zip', 'mov'
  ];

  // Cheap TLDs used by many legitimate sites too: only a small warning.
  var CAUTION_TLDS = ['live', 'shop', 'online', 'site', 'info', 'store', 'app'];

  var SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'cutt.ly', 'ow.ly',
    'rb.gy', 'shorturl.at', 'tiny.cc', 'buff.ly', 'rebrand.ly', 't.ly', 'v.gd', 'bl.ink', 's.id'];

  // Free hosting / form services: legitimate, but anyone can publish a fake
  // login page on them, so a "real" domain here proves nothing about the author.
  var FREE_HOSTS = ['github.io', 'netlify.app', 'vercel.app', 'pages.dev', 'workers.dev', 'web.app',
    'firebaseapp.com', 'glitch.me', 'wixsite.com', 'weebly.com', '000webhostapp.com', 'blogspot.com',
    'herokuapp.com', 'onrender.com', 'ngrok-free.app', 'ngrok.io', 'replit.dev', 'forms.gle',
    'sites.google.com', 'docs.google.com', 'storage.googleapis.com', 'r2.dev', 'webflow.io'];

  // Second-level public suffixes, so "ejemplo.com.hn" is read correctly.
  var MULTI_SUFFIXES = [
    'com.hn', 'org.hn', 'net.hn', 'edu.hn', 'gob.hn', 'co.uk', 'org.uk', 'ac.uk',
    'com.mx', 'gob.mx', 'org.mx', 'com.gt', 'gob.gt', 'com.sv', 'gob.sv', 'com.ni', 'gob.ni',
    'co.cr', 'go.cr', 'com.co', 'gov.co', 'com.ar', 'gob.ar', 'com.br', 'gov.br', 'com.es',
    'com.au', 'co.jp', 'co.in', 'com.pe', 'gob.pe', 'com.ec', 'com.pa', 'com.do', 'com.cn'
  ];

  var data = { BRANDS: BRANDS, RISKY_TLDS: RISKY_TLDS, CAUTION_TLDS: CAUTION_TLDS, FREE_HOSTS: FREE_HOSTS, SHORTENERS: SHORTENERS, MULTI_SUFFIXES: MULTI_SUFFIXES };
  // Freeze so no other script on the page can tamper with the lists.
  BRANDS.forEach(function (b) { Object.freeze(b.keywords); Object.freeze(b.domains); Object.freeze(b); });
  Object.keys(data).forEach(function (k) { Object.freeze(data[k]); });
  Object.freeze(data);

  root.SworfishGuard = root.SworfishGuard || {};
  root.SworfishGuard.data = data;
  if (typeof module !== 'undefined' && module.exports) module.exports = data;
})(typeof window !== 'undefined' ? window : globalThis);
