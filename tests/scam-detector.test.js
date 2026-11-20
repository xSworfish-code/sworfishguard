const test = require('node:test');
const assert = require('node:assert/strict');
const { analyzeMessage, clean, MAX_TEXT } = require('../js/scam-detector.js');

const ids = (r) => r.findings.map((f) => f.id);

test('fake bank SMS with a look-alike link: bank phishing', () => {
  const r = analyzeMessage('BANCO ATLANTIDA: Su cuenta ha sido bloqueada. Ingrese en bancatlan-seguridad.top/acceso antes de 24 horas.');
  assert.equal(r.level, 'high');
  assert.equal(r.type, 'bankPhishing');
  for (const id of ['dangerousLink', 'brandLinkMismatch', 'urgency', 'accountThreat']) assert.ok(ids(r).includes(id), id);
});

test('"new number" family scam asking for money', () => {
  const r = analyzeMessage('Hola mamá, este es mi número nuevo. Necesito que me hagas una transferencia urgente.');
  assert.equal(r.level, 'high');
  assert.equal(r.type, 'family');
  assert.ok(ids(r).includes('askNewNumber'));
  assert.ok(ids(r).includes('money'));
});

test('asking to forward a verification code is account takeover, even disguised', () => {
  for (const m of ['Hola, te enviamos un código por error, ¿me lo puedes reenviar? Es urgente',
                   'Te mandé un c0dig0 por equivocacion, me lo pasas porfa',
                   'dime el p.i.n. que te llegó']) {
    const r = analyzeMessage(m);
    assert.equal(r.type, 'accountTakeover', m);
    assert.equal(r.findings[0].id, 'askCode', m);
  }
});

test('legitimate one-time codes and bank alerts are not flagged', () => {
  for (const m of ['Tu código de verificación de Google es 482913. No lo compartas con nadie.',
                   'BAC Credomatic: su código de seguridad es 553201. Nunca lo comparta, ni con personal del banco.',
                   'Ficohsa: compra aprobada por L 1,250.00. Si no reconoce esta compra llame al número al reverso de su tarjeta.']) {
    const r = analyzeMessage(m);
    assert.equal(r.level, 'low', m);
    assert.ok(r.legitSigns.length > 0, m);
    assert.equal(r.type, null);
  }
});

test('normal conversations stay low, even when they mention money or favors', () => {
  for (const m of ['¿Nos vemos mañana a las 3 para ensayar?', '¿Me podés pasar los apuntes? No fui hoy',
                   'Ya te pasé lo de la pizza, eran 120 cada uno', 'Ganamos el partido 3 a 1!! Felicidades al equipo']) {
    assert.equal(analyzeMessage(m).level, 'low', m);
  }
});

test('each scam gets its type', () => {
  const cases = {
    delivery: 'HONDUCOR: su paquete está retenido. Pague el arancel de L 45 en honducor-envios.com',
    prize: '¡Felicidades! Ganaste un iPhone. Solo paga L 300 de envío para reclamarlo',
    job: 'Gana L 2,000 diarios desde tu casa dando like a videos. Escríbeme por Telegram',
    investment: 'Invierte hoy y duplica tu dinero, ganancias garantizadas',
    techSupport: 'Su PC tiene virus. Instale AnyDesk para que un técnico lo arregle',
    loan: 'Préstamo inmediato sin buró. Solo deposite L 500 de comisión',
    government: 'Bono tecnológico: regístrate con tu DNI en bonos-hn.click',
    fine: 'Tiene una multa de tránsito. Pague hoy en transito-hn.xyz'
  };
  for (const [type, m] of Object.entries(cases)) assert.equal(analyzeMessage(m).type, type, m);
});

test('English scams are detected too', () => {
  const r = analyzeMessage('Congratulations! You won a prize. Send money to claim it within 24 hours.');
  assert.equal(r.level, 'high');
  assert.equal(r.type, 'prize');
});

test('official links are recognized', () => {
  const r = analyzeMessage('Banco Atlántida le recuerda que puede consultar su saldo en https://www.bancatlan.hn');
  assert.equal(r.level, 'low');
  assert.ok(ids(r).includes('officialLink'));
});

test('cleaning undoes tricks and keeps a map to the original text', () => {
  const c = clean('C0D1G0 de B4nco');
  assert.equal(c.text, 'codigo de banco');
  const z = clean('co​di‌go');
  assert.equal(z.text, 'codigo', 'invisible characters are removed');
  assert.equal(clean('c o d i g o').text, 'codigo');
  assert.equal(clean('Ρaypal').text, 'paypal', 'Greek capital rho looks like P');
  assert.equal(clean('L 3,500 y 2008').text, 'l 3,500 y 2008', 'numbers are not touched');
  assert.equal(c.map.length, c.text.length);
});

test('highlights point at the exact suspicious phrases in the original message', () => {
  const msg = 'Hola mamá, este es mi número nuevo. Necesito que me hagas una transferencia urgente.';
  const r = analyzeMessage(msg);
  const parts = r.highlights.map((h) => msg.slice(h.start, h.end).toLowerCase());
  assert.ok(parts.some((p) => p.includes('número')), parts.join(' | '));
  assert.ok(parts.some((p) => p.includes('transferencia')), parts.join(' | '));
  for (const h of r.highlights) assert.ok(h.start < h.end && h.end <= msg.length);
  const withEmoji = '🎉🎉 Ganaste un premio 🎉 paga L 300 de envío';
  for (const h of analyzeMessage(withEmoji).highlights) {
    const piece = withEmoji.slice(h.start, h.end);
    assert.ok(!/^[\uDC00-\uDFFF]|[\uD800-\uDBFF]$/.test(piece), 'never cuts an emoji in half: ' + piece);
  }
});

test('empty input is invalid and long input is truncated', () => {
  assert.equal(analyzeMessage('   ').valid, false);
  assert.equal(analyzeMessage('hola '.repeat(2000)).truncated, true);
  assert.equal(MAX_TEXT, 5000);
});
