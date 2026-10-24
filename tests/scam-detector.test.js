const test = require('node:test');
const assert = require('node:assert/strict');
const { analyzeMessage, MAX_TEXT } = require('../js/scam-detector.js');

const ids = (r) => r.findings.map((f) => f.id);

test('fake bank SMS with a look-alike link is a likely scam', () => {
  const r = analyzeMessage('BANCO ATLANTIDA: Su cuenta ha sido bloqueada. Ingrese en bancatlan-seguridad.top/acceso antes de 24 horas.');
  assert.equal(r.level, 'high');
  assert.ok(ids(r).includes('dangerousLink'));
  assert.ok(ids(r).includes('brandLinkMismatch'));
  assert.ok(ids(r).includes('urgency'));
});

test('"new number" family scam asking for money', () => {
  const r = analyzeMessage('Hola mamá, este es mi número nuevo. Necesito que me hagas una transferencia urgente.');
  assert.equal(r.level, 'high');
  assert.ok(ids(r).includes('askNewNumber'));
  assert.ok(ids(r).includes('money'));
});

test('asking to forward a verification code is critical', () => {
  const r = analyzeMessage('Hola, te enviamos un código por error, ¿me lo puedes reenviar? Es urgente');
  assert.ok(ids(r).includes('askCode'));
  assert.equal(r.findings[0].severity, 'critical');
});

test('a legitimate one-time code that says "do not share" is not flagged', () => {
  const r = analyzeMessage('Tu código de verificación de Google es 482913. No lo compartas con nadie.');
  assert.equal(r.level, 'low');
  assert.ok(ids(r).includes('otpWarning'));
  assert.ok(!ids(r).includes('askCode'));
});

test('English scams are detected too', () => {
  const r = analyzeMessage('Congratulations! You won a prize. Send money to claim it within 24 hours.');
  assert.equal(r.level, 'high');
  assert.ok(ids(r).includes('prize'));
});

test('official links are recognized', () => {
  const r = analyzeMessage('Banco Atlántida le recuerda que puede consultar su saldo en https://www.bancatlan.hn');
  assert.equal(r.level, 'low');
  assert.ok(ids(r).includes('officialLink'));
});

test('normal messages are low risk', () => {
  assert.equal(analyzeMessage('¿Nos vemos mañana a las 3 para ensayar?').level, 'low');
});

test('empty input is invalid and long input is truncated', () => {
  assert.equal(analyzeMessage('   ').valid, false);
  assert.equal(analyzeMessage('hola '.repeat(2000)).truncated, true);
  assert.equal(MAX_TEXT, 5000);
});
