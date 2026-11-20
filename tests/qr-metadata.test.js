const test = require('node:test');
const assert = require('node:assert/strict');
const { classifyPayload, fitSize } = require('../js/qr-scanner.js');
const meta = require('../js/metadata.js');

// ------------------------------------------------------------------ QR
test('QR: links, including ones without http', () => {
  assert.deepEqual(classifyPayload('https://bancatlan.hn/x'), { type: 'url', url: 'https://bancatlan.hn/x' });
  assert.equal(classifyPayload('www.pago-parqueo.xyz/pagar').url, 'http://www.pago-parqueo.xyz/pagar');
  assert.equal(classifyPayload('  ').type, 'empty');
});

test('QR: dangerous schemes are flagged, never treated as links', () => {
  assert.deepEqual(classifyPayload('javascript:alert(1)'), { type: 'dangerous', scheme: 'javascript' });
  assert.equal(classifyPayload('data:text/html;base64,PHNjcmlwdD4=').type, 'dangerous');
});

test('QR: Wi-Fi networks with escapes', () => {
  const w = classifyPayload('WIFI:T:WPA;S:Casa\\;Rojas;P:clave\\:123;H:true;;');
  assert.equal(w.type, 'wifi');
  assert.equal(w.ssid, 'Casa;Rojas');
  assert.equal(w.security, 'WPA');
  assert.equal(w.hidden, true);
  assert.equal(w.passwordLength, 9);
  assert.equal(classifyPayload('WIFI:S:Cafe;T:nopass;;').security, 'open');
  assert.equal(classifyPayload('WIFI:T:WEP;S:Viejo;P:12345;;').security, 'WEP');
});

test('QR: SMS, phone, email, 2FA, crypto and contact cards', () => {
  assert.deepEqual(classifyPayload('SMSTO:+50499998888:Hola, gane un premio'), { type: 'sms', number: '+50499998888', body: 'Hola, gane un premio' });
  assert.deepEqual(classifyPayload('sms:+504123?body=Paga%20aqui'), { type: 'sms', number: '+504123', body: 'Paga aqui' });
  assert.deepEqual(classifyPayload('tel:+50422223333'), { type: 'phone', number: '+50422223333' });
  assert.equal(classifyPayload('mailto:a@b.com?subject=Hola&body=Prueba').subject, 'Hola');
  const otp = classifyPayload('otpauth://totp/GitHub:asaf?secret=JBSWY3DPEHPK3PXP&issuer=GitHub');
  assert.equal(otp.type, 'otp');
  assert.equal(otp.issuer, 'GitHub');
  assert.equal(otp.account, 'asaf');
  const btc = classifyPayload('bitcoin:bc1qxyz?amount=0.5');
  assert.deepEqual([btc.type, btc.coin, btc.address, btc.amount], ['crypto', 'bitcoin', 'bc1qxyz', '0.5']);
  const card = classifyPayload('BEGIN:VCARD\nVERSION:3.0\nFN:Ana Pérez\nTEL;TYPE=CELL:+504 9999-0000\nURL:https://ana.example\nEND:VCARD');
  assert.equal(card.type, 'contact');
  assert.equal(card.name, 'Ana Pérez');
  assert.deepEqual(card.urls, ['https://ana.example']);
});

test('QR: plain text and the query parser ignores __proto__', () => {
  assert.equal(classifyPayload('Mesa 4 - Menú del día').type, 'text');
  const m = classifyPayload('mailto:x@y.com?__proto__=1&subject=ok');
  assert.equal(m.subject, 'ok');
  assert.equal({}.polluted, undefined);
  assert.deepEqual(fitSize(4000, 3000, 1400), { width: 1400, height: 1050 });
  assert.deepEqual(fitSize(300, 200, 1400), { width: 300, height: 200 });
});

// ------------------------------------------------------------ metadata
// Builds a JPEG with an EXIF block: Make, Model, Orientation=6, DateTimeOriginal
// and GPS 14°46'12" N, 88°46'48" W (San Marcos de Ocotepeque area) altitude 1000 m.
function tiffBE() {
  const b = [];
  const u16 = (v) => b.push(v >> 8 & 255, v & 255);
  const u32 = (v) => b.push(v >>> 24 & 255, v >> 16 & 255, v >> 8 & 255, v & 255);
  const entries0 = 5, ifd0 = 8, ifd0Size = 2 + entries0 * 12 + 4;
  const dataStart = ifd0 + ifd0Size;
  const make = 'Apple\0', model = 'iPhone 15\0';
  const exifIfd = dataStart + 16, exifSize = 2 + 12 + 4;
  const date = '2026:11:10 08:30:00\0';
  const dateAt = exifIfd + exifSize;
  const gpsIfd = dateAt + date.length + (date.length % 2), gpsEntries = 6, gpsSize = 2 + gpsEntries * 12 + 4;
  const latAt = gpsIfd + gpsSize, lonAt = latAt + 24, altAt = lonAt + 24;
  b.push(0x4D, 0x4D, 0, 42); u32(ifd0);
  u16(entries0);
  u16(0x010F); u16(2); u32(make.length); u32(dataStart);
  u16(0x0110); u16(2); u32(model.length); u32(dataStart + 6);
  u16(0x0112); u16(3); u32(1); u16(6); u16(0);
  u16(0x8769); u16(4); u32(1); u32(exifIfd);
  u16(0x8825); u16(4); u32(1); u32(gpsIfd);
  u32(0);
  for (const s of [make, model]) for (const c of s) b.push(c.charCodeAt(0));
  while (b.length < exifIfd) b.push(0);
  u16(1); u16(0x9003); u16(2); u32(date.length); u32(dateAt); u32(0);
  for (const c of date) b.push(c.charCodeAt(0));
  while (b.length < gpsIfd) b.push(0);
  u16(gpsEntries);
  u16(1); u16(2); u32(2); b.push(78, 0, 0, 0);                 // N
  u16(2); u16(5); u32(3); u32(latAt);
  u16(3); u16(2); u32(2); b.push(87, 0, 0, 0);                 // W
  u16(4); u16(5); u32(3); u32(lonAt);
  u16(5); u16(1); u32(1); b.push(0, 0, 0, 0);
  u16(6); u16(5); u32(1); u32(altAt);
  u32(0);
  for (const [n, d] of [[14, 1], [46, 1], [12, 1], [88, 1], [46, 1], [48, 1], [1000, 1]]) { u32(n); u32(d); }
  return b;
}
function jpegWithExif() {
  const tiff = tiffBE();
  const app1 = [0x45, 0x78, 0x69, 0x66, 0, 0, ...tiff];
  const len = app1.length + 2;
  const xmp = [...Buffer.from('http://ns.adobe.com/xap/1.0/\0<x/>')];
  const icc = [...Buffer.from('ICC_PROFILE\0\x01\x01data')];
  const com = [...Buffer.from('Foto de Ana')];
  const seg = (m, d) => [0xFF, m, (d.length + 2) >> 8, (d.length + 2) & 255, ...d];
  return Uint8Array.from([0xFF, 0xD8,
    ...seg(0xE0, [...Buffer.from('JFIF\0\x01\x01\0\0\x01\0\x01\0\0')]),
    0xFF, 0xE1, len >> 8, len & 255, ...app1,
    ...seg(0xE1, xmp), ...seg(0xE2, icc), ...seg(0xFE, com),
    ...seg(0xDB, new Array(10).fill(1)),
    0xFF, 0xDA, 0, 4, 1, 2, 0x11, 0x22, 0x33, 0xFF, 0xD9]);
}

test('metadata: reads GPS, phone model and date from a JPEG', () => {
  const info = meta.inspect(jpegWithExif());
  assert.equal(info.format, 'jpeg');
  assert.deepEqual(info.gps, { lat: 14.77, lon: -88.78, altitude: 1000 });
  const f = Object.fromEntries(info.fields.map((x) => [x.id, x.value]));
  assert.equal(f.device, 'Apple iPhone 15');
  assert.equal(f.taken, '2026:11:10 08:30:00');
  assert.equal(f.comment, 'Foto de Ana');
  assert.equal(info.orientation, 6);
  assert.equal(info.risk, 'high');
  assert.ok(info.extras.includes('xmp'));
});

test('metadata: the clean copy keeps the image and rotation but nothing else', () => {
  const original = jpegWithExif();
  const { bytes, removedBytes } = meta.clean(original);
  assert.ok(removedBytes > 100);
  const again = meta.inspect(bytes);
  assert.equal(again.gps, null);
  assert.deepEqual(again.fields, []);
  assert.deepEqual(again.extras, []);
  assert.equal(again.orientation, 6, 'rotation kept so the photo is not sideways');
  assert.equal(again.risk, 'none');
  // image data after the scan marker is byte-for-byte the same
  const tail = (u) => Buffer.from(u.subarray(u.lastIndexOf(0xDA) - 1)).toString('hex');
  assert.equal(tail(bytes), tail(original));
  assert.ok(Buffer.from(bytes).includes(Buffer.from('ICC_PROFILE')), 'color profile kept');
  assert.ok(!Buffer.from(bytes).includes(Buffer.from('iPhone')));
});

test('metadata: PNG text chunks are found and removed', () => {
  const crcless = (type, data) => { const l = data.length; return [l >>> 24, l >> 16 & 255, l >> 8 & 255, l & 255, ...Buffer.from(type), ...data, 0, 0, 0, 0]; };
  const png = Uint8Array.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
    ...crcless('IHDR', new Array(13).fill(0)), ...crcless('tEXt', [...Buffer.from('Author\0Asaf')]),
    ...crcless('IDAT', [1, 2, 3]), ...crcless('IEND', [])]);
  const info = meta.inspect(png);
  assert.equal(info.fields[0].value, 'Author: Asaf');
  assert.equal(info.risk, 'medium');
  const out = meta.clean(png).bytes;
  assert.equal(meta.inspect(out).risk, 'none');
  assert.ok(!Buffer.from(out).includes(Buffer.from('Asaf')));
  assert.ok(Buffer.from(out).includes(Buffer.from('IDAT')));
});

test('metadata: broken or unknown files never crash', () => {
  assert.equal(meta.inspect(Uint8Array.from([1, 2, 3])).supported, false);
  assert.throws(() => meta.clean(Uint8Array.from([1, 2, 3])), /unsupported/);
  const cut = jpegWithExif().subarray(0, 60);       // truncated inside the EXIF
  assert.doesNotThrow(() => meta.inspect(cut));
  // an IFD that points to itself (infinite loop attempt)
  const evil = Uint8Array.from([0xFF, 0xD8, 0xFF, 0xE1, 0, 26, 0x45, 0x78, 0x69, 0x66, 0, 0,
    0x4D, 0x4D, 0, 42, 0, 0, 0, 8, 0, 1, 0x87, 0x69, 0, 4, 0, 0, 0, 1, 0, 0, 0, 8, 0xFF, 0xDA]);
  assert.doesNotThrow(() => meta.inspect(evil));
  assert.equal(meta.detectFormat(Uint8Array.from([0, 0, 0, 0x18, 0x66, 0x74, 0x79, 0x70, 0x68, 0x65, 0x69, 0x63, 0])), 'heic');
});
