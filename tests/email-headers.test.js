const test = require('node:test');
const assert = require('node:assert/strict');
const { analyzeHeaders, parseAddress, decodeWords, parseHeaders } = require('../js/email-headers.js');

const ids = (r) => r.findings.map((f) => f.id);

const legit = `Delivered-To: asaf@gmail.com
Received: by 2002:a05:7300:1234 with SMTP id abc; Mon, 10 Nov 2026 08:30:01 -0800 (PST)
Received: from mail-sor-f69.google.com (mail-sor-f69.google.com. [209.85.220.69])
        by mx.google.com with SMTPS id x; Mon, 10 Nov 2026 08:30:00 -0800 (PST)
Authentication-Results: mx.google.com;
       dkim=pass header.i=@accounts.google.com header.s=20230601 header.b=abc;
       spf=pass (google.com: domain of 3abc@accounts.google.com designates 209.85.220.69 as permitted sender) smtp.mailfrom=3abc@accounts.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=accounts.google.com
Return-Path: <3abc@accounts.google.com>
From: Google <no-reply@accounts.google.com>
To: asaf@gmail.com
Subject: =?UTF-8?Q?Alerta_de_seguridad?=
Message-ID: <abc123@google.com>
Date: Mon, 10 Nov 2026 16:30:00 +0000

Body text here: From: fake@evil.top
`;

const scam = `Received: from vps-123.hosting.example (unknown [185.220.101.4])
	by mx.google.com; Tue, 11 Nov 2026 03:12:00 -0800
Authentication-Results: mx.google.com;
       spf=softfail (google.com: domain of transitioning soporte@baccredomatic.com does not designate 185.220.101.4 as permitted sender) smtp.mailfrom=soporte@baccredomatic.com;
       dmarc=fail (p=QUARANTINE) header.from=baccredomatic.com
From: "BAC Credomatic" <soporte@baccredomatic.com>
Reply-To: <bac.verificacion@gmail.com>
Subject: Su cuenta será suspendida
Message-ID: <x1@vps-123.hosting.example>
`;

test('legit Google alert: everything passes, nothing flagged', () => {
  const r = analyzeHeaders(legit);
  assert.equal(r.valid, true);
  assert.deepEqual([r.auth.spf, r.auth.dkim, r.auth.dmarc], ['pass', 'pass', 'pass']);
  assert.equal(r.from.domain, 'accounts.google.com');
  assert.equal(r.subject, 'Alerta de seguridad');
  assert.deepEqual(ids(r), []);
  assert.equal(r.level, 'low');
  assert.equal(r.official, true);
  assert.equal(r.brand, 'Google');
  assert.equal(r.hops.length, 2);
  assert.equal(r.hops[0].ip, '209.85.220.69', 'first hop is the bottom Received header');
  assert.equal(r.headerCount, 10, 'the body is ignored');
});

test('spoofed bank: DMARC fail, reply goes to Gmail', () => {
  const r = analyzeHeaders(scam);
  assert.deepEqual(ids(r).slice(0, 1), ['dmarcFail']);
  assert.ok(ids(r).includes('spfSoftfail'));
  assert.ok(ids(r).includes('replyToDiffers'));
  assert.ok(ids(r).includes('messageIdDiffers'));
  assert.equal(r.level, 'high');
  assert.equal(r.official, false);
});

test('a brand name sent from free email or a different domain', () => {
  const free = analyzeHeaders('From: Banco Atlántida <atlantida.alertas@hotmail.com>\nSubject: Aviso\nTo: x@y.com');
  assert.ok(ids(free).includes('freeMailBrand'));
  assert.equal(free.level, 'high');
  const other = analyzeHeaders('From: "Netflix" <billing@netflix-pagos.top>\nSubject: Pago rechazado');
  assert.ok(ids(other).includes('brandMismatch'));
  assert.ok(ids(other).includes('fromDomainBad'));
  assert.ok(ids(other).includes('noAuth'));
});

test('display name hiding another email address', () => {
  const r = analyzeHeaders('From: "servicio@paypal.com" <cobros@pay-secure-mail.xyz>\nSubject: Factura');
  assert.ok(ids(r).includes('nameHasEmail'));
  assert.ok(ids(r).includes('brandMismatch'));
});

test('a normal word in the subject is not taken as a brand', () => {
  const r = analyzeHeaders('From: Ana <ana@gmail.com>\nSubject: Claro que sí, nos vemos\nReply-To: ana@gmail.com');
  assert.ok(!ids(r).includes('freeMailBrand'));
});

test('parsing details', () => {
  assert.deepEqual(parseAddress('=?UTF-8?B?QmFuY28gQXRsw6FudGlkYQ==?= <a@bancatlan.hn>'), { name: 'Banco Atlántida', address: 'a@bancatlan.hn', domain: 'bancatlan.hn' });
  assert.deepEqual(parseAddress('plain@example.com'), { name: '', address: 'plain@example.com', domain: 'example.com' });
  assert.equal(decodeWords('=?iso-8859-1?Q?Hola_=E1rbol?='), 'Hola árbol');
  assert.equal(parseHeaders('X-A: 1\n  continua\nX-B: 2')[0].value, '1 continua');
  assert.equal(analyzeHeaders('').valid, false);
  assert.equal(analyzeHeaders('hola, esto no son encabezados').valid, false);
});
