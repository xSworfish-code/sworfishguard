/*!
 * SworfishGuard — "Real or scam?" quiz
 *
 * Practice cases based on scams that are common in Honduras and Latin
 * America. Brands appear because scammers impersonate them; the "real"
 * cases use each brand's real official domain (see brands.js).
 * The people and phone numbers are made up.
 *
 * Author: Asaf Rojas (Sworfish Tech) — MIT License
 */
(function (root) {
  'use strict';

  var CASES = [
    { id: 'bankSms', kind: 'sms', answer: 'scam',
      es: { from: '+504 9812-4410', text: 'BAC: Su tarjeta fue BLOQUEADA por seguridad. Desbloquéela hoy en bac-hn-seguridad.top/validar o será cancelada.',
            why: 'El enlace no es baccredomatic.com, termina en .top y te apura con "hoy". Los bancos no desbloquean tarjetas por un enlace en un SMS.' },
      en: { from: '+504 9812-4410', text: 'BAC: Your card was BLOCKED for security. Unblock it today at bac-hn-seguridad.top/validar or it will be cancelled.',
            why: 'The link is not baccredomatic.com, it ends in .top and it rushes you with "today". Banks do not unblock cards through a link in a text.' } },
    { id: 'bankLink', kind: 'link', answer: 'real',
      es: { from: '', text: 'https://www.bancatlan.hn/personas',
            why: 'El dominio real es bancatlan.hn, el oficial de Banco Atlántida. "www" y "/personas" son solo partes de la misma página.' },
      en: { from: '', text: 'https://www.bancatlan.hn/personas',
            why: 'The real domain is bancatlan.hn, Banco Atlántida\'s official one. "www" and "/personas" are just parts of the same site.' } },
    { id: 'family', kind: 'whatsapp', answer: 'scam',
      es: { from: 'Número desconocido', text: 'Hola mami, este es mi número nuevo, se me arruinó el cel 😥 ¿Me puedes transferir L 3,500? Es urgente, mañana te los devuelvo.',
            why: 'Número nuevo + dinero urgente es la estafa del "familiar". Llama al número de siempre de esa persona antes de mandar algo.' },
      en: { from: 'Unknown number', text: 'Hi mom, this is my new number, my phone broke 😥 Can you transfer me L 3,500? It\'s urgent, I\'ll pay you back tomorrow.',
            why: 'New number + urgent money is the "family member" scam. Call the person\'s usual number before sending anything.' } },
    { id: 'netflixReceipt', kind: 'email', answer: 'real',
      es: { from: 'Netflix <info@mailer.netflix.com>', text: 'Tu recibo de noviembre. Monto: $7.99. Si tienes preguntas, visita netflix.com/help.',
            why: 'Viene de un subdominio de netflix.com, no pide contraseña ni datos de tarjeta y te manda a la ayuda en su propio dominio.' },
      en: { from: 'Netflix <info@mailer.netflix.com>', text: 'Your November receipt. Amount: $7.99. If you have questions, visit netflix.com/help.',
            why: 'It comes from a subdomain of netflix.com, it does not ask for your password or card and it sends you to help on its own domain.' } },
    { id: 'package', kind: 'sms', answer: 'scam',
      es: { from: 'HONDUCOR', text: 'Su paquete está retenido por falta de pago de L 45.00. Pague en honducor-envios.com/pago para recibirlo.',
            why: 'El sitio oficial de Correos de Honduras es honducor.gob.hn. Cobrar poquito por un paquete que no esperabas es un truco para robar los datos de tu tarjeta.' },
      en: { from: 'HONDUCOR', text: 'Your parcel is held for an unpaid fee of L 45.00. Pay at honducor-envios.com/pago to receive it.',
            why: 'Correos de Honduras\' official site is honducor.gob.hn. A small fee for a parcel you weren\'t expecting is a trick to steal your card details.' } },
    { id: 'steamTrade', kind: 'link', answer: 'scam',
      es: { from: '', text: 'https://steamcommunity.com.trade-offer.ru/tradeoffer/new',
            why: 'El dominio real se lee al final: trade-offer.ru. "steamcommunity.com" es solo un subdominio puesto adelante para engañarte.' },
      en: { from: '', text: 'https://steamcommunity.com.trade-offer.ru/tradeoffer/new',
            why: 'The real domain is read at the end: trade-offer.ru. "steamcommunity.com" is just a subdomain placed in front to fool you.' } },
    { id: 'whatsappCode', kind: 'whatsapp', answer: 'scam',
      es: { from: 'Amigo del grupo', text: 'Perdón, te llegó un código de 6 dígitos por error a tu número, ¿me lo puedes reenviar? Es para entrar a mi cuenta.',
            why: 'Ese código es para entrar a TU WhatsApp. Si lo compartes, te roban la cuenta y escriben a tus contactos pidiendo dinero.' },
      en: { from: 'Friend from a group', text: 'Sorry, a 6-digit code was sent to your number by mistake, can you forward it to me? It\'s to log into my account.',
            why: 'That code is for logging into YOUR WhatsApp. If you share it, they steal your account and message your contacts asking for money.' } },
    { id: 'googleAlert', kind: 'email', answer: 'real',
      es: { from: 'Google <no-reply@accounts.google.com>', text: 'Nuevo inicio de sesión en Windows. Si fuiste tú, no tienes que hacer nada. Si no, revisa tu actividad en myaccount.google.com.',
            why: 'Remitente de google.com, no te pide la contraseña y te manda a revisar en el sitio oficial. Aun así, lo más seguro es entrar escribiendo la dirección tú mismo.' },
      en: { from: 'Google <no-reply@accounts.google.com>', text: 'New sign-in on Windows. If this was you, you don\'t need to do anything. If not, check your activity at myaccount.google.com.',
            why: 'Sender on google.com, it does not ask for your password and it sends you to the official site. Still, the safest way is to type the address yourself.' } },
    { id: 'parkingQr', kind: 'qr', answer: 'scam',
      es: { from: 'Calcomanía pegada en un parquímetro', text: 'Escanea para pagar tu parqueo → pago-parqueo-hn.xyz',
            why: 'Pegar un QR falso encima del real se llama "quishing". Un .xyz desconocido no es la municipalidad; paga en el sitio o app oficial.' },
      en: { from: 'Sticker on a parking meter', text: 'Scan to pay for parking → pago-parqueo-hn.xyz',
            why: 'Sticking a fake QR on top of the real one is called "quishing". An unknown .xyz site is not the city; pay on the official site or app.' } },
    { id: 'tigoTopUp', kind: 'sms', answer: 'real',
      es: { from: 'Tigo', text: 'Tigo: Tu recarga de L 100 fue exitosa. Saldo disponible: L 112.50.',
            why: 'Es solo información de algo que tú hiciste: no tiene enlace, no pide datos ni pagos.' },
      en: { from: 'Tigo', text: 'Tigo: Your L 100 top-up was successful. Available balance: L 112.50.',
            why: 'It only informs you about something you did: no link, no request for data or payments.' } },
    { id: 'giveaway', kind: 'dm', answer: 'scam',
      es: { from: '@sorteos.oficial.hn', text: '¡Felicidades! Ganaste un iPhone 17 en nuestro sorteo 🎉 Solo paga L 300 de envío por Tigo Money para reclamarlo.',
            why: 'Si ganas algo de verdad no tienes que pagar para recibirlo. Premio + pago por adelantado = estafa.' },
      en: { from: '@sorteos.oficial.hn', text: 'Congratulations! You won an iPhone 17 in our giveaway 🎉 Just pay L 300 for shipping through Tigo Money to claim it.',
            why: 'If you really win something you don\'t pay to receive it. Prize + upfront payment = scam.' } },
    { id: 'googleFake', kind: 'link', answer: 'scam',
      es: { from: '', text: 'https://accounts.google.com.security-check.help/login',
            why: 'El dominio real es security-check.help (y .help es de los finales más usados en phishing). Todo lo de adelante es decoración.' },
      en: { from: '', text: 'https://accounts.google.com.security-check.help/login',
            why: 'The real domain is security-check.help (and .help is one of the endings most used for phishing). Everything in front is decoration.' } },
    { id: 'techSupport', kind: 'email', answer: 'scam',
      es: { from: 'Microsoft Soporte <microsoft.soporte.hn@outlook.com>', text: 'Su licencia de Windows venció y su PC tiene virus. Llame ya al +1 (888) 555-0199 e instale AnyDesk para que un técnico lo arregle.',
            why: 'Microsoft no escribe desde una cuenta de outlook.com ni te pide instalar programas de acceso remoto. Con AnyDesk controlan tu compu.' },
      en: { from: 'Microsoft Support <microsoft.soporte.hn@outlook.com>', text: 'Your Windows license expired and your PC has viruses. Call +1 (888) 555-0199 now and install AnyDesk so a technician can fix it.',
            why: 'Microsoft does not write from an outlook.com account or ask you to install remote access software. With AnyDesk they control your computer.' } },
    { id: 'robloxLink', kind: 'link', answer: 'real',
      es: { from: '', text: 'https://www.roblox.com/home',
            why: 'roblox.com es el dominio oficial. Ojo con copias como roblox.com.gift-codes.live o rob1ox.com.' },
      en: { from: '', text: 'https://www.roblox.com/home',
            why: 'roblox.com is the official domain. Watch out for copies like roblox.com.gift-codes.live or rob1ox.com.' } }
  ];

  CASES.forEach(function (c) { Object.freeze(c.es); Object.freeze(c.en); Object.freeze(c); });
  Object.freeze(CASES);

  /** Score summary for a finished round. answers: { caseId: 'real'|'scam' } */
  function grade(answers, ids) {
    var list = ids || CASES.map(function (c) { return c.id; });
    var right = 0, wrong = [];
    list.forEach(function (id) {
      var c = CASES.filter(function (x) { return x.id === id; })[0];
      if (!c) return;
      if (answers[id] === c.answer) right++; else wrong.push(id);
    });
    var pct = list.length ? Math.round(right / list.length * 100) : 0;
    return { right: right, total: list.length, pct: pct, wrong: wrong, level: pct >= 90 ? 'expert' : pct >= 70 ? 'good' : pct >= 40 ? 'fair' : 'start' };
  }

  var api = { CASES: CASES, grade: grade };
  root.SworfishGuard = root.SworfishGuard || {};
  root.SworfishGuard.quiz = Object.freeze(api);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
