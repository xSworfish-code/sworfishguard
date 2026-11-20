/*
 * Held-out set: written BEFORE improving the detectors and never used to
 * tune them. It checks that the improvements work on cases the rules were
 * not written for.
 *
 * Results (November 2026), measured once, before looking at the misses:
 *   messages 70.0% with v1.0 -> 90.0% with v1.1 (27/30); passwords 65.0% -> 100.0% (20/20).
 * Three misses were then fixed and copied into corpus.js, so from now on
 * this set is no longer "unseen" for those three cases.
 */
module.exports.messages = [
  ['scam', 'Davivienda: hemos detectado un acceso no autorizado. Valide su identidad en davivienda-hn.info para evitar el bloqueo de su cuenta'],
  ['scam', 'Hola hijo, soy tu tía Rosa, este es mi nuevo número. Me podés mandar 1500 por Tigo Money? te los devuelvo el viernes'],
  ['scam', 'Buenas, me equivoqué de número y te mandé un código de verificación, ¿me lo podrías mandar por favor?'],
  ['scam', 'Correos de Honduras: Su paquete no pudo ser entregado por dirección incompleta. Actualice aquí: honducor.envio-hn.com'],
  ['scam', 'Usted ganó una motocicleta en la rifa de aniversario de Claro. Para el traspaso deposite L 1,200 a la cuenta 2001-445-99'],
  ['scam', 'Trabajo fácil: te pagamos L 150 por cada reseña de 5 estrellas en Google Maps. Escribe al +504 8899 1122'],
  ['scam', 'Plataforma de inversión con IA: gana 30% semanal garantizado. Cupos limitados, invierte hoy'],
  ['scam', 'Aviso de seguridad Microsoft: su equipo está infectado. Llame al soporte técnico 1-800-555-0123 inmediatamente'],
  ['scam', 'Tu cuenta de Instagram será eliminada en 24 horas si no confirmas tu identidad: ig-verificacion.com'],
  ['scam', 'Banpaís le informa que su tarjeta ha sido suspendida temporalmente. Reactívela ingresando su usuario y clave en banpais-online.net'],
  ['scam', 'Hola! Le escribe un agente de Western Union, tiene una remesa pendiente de $500. Envíe su número de identidad para liberarla'],
  ['scam', 'Te vi en el grupo de ventas, quiero comprar tu celular. Ya te hice el depósito, mándame el código que te llegó para confirmar'],
  ['scam', 'Oye, ¿eres tú en este video? jajaja mira: video-viral-hn.top/watch'],
  ['scam', 'Your Netflix membership has been suspended. Update your billing details now at netflix-billing-update.com'],
  ['scam', 'FedEx: Your parcel is waiting for customs clearance. Pay the $2.50 fee here: fedex-delivery-hn.xyz'],
  ['scam', 'Gane dinero desde casa! Solo necesita pagar L 300 de inscripción y empezará a recibir pagos diarios'],
  ['scam', 'Este es el número nuevo de papá, el otro se me dañó. Mándame 800 lempiras de saldo urgente'],
  ['scam', 'SAR: Su RTN presenta inconsistencias. Regularice su situación en las próximas 48 horas en sar-hn.online o será multado'],
  ['legit', 'Davivienda: Transferencia recibida por L 2,300.00 en su cuenta terminada en 5512.'],
  ['legit', 'Tu código de acceso de Facebook es 774120. No lo compartas.'],
  ['legit', 'Hola tía, ¿cómo sigue la abuela? Mañana pasamos a visitarla'],
  ['legit', 'Ya está la comida, vengan a almorzar'],
  ['legit', 'El ensayo de la banda se cambió para el viernes a las 4 en el gimnasio'],
  ['legit', '¿Me podés pasar los apuntes de matemáticas? No fui hoy'],
  ['legit', 'Te deposité lo de la rifa de la iglesia, son 50 lempiras'],
  ['legit', 'Claro: Hiciste una recarga de L 50. Disfruta tu paquete de internet por 3 días.'],
  ['legit', 'Spotify: Your receipt for Spotify Premium. Total: $5.99'],
  ['legit', 'Gracias por tu compra en Supermercados La Colonia. Acumulaste 25 puntos.'],
  ['legit', 'Felicidades por graduarte! Estamos muy orgullosos de vos'],
  ['legit', 'Recordatorio: mañana vence el plazo para inscribirse en el torneo de ajedrez del colegio']
];
module.exports.passwords = {
  weak: ['sanpedrosula', 'Olimpia1912', 'Honduras2026!', 'Catracha15', 'Mariposa22', 'Ocotepeque1', 'qwertyuiop1', 'Luis2005',
         'Valentina!', 'Junior123', 'Chelsea10', 'Abc12345', 'Messi1010', 'Jesucristo1', 'baleada1'],
  strong: ['vR8!nQ3#xT6@pL2m', 'tormenta-ladrillo-pupitre-coco-arena', 'zebra canoa limon farol bosque', 'Wq7$Lx2!Np9#Kd4@', 'mango.reloj.silla.tigre.nube.cafe']
};
