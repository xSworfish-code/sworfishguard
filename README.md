# SworfishGuard

![Tests](https://github.com/xSworfish-code/sworfishguard/actions/workflows/tests.yml/badge.svg)
![CodeQL](https://github.com/xSworfish-code/sworfishguard/actions/workflows/codeql.yml/badge.svg)
![License: MIT](https://img.shields.io/badge/license-MIT-0075DE.svg)

This is one of my first projects. I'm a high school student from Honduras and I want to study computer science and specialize in cybersecurity, so I decided to build something I could actually use and learn from at the same time.

SworfishGuard is a set of security tools that run in the browser. You can check a password, a link, a weird WhatsApp message, a QR code, an email or a photo, and it tells you what it found and why. Everything happens on your own device. Nothing gets saved or sent to a server.

Live demo: https://xsworfish-code.github.io/sworfishguard/

[Leer en español](#español)

## How I made it

I used AI (Claude) as support while building this. It helped me write and review the code and explained the security concepts behind each tool, like entropy, hashing and k-anonymity. I'm using the project to learn those ideas properly, and I'll keep improving it as I understand more.

## What it can do

- **Password analyzer:** thinks like a real cracking program. It splits the password into the pieces an attacker would try (leaked passwords, Spanish and English words, names, Honduran words like "catracho" or "olimpia", years, dates, keyboard rows, "a→4" swaps...) and shows how many guesses each piece costs. You can also type your name or birthday (it stays on the page) to see if you used them.
- **Breach checker:** tells you if a password appeared in a real data breach, using the [Have I Been Pwned](https://haveibeenpwned.com/Passwords) database. Your password is never sent. Only the first 5 characters of its SHA-1 hash leave the browser.
- **Generator:** passphrases from big word lists (4,096 Spanish words or the EFF's 7,776 English words), random passwords with at least one of each chosen character type, and PINs that skip the ones people use most (1234, years, dates, 2580...).
- **Link checker:** looks at a link without opening it, shows it split into parts so you can see the real domain, and warns you about fake bank domains, typos, letters from other alphabets, shorteners and other common tricks.
- **Message checker:** marks the suspicious phrases inside the message, says what type of scam it looks like (family "new number", stolen WhatsApp code, fake parcel, fake job, fake bank...) and what to do. It understands tricks like "c0dig0" or "p.i.n." and Honduran ways of writing ("sos vos", "ocupo", "pisto").
- **QR code checker:** reads a QR from a photo, a screenshot or the camera and shows what's inside before you open it. Links go through the link checker, and it also understands Wi-Fi networks, payments, 2FA setup codes and contacts. Fake QR stickers on parking meters and menus ("quishing") are a growing scam.
- **Email checker:** you paste the headers of an email and it shows whether it passed SPF, DKIM and DMARC, and whether the sender name, the "reply to" address or the domain don't match.
- **Photo metadata:** shows if a photo has the GPS location where it was taken, the phone model or the date, and gives you a clean copy without re-compressing the photo.
- **File fingerprint:** checks that a file you downloaded wasn't modified, by comparing its SHA-256.
- **Real or scam? quiz:** 14 practice cases (SMS, WhatsApp, emails, links, QR) with an explanation for each one.
- **Personal checkup:** 12 questions about your habits and a list of what to fix first.
- **Glossary:** security words explained in a simple way and in a technical way.

There's a Basic mode with simple explanations and an Expert mode that shows the math and the raw data. The site is in Spanish and English, and you can install it on your phone like an app. It works without internet (except the breach check, which needs it).

## How accurate is it

I wanted to know if my changes really made the detectors better, so I wrote a test set: 81 messages (scams and normal ones, including tricky cases like real bank codes or friends talking about money), 50 passwords and 20 links. `npm run benchmark` measures it.

I also wrote a second, separate set of 30 messages and 20 passwords **before** changing the code and didn't use it to adjust anything, because adjusting rules to the same examples you measure with gives numbers that look better than reality. That second set is the honest result:

| | Version 1.0 | Version 1.1 |
|---|---|---|
| Messages, unseen set | 70% | **90%** |
| Passwords, unseen set | 65% | **100%** |
| Messages, main set (false alarms) | 80.5% (5 false alarms) | 100% (0) |
| Passwords, main set | 84% | 100% |
| Links, main set | 95% | 100% |

The main set was used while improving the rules, so its 100% is expected. The tests fail if accuracy on it ever drops below 95%. These are still my own examples, not a scientific study, and real scammers keep inventing new messages.

## Honduran banks and services

The link, message and email checkers know the official domains of 36 brands. These are the ones from Honduras:

| Brand | Official domain |
|---|---|
| Banco Atlántida | `bancatlan.hn` |
| BAC Credomatic | `baccredomatic.com` |
| Ficohsa | `ficohsa.hn`, `ficohsa.com` |
| Banpaís | `banpais.hn`, `corporacionbi.com` |
| Banco de Occidente | `bancocci.hn` |
| Davivienda Honduras | `davivienda.com.hn` |
| Tigo / Claro | `tigo.com.hn`, `claro.com.hn` |
| Honducor | `honducor.gob.hn` |
| Banco LAFISE | `lafise.com` |
| SAR (taxes) | `sar.gob.hn` |
| RNP (ID cards) | `rnp.hn` |
| ENEE (electricity) | `enee.hn` |

The first ones were checked in October 2026 and the last four in November 2026. In [`js/brands.js`](js/brands.js) there's a note with where I confirmed each one.

The list of risky domain endings comes from the Interisle *Phishing Landscape 2025* report and from Spamhaus. You can add more brands in the same file.

## Security stuff I tried to get right

- No server, no cookies, no analytics. The fonts are inside the repo, so the page doesn't load anything from other sites.
- How the breach check keeps the password private:

```
password  ──SHA-1──▶  5BAA6 1E4C9B93F3F0682250B6CF8331B7EE68FD8
                      └─┬─┘ └───────────────┬────────────────┘
                     sent to API      stays in your browser
```

- Text you type is always shown as plain text, never as HTML, and the page has a strict Content Security Policy with Trusted Types so the browser blocks code injection.
- Password fields clear themselves after 5 minutes without activity.
- The camera is only used to read the QR. Frames are read in memory, nothing is recorded, and the camera turns off as soon as it finds a code or you leave the page.
- The QR reader is the open-source [jsQR](https://github.com/cozmo/jsQR) library. I copied it into the repo instead of loading it from a CDN, and a test checks its SHA-256, so if someone changes that file the tests fail.
- The offline mode only saves the app's own files. The service worker never touches requests to other sites.
- GitHub runs the tests and a CodeQL security scan every time I push changes. There's also a test that checks my own code for dangerous things like `innerHTML` or `eval`.

More details in [SECURITY.md](SECURITY.md).

## Project structure

```
sworfishguard/
├── index.html                 # UI (Notion-inspired design)
├── css/styles.css             # Design tokens, light/dark, responsive
├── fonts/                     # Inter + Source Serif 4 (SIL OFL), self-hosted
├── js/
│   ├── password-analyzer.js   # Attacker-style estimate: matching + dynamic programming
│   ├── dictionaries.js        # Leaked passwords, words, names, Honduras list (generated)
│   ├── breach-check.js        # HIBP range API (k-anonymity)
│   ├── generator.js           # Passwords and passphrases
│   ├── wordlists.js           # 4096 Spanish / 7776 English words (generated)
│   ├── phishing-detector.js   # URL heuristics, punycode, homographs
│   ├── scam-detector.js       # Scam message heuristics
│   ├── brands.js              # Verified official domains, risky TLDs
│   ├── qr-scanner.js          # What a QR code contains (link, Wi-Fi, payment...)
│   ├── email-headers.js       # SPF / DKIM / DMARC and sender checks
│   ├── metadata.js            # EXIF/GPS reader and cleaner (JPEG, PNG)
│   ├── quiz.js                # "Real or scam?" cases
│   ├── vendor/jsQR.js         # QR decoder (Apache-2.0), pinned by hash
│   ├── file-hash.js           # SHA-256 / SHA-1 / SHA-512
│   ├── checkup.js             # Personal security checkup
│   ├── glossary.js            # Terms in two levels
│   ├── i18n.js                # Spanish / English strings
│   └── app.js                 # UI wiring
├── sw.js, manifest.webmanifest, icons/   # Offline mode / installable app
├── tools/build-dictionaries.py  # Builds the dictionaries from open data
├── tests/                     # 106 tests (node:test), incl. security and accuracy
│   ├── benchmark.js           # Accuracy measurement
│   └── fixtures/              # Test messages, passwords and links
├── .github/                   # Tests + CodeQL workflows, Dependabot
└── .well-known/security.txt   # How to report vulnerabilities (RFC 9116)
```

## Running it

Just open `index.html` in your browser. To run the tests you need Node.js 22 or newer:

```bash
npm test
npm run benchmark   # accuracy of the detectors
```

## Things I want to add

- [x] Make it work offline (PWA)
- [x] A QR code checker that shows the link inside a QR before you open it
- [x] An email header analyzer (SPF / DKIM / DMARC)
- [ ] More banks and services from Central America
- [ ] Read QR codes and links inside PDF files
- [ ] More quiz cases, based on real messages people send me

## Limitations

The link, message and email checkers use rules, so they can make mistakes. A link with no warnings isn't guaranteed to be safe. If you're not sure, type the official address yourself. The photo cleaner reads JPEG and PNG; other formats (like HEIC) get a re-saved JPEG copy instead.

## Credits

Made by Asaf Rojas (Sworfish Tech), Honduras. MIT License, see [LICENSE](LICENSE).

Breach data from [Have I Been Pwned](https://haveibeenpwned.com) by Troy Hunt. The password analyzer follows the method of zxcvbn (Daniel Lowe Wheeler, USENIX Security 2016), written from scratch. Dictionaries and word lists come from open data; see [THIRD_PARTY.md](THIRD_PARTY.md). QR decoding with [jsQR](https://github.com/cozmo/jsQR) by Cosmo Wolfe (Apache License 2.0, see `js/vendor/jsQR-LICENSE.txt`). Fonts: Inter and Source Serif 4 (SIL Open Font License).

## Español

Este es uno de mis primeros proyectos. Soy estudiante de colegio en Honduras y quiero estudiar computación con especialidad en ciberseguridad, así que quise hacer algo que pudiera usar de verdad y que me sirviera para aprender.

SworfishGuard es un conjunto de herramientas de seguridad que funciona en el navegador. Puedes revisar una contraseña, un link, un mensaje raro de WhatsApp, un código QR, un correo o una foto, y te dice qué encontró y por qué. Todo pasa en tu propio dispositivo; no se guarda ni se envía nada a un servidor.

Usé IA (Claude) como apoyo mientras lo hacía: me ayudó a escribir y revisar el código y me explicó los conceptos de seguridad de cada herramienta, como la entropía, los hashes y el k-anonimato. Estoy usando el proyecto para aprender esas ideas bien y lo voy a seguir mejorando.

Lo que tiene:

- Analizador de contraseñas: la divide como lo haría un programa de ataque (contraseñas filtradas, palabras, nombres, palabras hondureñas, años, fechas, teclado, cambios como a→4) y te muestra cuánto cuesta cada parte. Puedes poner tu nombre o tu fecha de nacimiento para ver si los usaste.
- Revisión de filtraciones: dice si una contraseña apareció en hackeos reales sin enviarla (solo salen 5 caracteres de su huella SHA-1).
- Generador de frases con listas grandes de palabras, contraseñas al azar y PINs que evitan los típicos (1234, años, fechas).
- Revisor de links: detecta dominios falsos de bancos hondureños y de marcas conocidas, letras de otros alfabetos y acortadores.
- Revisor de mensajes: marca las frases sospechosas dentro del mensaje, te dice qué tipo de estafa parece y qué hacer. Entiende trucos como "c0dig0" o "p.i.n." y cómo escribimos en Honduras.
- Revisor de códigos QR: lee el QR de una foto, captura o la cámara y te dice a dónde lleva antes de abrirlo (también redes Wi-Fi, pagos y contactos).
- Revisor de correos: pegas los encabezados y te dice si pasó SPF, DKIM y DMARC y si el remitente no cuadra.
- Metadatos de fotos: muestra si una foto tiene tu ubicación GPS y te da una copia limpia sin perder calidad.
- Quiz "¿Real o fraude?" con casos para practicar.
- Huella digital de archivos, chequeo de hábitos y un glosario.

Medí la precisión con mensajes y contraseñas que no usé para ajustar las reglas: los mensajes pasaron de 70 % a 90 % de aciertos y las contraseñas de 65 % a 100 % (detalles arriba, en "How accurate is it").

Se puede instalar en el teléfono como app y funciona sin internet (menos la revisión de filtraciones). Para usarlo, abre `index.html` o entra a la demo. Las pruebas corren con `npm test`.
