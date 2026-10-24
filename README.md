# SworfishGuard

![Tests](https://github.com/xSworfish-code/sworfishguard/actions/workflows/tests.yml/badge.svg)
![CodeQL](https://github.com/xSworfish-code/sworfishguard/actions/workflows/codeql.yml/badge.svg)
![License: MIT](https://img.shields.io/badge/license-MIT-0075DE.svg)

This is one of my first projects. I'm a high school student from Honduras and I want to study computer science and specialize in cybersecurity, so I decided to build something I could actually use and learn from at the same time.

SworfishGuard is a small set of security tools that run in the browser. You can check a password, a link, a weird message you got on WhatsApp or a file you downloaded, and it tells you what it found and why. Everything happens on your own device. Nothing gets saved or sent to a server.

Live demo: https://xsworfish-code.github.io/sworfishguard/

[Leer en español](#español)

## How I made it

I used AI (Claude) as support while building this. It helped me write and review the code and explained the security concepts behind each tool, like entropy, hashing and k-anonymity. I'm using the project to learn those ideas properly, and I'll keep improving it as I understand more.

## What it can do

- **Password analyzer:** estimates how long a password would take to crack and points out what an attacker would try first (common words, dates, phone numbers, "P4ssw0rd" style swaps, keyboard rows like qwerty).
- **Breach checker:** tells you if a password appeared in a real data breach, using the [Have I Been Pwned](https://haveibeenpwned.com/Passwords) database. Your password is never sent. Only the first 5 characters of its SHA-1 hash leave the browser.
- **Generator:** makes random passwords or passphrases you can actually remember.
- **Link checker:** looks at a link without opening it and warns you about fake bank domains, typos, letters from other alphabets, shorteners and other common tricks.
- **Message checker:** looks for scam patterns in SMS or WhatsApp messages, like someone asking for a verification code or the "hi mom, this is my new number" scam.
- **File fingerprint:** checks that a file you downloaded wasn't modified, by comparing its SHA-256.
- **Personal checkup:** 12 questions about your habits and a list of what to fix first.
- **Glossary:** security words explained in a simple way and in a technical way.

There's a Basic mode with simple explanations and an Expert mode that shows the math and the raw data. The site is in Spanish and English.

## Honduran banks and services

The link and message checkers know the official domains of 30 brands. These are the ones from Honduras (last checked October 2026):

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

The list of risky domain endings comes from the Interisle *Phishing Landscape 2025* report and from Spamhaus. You can add more brands in [`js/brands.js`](js/brands.js).

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
- GitHub runs the tests and a CodeQL security scan every time I push changes. There's also a test that checks my own code for dangerous things like `innerHTML` or `eval`.

More details in [SECURITY.md](SECURITY.md).

## Project structure

```
sworfishguard/
├── index.html                 # UI (Notion-inspired design)
├── css/styles.css             # Design tokens, light/dark, responsive
├── fonts/                     # Inter + Source Serif 4 (SIL OFL), self-hosted
├── js/
│   ├── password-analyzer.js   # Entropy + pattern detection
│   ├── breach-check.js        # HIBP range API (k-anonymity)
│   ├── generator.js           # Passwords and passphrases
│   ├── wordlists.js           # 256-word lists (es / en)
│   ├── phishing-detector.js   # URL heuristics, punycode, homographs
│   ├── scam-detector.js       # Scam message heuristics
│   ├── brands.js              # Verified official domains, risky TLDs
│   ├── file-hash.js           # SHA-256 / SHA-1 / SHA-512
│   ├── checkup.js             # Personal security checkup
│   ├── glossary.js            # Terms in two levels
│   ├── i18n.js                # Spanish / English strings
│   └── app.js                 # UI wiring
├── tests/                     # 74 tests (node:test), incl. security.test.js
├── .github/                   # Tests + CodeQL workflows, Dependabot
└── .well-known/security.txt   # How to report vulnerabilities (RFC 9116)
```

## Running it

Just open `index.html` in your browser. To run the tests you need Node.js 22 or newer:

```bash
npm test
```

## Things I want to add

- [ ] Make it work offline (PWA)
- [ ] A QR code checker that shows the link inside a QR before you open it
- [ ] More banks and services from Central America
- [ ] An email header analyzer (SPF / DKIM / DMARC)

## Limitations

The link and message checkers use rules, so they can make mistakes. A link with no warnings isn't guaranteed to be safe. If you're not sure, type the official address yourself.

## Credits

Made by Asaf Rojas (Sworfish Tech), Honduras. MIT License, see [LICENSE](LICENSE).

Breach data from [Have I Been Pwned](https://haveibeenpwned.com) by Troy Hunt. Fonts: Inter and Source Serif 4 (SIL Open Font License).

## Español

Este es uno de mis primeros proyectos. Soy estudiante de colegio en Honduras y quiero estudiar computación con especialidad en ciberseguridad, así que quise hacer algo que pudiera usar de verdad y que me sirviera para aprender.

SworfishGuard es un conjunto de herramientas de seguridad que funciona en el navegador. Puedes revisar una contraseña, un link, un mensaje raro de WhatsApp o un archivo descargado, y te dice qué encontró y por qué. Todo pasa en tu propio dispositivo; no se guarda ni se envía nada a un servidor.

Usé IA (Claude) como apoyo mientras lo hacía: me ayudó a escribir y revisar el código y me explicó los conceptos de seguridad de cada herramienta, como la entropía, los hashes y el k-anonimato. Estoy usando el proyecto para aprender esas ideas bien y lo voy a seguir mejorando.

Lo que tiene:

- Analizador de contraseñas: calcula cuánto tardarían en adivinarla y señala lo que un atacante probaría primero.
- Revisión de filtraciones: dice si una contraseña apareció en hackeos reales sin enviarla (solo salen 5 caracteres de su huella SHA-1).
- Generador de contraseñas y de frases fáciles de recordar.
- Revisor de links: detecta dominios falsos de bancos hondureños y de marcas conocidas, letras de otros alfabetos y acortadores.
- Revisor de mensajes: busca estafas típicas como pedir un código o el "mamá, este es mi número nuevo".
- Huella digital de archivos, chequeo de hábitos y un glosario.

Para usarlo, abre `index.html` o entra a la demo. Las pruebas corren con `npm test`.
