# Changelog

## 1.1.0 (November 2026)

New tools
- QR code checker: reads a QR from a photo, screenshot (paste) or the camera, identifies what it contains (link, Wi-Fi, SMS, phone, email, contact, 2FA setup, crypto payment, app link) and analyzes it. Uses jsQR 1.4.0, bundled and pinned by hash.
- Email checker: reads SPF, DKIM and DMARC results from the headers and compares From, Reply-To, Return-Path, Message-ID and the display name (brand names sent from free email, a fake address inside the name, lookalike domains).
- Photo metadata: shows GPS location, device, date and other EXIF/XMP/IPTC/PNG text data, and makes a clean copy without re-compressing (keeps only rotation and color profile).
- "Real or scam?" quiz with 14 cases in Spanish and English.

Better existing tools
- Password analyzer rewritten: it now finds every piece an attacker would try (12,000 leaked passwords, 26,000 Spanish and English words, names, surnames, Honduran words, your own details, keyboard walks, sequences, repeats, years, dates, phone numbers, leetspeak, reversed words) and picks the cheapest split with dynamic programming, like zxcvbn. Four attack scenarios. Optional personal details field.
- Clearer password explanations: the password shown split into pieces with the guesses each one costs, what makes it weak, how to improve it and a stronger example.
- Generator: Spanish list of 4,096 words and the EFF list of 7,776 English words (was 256), 6 words by default, optional symbol, word language, PIN mode that skips predictable PINs, and strength measured with the analyzer.
- Scam detector rewritten: cleans tricks ("c0dig0", "p.i.n.", invisible and look-alike characters), separates bait from requests, names 15 types of scam with what to do, highlights the suspicious phrases in the message, and recognizes signs of legitimate messages (real one-time codes, bank alerts).
- Link checker: the link is shown split into parts with the real domain marked, plus what to do. Shortened links count as suspicious, and links in messages are no longer cut short at unknown endings (".ru").
- Accuracy measured on a test set and on a separate unseen set: messages 70% → 90%, passwords 65% → 100% on the unseen set (see README).

Improvements
- Installable app with offline mode (service worker, manifest, icons).
- Quick start grid on the home page and a tool picker on phones.
- New verified entities: Banco LAFISE, SAR, RNP, ENEE, plus Temu and Shein (36 brands).
- The link checker now marks a full official domain used as a prefix (`steamcommunity.com.trade-offer.ru`) as critical, and "BAC" alone is recognized as the brand.
- New scam rules: remote access apps (AnyDesk, TeamViewer), "verify your account" requests and fake government bonuses or tax refunds.
- 4 new glossary terms: quishing, EXIF metadata, SPF/DKIM/DMARC and remote access.
- Opening a link like `#qr` switches to that tool even if the page is already open.
- 106 tests (was 74), including accuracy gates and one that checks the quiz answers against the detectors.

## 1.0.0 (October 2026)

First version.

- Password analyzer with entropy, crack time estimates and pattern detection (common passwords, words, leetspeak, keyboard rows, sequences, repeats, years, dates and phone numbers).
- Breach checker using the Have I Been Pwned range API with k-anonymity.
- Password and passphrase generator (256-word lists in Spanish and English).
- Link checker with the official domains of 30 brands, including Honduran banks, homograph detection and a list of risky domain endings.
- Scam message checker for SMS, WhatsApp and email.
- File fingerprint (SHA-256, SHA-1, SHA-512).
- Personal security checkup and glossary.
- Basic and Expert modes, Spanish and English, light and dark mode.
- Strict Content Security Policy with Trusted Types, self-hosted fonts, unit tests, a security test, CodeQL and Dependabot.
