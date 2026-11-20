# Third-party code and data

SworfishGuard's own code is MIT licensed. These files include work by other people:

| File | What | Source | License |
|---|---|---|---|
| `js/vendor/jsQR.js` | QR code decoder, version 1.4.0, unchanged | [cozmo/jsQR](https://github.com/cozmo/jsQR) by Cosmo Wolfe | Apache 2.0 (see `js/vendor/jsQR-LICENSE.txt`) |
| `js/dictionaries.js` | 12,000 most common leaked passwords | Mark Burnett's 10 million passwords, via [@zxcvbn-ts/language-common](https://www.npmjs.com/package/@zxcvbn-ts/language-common) 4.2.0 | Public domain (as stated by the author) |
| `js/dictionaries.js` | Common Spanish and English words | OpenSubtitles 2024 via [OPUS](https://opus.nlpl.eu/) (Helsinki-NLP), via @zxcvbn-ts/language-es-es 4.1.3 and @zxcvbn-ts/language-en 4.1.2 | ODC-BY (attribution) |
| `js/dictionaries.js` | First names, surnames, keyboard layouts | [zxcvbn-ts](https://github.com/zxcvbn-ts/zxcvbn) | MIT |
| `js/wordlists.js` (English) | EFF long word list, 7,776 words | [Electronic Frontier Foundation](https://www.eff.org/deeplinks/2016/07/new-wordlists-random-passphrases) | CC BY 4.0 |
| `js/wordlists.js` (Spanish) | 4,096 words chosen from the OpenSubtitles list above | OPUS / OpenSubtitles 2024 | ODC-BY |
| `fonts/` | Inter, Source Serif 4 | Google Fonts projects | SIL Open Font License (see `fonts/OFL.txt`) |

The Honduras word list and the extra Honduran names in `tools/build-dictionaries.py` were written for this project.

The password analyzer's method (matching + dynamic programming over guesses) follows the paper *zxcvbn: Low-Budget Password Strength Estimation* by Daniel Lowe Wheeler (USENIX Security 2016). The code in `js/password-analyzer.js` is my own implementation, not a copy of zxcvbn.

To rebuild the dictionaries: download the three npm packages above (`npm pack`), unpack them in one folder and run `python3 tools/build-dictionaries.py <folder>`.
