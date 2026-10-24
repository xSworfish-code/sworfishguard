# Security policy

## What is protected and how

| What | How |
|---|---|
| Passwords typed into the tools | They stay in memory, in the browser. Nothing is stored, logged or sent. The fields clear after 5 minutes without activity and when you leave the page, so the back/forward cache can't bring them back. |
| The breach check | k-anonymity: only the first 5 hex characters of the SHA-1 hash go to `api.pwnedpasswords.com`. The request asks for padding and sends no cookies, no referrer and no cache headers, with a 10 s timeout. Each response line has to match `^[0-9A-F]{35}:\d+$`. |
| Messages, links and files | They never leave the device. Files are hashed locally with the Web Crypto API, up to 512 MB. |
| The page itself (XSS) | User input is only rendered with `textContent`. The CSP allows no inline code and no third parties, and Trusted Types makes the browser block HTML injection sinks. |
| Visitors' privacy | No analytics, cookies or CDNs. Fonts are served from the repo, so there are no requests to Google. |
| Randomness | `crypto.getRandomValues` with rejection sampling. A test fails if `Math.random` appears anywhere. |
| The code | GitHub Actions runs the unit tests, a security test over the source code, CodeQL and Dependabot. |

## Content Security Policy

```
default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:;
connect-src https://api.pwnedpasswords.com; base-uri 'none'; form-action 'none'; object-src 'none';
require-trusted-types-for 'script'; trusted-types 'none'; upgrade-insecure-requests
```

Scripts, styles and fonts also allow `file:`, so the page works when you open it from disk.

GitHub Pages doesn't let you set HTTP headers, so the policy goes in a `<meta>` tag. That means `frame-ancestors` and HSTS aren't available here. If you host it somewhere else, send the policy as a header and add `frame-ancestors 'none'`.

## Limitations

The phishing and scam detectors work with rules. They get things wrong in both directions and can't prove that a site or a message is safe.

Password strength is an estimate based on common patterns. Real attackers have more tricks.

The official brand domains were checked in October 2026 and may change.

## Reporting a vulnerability

Please report it privately from the repository's Security tab ("Report a vulnerability"). The contact is also in [`.well-known/security.txt`](.well-known/security.txt). Don't include real passwords in the report. I'll answer as soon as I can. This is a student project, so any feedback helps.
