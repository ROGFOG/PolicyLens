# PolicyLens

Read a Content Security Policy without hunting through every directive by hand.
Paste a policy or response headers, inspect the script restrictions, then save
findings as JSON. The input stays in the browser.

[Try PolicyLens](https://rogfog.github.io/PolicyLens/)

![PolicyLens workbench](docs/screenshot.png)

## Start with a policy

```http
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
```

This example produces six findings: inline permissions for script elements and
attributes, missing base-uri, frame-ancestors and form-action, plus an HSTS
transport note. Those three CSP directives need their own values even when
default-src is set. The HSTS note needs the actual HTTPS deployment context.

The analyzer also handles duplicate directives, script-source fallbacks,
unsafe-eval, broad sources and mixed 'none' lists. Header input adds checks for
nosniff, Report-Only, HSTS and Referrer-Policy. Each finding links to a reference;
the severity filter and JSON export work on the same report.

## Known issues

Comma-separated policy lists are detected and skipped. Separate CSP headers are
reviewed individually, although browsers enforce them together. Nonce generation,
hash matching, HTTPS deployment and browser compatibility need a running page to
check. Treat the report as a starting point for testing policy changes.

## Local development

Node.js 24+ and npm:

```sh
npm ci --ignore-scripts
npm test
npm run dev
```

Open http://127.0.0.1:4173. `npm run build` writes the Pages site to `dist/`.
There are no runtime dependencies, network requests from the analyzer or saved
inputs. `src/analyze.ts` holds the rules; `src/main.ts` handles the form and export.

[Разбор примера и устройства анализатора](docs/design.ru.md) explains fallback
order and why duplicate directives keep their first value.

Checked on Windows with Node.js 24.14.0: 12 tests and the TypeScript/static build.
CI repeats the tests and build on Ubuntu before publication.

References: [MDN CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy),
[CSP Level 3](https://www.w3.org/TR/CSP3/). Source: [MIT](LICENSE).
