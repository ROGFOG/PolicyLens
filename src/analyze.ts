export type Severity = 'high' | 'warning' | 'note';
export interface Finding { id: string; severity: Severity; title: string; detail: string; reference: string }
export interface Report { findings: Finding[]; policyCount: number; headerCount: number }
const MDN = 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/';

/** Review one response or a bare CSP. Never fetches a URL or executes input. */
export function analyze(input: string): Report {
  if (!input.trim()) throw new Error('Paste response headers or a Content Security Policy first.');
  if (input.length > 100_000) throw new Error('Input is limited to 100,000 characters.');
  const headers = new Map<string, string[]>();
  const findings: Finding[] = [];
  const add = (id: string, severity: Severity, title: string, detail: string, header = 'Content-Security-Policy') => findings.push({ id, severity, title, detail, reference: MDN + header });
  const lines = input.trim().split(/\r?\n/);
  const isHeaders = lines.some(line => /^(?:content-security-policy(?:-report-only)?|strict-transport-security|x-[\w-]+|referrer-policy|content-type|permissions-policy|server|date|cache-control|location):/i.test(line.trim()));
  if (isHeaders) {
    for (const line of lines) {
      if (!line.trim() || /^HTTP\/\S+\s+\d{3}/i.test(line)) continue;
      const match = /^([\w-]+):\s*(.*)$/.exec(line.trim());
      if (!match) { add('invalid-header', 'warning', 'Unrecognized header line', 'Use one complete HTTP header per line. Folded lines are not supported.'); continue; }
      const key = match[1].toLowerCase();
      headers.set(key, [...(headers.get(key) ?? []), match[2]]);
    }
  } else headers.set('content-security-policy', [input.trim()]);
  const policies = headers.get('content-security-policy') ?? [];
  const reportOnly = headers.get('content-security-policy-report-only') ?? [];
  if (!policies.length) add('missing-csp', 'warning', 'No enforcing CSP found', reportOnly.length ? 'Report-Only policies collect violations but do not block content. Test a policy before enabling enforcement.' : 'Consider a CSP tailored to the scripts and resources your application needs.');
  if (policies.length > 1 || policies.some(value => value.includes(','))) add('multiple-csp', 'note', 'Multiple policies need a combined review', 'Browsers enforce policies together. The checks below review individual policies; an individual warning may be mitigated by another policy. Comma-separated policies are not analyzed.');

  for (const [index, policy] of policies.entries()) {
    if (policy.includes(',')) continue;
    const prefix = policies.length > 1 ? `Policy ${index + 1}: ` : '';
    const directives = new Map<string, string[]>();
    for (const part of policy.split(';')) {
      const tokens = part.trim().split(/\s+/);
      const name = tokens.shift()?.toLowerCase();
      if (!name) continue;
      if (!/^[a-z][a-z0-9-]*$/.test(name)) { add('invalid-directive', 'warning', prefix + 'Invalid directive name', 'Check the CSP syntax. This review is not a complete browser parser.'); continue; }
      if (directives.has(name)) { add('duplicate-directive', 'warning', prefix + `Repeated ${name}`, 'Browsers use the first occurrence of a directive in a policy, rather than merging repeated directives.'); continue; }
      directives.set(name, tokens);
      if (tokens.includes("'none'") && tokens.length > 1) add('mixed-none', 'warning', prefix + `${name} mixes 'none' with sources`, "The 'none' keyword is ignored when mixed with other sources. Use it alone to block a resource type.");
    }
    const fallback = directives.get('default-src');
    for (const [kind, sources] of [
      ['script elements', directives.get('script-src-elem') ?? directives.get('script-src') ?? fallback],
      ['script attributes', directives.get('script-src-attr') ?? directives.get('script-src') ?? fallback],
    ] as const) {
      if (!sources) { add('unrestricted-scripts', 'high', prefix + `No restriction on ${kind}`, 'Set script-src or default-src. Test changes with your actual application before enforcing them.'); continue; }
      const nonceOrHash = sources.some(value => /^'(?:nonce-|sha(?:256|384|512)-).+'$/.test(value));
      if (sources.includes("'unsafe-inline'")) add('inline-script', nonceOrHash ? 'note' : 'high', prefix + `Inline permission in ${kind}`, nonceOrHash ? "A nonce or hash is present. Modern browsers ignore 'unsafe-inline' in this source list; inspect legacy-browser behavior and nonce generation separately." : "Inline scripts or handlers can weaken CSP protection. Prefer external scripts, nonces or hashes appropriate to the directive.");
      const broad = sources.some(value => value === '*' || value === 'https:' || value === 'http:' || value === 'data:' || value.startsWith('*.') || value.includes('://*.'));
      if (broad) add('broad-scripts', nonceOrHash && sources.includes("'strict-dynamic'") ? 'note' : 'warning', prefix + `Broad sources for ${kind}`, 'Broad sources deserve review. strict-dynamic with a nonce or hash can change source-list behavior in supporting browsers.');
    }
    const evalSources = directives.get('script-src') ?? fallback;
    if (evalSources?.includes("'unsafe-eval'")) add('unsafe-eval', 'high', prefix + 'String evaluation is allowed', 'Remove unsafe-eval where possible. Review dependencies that require string-to-code evaluation.');
    if (!(directives.get('object-src') ?? fallback)) add('missing-object', 'warning', prefix + 'Object sources are unrestricted', "Consider object-src 'none' when embedded objects are unnecessary.");
    if (!directives.has('base-uri')) add('missing-base', 'warning', prefix + 'Base URL is unrestricted', "base-uri does not inherit default-src. Consider base-uri 'none' or 'self' for your application.");
    if (!directives.has('frame-ancestors')) add('missing-ancestors', 'note', prefix + 'No frame-ancestors directive', 'frame-ancestors does not inherit default-src. Set an explicit embedding policy if needed; X-Frame-Options may provide a separate restriction.');
    if (!directives.has('form-action')) add('missing-form', 'note', prefix + 'Form destinations are unrestricted', 'form-action does not inherit default-src. Restrict it to the destinations your forms need.');
  }
  if (isHeaders) {
    const nosniff = headers.get('x-content-type-options');
    if (!nosniff || nosniff.length !== 1 || nosniff[0].toLowerCase() !== 'nosniff') add('nosniff', 'warning', 'Check X-Content-Type-Options', 'Use a single X-Content-Type-Options: nosniff header and serve correct Content-Type values.', 'X-Content-Type-Options');
    const referrer = headers.get('referrer-policy');
    if (!referrer) add('referrer', 'note', 'No explicit Referrer-Policy', 'Modern browsers have a default policy. Choose an explicit policy if your application needs stricter referrer handling.', 'Referrer-Policy');
    if (!headers.has('strict-transport-security')) add('hsts', 'note', 'Review HTTPS transport policy', 'HSTS applies to HTTPS responses. The pasted text does not establish whether HTTPS is used; evaluate deployment before enabling HSTS or includeSubDomains.', 'Strict-Transport-Security');
    if (headers.has('content-security-policy-report-only')) add('report-only', 'note', 'Report-Only policy is present', 'The Report-Only policy is not enforced and is not included in the checks of enforcing policies.', 'Content-Security-Policy-Report-Only');
  }
  const rank = { high: 0, warning: 1, note: 2 };
  findings.sort((a, b) => rank[a.severity] - rank[b.severity]);
  return { findings, policyCount: policies.length, headerCount: isHeaders ? [...headers.values()].reduce((n, values) => n + values.length, 0) : 0 };
}
