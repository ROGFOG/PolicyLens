import { analyze } from './analyze.js';
import type { Report } from './analyze.js';
const element = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const input = element<HTMLTextAreaElement>('headers');
const results = element<HTMLDivElement>('results');
const error = element<HTMLParagraphElement>('error');
const download = element<HTMLButtonElement>('download');
let report: Report | undefined;
const example = "Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https:; object-src 'none';\nX-Content-Type-Options: nosniff\nReferrer-Policy: strict-origin-when-cross-origin";
function render() {
  results.replaceChildren();
  if (!report) { results.textContent = 'Paste a policy to start a review.'; return; }
  const filter = element<HTMLSelectElement>('filter').value;
  const visible = report.findings.filter(finding => filter === 'all' || finding.severity === filter);
  for (const finding of visible) {
    const article = document.createElement('article'); article.className = `finding ${finding.severity}`;
    const severity = document.createElement('span'); severity.className = 'severity'; severity.textContent = finding.severity;
    const title = document.createElement('h3'); title.textContent = finding.title;
    const detail = document.createElement('p'); detail.textContent = finding.detail;
    const reference = document.createElement('a'); reference.href = finding.reference; reference.textContent = 'Read the reference ↗'; reference.target = '_blank'; reference.rel = 'noopener noreferrer';
    article.append(severity, title, detail, reference); results.append(article);
  }
  if (!visible.length) { const empty = document.createElement('p'); empty.className = 'empty'; empty.textContent = report.findings.length ? 'No observations in this category.' : 'No supported rule raised an observation. This does not establish that a policy is secure.'; results.append(empty); }
}
element<HTMLFormElement>('review').addEventListener('submit', event => {
  event.preventDefault(); error.textContent = '';
  try { report = analyze(input.value); element('summary').textContent = `${report.findings.length} observations`; download.hidden = false; render(); }
  catch (reason) { report = undefined; download.hidden = true; element('summary').textContent = 'Check input'; error.textContent = reason instanceof Error ? reason.message : 'Review failed.'; render(); }
});
element('example').addEventListener('click', () => { input.value = example; input.focus(); });
element('clear').addEventListener('click', () => { input.value = ''; report = undefined; error.textContent = ''; element('summary').textContent = 'Awaiting input'; download.hidden = true; render(); input.focus(); });
element('filter').addEventListener('change', render);
download.addEventListener('click', () => { if (!report) return; const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })); const link = document.createElement('a'); link.href = url; link.download = 'policylens-report.json'; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); });
