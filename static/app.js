const $ = id => document.getElementById(id);
let currentReport = null;
function displayText(value) { return String(value).replace(/FIREWORKS_API_KEY and FIREWORKS_MODEL/g, 'the reasoning model credentials and model').replace(/Fireworks/gi, 'Reasoning model'); }
function node(tag, text, className) { const el = document.createElement(tag); if (text !== undefined) el.textContent = text; if (className) el.className = className; return el; }
async function api(path, options) { const res = await fetch(path, options); const data = await res.json(); if (!res.ok) throw new Error(data.error || 'Request failed'); return data; }
api('/api/config').then(c => { $('configuration').textContent = `Powered by Jev · ${c.fireworks && c.jev ? 'Ready to analyze' : 'Model setup needed'}`; }).catch(() => { $('configuration').textContent = 'Could not check model configuration'; });
async function scan(demo = false) {
  $('error').hidden = true; $('report').hidden = true; $('activity').hidden = false;
  $('scan-button').disabled = $('demo-button').disabled = true; $('activity-text').textContent = 'Preparing assessment…';
  try {
    const job = await api('/api/scans', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: $('repo').value.trim(), demo }) });
    while (true) {
      const state = await api(`/api/scans/${job.id}`);
      $('activity-text').textContent = displayText(state.message);
      if (state.status === 'failed') throw new Error(state.message);
      if (state.status === 'completed') { currentReport = state.report; render(); break; }
      await new Promise(resolve => setTimeout(resolve, 1200));
    }
  } catch (error) { $('error').textContent = displayText(error.message); $('error').hidden = false; }
  finally { $('activity').hidden = true; $('scan-button').disabled = $('demo-button').disabled = false; }
}
$('scan-form').addEventListener('submit', e => { e.preventDefault(); scan(); });
$('demo-button').addEventListener('click', () => scan(true));
function render() {
  const r = currentReport;
  $('report-label').textContent = r.mode === 'demo' ? 'SAMPLE REPORT · STATIC RULES ONLY' : 'REPOSITORY ASSESSMENT';
  $('report-title').textContent = r.repository;
  $('report-meta').textContent = `Commit ${r.commit.slice(0, 12)} · ${new Date(r.created_at).toLocaleString()}`;
  $('verdict').textContent = r.verdict; $('coverage-status').textContent = r.coverage_status;
  $('finding-count').textContent = r.findings.length; $('file-count').textContent = r.files.length;
  $('candidate-count').textContent = `${r.candidate_count} candidate files discovered`;
  $('high-count').textContent = r.findings.filter(f => ['high','critical'].includes(f.severity)).length;
  $('severity').value = 'all'; renderFindings(); $('dimensions').replaceChildren();
  if (!Object.keys(r.dimensions).length) $('dimensions').append(node('p', 'Jev did not run. No AI probabilities are available.', 'muted'));
  for (const [key, probability] of Object.entries(r.dimensions)) {
    const row = node('div', undefined, 'dimension'); row.append(node('span', key.replaceAll('_',' ')), node('b', `${Math.round(probability * 100)}%`));
    const bar = node('progress'); bar.max = 1; bar.value = probability; bar.setAttribute('aria-label', key.replaceAll('_',' ')); row.append(bar); $('dimensions').append(row);
  }
  $('providers').replaceChildren();
  for (const [key, value] of Object.entries(r.providers)) { const row = node('div', undefined, 'provider'); row.append(node('b', key === 'jev' ? 'Jev' : 'Reasoning model'), node('span', key === 'jev' ? value : value === 'Not run' ? 'Not run' : 'Analysis completed')); $('providers').append(row); }
  $('warnings').replaceChildren(...r.warnings.map(w => node('li', displayText(w))));
  $('coverage-note').textContent = `Inspected ${r.files.length} of ${r.candidate_count} candidate files. ${r.skipped.length} skipped entries. Repository tree ${r.tree_truncated ? 'was truncated by GitHub' : 'was not truncated'}. Only supported text formats are selected; dependencies and external servers are not followed.`;
  $('files').replaceChildren();
  for (const f of r.files) { const row = node('div', undefined, 'file-row'); row.append(node('span', f.path), node('span', `${f.kind} · ${f.lines} lines`)); $('files').append(row); }
  for (const f of r.skipped) { const row = node('div', undefined, 'file-row'); row.append(node('span', f.path), node('span', `Skipped: ${f.reason}`)); $('files').append(row); }
  $('report').hidden = false; $('how').hidden = true; $('report').scrollIntoView({ behavior: 'smooth', block: 'start' });
}
function renderFindings() {
  const findings = currentReport.findings.filter(f => $('severity').value === 'all' || f.severity === $('severity').value);
  $('findings').replaceChildren();
  if (!findings.length) $('findings').append(node('p', 'No findings in this view. Check assessment coverage and model availability before drawing conclusions.', 'empty'));
  for (const f of findings) {
    const card = node('article', undefined, 'finding'), top = node('div', undefined, 'finding-top');
    top.append(node('span', f.severity, `badge ${f.severity}`), node('span', displayText(f.origin)), node('span', `${f.verification}${f.support_probability === undefined ? '' : ` · ${Math.round(f.support_probability * 100)}% support`}`));
    card.append(top, node('h4', f.title));
    if (currentReport.mode === 'live') {
      const link = node('a', `${f.path}:${f.line}`, 'source'); link.href = `https://github.com/${currentReport.repository}/blob/${currentReport.commit}/${f.path.split('/').map(encodeURIComponent).join('/')}#L${f.line}`; link.target = '_blank'; link.rel = 'noopener noreferrer'; card.append(link);
    } else card.append(node('span', `${f.path}:${f.line}`, 'source'));
    card.append(node('p', f.explanation), node('pre', f.evidence));
    const fix = node('p', undefined, 'fix'); fix.append(node('b', 'RECOMMENDED ACTION'), document.createTextNode(f.remediation)); card.append(fix); $('findings').append(card);
  }
}
$('severity').addEventListener('change', renderFindings);
function download(text, type, extension) { const url = URL.createObjectURL(new Blob([text], { type })); const a = node('a'); a.href = url; a.download = `agents-be-safe-report.${extension}`; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); }
$('download-json').addEventListener('click', () => download(JSON.stringify(currentReport, null, 2), 'application/json', 'json'));
// Quote untrusted report text; escape Markdown HTML and link syntax in exported reports.
function md(value) { return String(value).replace(/[\\`*_{}\[\]()<>#!|]/g, '\\$&'); }
$('download-md').addEventListener('click', () => {
  const r = currentReport;
  const lines = ['# Agents Be Safe report', '', `Repository: ${md(r.repository)}`, `Commit: ${md(r.commit)}`, `Created: ${md(r.created_at)}`, `Mode: ${md(r.mode)}`, '', `Assessment: ${md(r.verdict)}`, `Coverage: ${md(r.coverage_status)}`, '', '## Engines', ...Object.entries(r.providers).map(([k,v]) => `- ${md(k)}: ${md(v)}`), '', '## Jev risk probabilities', ...Object.entries(r.dimensions).map(([k,v]) => `- ${md(k)}: ${Math.round(v*100)}%`), '', '## Findings'];
  for (const f of r.findings) lines.push('', `### ${md(f.severity.toUpperCase())}: ${md(f.title)}`, `${md(f.path)}:${f.line}`, '', md(f.explanation), '', `Evidence: ${md(f.evidence)}`, '', `Action: ${md(f.remediation)}`, '', `${md(f.origin)} · ${md(f.verification)}${f.support_probability === undefined ? '' : ` · support ${Math.round(f.support_probability*100)}%`}`);
  lines.push('', '## Coverage', `${r.files.length}/${r.candidate_count} candidate files inspected; tree truncated: ${r.tree_truncated}`, ...r.files.map(f => `- ${md(f.path)} (${md(f.kind)})`), ...r.skipped.map(f => `- Skipped ${md(f.path)}: ${md(f.reason)}`), '', '## Limitations', ...r.warnings.map(w => `- ${md(w)}`));
  download(lines.join('\n'), 'text/markdown', 'md');
});
$('print').addEventListener('click', () => { document.querySelector('.coverage').open = true; $('severity').value = 'all'; renderFindings(); window.print(); });
