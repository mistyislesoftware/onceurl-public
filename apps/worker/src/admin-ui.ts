export const ADMIN_DOCUMENT = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow,noarchive"><title>OnceURL abuse response</title><script src="/internal/admin/client.js" defer></script></head><body><main>
<h1>Abuse response</h1><p>Reports require an operator decision. Protective access-code locks are not confirmed abuse. Secret content is unavailable here.</p>
<button id="reports" type="button">Load recent reports</button><pre id="report-list"></pre>
<form id="inspection"><label>Internal capability locator <input id="locator" required maxlength="53" pattern="loc1_[0-9a-f]{48}" autocomplete="off"></label><button>Inspect safe metadata</button></form><pre id="metadata"></pre>
<form id="enforcement"><label>Action <select id="action"><option value="disable">Disable</option><option value="abuse_lock">Abuse lock</option><option value="delete">Delete permanently</option><option value="release">Release protective lock</option></select></label>
<label>Reason <select id="reason"><option>phishing</option><option>malware</option><option>harassment</option><option>spam</option><option>other</option></select></label>
<label>Report handle (optional) <input id="report-id" maxlength="48" autocomplete="off"></label><label><input id="confirmed" type="checkbox">I independently confirm abuse (enforcement only)</label><button>Apply decision</button></form><p id="status" role="status"></p>
<p>Delete cannot be undone. A consumed, expired or deleted secret cannot be reopened. Operator absence and escalation follow the separately approved operations runbook.</p>
</main></body></html>`;

export const ADMIN_CLIENT = `(() => {
  const element = id => document.getElementById(id);
  let pending = null;
  const post = async (path, body, token) => {
    const response = await fetch('/internal/admin/' + path, { method: 'POST', cache: 'no-store', headers: { 'content-type': 'application/json', ...(token ? { 'X-OnceURL-CSRF': token } : {}) }, body: JSON.stringify(body) });
    if (!response.ok) throw new Error('unavailable');
    return response.json();
  };
  element('reports').onclick = async () => {
    try { element('report-list').textContent = JSON.stringify(await post('reports', {}), null, 2); }
    catch { element('status').textContent = 'Reports are unavailable.'; }
  };
  element('inspection').onsubmit = async event => {
    event.preventDefault();
    try { element('metadata').textContent = JSON.stringify(await post('inspect', { locator: element('locator').value }), null, 2); }
    catch { element('status').textContent = 'Metadata is unavailable.'; }
  };
  element('enforcement').onsubmit = async event => {
    event.preventDefault();
    const fields = { locator: element('locator').value, action: element('action').value, reason: element('reason').value, ...(element('report-id').value ? { report_id: element('report-id').value } : {}), confirm_abuse: element('confirmed').checked };
    if (!pending || JSON.stringify(pending.fields) !== JSON.stringify(fields)) pending = { fields, mutation: { ...fields, operation_id: crypto.randomUUID() } };
    const button = event.submitter;
    if (button) button.disabled = true;
    try {
      const control = await post('csrf', pending.mutation);
      await post('action', pending.mutation, control.csrf_token);
      pending = null;
      element('status').textContent = 'Decision durably recorded. Catalogue/audit projections may lag.';
    } catch { element('status').textContent = 'Decision unavailable or outcome unknown. Retry unchanged fields to reuse the same operation.'; }
    finally { if (button) button.disabled = false; }
  };
  window.addEventListener('pagehide', () => { pending = null; for (const id of ['locator', 'report-id']) element(id).value = ''; element('metadata').textContent = ''; element('report-list').textContent = ''; });
})();`;
