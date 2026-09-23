// Render the captured assurance report; the page stays usable if this fails.
fetch('/evidence/assurance-report.json').then(r => r.json()).then(report => {
  const box = document.getElementById('tests');
  const esc = s => String(s).replace(/[&<>"]/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;'}[c]));
  box.innerHTML = report.tests.map(t => `<article class="test"><span class="badge${t.passed ? '' : ' deny'}">${t.passed ? 'PASS' : 'FAIL'}</span><div><h3>${esc(t.name)}</h3><p>${esc(t.evidence || '')}</p><small>${esc(t.control || '')}${t.profile ? ' · ' + esc(t.profile) : ''}</small></div></article>`).join('');
}).catch(() => {});
