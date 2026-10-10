let targetHash = null;

async function buildTable() {
  const btn = document.getElementById('buildBtn');
  btn.disabled = true;
  btn.textContent = 'Building…';
  const res = await fetch('/api/build', { method: 'POST' });
  const stats = await res.json();
  btn.textContent = 'Rebuild table';
  btn.disabled = false;

  const el = document.getElementById('tableStats');
  el.style.display = 'flex';
  el.innerHTML = `
    <div class="stat"><span>Tables built</span><span>${stats.tables_built}</span></div>
    <div class="stat"><span>Chains stored</span><span>${stats.total_stored.toLocaleString()} / ${stats.total_space.toLocaleString()}</span></div>
    <div class="stat"><span>Chain length</span><span>${stats.chain_length} steps each</span></div>
    <div class="stat"><span>Collisions dropped</span><span>${stats.collisions_dropped.toLocaleString()}</span></div>
    <div class="stat"><span>Build time</span><span>${stats.build_ms} ms</span></div>
  `;
  document.getElementById('crackBtn').disabled = false;
  document.getElementById('sampleBtn').disabled = false;
}

async function computeHash() {
  const pw = document.getElementById('pwInput').value.toLowerCase();
  const res = await fetch('/api/hash', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password: pw }),
  });
  const data = await res.json();
  if (data.error) { alert(data.error); return; }

  targetHash = data.hash;
  const out = document.getElementById('hashOut');
  out.style.display = 'flex';
  out.innerHTML = `
    <div class="stat"><span>Plaintext</span><span>${data.password}</span></div>
    <div class="stat"><span>MD5 hash</span><span>${data.hash}</span></div>
  `;
}

async function sampleFromTable() {
  const res = await fetch('/api/sample');
  const data = await res.json();
  if (data.error) { alert(data.error); return; }
  document.getElementById('pwInput').value = data.password;
  await computeHash();
}

async function runAttack() {
  if (!targetHash) { alert('Hash a password first.'); return; }
  const logEl = document.getElementById('searchLog');
  const traceEl = document.getElementById('trace');
  const verdictEl = document.getElementById('verdict');
  logEl.innerHTML = '<div class="empty">Searching…</div>';
  traceEl.innerHTML = '';
  verdictEl.innerHTML = '';

  const res = await fetch('/api/crack', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ hash: targetHash }),
  });
  const data = await res.json();
  if (data.error) { alert(data.error); return; }

  // Render search log with per-event detail
  logEl.innerHTML = '';
  data.search_log.forEach(entry => {
    const row = document.createElement('div');
    let cls = 'log-row';
    let msg = `${entry.positions_checked} positions scanned`;

    if (entry.hit) {
      cls += ' hit';
      msg += ' → match found';
    } else {
      msg += ' → no match';
    }

    row.className = cls;
    row.innerHTML = `<span>Table ${entry.table}</span><span>${msg}</span>`;
    logEl.appendChild(row);

    // Show individual events (false alarms and matches) for transparency
    if (entry.events && entry.events.length > 0) {
      entry.events.forEach(ev => {
        const evRow = document.createElement('div');
        if (ev.type === 'match') {
          evRow.className = 'log-row hit';
          evRow.innerHTML = `<span style="padding-left:12px">↳ pos ${ev.position}</span><span>chain "${ev.chain_start}" → recovered at step ${ev.matched_step}</span>`;
        } else {
          evRow.className = 'log-row alarm';
          evRow.innerHTML = `<span style="padding-left:12px">↳ pos ${ev.position}</span><span>chain "${ev.chain_start}" → endpoint matched but hash not in chain</span>`;
        }
        logEl.appendChild(evRow);
      });
    }
  });

  // Render full regeneration trace — every step, full hashes
  if (data.regen_trace && data.regen_trace.length > 0) {
    data.regen_trace.forEach((s, i) => {
      const isLast = i === data.regen_trace.length - 1 && data.recovered;
      const row = document.createElement('div');
      row.className = 'trace-row' + (isLast ? ' found' : '');
      row.innerHTML = `<span>${s.step}</span><span>${s.password}</span><span>${s.hash}</span>`;
      traceEl.appendChild(row);
    });
  }

  // Render verdict with verification proof and timing
  if (data.recovered) {
    verdictEl.innerHTML = `<div class="verdict success">
      <div>Recovered: <strong>${data.recovered}</strong></div>
      <div style="margin-top:4px;font-size:11px;opacity:0.8">MD5("${data.recovered}") = ${data.target_hash}</div>
      <div style="margin-top:2px;font-size:11px;opacity:0.6">Verified: ${data.verified ? '✓ hash matches' : '✗ mismatch'} · ${data.crack_ms} ms</div>
    </div>`;
  } else {
    verdictEl.innerHTML = `<div class="verdict fail">
      <div>Not recovered across ${data.search_log.length} table${data.search_log.length > 1 ? 's' : ''}.</div>
      <div style="margin-top:4px;font-size:11px;opacity:0.8">This can happen (~4%) since coverage isn't 100%.</div>
      <div style="margin-top:2px;font-size:11px;opacity:0.6">Search time: ${data.crack_ms} ms</div>
    </div>`;
  }
}

document.getElementById('buildBtn').addEventListener('click', buildTable);
document.getElementById('hashBtn').addEventListener('click', computeHash);
document.getElementById('crackBtn').addEventListener('click', runAttack);
document.getElementById('sampleBtn').addEventListener('click', sampleFromTable);
