/* opencraysec report. Every piece of text from the data is inserted with textContent. */
(function () {
  'use strict';

  var SEV = ['critical', 'high', 'medium', 'low', 'unknown'];
  var REACH_LABEL = {
    used_symbol: 'Calls an affected function',
    imported: 'Imported',
    not_found: 'Not imported by your code',
    unknown: 'Unknown',
    not_checked: 'Not checked'
  };

  function h(tag, attrs) {
    var el = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        if (k === 'class') el.className = attrs[k];
        else if (k === 'text') el.textContent = attrs[k];
        else if (k === 'href') { var u = safeUrl(attrs[k]); if (u) { el.setAttribute('href', u); el.setAttribute('target', '_blank'); el.setAttribute('rel', 'noopener noreferrer'); } }
        else el.setAttribute(k, attrs[k]);
      });
    }
    for (var i = 2; i < arguments.length; i++) {
      var c = arguments[i];
      if (c == null || c === false) continue;
      el.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    }
    return el;
  }

  function safeUrl(u) {
    try { var p = new URL(u); return (p.protocol === 'https:' || p.protocol === 'http:') ? p.href : null; } catch (e) { return null; }
  }

  function css(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }
  function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); }
  function $(id) { return document.getElementById(id); }
  function sevBadge(s) { return h('span', { class: 'badge ' + (SEV.indexOf(s) >= 0 ? s : 'unknown'), text: s || 'unknown' }); }
  function when(ts) { if (!ts) return '-'; var d = new Date(ts); return isNaN(d) ? ts : d.toLocaleString(); }
  function pct(x) { return x == null ? '-' : (x * 100).toFixed(x >= 0.1 ? 0 : 1) + '%'; }

  var charts = [];
  function destroyCharts() { charts.forEach(function (c) { c.destroy(); }); charts = []; }

  function kpi(label, value, hint, cls) {
    return h('div', { class: 'card kpi ' + (cls || '') }, h('div', { class: 'label', text: label }), h('div', { class: 'value', text: String(value) }), h('div', { class: 'hint', text: hint || '' }));
  }

  function renderKpis(s) {
    var k = s.kpis, box = $('kpis');
    clear(box);
    box.appendChild(kpi('Open findings', k.open, k.packages_checked + ' packages checked', k.open ? '' : 'good'));
    box.appendChild(kpi('Critical + high', k.open_critical_high, 'fix these first', k.open_critical_high ? 'bad' : 'good'));
    box.appendChild(kpi('Malicious packages', k.malicious_open || 0, 'lockfiles and MCP servers', k.malicious_open ? 'bad' : 'good'));
    box.appendChild(kpi('Exploited in the wild', k.exploited_open, 'CISA KEV', k.exploited_open ? 'bad' : 'good'));
    box.appendChild(kpi('Run code at install', k.install_scripts || 0, 'review, not a vulnerability', ''));
    box.appendChild(kpi('Used by your code', k.used_in_code, 'calls an affected function', k.used_in_code ? 'bad' : ''));
    box.appendChild(kpi('Confirmed fixed', k.resolved_verified, 'verified by a re-scan', 'good'));
    box.appendChild(kpi('Changes recorded', k.recorded_fixes, 'reported by the AI'));
    box.appendChild(kpi('Assistant config issues', k.agent_config_issues || 0, 'rule files, MCP, hooks', k.agent_config_issues ? 'bad' : ''));
    box.appendChild(kpi('Suspected code issues', k.code_suspected, 'to be confirmed'));
    box.appendChild(kpi('Runtime products to review', k.runtime_scans ? k.runtime_attention : '-', k.runtime_scans ? (k.runtime_cves + ' CVE(s) listed by NVD') : 'run scan-runtime', k.runtime_attention ? 'bad' : ''));
    box.appendChild(kpi('Scans', k.scans, 'last: ' + when(k.last_scan)));
  }

  function fallbackTable(id, rows) {
    var box = $(id);
    clear(box);
    if (!rows.length) return;
    box.appendChild(h('div', { text: 'Charts are unavailable (the chart library could not be loaded). Data:' }));
    var t = h('table');
    rows.forEach(function (r) { t.appendChild(h('tr', null, h('td', { text: r[0] }), h('td', { text: String(r[1]) }))); });
    box.appendChild(t);
  }

  function chartOpts(extra) {
    var base = {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { labels: { color: css('--muted'), boxWidth: 12 } } },
      scales: {}
    };
    return Object.assign(base, extra || {});
  }

  function axes(stacked) {
    var grid = { color: css('--line') }, ticks = { color: css('--muted') };
    return { x: { stacked: !!stacked, grid: { display: false }, ticks: ticks }, y: { stacked: !!stacked, beginAtZero: true, grid: grid, ticks: Object.assign({ precision: 0 }, ticks) } };
  }

  function renderCharts(s) {
    destroyCharts();
    var hasChart = typeof window.Chart === 'function';
    var tl = s.timeline || [];
    var sevNow = s.severity_now || {};
    var reach = s.reachability || {};
    var tops = s.top_packages || [];
    var act = s.activity || [];

    ['timeline', 'severity', 'packages', 'reach', 'activity'].forEach(function (n) { clear($('f-' + n)); });
    if (!hasChart) {
      fallbackTable('f-timeline', tl.map(function (t) { return [when(t.ts), t.total + ' findings']; }));
      fallbackTable('f-severity', SEV.map(function (x) { return [x, sevNow[x] || 0]; }));
      fallbackTable('f-packages', tops.map(function (t) { return [t.package, t.findings + ' findings, score ' + t.score]; }));
      fallbackTable('f-reach', Object.keys(reach).map(function (x) { return [REACH_LABEL[x] || x, reach[x]]; }));
      fallbackTable('f-activity', act.map(function (a) { return [a.day, a.scans + ' scans, ' + a.resolved + ' resolved']; }));
      document.querySelectorAll('.chart-box').forEach(function (b) { b.style.display = 'none'; });
      return;
    }
    document.querySelectorAll('.chart-box').forEach(function (b) { b.style.display = ''; });
    var color = function (x) { return css('--' + x); };

    charts.push(new Chart($('c-timeline'), {
      type: 'bar',
      data: {
        labels: tl.map(function (t) { return when(t.ts); }),
        datasets: SEV.map(function (x) {
          return { label: x, data: tl.map(function (t) { return (t.by_severity || {})[x] || 0; }), backgroundColor: color(x), stack: 's', borderRadius: 3 };
        }).concat([{ type: 'line', label: 'exploited (KEV)', data: tl.map(function (t) { return t.exploited || 0; }), borderColor: color('critical'), backgroundColor: color('critical'), borderWidth: 2, pointRadius: 3, tension: 0.25, yAxisID: 'y' }]).concat(tl.some(function (t) { return t.malicious; }) ? [{ type: 'line', label: 'malicious packages', data: tl.map(function (t) { return t.malicious || 0; }), borderColor: color('critical'), backgroundColor: color('critical'), borderWidth: 2, borderDash: [5, 4], pointStyle: 'rectRot', pointRadius: 4, tension: 0.25, yAxisID: 'y' }] : [])
      },
      options: chartOpts({ scales: axes(true) })
    }));

    charts.push(new Chart($('c-severity'), {
      type: 'doughnut',
      data: { labels: SEV, datasets: [{ data: SEV.map(function (x) { return sevNow[x] || 0; }), backgroundColor: SEV.map(color), borderColor: css('--panel'), borderWidth: 2 }] },
      options: chartOpts({ cutout: '62%' })
    }));

    charts.push(new Chart($('c-packages'), {
      type: 'bar',
      data: { labels: tops.map(function (t) { return t.package; }), datasets: [{ label: 'risk score', data: tops.map(function (t) { return t.score; }), backgroundColor: tops.map(function (t) { return color(SEV.indexOf(t.severity) >= 0 ? t.severity : 'unknown'); }), borderRadius: 4 }] },
      options: chartOpts({ indexAxis: 'y', plugins: { legend: { display: false } }, scales: { x: axes(false).y, y: axes(false).x } })
    }));

    var rk = ['used_symbol', 'imported', 'unknown', 'not_found', 'not_checked'].filter(function (x) { return reach[x]; });
    var rcol = { used_symbol: color('critical'), imported: color('high'), unknown: color('unknown'), not_found: color('low'), not_checked: color('muted') };
    charts.push(new Chart($('c-reach'), {
      type: 'doughnut',
      data: { labels: rk.map(function (x) { return REACH_LABEL[x]; }), datasets: [{ data: rk.map(function (x) { return reach[x]; }), backgroundColor: rk.map(function (x) { return rcol[x]; }), borderColor: css('--panel'), borderWidth: 2 }] },
      options: chartOpts({ cutout: '62%' })
    }));

    charts.push(new Chart($('c-activity'), {
      type: 'bar',
      data: {
        labels: act.map(function (a) { return a.day; }),
        datasets: [
          { label: 'scans', data: act.map(function (a) { return a.scans; }), backgroundColor: css('--brand'), borderRadius: 3 },
          { label: 'fixes recorded by AI', data: act.map(function (a) { return a.recorded_fixes; }), backgroundColor: css('--medium'), borderRadius: 3 },
          { label: 'confirmed fixed (re-scan)', data: act.map(function (a) { return a.resolved; }), backgroundColor: css('--ok'), borderRadius: 3 }
        ]
      },
      options: chartOpts({ scales: axes(false) })
    }));
  }

  function refLinks(refs) {
    var box = h('span');
    (refs || []).forEach(function (r) {
      var u = safeUrl(r);
      if (!u) return;
      var host = new URL(u).hostname.replace(/^www\./, '');
      box.appendChild(h('a', { href: u, text: host, class: 'tag' }));
    });
    return box;
  }

  function changeTag(c) {
    var from = (c.from || []).join(', ') || '(new)', to = (c.to || []).join(', ') || '(removed)';
    return h('span', { class: 'tag change mono', text: c.package + ': ' + from + ' → ' + to });
  }

  function renderFixes(s) {
    var box = $('fixes');
    clear(box);
    var fixes = s.fixes || [];
    if (!fixes.length) {
      box.appendChild(h('div', { class: 'empty', text: 'No fixes recorded yet. When an AI changes your dependencies and calls record_fix (or verify_fix), they appear here.' }));
      return;
    }
    fixes.forEach(function (f) {
      var recorded = f.kind === 'recorded';
      var verified = recorded ? f.verified : f.trustworthy;
      var card = h('div', { class: 'card fix ' + (verified ? 'verified' : '') });
      var head = h('div', { class: 'head' },
        h('span', { class: 'tag ' + (verified ? 'good' : ''), text: recorded ? (verified ? 'Recorded by AI · verified by re-scan' : 'Recorded by AI · not yet verified') : 'Confirmed gone by re-scan' }),
        h('span', { class: 'sub', text: when(f.ts) + (f.client ? ' · ' + f.client : '') }));
      card.appendChild(head);
      card.appendChild(h('div', { class: 'title', text: recorded ? (f.summary || '(no summary)') : (f.ids || []).length + ' vulnerabilit' + ((f.ids || []).length === 1 ? 'y' : 'ies') + ' no longer present' }));
      var dl = h('dl');
      function row(k, v) { if (v == null || v === '' || (Array.isArray(v) && !v.length)) return; dl.appendChild(h('dt', { text: k })); dl.appendChild(h('dd', null, typeof v === 'string' ? document.createTextNode(v) : v)); }
      if (recorded) {
        row('Why', f.reason);
        var ch = (f.changes || []);
        if (ch.length) { var cb = h('span'); ch.forEach(function (c) { cb.appendChild(changeTag(c)); }); row('Lockfile changes', cb); }
        else row('Lockfile changes', f.baseline_found === false ? 'No earlier snapshot to compare with.' : 'No dependency version changed since the last snapshot.');
        row('Files', (f.files || []).join(', '));
        row('Commands', (f.commands || []).join(' ; '));
        row('Commit', f.commit);
      }
      var details = f.findings || [];
      if (details.length) {
        var list = h('div');
        details.forEach(function (d) {
          list.appendChild(h('div', null, sevBadge(d.severity), document.createTextNode(' '), h('span', { class: 'mono', text: d.id }), document.createTextNode(' ' + (d.package || '') + (d.version ? '@' + d.version : '') + ' — ' + (d.summary || '')), document.createTextNode(' '), refLinks(d.refs)));
        });
        row('Vulnerabilities', list);
      } else {
        row('Advisories', (f.ids || []).join(', '));
      }
      if (recorded && (f.unknown_ids || []).length) row('Not in last scan', f.unknown_ids.join(', '));
      card.appendChild(dl);
      box.appendChild(card);
    });
  }

  var state = { sort: 'severity', dir: -1, filter: 'all', q: '' };
  var SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 };

  function findingsRows(s) {
    var rows = (s.findings || []).slice();
    rows = rows.filter(function (f) {
      if (state.filter !== 'all' && f.severity !== state.filter) return false;
      if (!state.q) return true;
      var hay = [f.id, (f.aliases || []).join(' '), f.package, f.summary, (f.cwes || []).join(' ')].join(' ').toLowerCase();
      return hay.indexOf(state.q.toLowerCase()) >= 0;
    });
    var key = {
      severity: function (f) { return (f.malicious ? 20 : 0) + (f.exploited ? 10 : 0) + SEV_RANK[f.severity]; },
      package: function (f) { return (f.package || '').toLowerCase(); },
      cvss: function (f) { return f.cvss || 0; },
      epss: function (f) { return f.epss || 0; },
      advisory: function (f) { return f.id; }
    }[state.sort] || function () { return 0; };
    rows.sort(function (a, b) { var x = key(a), y = key(b); return (x < y ? -1 : x > y ? 1 : 0) * state.dir; });
    return rows;
  }

  function renderFindings(s) {
    var thead = document.querySelector('#findings thead'), tbody = document.querySelector('#findings tbody');
    clear(thead); clear(tbody);
    var cols = [['severity', 'Severity'], ['advisory', 'Advisory'], ['package', 'Package'], ['cvss', 'CVSS'], ['epss', 'EPSS'], [null, 'Your code'], [null, 'Fix'], [null, 'Why / references']];
    var tr = h('tr');
    cols.forEach(function (c) {
      var th = h('th', { text: c[1] + (c[0] && state.sort === c[0] ? (state.dir < 0 ? ' ▾' : ' ▴') : '') });
      if (c[0]) th.addEventListener('click', function () { if (state.sort === c[0]) state.dir = -state.dir; else { state.sort = c[0]; state.dir = -1; } renderFindings(s); });
      tr.appendChild(th);
    });
    thead.appendChild(tr);

    var bar = $('filters');
    clear(bar);
    ['all'].concat(SEV).forEach(function (x) {
      var b = h('button', { class: 'chip', type: 'button', 'aria-pressed': String(state.filter === x), text: x });
      b.addEventListener('click', function () { state.filter = x; renderFindings(s); });
      bar.appendChild(b);
    });
    var q = h('input', { type: 'search', placeholder: 'Search id, package, CWE…', value: state.q, 'aria-label': 'Search findings' });
    q.addEventListener('input', function () { state.q = q.value; renderFindings(s); var n = $('filters').querySelector('input'); if (n) { n.focus(); n.setSelectionRange(n.value.length, n.value.length); } });
    bar.appendChild(q);

    var rows = findingsRows(s);
    if (!rows.length) {
      tbody.appendChild(h('tr', null, h('td', { colspan: String(cols.length), class: 'empty', text: (s.findings || []).length ? 'No findings match the filter.' : 'No vulnerable dependencies in the latest scan.' })));
      return;
    }
    rows.forEach(function (f) {
      var reach = f.reach ? (REACH_LABEL[f.reach.level] || f.reach.level) : 'Not checked';
      var tr = h('tr', null,
        h('td', null, sevBadge(f.severity), f.malicious ? h('div', null, h('span', { class: 'tag hot', text: 'MALICIOUS' })) : null, f.exploited ? h('div', null, h('span', { class: 'tag hot', text: 'EXPLOITED' })) : null),
        h('td', null, h('div', { class: 'mono', text: f.id }), h('div', { class: 'sub mono', text: (f.aliases || []).slice(0, 2).join(' ') })),
        h('td', null, h('div', { text: f.package }), h('div', { class: 'sub mono', text: f.version + ' · ' + f.ecosystem + (f.dev ? ' · dev' : '') }), f.source ? h('div', { class: 'sub mono', text: f.source }) : null),
        h('td', { text: f.cvss == null ? '-' : f.cvss.toFixed(1) }),
        h('td', { text: pct(f.epss) }),
        h('td', null, h('div', { text: f.malicious ? 'Not assessed (malicious package)' : reach }), f.reach && f.reach.evidence && f.reach.evidence.length ? h('div', { class: 'sub mono', text: f.reach.evidence[0] }) : null),
        h('td', { class: 'mono', text: (f.fixed_in || []).length ? f.fixed_in[0] : (f.malicious ? 'remove it' : 'none') }),
        h('td', null, h('div', { text: f.summary || '' }), (f.cwes || []).length ? h('div', { class: 'sub', text: (f.cwes || []).join(', ') }) : null, refLinks(f.refs)));
      tbody.appendChild(tr);
    });
  }

  function renderCode(s) {
    var thead = document.querySelector('#code thead'), tbody = document.querySelector('#code tbody');
    clear(thead); clear(tbody);
    var code = s.code;
    var tr = h('tr');
    ['Severity', 'Rule', 'CWE', 'Where', 'What to do'].forEach(function (t) { tr.appendChild(h('th', { text: t })); });
    thead.appendChild(tr);
    if (!code || !(code.findings || []).length) {
      tbody.appendChild(h('tr', null, h('td', { colspan: '5', class: 'empty', text: code ? 'No suspected issues in the last code scan (' + (code.files_scanned || 0) + ' files).' : 'No code scan has been run yet (scan_code).' })));
      return;
    }
    code.findings.forEach(function (f) {
      tbody.appendChild(h('tr', null,
        h('td', null, sevBadge(f.severity)),
        h('td', null, h('div', { text: f.title }), h('div', { class: 'sub mono', text: f.rule })),
        h('td', { text: f.cwe || '-' }),
        h('td', { class: 'mono', text: f.file + ':' + f.line }),
        h('td', { text: f.advice || '' })));
    });
  }

  function renderAgent(s) {
    var thead = document.querySelector('#agent thead'), tbody = document.querySelector('#agent tbody');
    var notes = $('agent-notes');
    clear(thead); clear(tbody); clear(notes);
    var a = s.agent_config;
    var tr = h('tr');
    ['Severity', 'Rule', 'CWE', 'Where', 'What to do'].forEach(function (t) { tr.appendChild(h('th', { text: t })); });
    thead.appendChild(tr);
    if (!a) {
      tbody.appendChild(h('tr', null, h('td', { colspan: '5', class: 'empty', text: 'No assistant configuration scan has been run yet (opencraysec scan-agent-config, or the MCP tool scan_agent_config).' })));
      return;
    }
    var list = a.findings || [];
    if (!list.length) {
      tbody.appendChild(h('tr', null, h('td', { colspan: '5', class: 'empty', text: 'No finding in ' + (a.files_scanned || 0) + ' assistant configuration file(s). That is not proof they are safe.' })));
    }
    list.forEach(function (f) {
      tbody.appendChild(h('tr', null,
        h('td', null, sevBadge(f.severity), f.source === 'osv' ? h('div', { class: 'sub', text: 'advisory' }) : h('div', { class: 'sub', text: 'suspected' })),
        h('td', null, h('div', { text: f.title }), h('div', { class: 'sub mono', text: f.rule })),
        h('td', { text: f.cwe || '-' }),
        h('td', { class: 'mono', text: f.file + ':' + f.line }),
        h('td', { text: f.advice || '' })));
    });
    var lines = [];
    if (a.packages_checked) lines.push(a.packages_checked + ' MCP server package(s) with an exact version were checked against advisory data.');
    (a.unchecked || []).forEach(function (u) { lines.push('unchecked ' + u[0] + ': ' + u[1]); });
    if (a.home_scanned) lines.push('The home directory configuration was read as well.');
    (a.notes || []).forEach(function (n) { lines.push(n); });
    lines.forEach(function (l) { notes.appendChild(h('div', { class: 'notes', text: l })); });
  }

  function renderInstalls(s) {
    var thead = document.querySelector('#installs thead'), tbody = document.querySelector('#installs tbody');
    clear(thead); clear(tbody);
    var tr = h('tr');
    ['Package', 'Version', 'Ecosystem', 'Lockfile'].forEach(function (t) { tr.appendChild(h('th', { text: t })); });
    thead.appendChild(tr);
    var list = s.install_scripts || [], total = (s.kpis || {}).install_scripts || 0;
    if (!list.length) {
      tbody.appendChild(h('tr', null, h('td', { colspan: '4', class: 'empty', text: 'No package in the latest scan is recorded as running an install script. Lockfiles that cannot say are listed in the notes at the top.' })));
      return;
    }
    list.forEach(function (p) {
      tbody.appendChild(h('tr', null,
        h('td', null, h('div', { text: p.package }), p.dev ? h('div', { class: 'sub', text: 'development only' }) : null),
        h('td', { class: 'mono', text: p.version }),
        h('td', { text: p.ecosystem }),
        h('td', { class: 'mono', text: p.source })));
    });
    if (total > list.length) {
      tbody.appendChild(h('tr', null, h('td', { colspan: '4', class: 'empty', text: '... and ' + (total - list.length) + ' more (see the JSON report).' })));
    }
  }

  var RUNTIME_BADGE = { eol: 'high', outdated: 'medium', current: 'low', unknown: 'unknown' };

  function renderRuntime(s) {
    var thead = document.querySelector('#runtime thead'), tbody = document.querySelector('#runtime tbody');
    var notes = $('runtime-notes');
    clear(thead); clear(tbody); clear(notes);
    var rt = s.runtime;
    var tr = h('tr');
    ['Status', 'Product', 'Release line', 'Newest patch', 'CVEs (NVD)', 'What to do'].forEach(function (t) { tr.appendChild(h('th', { text: t })); });
    thead.appendChild(tr);
    if (!rt || !(rt.results || []).length) {
      tbody.appendChild(h('tr', null, h('td', { colspan: '6', class: 'empty', text: rt ? 'The last runtime scan judged nothing (see the notes below).' : 'No runtime scan has been run yet (opencraysec scan-runtime, or the MCP tool scan_runtime).' })));
    } else {
      rt.results.forEach(function (r) {
        var cves;
        if (!r.nvd) {
          cves = h('td', { class: 'sub', text: 'not asked (--nvd)' });
        } else if (r.nvd.error) {
          cves = h('td', { class: 'sub', text: 'NVD: ' + r.nvd.error });
        } else if (!(r.nvd.cves || []).length) {
          cves = h('td', { text: 'none listed for this version' });
        } else {
          cves = h('td', null);
          r.nvd.cves.slice(0, 6).forEach(function (c) {
            cves.appendChild(h('div', { class: 'cve' },
              h('span', { class: 'mono', text: c.id }),
              h('span', { text: '  ' + (c.cvss == null ? '' : 'CVSS ' + c.cvss.toFixed(1)) + (c.known_exploited ? '  exploited' : '') }),
              h('div', { class: 'sub', text: (c.affects || []).join('; ') })));
          });
          if (r.nvd.cves.length > 6) cves.appendChild(h('div', { class: 'sub', text: '... and ' + (r.nvd.cves.length - 6) + ' more' }));
        }
        tbody.appendChild(h('tr', null,
          h('td', null, h('span', { class: 'badge ' + (RUNTIME_BADGE[r.status] || 'unknown'), text: r.status })),
          h('td', null, h('div', { text: r.product + ' ' + r.version }), h('div', { class: 'sub mono', text: r.source }), r.scanned ? h('div', { class: 'sub', text: 'scanned ' + when(r.scanned) }) : null),
          h('td', null, h('div', { text: r.cycle || '-' }), r.eol_from ? h('div', { class: 'sub', text: 'end of life ' + r.eol_from }) : null),
          h('td', { class: 'mono', text: r.latest || '-' }),
          cves,
          h('td', { text: r.advice || '' })));
      });
    }
    if (rt) {
      (rt.notes || []).forEach(function (n) { notes.appendChild(h('div', { class: 'sub', text: n })); });
      var d = rt.data || {};
      notes.appendChild(h('div', { class: 'sub', text: 'Scanned ' + when(rt.ts) + ' · end-of-life data ' + (d.lifecycle_updated_at || 'not downloaded') }));
    }
  }

  function renderMeta(s) {
    $('subtitle').textContent = s.workspace + ' · ' + s.kpis.scans + ' scans · last scan ' + when(s.kpis.last_scan);
    var notes = $('notes');
    clear(notes);
    (s.notes || []).forEach(function (n) { notes.appendChild(h('div', { class: 'notes', text: n })); });
    var src = $('sources');
    clear(src);
    var ds = s.data_sources || [];
    if (ds.length) src.appendChild(h('div', { class: 'sub', text: 'Advisory data used: ' + ds.map(function (d) { return d.ecosystem + ' (' + d.mode + (d.updated_at ? ', updated ' + d.updated_at : '') + (d.malicious_records == null ? '' : ', ' + d.malicious_records + ' malicious-package reports') + ')'; }).join(' · ') }));
  }

  function render(s) {
    if (s.empty) {
      $('subtitle').textContent = 'No activity recorded yet';
      clear($('kpis'));
      $('kpis').appendChild(h('div', { class: 'empty card', text: 'The log is empty. Run a scan (opencraysec scan, or the MCP tool scan_dependencies) and reload.' }));
      return;
    }
    renderMeta(s); renderKpis(s); renderCharts(s); renderFixes(s); renderFindings(s); renderInstalls(s); renderRuntime(s); renderAgent(s); renderCode(s);
  }

  function fillWorkspaces(s, onChange) {
    var sel = $('ws');
    clear(sel);
    (s.workspaces || []).forEach(function (w) {
      var o = h('option', { value: w.path, text: w.path + ' (' + w.events + ' events)' });
      if (w.path === s.workspace) o.selected = true;
      sel.appendChild(o);
    });
    sel.onchange = function () { onChange(sel.value); };
  }

  function token() { return new URLSearchParams(location.search).get('token'); }

  function fetchSummary(ws) {
    var p = new URLSearchParams();
    if (ws) p.set('workspace', ws);
    if (token()) p.set('token', token());
    return fetch('/api/summary?' + p.toString(), { headers: { Accept: 'application/json' } }).then(function (r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    });
  }

  function start() {
    var embedded = $('embedded-data');
    if (embedded) {
      var s = JSON.parse(embedded.textContent);
      fillWorkspaces(s, function () {});
      $('ws').disabled = true;
      render(s);
      return;
    }
    function load(ws) {
      fetchSummary(ws).then(function (s) { fillWorkspaces(s, load); render(s); }).catch(function (e) {
        $('subtitle').textContent = 'Could not load the report: ' + e.message;
      });
    }
    load(null);
  }

  if (document.readyState === 'complete') start(); else window.addEventListener('load', start);
})();
