import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { ReportModel } from "../types.js";
import { withReportCommands } from "./commands.js";

function templatePath(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  return join(here, "../../templates/report.html");
}

export function renderHtml(report: ReportModel): string {
  let template: string;
  try {
    template = readFileSync(templatePath(), "utf8");
  } catch {
    template = FALLBACK_HTML;
  }
  const normalized: ReportModel = {
    ...report,
    entries: report.entries.map(withReportCommands),
  };
  const json = JSON.stringify(normalized).replace(/</g, "\\u003c");
  return template.replace("<!--SUPPLYWARDEN_DATA-->", json);
}

export function writeHtml(report: ReportModel, path: string): string {
  writeFileSync(path, renderHtml(report));
  return path;
}

const FALLBACK_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>supplywarden report</title>
  <style>
    :root { color-scheme: light dark; --bg: #0f1419; --fg: #e7ecf3; --muted: #9aa7b8; --card: #1a222c; --ok: #3dd68c; --warn: #f5c14a; --bad: #ff6b6b; --accent: #6cb6ff; }
    body { font-family: ui-sans-serif, system-ui, sans-serif; margin: 0; background: var(--bg); color: var(--fg); }
    header { padding: 24px 32px; border-bottom: 1px solid #2a3542; }
    h1 { margin: 0 0 8px; font-size: 22px; }
    h2 { font-size: 16px; margin: 0 0 12px; }
    .meta { color: var(--muted); font-size: 13px; }
    main { padding: 24px 32px; }
    .cards { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 24px; }
    .card { background: var(--card); padding: 16px 18px; border-radius: 10px; min-width: 140px; }
    .card b { display: block; font-size: 22px; }
    .card span { color: var(--muted); font-size: 12px; }
    .panel { background: var(--card); border-radius: 10px; padding: 16px 18px; margin-bottom: 24px; }
    table { width: 100%; border-collapse: collapse; background: var(--card); border-radius: 10px; overflow: hidden; }
    th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid #2a3542; font-size: 14px; vertical-align: top; }
    th { color: var(--muted); font-weight: 600; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 700; margin-right: 4px; }
    .OK { background: #163627; color: var(--ok); }
    .REMOVABLE, .RESOLVED, .CONFIRMED_REMOVABLE { background: #163627; color: var(--ok); }
    .OVERDUE, .STALE, .DRIFT, .KEEP, .UNTRACKED { background: #3a2e12; color: var(--warn); }
    .NEW, .VERIFY_FAILED { background: #3a1515; color: var(--bad); }
    input { background: #0f1419; color: var(--fg); border: 1px solid #2a3542; border-radius: 8px; padding: 8px 10px; margin-bottom: 16px; width: 280px; }
    .detail { white-space: pre-wrap; color: var(--muted); font-size: 12px; }
    details { margin-top: 6px; }
    summary { cursor: pointer; color: var(--accent); font-size: 12px; }
    .chain { font-family: ui-monospace, monospace; font-size: 12px; color: var(--muted); margin: 2px 0; }
    code { font-family: ui-monospace, monospace; font-size: 12px; background: #0f1419; padding: 1px 6px; border-radius: 4px; color: var(--accent); white-space: nowrap; }
  </style>
</head>
<body>
  <header>
    <h1 id="title">supplywarden</h1>
    <div class="meta" id="meta"></div>
  </header>
  <main>
    <div class="cards" id="cards"></div>
    <div id="removable"></div>
    <input id="filter" placeholder="Filter package / status"/>
    <table>
      <thead><tr><th>Package</th><th>Status</th><th>Action</th><th>ReviewBy</th></tr></thead>
      <tbody id="rows"></tbody>
    </table>
  </main>
  <script type="application/json" id="supplywarden-data"><!--SUPPLYWARDEN_DATA--></script>
  <script>
    const REASON = {
      'not-in-tree': 'No longer in the lockfile',
      'no-vulnerable-version': 'No vulnerable version left in the tree',
      'already-at-patched': 'package.json already depends on the patched version — override is leftover',
      'root-upgrade-candidate': 'Only the forced version is in the tree — consider a root upgrade',
      'audit-clear': 'Live audit no longer lists this package'
    };
    function esc(s) {
      return String(s ?? '').replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    }
    function formatAction(s) {
      return esc(s).replace(/\x60([^\x60]+)\x60/g, '<code>$1</code>');
    }
    function nextCommands(e) {
      if (e.commands && e.commands.length) return e.commands;
      const pkg = (e.entry && e.entry.package) || '';
      const st = e.statuses && e.statuses.length ? e.statuses : [e.status];
      if (st.includes('NEW')) return ['supplywarden fix --apply'];
      if (st.includes('UNTRACKED')) {
        const cmds = ['supplywarden init'];
        if (st.includes('REMOVABLE') || st.includes('RESOLVED')) cmds.push('supplywarden verify ' + pkg + ' --apply');
        return cmds;
      }
      if (st.includes('DRIFT')) return ['supplywarden sync'];
      if (st.includes('VERIFY_FAILED') || st.includes('PENDING_VERIFY')) return ['supplywarden verify ' + pkg];
      if (st.includes('REMOVABLE') || st.includes('RESOLVED') || e.verifyOutcome === 'CONFIRMED_REMOVABLE') {
        return ['supplywarden verify ' + pkg + ' --apply'];
      }
      return pkg ? ['supplywarden why ' + pkg] : [];
    }
    function rewriteLegacy(s, pkg) {
      return String(s || '')
        .replaceAll('supplywarden check --apply', 'supplywarden verify ' + pkg + ' --apply')
        .replaceAll('supplywarden verify --apply', 'supplywarden verify ' + pkg + ' --apply')
        .replace(/supplywarden analyze(?: --audit)?/g, 'supplywarden fix --apply')
        .replace(/supplywarden fix \\S+ --apply --yes/g, 'supplywarden fix --apply')
        .replace(/ --yes\\b/g, '')
        .replace(/supplywarden verify(?! \\S)/g, 'supplywarden verify ' + pkg);
    }
    function actionCell(e) {
      const pkg = (e.entry && e.entry.package) || '';
      const cmds = nextCommands(e).map((c) => '<code>' + esc(c) + '</code>').join(' ');
      const note = rewriteLegacy(e.suggestedAction || '', pkg);
      return cmds + (note ? '<div class="detail">' + formatAction(note) + '</div>' : '');
    }
    const report = JSON.parse(document.getElementById('supplywarden-data').textContent || '{}');
    document.getElementById('title').textContent = report.title || 'supplywarden report';
    document.getElementById('meta').textContent = (report.cwd || '') + ' · ' + (report.generatedAt || '');
    const cards = document.getElementById('cards');
    for (const [k, v] of Object.entries(report.summary || {})) {
      const el = document.createElement('div');
      el.className = 'card';
      el.innerHTML = '<b>' + esc(v) + '</b><span>' + esc(k) + '</span>';
      cards.appendChild(el);
    }
    function canRemove(e) {
      return (e.statuses || []).includes('REMOVABLE') || (e.statuses || []).includes('RESOLVED');
    }
    function actionRank(e) {
      const st = e.statuses || [e.status];
      if (e.status === 'NEW' || st.includes('NEW')) return 0;
      if (e.status === 'VERIFY_FAILED' || st.includes('VERIFY_FAILED')) return 1;
      if (e.status === 'OVERDUE' || st.includes('OVERDUE')) return 2;
      if (e.status === 'DRIFT' || st.includes('DRIFT')) return 3;
      if (st.includes('REMOVABLE') || st.includes('RESOLVED')) return 4;
      if (e.status === 'UNTRACKED' || st.includes('UNTRACKED')) return 5;
      if (e.status === 'PENDING_VERIFY' || st.includes('PENDING_VERIFY')) return 6;
      return 7;
    }
    const sorted = (report.entries || []).slice().sort((a, b) => {
      const d = actionRank(a) - actionRank(b);
      if (d !== 0) return d;
      return String(a.entry.package).localeCompare(String(b.entry.package));
    });
    const removable = sorted.filter(canRemove);
    if (removable.length) {
      const panel = document.getElementById('removable');
      panel.className = 'panel';
      let html = '<h2>Safe to remove</h2><table><thead><tr><th>Package</th><th>Reason</th><th>Action</th><th>GHSA</th></tr></thead><tbody>';
      for (const e of removable) {
        const ghsa = (e.entry.advisories || []).map((a) => a.ghsaId).filter(Boolean).join(', ') || '—';
        html += '<tr><td><strong>' + esc(e.entry.package) + '@' + esc(e.entry.forcedVersion) + '</strong></td>' +
          '<td>' + esc(REASON[e.removableReason] || '—') + '</td>' +
          '<td>' + actionCell(e) + '</td>' +
          '<td>' + esc(ghsa) + '</td></tr>';
      }
      html += '</tbody></table>';
      panel.innerHTML = html;
    }
    function graphBlock(e) {
      const roots = e.roots || e.entry.rootPackages || [];
      const chains = e.chains || e.entry.dependencyChains || [];
      const versions = e.installedVersions || [];
      if (!roots.length && !chains.length && !versions.length) return '';
      let body = '';
      if (versions.length) body += '<div class="chain">Lockfile: ' + esc(versions.join(', ')) + ' (forced: ' + esc(e.entry.forcedVersion) + ')</div>';
      if (roots.length) body += '<div class="chain">Roots: ' + esc(roots.join(', ')) + '</div>';
      for (const c of chains) body += '<div class="chain">' + esc(c) + '</div>';
      return '<details><summary>Roots &amp; dependency chains</summary>' + body + '</details>';
    }
    function render(filter) {
      const tbody = document.getElementById('rows');
      tbody.innerHTML = '';
      for (const e of sorted) {
        const hay = (e.entry.package + ' ' + e.status + ' ' + (e.suggestedAction || '')).toLowerCase();
        if (filter && !hay.includes(filter)) continue;
        const tr = document.createElement('tr');
        const st = (e.statuses || [e.status]).join(' + ');
        const outcome = e.verifyOutcome ? ' <span class="badge ' + esc(e.verifyOutcome) + '">' + esc(e.verifyOutcome) + '</span>' : '';
        tr.innerHTML = '<td><strong>' + esc(e.entry.package) + '@' + esc(e.entry.forcedVersion) + '</strong><div class="detail">' + esc(e.entry.reason || '') + '</div>' + graphBlock(e) + '</td>' +
          '<td><span class="badge ' + esc(e.status) + '">' + esc(st) + '</span>' + outcome + '</td>' +
          '<td>' + actionCell(e) + '</td>' +
          '<td>' + esc(e.entry.reviewBy || '') + '</td>';
        tbody.appendChild(tr);
      }
    }
    render('');
    document.getElementById('filter').addEventListener('input', (ev) => render(ev.target.value.toLowerCase()));
  </script>
</body>
</html>
`;
