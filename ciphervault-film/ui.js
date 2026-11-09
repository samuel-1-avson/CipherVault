// Hermes Desktop (light theme, and its dark "sealed" state), redrawn from the real app's structure and the CipherVault
// plugin's own labels (plugins/ciphervault/desktop/plugin.js). State in → HTML out. Every element the sprite, the cursor
// or the spotlight needs carries data-a="key" so its position is measured from the live DOM each frame.
export const WIN = { x: 48, y: 24, w: 1824, h: 994 };
export const TB = { y: 1032, h: 48 };
const esc = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
export { esc };

// tiny line icons (stroke = currentColor)
const I = {
  new: '<path d="M4 5h9M4 9h6M4 13h5M13 11v6M10 14h6"/>',
  tools: '<path d="M5 15l6-6M10 4l4 4-2 2-4-4zM4 16l2-2"/>',
  msg: '<path d="M4 5h12v8H9l-3 3v-3H4z"/>',
  art: '<path d="M6 3h6l3 3v11H6zM12 3v3h3"/>',
  search: '<circle cx="9" cy="9" r="4.5"/><path d="M12.5 12.5L16 16"/>',
  pin: '<path d="M7 3h6l-1 5 3 3H5l3-3zM10 11v6"/>',
  spk: '<path d="M4 8h3l4-3v10l-4-3H4zM14 7c1.5 1.5 1.5 4.5 0 6"/>',
  gear: '<circle cx="10" cy="10" r="2.5"/><path d="M10 3v2M10 15v2M3 10h2M15 10h2M5 5l1.4 1.4M13.6 13.6L15 15M5 15l1.4-1.4M13.6 6.4L15 5"/>',
  panel: '<rect x="3" y="4" width="14" height="12" rx="2"/><path d="M12 4v12"/>',
  plus: '<path d="M10 4v12M4 10h12"/>',
  mic: '<rect x="8" y="3" width="4" height="9" rx="2"/><path d="M5 10c0 3 2.2 5 5 5s5-2 5-5M10 15v2"/>',
  term: '<rect x="3" y="4" width="14" height="12" rx="2"/><path d="M6 8l2 2-2 2M10 12h4"/>',
  file: '<path d="M6 3h6l3 3v11H6z"/>',
  folder: '<path d="M3 6h5l2 2h7v8H3z"/>',
  lock: '<rect x="5" y="9" width="10" height="8" rx="1.5"/><path d="M7 9V7a3 3 0 016 0v2"/>',
  web: '<circle cx="10" cy="10" r="6.5"/><path d="M3.5 10h13M10 3.5c2 2 2 11 0 13M10 3.5c-2 2-2 11 0 13"/>',
  shield: '<path d="M10 3l6 2v5c0 4-3 6-6 7-3-1-6-3-6-7V5z"/>',
  vault: '<rect x="3" y="4" width="14" height="12" rx="2"/><circle cx="10" cy="10" r="2.6"/><path d="M10 7.4V6M12.6 10H14"/>',
  git: '<circle cx="6" cy="5" r="1.8"/><circle cx="6" cy="15" r="1.8"/><circle cx="14" cy="9" r="1.8"/><path d="M6 7v6M14 11c0 2-3 2-6 3"/>',
  key: '<circle cx="7" cy="10" r="3"/><path d="M10 10h7M14 10v3M16 10v2"/>',
  check: '<path d="M4 10l4 4 8-8"/>',
  x: '<path d="M5 5l10 10M15 5L5 15"/>',
};
export const ic = (n, s = 18, sw = 1.6) => `<svg class="ic" width="${s}" height="${s}" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="${sw}" stroke-linecap="round" stroke-linejoin="round">${I[n] || ''}</svg>`;

// ───────── desktop: wallpaper + taskbar + toast
export function desk(D) {
  let h = '<div id="wall"></div>';
  h += taskbar(D.tb || {});
  if (D.toast) h += toast(D.toast);
  return h;
}
function taskbar(T) {
  const icons = [['win', ''], ['search', ''], ['hermes', 'tb-hermes'], ['term', ''], ['folder', '']];
  const glyph = n => n === 'win' ? '<i class="winlogo"><b></b><b></b><b></b><b></b></i>'
    : n === 'hermes' ? `<i class="happ" data-a="tb-hermes">${ic('msg', 22, 1.8)}</i>` : `<i class="tic">${ic(n === 'search' ? 'search' : n, 22, 1.7)}</i>`;
  return `<div id="taskbar"><div class="tbc">${icons.map(([n]) => `<span class="tbi ${n === 'hermes' && T.hot ? 'hot' : ''} ${n === 'hermes' ? 'run' : ''}">${glyph(n)}</span>`).join('')}</div>
    <div class="tray"><span>ENG</span><span class="clk"><b>4:52 PM</b><b>11/9/2026</b></span></div></div>`;
}
function toast(T) {
  return `<div class="toast2" data-a="toast" style="opacity:${T.op};transform:translateX(${T.x || 0}px)">
    <div class="th2"><svg data-a="toast-icon" width="22" height="22" viewBox="0 0 11 11" shape-rendering="crispEdges"><rect x="1" y="1" width="9" height="9" fill="#6E4206"/><rect x="2" y="2" width="7" height="7" fill="#F5A524"/><rect x="2" y="2" width="4" height="1" fill="#FFD47E"/><rect x="4" y="5" width="3" height="3" fill="#6E4206"/><rect x="5" y="6" width="1" height="1" fill="#FFF2CC"/><rect x="3" y="3" width="1" height="1" fill="#1B1A17"/><rect x="7" y="3" width="1" height="1" fill="#1B1A17"/></svg><b>CipherVault</b><span class="tnow">now</span></div>
    <div class="tt" data-a="toast-title">Zero-knowledge secrets for AI agents</div>
    <div class="tb2" data-a="toast-body">github.com/samuel-1-avson/CipherVault</div>
    <div class="tb3" data-a="toast-pr">Hermes plugin catalog · PR #151642</div></div>`;
}

// ───────── the Hermes window
export function appWin(A) {
  const st = A.winSt || {};
  return `<div class="win" data-a="win" style="left:${WIN.x}px;top:${WIN.y}px;width:${WIN.w}px;height:${WIN.h}px;${st.op !== undefined ? `opacity:${st.op};` : ''}${st.tf ? `transform:${st.tf};transform-origin:${st.org || '50% 50%'};` : ''}">
    <div class="tbar"><span class="tbl">${ic('panel', 16)}<span class="tsep"></span>${ic('search', 16)}</span><span class="ttl">${esc(A.title || 'Hermes')}</span>
      <span class="caps"><i>─</i><i>▢</i><i>✕</i></span></div>
    <div class="body">${sidebar(A)}${main(A)}${A.pane ? pane(A.pane) : ''}</div>
    ${statusbar(A.status || {})}
    ${A.boot ? `<div class="boot" style="opacity:${A.boot.op}"><div class="spin2" style="transform:rotate(${A.boot.rot || 0}deg)"></div><div>${esc(A.boot.text)}</div></div>` : ''}
  </div>`;
}
function sidebar(A) {
  const S = A.sessions || [];
  return `<div class="side">
    <div class="nav"><div class="ni">${ic('new')}<span>New session</span></div><div class="ni">${ic('tools')}<span>Skills &amp; Tools</span></div>
      <div class="ni">${ic('msg')}<span>Messaging</span></div><div class="ni">${ic('art')}<span>Artifacts</span></div></div>
    <div class="ssearch">${ic('search', 16)}<span>Search sessions…</span></div>
    <div class="sect">${'<i class="sq"></i>'}PINNED</div><div class="hint">Shift-click a chat to pin · drag to reorder</div>
    <div class="sect">${'<i class="sq"></i>'}SESSIONS <span class="cnt">${S.length + 37}</span></div>
    <div class="proj"><i class="pj">s</i>shop-api <span class="cnt">${S.length}</span></div>
    ${S.map((s, i) => `<div class="sess ${s.on ? 'on' : ''}" data-a="sess-${i}"><i class="dot ${s.run ? 'run' : ''}"></i><span>${esc(s.name)}</span></div>`).join('')}
    <div class="proj"><i class="pj">h</i>hermes-home <span class="cnt">3</span></div>
    <div class="sess"><i class="dot"></i><span>Weekly cron digest</span></div>
  </div>`;
}
function main(A) {
  const C = A.composer || {};
  return `<div class="main">
    <div class="mtop"><span class="crumb">${esc(A.crumb || 'shop-api')}</span><span class="mic">${ic('spk', 17)}${ic('gear', 17)}${ic('panel', 17)}</span></div>
    <div class="msgs" style="${A.blurChat ? `filter:blur(${A.blurChat}px);` : ''}"><div class="col">${(A.msgs || []).map(msg).join('')}</div></div>
    <div class="cwrap"><div class="comp ${C.focus ? 'focus' : ''}" data-a="comp">
      <span class="cplus">${ic('plus', 18)}</span>
      <span class="ctext" data-a="ctext">${C.text ? C.text : '<span class="ph">What\'s on your mind?</span>'}${C.caret ? '<i class="caret" data-a="caret"></i>' : '<i data-a="caret"></i>'}</span>
      <span class="cmic">${ic('mic', 18)}</span><span class="csend ${C.text ? '' : 'dim'}" data-a="send">${ic('check', 16, 2.2)}</span>
    </div></div>
  </div>`;
}
// transcript items
function msg(m) {
  const op = m.op !== undefined ? `opacity:${m.op};` : '', tf = m.tf ? `transform:${m.tf};` : '';
  const a = m.id ? ` data-a="${m.id}"` : '';
  if (m.k === 'u') return `<div class="u"${a} style="${op}${tf}">${m.html}</div>`;
  if (m.k === 'a') return `<div class="a"${a} style="${op}${tf}">${m.html}</div>`;
  if (m.k === 'gap') return `<div style="height:${m.h}px;flex:none"></div>`;
  if (m.k === 'tool') {
    const s = m.st === 'run' ? '<i class="spin"></i>' : m.st === 'ok' ? `<span class="ok">${ic('check', 15, 2.2)}</span>` : m.st === 'blocked' ? '<span class="blk">BLOCKED</span>' : '';
    return `<div class="tool ${m.st || ''}"${a} style="${op}${tf}"><span class="g">${ic(m.icon || 'term', 14, 1.8)}</span><b>${esc(m.name)}</b><code>${m.arg || ''}</code><span class="st">${s}</span></div>`;
  }
  if (m.k === 'card') return `<div class="card ${m.cls || ''}"${a} style="${op}${tf}${m.h !== undefined ? `max-height:${m.h}px;` : ''}">${m.html}</div>`;
  if (m.k === 'block') return `<div class="card block"${a} style="${op}${tf}"><div class="bh">${ic('shield', 16, 1.9)}<b>Blocked by CipherVault guard</b><span class="hk">pre_tool_call</span></div><div class="bm">${m.html}</div></div>`;
  return '';
}
// JSON-ish key/value widget rows: [[key, valueHTML, opts]]
export function kv(rows) {
  return `<div class="kv">${rows.map(([k, v, o = {}]) => `<div class="kr ${o.cls || ''}"${o.id ? ` data-a="${o.id}"` : ''} style="${o.op !== undefined ? `opacity:${o.op}` : ''}"><span class="kk">"${k}"</span><span class="kc">:</span><span class="kvv">${v}</span></div>`).join('')}</div>`;
}
export const jstr = s => `<span class="js">"${s}"</span>`;
export const jnum = n => `<span class="jn">${n}</span>`;
export const jbool = b => `<span class="jb">${b}</span>`;

// ───────── right pane stack
function pane(P) {
  const tabs = P.tabs || [P.type];
  const st = P.w !== undefined ? `width:${P.w}px;` : '';
  return `<div class="pane" data-a="pane" style="${st}"><div class="ptabs">${tabs.map((t, i) => `<span class="${t === P.type ? 'on' : ''}" data-a="ptab-${i}">${t === 'ciphervault' ? ic('vault', 14) : ''}${t}</span>`).join('')}</div>
    <div class="pc" style="${P.blur ? `filter:blur(${P.blur}px)` : ''}">${{ Files: files, Terminal: term, ciphervault: cvPane, Review: review, Preview: preview }[P.type](P)}</div></div>`;
}
// Files: P.rows = [{name, depth, dir, cls, id, tag}]
function files(P) {
  return `<div class="tree">${(P.rows || []).map(r => `<div class="fr ${r.cls || ''}" ${r.id ? `data-a="${r.id}"` : ''} style="padding-left:${12 + r.depth * 18}px;${r.op !== undefined ? `opacity:${r.op};` : ''}">
    <span class="fi">${ic(r.dir ? 'folder' : r.lock ? 'lock' : 'file', 15)}</span><span class="fn">${esc(r.name)}</span>${r.tag ? `<span class="ftag">${r.tag}</span>` : ''}${r.px ? r.px : ''}</div>`).join('')}</div>`;
}
// Terminal: P.lines = [html]
function term(P) {
  return `<div class="tm"><div class="tmh">PowerShell · C:\\dev\\shop-api</div>${(P.lines || []).map(l => `<div class="tl">${l}</div>`).join('')}</div>`;
}
// the real CipherVault pane (labels from desktop/plugin.js)
function cvPane(P) {
  const d = P.d || {}, row = (k, v, id) => `<div class="cvr" ${id ? `data-a="${id}"` : ''}><span>${k}</span><b class="${P.hot === id ? 'hot' : ''}">${esc(v)}</b></div>`;
  return `<div class="cv"><div class="cvt" data-a="cv-title">CIPHERVAULT SECRETS</div>
    <div class="cvw">workspace: C:\\dev\\shop-api</div>
    <div class="cvc" data-a="cv-card">${row('Vault', d.vault || '3f9a1c2e', 'cv-vault')}${row('Head', d.head || '8b41d0a7', 'cv-head')}${row('Tracked files', d.files ?? 1, 'cv-files')}${row('Operators', d.ops ?? 3, 'cv-ops')}${row('Epoch', d.epoch ?? 1, 'cv-epoch')}${row('CLI', '1.0.31', 'cv-cli')}</div>
    <div class="cvs">TRACKED PATHS</div>${(d.paths || ['.env']).map((p, i) => `<div class="cvp" data-a="cv-path-${i}">${esc(p)}</div>`).join('')}
    <div class="cvb"><span>Copy scan prompt</span><span>Copy run prompt</span><span>Copy push prompt</span><span>Copy drill prompt</span></div>
    <div class="cvl">Refresh</div>
    <div class="cvf ${P.footHot ? 'hot' : ''}" data-a="cv-foot">Values never print. Operators see ciphertext only. Binary via bootstrap, $CIPHERVAULT_BIN, or PATH.</div></div>`;
}
// Review: staged changes
function review(P) {
  return `<div class="rv"><div class="rvh">${ic('git', 15)} Staged changes <span class="cnt">${(P.rows || []).length}</span></div>${(P.rows || []).map(r => `<div class="rvr ${r.cls || ''}" ${r.id ? `data-a="${r.id}"` : ''} style="${r.tf ? `transform:${r.tf};` : ''}${r.op !== undefined ? `opacity:${r.op};` : ''}">
    <span class="fi">${ic(r.lock ? 'lock' : 'file', 15)}</span><span class="fn">${esc(r.name)}</span><span class="rvs">${r.stat || ''}</span></div>`).join('')}
    ${P.unstaged ? `<div class="rvh sub">Changes <span class="cnt">${P.unstaged.length}</span></div>${P.unstaged.map(r => `<div class="rvr ${r.cls || ''}" ${r.id ? `data-a="${r.id}"` : ''} style="${r.op !== undefined ? `opacity:${r.op};` : ''}"><span class="fi">${ic('lock', 15)}</span><span class="fn">${esc(r.name)}</span><span class="rvs">${r.stat || ''}</span></div>`).join('')}` : ''}
    ${P.commit ? `<div class="rvc" data-a="rv-commit">${P.commit}</div>` : ''}</div>`;
}
// Preview: a file with line numbers. P.lines = [html]
function preview(P) {
  return `<div class="pv"><div class="pvh">${ic('file', 15)} ${esc(P.file)}${P.dirty ? ' <i class="dirty"></i>' : ''}</div><div class="code">${(P.lines || []).map((l, i) => `<div class="cl ${P.hl && P.hl.includes(i) ? 'hl' : ''}" data-a="pl-${i}"><span class="no">${i + 1}</span><span class="tx">${l}</span></div>`).join('')}</div></div>`;
}
function statusbar(S) {
  const dot = S.chip === 'green' ? 'g' : S.chip === 'grey' ? 'z' : 'a';
  return `<div class="sbar"><span class="sbl"><span>⌘</span><span class="${S.gw === 'starting' ? 'warn' : ''}">${ic('key', 13)} Gateway ${S.gw === 'starting' ? 'starting…' : 'ready'}</span><span>Agents</span><span>Cron</span></span>
    <span class="sbr">${S.noChip ? '' : `<span class="chip" data-a="chip"><i class="cd ${dot}" data-a="chipdot"></i>cv • vault</span>`}<span>Hermes-4 · Med</span><span class="ver"># v0.16.0</span></span></div>`;
}
