import { clamp, seg, eo, back, hash } from '/core/lib.js';
import * as UI from './ui.js';
import * as SP from './sprite.js';
import * as FM from './film.js';

const Q = new URLSearchParams(location.search), NOSUBS = Q.has('nosubs'), CUT = Q.get('cut') === 'H' ? 'H' : 'F';
const wL = document.getElementById('wL'), wD = document.getElementById('wD'), spr = document.getElementById('spr'), hudEl = document.getElementById('hud');
const mbg = document.getElementById('mbg'), mbw = document.getElementById('mbw');

const words = await (await fetch('voices/words.json')).json();
words.__dur = await (await fetch('voices/dur.json')).json();
const { C, CUR } = FM.build(words, CUT);
window.DUR = FM.DUR;
window.EV = FM.EV.slice().sort((a, b) => a.t - b.t);
window.SUBS = FM.SUBS.map(s => ({ t0: s.t0, t1: s.t1, text: s.text.replace(/[{}`]/g, '') }));
window.CUT = CUT;

const tf = ([cx, cy, z]) => `translate(960px,540px) scale(${z}) translate(${-cx}px,${-cy}px)`;
function render(t) {
  t = Math.min(t, FM.DUR - 1e-4);
  const F = FM.frame(t), [cx, cy, z] = F.cam;
  const html = UI.desk(F.desk || {}) + (F.app ? UI.appWin(F.app) : '');
  const D = F.dark, base = D.base === 'L' ? wL : wD, over = D.over ? (D.over === 'L' ? wL : wD) : null;
  base.innerHTML = html; base.style.display = ''; base.style.clipPath = ''; base.style.zIndex = 1;
  if (over) { over.innerHTML = html; over.style.display = ''; over.style.zIndex = 2; } else (base === wL ? wD : wL).style.display = 'none';
  for (const el of [wL, wD, spr]) el.style.transform = tf(F.cam);
  // anchors: world coordinates of a point on a measured element
  let cache = {};
  const A = (key, fx = .5, fy = 0) => { const el = cache[key] !== undefined ? cache[key] : (cache[key] = base.querySelector(`[data-a="${key}"]`));
    if (!el) return null; const r = el.getBoundingClientRect(); return { x: (r.left + r.width * fx - 960) / z + cx, y: (r.top + r.height * fy - 540) / z + cy, w: r.width / z, h: r.height / z }; };
  // post-layout elements (e.g. a line lifted out of one card and flown into another)
  for (const p of F.post) { const h = p(base, A); if (h) { base.insertAdjacentHTML('beforeend', h); if (over) over.insertAdjacentHTML('beforeend', h); cache = {}; } }
  if (over) { const c = A(D.at, .5, .5) || { x: 960, y: 540 }; over.style.clipPath = `circle(${D.r}px at ${c.x}px ${c.y}px)`; }
  // motion blur only on whip pans (camera velocity → anisotropic Gaussian on an untransformed wrapper)
  const [px, py] = FM.camAt(t - 1 / 30), vx = (cx - px) * z, vy = (cy - py) * z;
  const bx = Math.min(32, Math.max(0, Math.abs(vx) - 28) * .3), by = Math.min(32, Math.max(0, Math.abs(vy) - 28) * .3);
  mbg.setAttribute('stdDeviation', `${bx.toFixed(2)} ${by.toFixed(2)}`); mbw.style.filter = bx > .6 || by > .6 ? 'url(#mb)' : '';
  spr.innerHTML = sprites(F, t, A, z) + F.fx.map(f => f(A)).join('');
  hud(F, t, A, z, cx, cy);
}
function sprites(F, t, A, z) {
  let h = '';
  const c = C.eval(t, A);
  if (c) {
    h += SP.sprite(c);
    for (const j of C.jumps) if (t >= j.t1 && t < j.t1 + .4) { const L = C.eval(j.t1 + .001, A); if (L) h += SP.dust(L.x, L.y, seg(t, j.t1, j.t1 + .4), Math.max(3, L.px * .7), 6, j.t1 * 10, F.hud.dark ? '#475569' : '#CBD5E1'); }
  }
  const cu = CUR.eval(t, A);
  if (cu) {
    if (cu.sp > 900) for (let i = 1; i <= 4; i++) { const g = CUR.eval(t - i * .012, A); if (g) h += cursorSvg(g.x, g.y, 1, cu.op * .16 * (5 - i) / 4, z); }
    if (cu.ring > 0) h += `<div class="ring" style="left:${cu.x - 26 * cu.ring - 4}px;top:${cu.y - 26 * cu.ring - 4}px;width:${52 * cu.ring + 8}px;height:${52 * cu.ring + 8}px;opacity:${(1 - cu.ring) * .8};border-width:${3 / z}px"></div>`;
    h += cursorSvg(cu.x, cu.y, cu.sc, cu.op, z);
  }
  return h;
}
// the cursor keeps a constant on-screen size (1.6× system size, as screen recorders do)
const cursorSvg = (x, y, sc, op, z) => { const s = 1.6 * sc / z;
  return `<svg style="position:absolute;left:${x - 2 * s}px;top:${y - 2 * s}px;opacity:${op};filter:drop-shadow(0 ${2 / z}px ${3 / z}px rgba(0,0,0,.3))" width="${22 * s}" height="${30 * s}" viewBox="0 0 22 30"><path d="M2 2 L2 24 L7.5 18.5 L11 27 L15 25.2 L11.6 17 L19 17 Z" fill="#000" stroke="#fff" stroke-width="1.6" stroke-linejoin="round"/></svg>`; };

function hud(F, t, A, z, cx, cy) {
  const H = F.hud; let h = '';
  const scr = p => ({ x: (p.x - cx) * z + 960, y: (p.y - cy) * z + 540 });
  if (H.dim) h += `<div class="spot" style="background:rgba(8,12,22,${H.dim})"></div>`;
  if (H.spot) { const p = A(H.spot.key, .5, .5); if (p) { const s = scr(p), r = Math.max(p.w * .5, p.h) * z * (H.spot.wide || 1) + 50;
    h += `<div class="spot" style="opacity:${H.spot.op};background:radial-gradient(ellipse ${r * 1.7}px ${r}px at ${s.x}px ${s.y}px, transparent 55%, rgba(8,12,22,.62) 100%)"></div>`; } }
  if (H.chap && !H.wipe) h += `<div class="chap ${H.dark ? 'dk' : ''}" style="opacity:${H.chap.op}"><b>${H.chap.no}</b>${H.chap.nm}</div>`;
  if (H.ramp) h += `<div class="ramp" style="opacity:${H.ramp.op}">${H.ramp.blink ? '▶▶' : '▷▷'} 4×</div>`;
  if (H.keys) h += `<div class="keys" style="opacity:${H.keys.op};transform:translateY(${H.keys.y}px)">${H.keys.keys.map(k => `<i class="${H.keys.dn ? 'dn' : ''}">${k}</i>`).join('')}<span>${H.keys.label}</span></div>`;
  if (H.cap && !NOSUBS) h += `<div class="cap ${H.dark ? 'dk' : ''}" style="opacity:${H.cap.op};transform:translate(-50%,${H.cap.y}px)">${H.cap.text.replace(/\{([^}]*)\}/g, '<em>$1</em>').replace(/`([^`]*)`/g, '<code>$1</code>')}</div>`;
  if (H.wipe) h += wipe(H.wipe, t);
  if (H.fade) h += `<div class="fade" style="opacity:${H.fade}"></div>`;
  if (t < .5) h += `<div class="fade" style="opacity:${1 - eo(t / .5)}"></div>`;
  hudEl.innerHTML = h;
}
// chapter seam: slate pixel blocks sweep bottom-left → top-right, the chapter label, then reveal; the vault runs across
function wipe(Wp, t) {
  const S = 60, cols = 32, rows = 18, p = Wp.p; let s = '<div class="wipe">';
  const pal = ['#0F172A', '#162036', '#1E293B'];
  for (let r = 0; r < rows; r++) for (let c = 0; c < cols; c++) {
    const d = (c / cols) * .55 + ((rows - r) / rows) * .2 + hash(c * 13.1 + r * 7.7) * .12;
    const a = clamp((p / .42 - d) / .18), b = clamp(((p - .55) / .42 - d) / .18), k = a * (1 - b);
    if (k <= 0) continue; const sz = S * k;
    s += `<b style="left:${c * S + (S - sz) / 2}px;top:${r * S + (S - sz) / 2}px;width:${sz + .5}px;height:${sz + .5}px;background:${pal[Math.floor(hash(c * 3.7 + r * 11.3) * 3)]}"></b>`;
  }
  const lo = clamp(Math.min((p - .28) / .12, (.84 - p) / .1));
  if (lo > 0 && Wp.nm) s += `<div class="wlabel" style="opacity:${lo};transform:translateY(calc(-50% + ${(1 - lo) * 16}px))"><div class="no">${Wp.no}</div><div class="nm">${Wp.nm}</div></div>`;
  if (lo > 0) s += SP.sprite({ x: 260 + p * 1400, y: 820, px: 6, legs: Math.floor(t * 12) % 2 ? 'walkA' : 'walkB', op: lo, dial: Math.floor(t * 10) });
  return s + '</div>';
}
window.render = render;
await document.fonts.load('16px Inter'); await document.fonts.load('600 16px Inter'); await document.fonts.load('14px Mono'); await document.fonts.load('700 14px Mono');
render(+(Q.get('t') || 0));
window.READY = true;
