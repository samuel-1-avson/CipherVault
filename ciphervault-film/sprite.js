// The vault sprite: an original 18×12 square-pixel safe (body 12×10, legs 2 rows, arm nubs at the sides).
// Amber-gold so it finds the eye in a blue/grey UI; props share the same pixel grid.
export const AMB = '#F5A524', AMB_D = '#C9780A', OUT = '#6E4206', HI = '#FFD47E', EYE = '#1B1A17', METAL = '#FFF2CC', INSIDE = '#2A1D08';

// ring pixels of the dial, clockwise from 12 o'clock (used for the turning notch)
const RING = [[8, 4], [9, 4], [10, 5], [10, 6], [9, 7], [8, 7], [7, 6], [7, 5]];

// returns [[c, r, colour]]
export function grid({ eyes = 'n', arms = 'down', legs = 'stand', dial = 0, door = 0 } = {}) {
  const P = new Map(), put = (c, r, v) => P.set(c + ',' + r, v);
  // body with rounded corners
  for (let r = 0; r < 10; r++) for (let c = 3; c <= 14; c++) {
    if ((r === 0 || r === 9) && (c === 3 || c === 14)) continue;
    const edge = r === 0 || r === 9 || c === 3 || c === 14;
    put(c, r, edge ? OUT : r === 8 ? AMB_D : (r === 1 && c > 4 && c < 10) || (c === 4 && r > 1 && r < 5) ? HI : AMB);
  }
  // hinges on the left edge
  put(3, 2, EYE); put(3, 7, EYE);
  if (door > 0) {
    // door swung open: dark interior, the open door drawn as a thin slab on the left
    for (let r = 1; r < 9; r++) for (let c = 5; c <= 12; c++) put(c, r, INSIDE);
    for (let r = 1; r < 9; r++) put(4, r, door > .5 ? HI : AMB);
  } else {
    // dial: ring + metal centre + notch that turns in 45° steps
    for (const [c, r] of RING) put(c, r, OUT);
    put(8, 5, METAL); put(9, 5, METAL); put(8, 6, METAL); put(9, 6, METAL);
    const n = RING[((Math.round(dial) % 8) + 8) % 8]; put(n[0], n[1], METAL);
  }
  // arms
  const A = { down: [[1, 5], [2, 5], [1, 6], [2, 6], [15, 5], [16, 5], [15, 6], [16, 6]],
    up: [[1, 0], [2, 0], [1, 1], [2, 1], [2, 2], [15, 0], [16, 0], [15, 1], [16, 1], [15, 2]],
    wave: [[1, 5], [2, 5], [1, 6], [2, 6], [15, 0], [16, 0], [15, 1], [16, 1], [15, 2]],
    push: [[0, 4], [1, 4], [2, 4], [15, 4], [16, 4], [17, 4]],
    tuck: [] }[arms] || [];
  for (const [c, r] of A) put(c, r, OUT);
  // legs
  const L = { stand: [[5, 2], [6, 2], [11, 2], [12, 2]], walkA: [[5, 2], [6, 1], [11, 2], [12, 1]], walkB: [[5, 1], [6, 2], [11, 1], [12, 2]],
    tuck: [[5, 1], [6, 1], [11, 1], [12, 1]], none: [] }[legs];
  for (const [c, h] of L) for (let r = 10; r < 10 + h; r++) put(c, r, OUT);
  // eyes (above the dial)
  if (door <= 0) {
    const E = { n: [[6, 2], [6, 3], [11, 2], [11, 3]], r: [[7, 2], [7, 3], [12, 2], [12, 3]], l: [[5, 2], [5, 3], [10, 2], [10, 3]],
      u: [[6, 1], [6, 2], [11, 1], [11, 2]], d: [[6, 3], [6, 4], [11, 3], [11, 4]],
      blink: [[6, 3], [11, 3]], happy: [[5, 3], [6, 2], [7, 3], [10, 3], [11, 2], [12, 3]], wide: [[6, 1], [6, 2], [6, 3], [11, 1], [11, 2], [11, 3]],
      shut: [[5, 3], [6, 3], [7, 3], [10, 3], [11, 3], [12, 3]], angry: [[5, 1], [6, 2], [6, 3], [12, 1], [11, 2], [11, 3]] }[eyes] || [];
    for (const [c, r] of E) put(c, r, EYE);
  }
  return [...P].map(([k, v]) => { const [c, r] = k.split(',').map(Number); return [c, r, v]; });
}

// x,y = midpoint under the feet (world coords); px = pixel side; sq>0 squash, <0 stretch; flip faces left; rot radians
export function sprite({ x, y, px = 7, flip = false, sq = 0, rot = 0, op = 1, shadow = 0, tint = null, ...pose }) {
  const G = grid(pose); let s = '';
  for (let [c, r, v] of G) { if (flip) c = 17 - c; s += `<rect x="${c}" y="${r}" width="1.04" height="1.04" fill="${tint || v}"/>`; }
  const sy = 1 - sq, sx = 1 + sq * .7, w = 18 * px * sx, h = 12 * px * sy;
  const sh = shadow > 0 ? `<div style="position:absolute;left:${x - 6 * px}px;top:${y - px * .4}px;width:${12 * px}px;height:${px * .8}px;border-radius:50%;background:rgba(0,0,0,${.16 * shadow})"></div>` : '';
  return sh + `<svg class="px" viewBox="0 0 18 12" width="${w}" height="${h}" style="left:${x - w / 2}px;top:${y - h}px;opacity:${op};transform:rotate(${rot}rad);transform-origin:50% 60%" shape-rendering="crispEdges">${s}</svg>`;
}
// pixel centres in world coords (bursts, births)
export function pixels(o) {
  const { x, y, px = 7, flip = false } = o;
  return grid(o).map(([c, r, v]) => ({ x: x + ((flip ? 17 - c : c) - 9 + .5) * px, y: y + (r - 12 + .5) * px, v }));
}
export function pixart(rows, { x, y, px = 7, pal, op = 1 }) {
  let s = ''; rows.forEach((row, r) => [...row].forEach((ch, c) => { if (pal[ch]) s += `<rect x="${c}" y="${r}" width="1.04" height="1.04" fill="${pal[ch]}"/>`; }));
  const W = rows[0].length, H = rows.length;
  return `<svg class="px" viewBox="0 0 ${W} ${H}" width="${W * px}" height="${H * px}" style="left:${x}px;top:${y}px;opacity:${op}" shape-rendering="crispEdges">${s}</svg>`;
}
export const BANG = (x, y, px = 6, op = 1) => pixart(['.kkk.', 'kwwwk', 'kwkwk', 'kwkwk', 'kwwwk', 'kwkwk', 'kwwwk', '.kkk.', '..k..'], { x, y, px, op, pal: { w: '#fff', k: EYE } });
export const SPARK = (x, y, px = 6, col = AMB, op = 1) => pixart(['..y..', '..y..', 'yy.yy', '..y..', '..y..'], { x: x - 2.5 * px, y: y - 2.5 * px, px, op, pal: { y: col } });
export const CHECK = (x, y, px = 6, op = 1) => pixart(['.....g', '....gg', 'g..gg.', 'gggg..', '.gg...'], { x, y, px, op, pal: { g: '#16A34A' } });
export const LOCK = (x, y, px = 6, op = 1) => pixart(['..kkkk..', '.k....k.', '.k....k.', 'kkkkkkkk', 'kaaaaaak', 'kaaeeaak', 'kaaeeaak', 'kaaaaaak', 'kkkkkkkk'], { x: x - 4 * px, y: y - 9 * px, px, op, pal: { k: OUT, a: AMB, e: EYE } });
export const STAMP = (x, y, px = 6, op = 1) => pixart(['...kk...', '...kk...', '..kkkk..', '..kaak..', 'kkkkkkkk', 'krrrrrrk', 'kkkkkkkk'], { x: x - 4 * px, y: y - 7 * px, px, op, pal: { k: OUT, a: AMB, r: '#DC2626' } });
export const ZZZ = (x, y, px = 5, op = 1) => pixart(['zzzz', '..z.', '.z..', 'zzzz'], { x, y, px, op, pal: { z: '#94A3B8' } });
export function dust(x, y, t, px = 5, n = 6, seed = 1, col = '#CBD5E1') {
  if (t <= 0 || t >= 1) return ''; let s = '';
  for (let i = 0; i < n; i++) {
    const side = i % 2 ? 1 : -1, k = (i >> 1) + 1, e = 1 - Math.pow(1 - t, 2);
    const dx = side * (18 + k * 16 + ((seed * 7 + i * 13) % 9)) * e, dy = -(8 + k * 5) * Math.sin(Math.PI * t * .9), sz = px * (1 - t * .7);
    s += `<div style="position:absolute;left:${x + dx - sz / 2}px;top:${y + dy - sz}px;width:${sz}px;height:${sz}px;background:${col};opacity:${1 - t}"></div>`;
  }
  return s;
}
