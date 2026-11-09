// Frame render for this film, on the library's page loader (core/render/page.mjs). Same pipeline as core/render/video.mjs
// (JPEG screenshots → ffmpeg per worker → lossless concat), with one Windows workaround: playwright's browser.close() can
// hang forever on this machine, so closing is bounded and the process exits explicitly.
//   node tools/render.mjs video  [--q cut=H] [--fps 30] [--workers 5] --out out/video.mp4
//   node tools/render.mjs stills [--q cut=H] --out out/stills --prefix a_ t1 t2 …
//   node tools/render.mjs export [--q cut=H] --out out/events.json      (DUR + EV for the mixer, SUBS for the .srt)
import fs from 'fs'; import path from 'path'; import { spawn, execFileSync } from 'child_process'; import { fileURLToPath, pathToFileURL } from 'url';
const LIB = process.env.LIB || path.join(process.env.USERPROFILE || process.env.HOME, 'lemo-opuscar');
const { openDemo, closeServer } = await import(pathToFileURL(path.join(LIB, 'core/render/page.mjs')).href);
const HERE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const [mode, ...args] = process.argv.slice(2);
const opt = (k, d) => { const i = args.indexOf(k); if (i < 0) return d; const v = args[i + 1]; args.splice(i, 2); return v; };
const Q = opt('--q', ''), FPS = +opt('--fps', 30), WK = +opt('--workers', 5), OUT = path.resolve(HERE, opt('--out', 'out/video.mp4')), PREFIX = opt('--prefix', 't_');
const close = async b => { await Promise.race([b.close().catch(() => {}), new Promise(r => setTimeout(r, 2500))]); };
const done = code => { try { closeServer(); } catch {} process.exit(code); };

if (mode === 'stills') {
  fs.mkdirSync(OUT, { recursive: true });
  const { browser, page } = await openDemo(HERE, { q: Q, warnings: true });
  for (const ts of args) { await page.evaluate(t => window.render(t), parseFloat(ts)); const f = path.join(OUT, `${PREFIX}${ts}.jpg`); await page.screenshot({ path: f, type: 'jpeg', quality: 90 }); console.log(f); }
  await close(browser); done(0);
}
if (mode === 'export') {
  const { browser, page } = await openDemo(HERE, { q: Q, gl: false });
  const data = await page.evaluate(() => ({ dur: window.DUR, cut: window.CUT, ev: window.EV, subs: window.SUBS.map(s => ({ t0: +s.t0.toFixed(2), t1: +s.t1.toFixed(2), text: s.text })) }));
  fs.mkdirSync(path.dirname(OUT), { recursive: true }); fs.writeFileSync(OUT, JSON.stringify(data));
  const SUBS = opt('--subs', null); if (SUBS) fs.writeFileSync(path.resolve(HERE, SUBS), JSON.stringify(data.subs, null, 1));
  console.log('export', OUT, 'dur', data.dur.toFixed(2), 'events', data.ev.length, 'subs', data.subs.length);
  await close(browser); done(0);
}
if (mode === 'video') {
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  const segDir = fs.mkdtempSync(path.join(path.dirname(OUT), '.segs-'));
  const probe = await openDemo(HERE, { q: Q }); const DUR = await probe.page.evaluate(() => window.DUR); await close(probe.browser);
  const TOTAL = Math.round(DUR * FPS), per = Math.ceil(TOTAL / WK), t0 = Date.now();
  await Promise.all([...Array(WK)].map(async (_, w) => {
    const a = w * per, b = Math.min(TOTAL, a + per); if (a >= b) return;
    const { browser, page } = await openDemo(HERE, { q: Q });
    const ff = spawn('ffmpeg', ['-y', '-loglevel', 'error', '-f', 'image2pipe', '-framerate', String(FPS), '-c:v', 'mjpeg', '-i', '-',
      '-c:v', 'libx264', '-preset', 'medium', '-crf', '15', '-pix_fmt', 'yuv420p', `seg_${w}.mp4`], { cwd: segDir, stdio: ['pipe', 'inherit', 'inherit'] });
    const closed = new Promise(r => ff.on('close', r));
    for (let f = a; f < b; f++) {
      await page.evaluate(t => window.render(t), f / FPS);
      const buf = await page.screenshot({ type: 'jpeg', quality: 95 });
      if (!ff.stdin.write(buf)) await new Promise(r => ff.stdin.once('drain', r));
      if ((f - a) % 150 === 0) console.log(`w${w} ${f - a}/${b - a}  ${((Date.now() - t0) / 1000).toFixed(0)}s`);
    }
    ff.stdin.end(); const code = await closed; await close(browser);
    if (code !== 0) { console.error(`ffmpeg failed for worker ${w} (exit ${code})`); done(1); }
  }));
  fs.writeFileSync(path.join(segDir, 'segs.txt'), [...Array(WK)].map((_, w) => `file 'seg_${w}.mp4'`).filter((_, w) => w * per < TOTAL).join('\n'));
  execFileSync('ffmpeg', ['-y', '-loglevel', 'error', '-f', 'concat', '-safe', '0', '-i', 'segs.txt', '-c', 'copy', 'merged.mp4'], { cwd: segDir, stdio: ['ignore', 'inherit', 'inherit'] });
  fs.renameSync(path.join(segDir, 'merged.mp4'), OUT); fs.rmSync(segDir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  console.log('done', OUT, TOTAL, 'frames', ((Date.now() - t0) / 1000).toFixed(0) + 's'); done(0);
}
console.error('usage: node tools/render.mjs video|stills|export …'); process.exit(2);
