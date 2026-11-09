"""Score + foley + voice → out/mix_<cut>.wav, all driven by out/events_<cut>.json (the page's own window.EV), so sound and
picture share one clock.   python sound.py F|H
Two resolutions: a hi-fi band (Salamander piano, Karoryfer jazz double bass, MuldjordKit drums, VCSL shaker / glockenspiel /
bowed vibraphone) is the world; a band-limited square wave is the vault sprite's voice. 96 BPM, 2.5 s bars, a 4-bar loop
(Dm9 → B♭maj7 → Fmaj7 → C) restarted at every segment, so either playlist stays on the grid.
Shape: piano pulse intro → band enters → drums drop before the guard, true silence, the block hits on a downbeat → band →
chip arpeggio under the 4× drill, near-silence before its freeze → low-passed "night" band once Hermes turns dark →
a final Fmaj9 under the end-card toast and the sprite's motif, slower."""
import sys, os, json, numpy as np, soundfile as sf, soxr
LIB = os.environ.get('LIB') or os.path.join(os.path.expanduser('~'), 'lemo-opuscar'); sys.path.insert(0, LIB)
from core.audio.sfx import SR, bp, lp, hp, noise, add, compress, limit, click as sclick
from core.audio import sampler as S
HERE = os.path.dirname(os.path.abspath(__file__))
CUT = sys.argv[1] if len(sys.argv) > 1 else 'F'
EVJ = json.load(open(os.path.join(HERE, 'out', f'events_{CUT}.json'), encoding='utf-8')); E = EVJ['ev']; DUR = EVJ['dur']
rng = np.random.default_rng(11); S.seed(11)
NS = int((DUR + 2) * SR)
B, BAR = .625, 2.5
def tt(d): return np.arange(int(round(d * SR))) / SR
def db(x): return 10 ** (x / 20)
def ev_(tp): return [e for e in E if e['type'] == tp]
def hz(p): return S.hz(p)

# ───────── pixel voice
def pulse(f, d, duty=.25, vol=1., att=.003, rel=.05, slide=None):
    t = tt(d); fr = np.full(len(t), float(f)) if slide is None else f * (slide ** (t / d))
    ph = np.cumsum(fr) / SR; x = np.zeros(len(t))
    for k in range(1, 24):
        fk = fr * k; m = fk < 16000
        x += m * (np.sin(np.pi * k * duty) / k) * np.cos(2 * np.pi * k * (ph - duty / 2))
    e = np.minimum(1, t / att) * np.minimum(1, (d - t) / rel).clip(0)
    return (x * e * vol * .5).astype(np.float32)
def crush(x, bits=5): q = 2 ** bits; return (np.round(x * q) / q).astype(np.float32)
def nz(d, lo, hi, vol=1., tau=None):
    x = bp(rng.standard_normal(int(d * SR)), lo, hi) * vol
    if tau: x *= np.exp(-tt(d)[:len(x)] / tau)
    return x.astype(np.float32)

# ───────── segments and windows
SEG = sorted(ev_('seg'), key=lambda e: e['t'])
for i, s in enumerate(SEG): s['t1'] = SEG[i + 1]['t'] if i + 1 < len(SEG) else DUR
def inseg(tp, s): return [e for e in E if e['type'] == tp and s['t'] <= e['t'] < s['t1']]
FREEZE = [(e['t'], e['t'] + e['d']) for e in ev_('freeze')]
SIL = [(e['t'], e['t'] + e['d']) for e in ev_('silence')]
DRUMS_OFF = list(FREEZE) + list(SIL)
for s in SEG:
    if s['mood'] == 'intro': DRUMS_OFF.append((s['t'], s['t1']))
    if s['mood'] == 'drop':
        blk = inseg('block', s); DRUMS_OFF.append((s['t'], blk[0]['t'] if blk else s['t1']))
    if s['mood'] == 'resolve':
        mn = inseg('minimize', s); DRUMS_OFF.append((mn[0]['t'] if mn else s['t'], s['t1']))
def off(t, W=DRUMS_OFF): return any(a - .02 <= t < b for a, b in W)

PROG = [('D2', ['F3', 'A3', 'C4', 'E4']), ('Bb1', ['F3', 'A3', 'D4', 'F4']), ('F2', ['E3', 'A3', 'C4', 'F4']), ('C2', ['E3', 'G3', 'C4', 'D4'])]
def chord(s, t): return PROG[int((t - s['t']) / BAR + 1e-6) % 4]
EVN = []
def N(t, inst, p, d, v, pan=0., g=1.):
    if t < DUR - .05: EVN.append((t, inst, p, d, v, pan, g))

def groove(s, a, b, style='full'):
    n0 = int(np.ceil((a - s['t']) / B - 1e-6))
    for n in range(n0, 10000):
        t = s['t'] + n * B
        if t >= b - 1e-6: break
        bi = n % 4; root, ch = PROG[(n // 4) % 4]
        if off(t, FREEZE + SIL): continue
        dr = not off(t)
        if dr and style in ('full', 'half', 'light'):
            if style == 'full':
                if bi in (0, 2): N(t, 'drum_kit', 'kick_drum_left', .3, .72)
                if bi == 2: N(t + B * .5, 'drum_kit', 'kick_drum_left', .3, .42)
                if bi in (1, 3): N(t, 'drum_kit', 'snare_2', .3, .36, .05); N(t, 'claps', None, .3, .3, .08)
                for q in (.25, .75): N(t + q * B, 'shaker', 'down', .12, .16, -.35)
            elif style == 'half':
                if bi == 0: N(t, 'drum_kit', 'kick_drum_left', .3, .66)
                if bi == 2: N(t, 'drum_kit', 'snare_2', .3, .34, .05)
            for h in (0, .5): N(t + h * B, 'drum_kit', 'hi_hat_closed', .1, (.26 if h == 0 else .15) * (.7 if style == 'light' else 1), .3)
        N(t, 'jazz_bass', root, .3, .62); N(t + B / 2, 'jazz_bass', root if bi != 3 else S.name(S.midi(root) + 7), .22, .4)
        if bi == 0: [N(t + j * .012, 'piano', p, 1.8, .34, -.15) for j, p in enumerate(ch)]
        elif style in ('full', 'half'): [N(t + B / 2, 'piano', p, .22, .2, -.15) for p in ch[1:]]

chipbuf = np.zeros((NS, 2), np.float32); bandx = np.zeros((NS, 2), np.float32)
MOTIF = [('A5', 0, 1), ('D6', 1, 1), ('C6', 2, 1), ('A5', 3, 2), ('F5', 6, 1), ('G5', 7, 1), ('A5', 8, 3)]   # in 8ths
def motif(t0, unit=B / 2, vol=.22, pan=.15, glock=True, notes=MOTIF):
    for p, o, d in notes:
        ts = t0 + o * unit; add(chipbuf, pulse(hz(p), d * unit * .9, .25, vol), ts, 1, pan)
        if glock: add(bandx, S.note('glockenspiel', p, d * unit, .4), ts, .45, pan)

for s in SEG:
    m, a, b = s['mood'], s['t'], s['t1']
    if m == 'intro':
        land = inseg('hit', s); tl = land[0]['t'] if land else a + 7.5
        ARP = ['D4', 'F4', 'A4', 'C5', 'E5', 'C5', 'A4', 'F4']; t, i = a + .3, 0
        while t < tl - .01: N(t, 'piano', ARP[i % 8], .5, .16 + .16 * (t - a) / (tl - a), -.2); t += B / 2; i += 1
        for p in ['D3', 'A3', 'E4']: EVN.append(dict(t=a + .2, inst='vibraphone_bowed', pitch=p, dur=tl - a, vel=.32, pan=.1, attack=.8))
        for k, tk in enumerate(np.arange(a + 5.0, tl - .01, B)): N(tk, 'jazz_bass', 'D2', .5, .4 + .1 * k / 4)
        rs = noise(1.2); rs = hp(rs, 900) * np.linspace(0, 1, len(rs)) ** 2 * .07; add(bandx, rs.astype(np.float32), tl - 1.2, 1, 0)
        groove(s, tl, b, 'light')
        motif(tl + .02, vol=.1, notes=MOTIF[:3], glock=True)
        mo = inseg('morph', s)
        if mo:
            for k, p in enumerate(['D5', 'F5', 'A5', 'C6', 'D6', 'F6']): add(chipbuf, pulse(hz(p), .08, .125, .2), mo[0]['t'] + k * .1, 1, (k - 3) * .12)
    elif m == 'band_in':
        groove(s, a, a + BAR, 'light'); groove(s, a + BAR, b, 'full')
    elif m == 'band':
        groove(s, a, b, 'full')
    elif m == 'drop':
        blk = inseg('block', s); tb = blk[0]['t'] if blk else b
        for n in range(int((tb - a) / B)):
            t = a + n * B
            if off(t, SIL): continue
            root, ch = chord(s, t)
            if n % 2 == 0: N(t, 'jazz_bass', 'D2' if n % 8 < 4 else 'Bb1', 1.1, .5)
            if n % 4 == 0: [N(t + j * .02, 'piano', p, 2.4, .22, -.15) for j, p in enumerate(ch)]
            N(t + B / 2, 'drum_kit', 'hi_hat_closed', .1, .1, .3)
        N(tb, 'drum_kit', 'crash_left', 3, .8, -.2); N(tb, 'drum_kit', 'kick_drum_left', .5, 1.)
        N(tb, 'jazz_bass', 'D1', 2.4, .9); [N(tb + j * .015, 'piano', p, 2.4, .5, -.1) for j, p in enumerate(['D2', 'A2', 'F3', 'A3', 'D4'])]
        groove(s, tb + BAR, b, 'half')
    elif m == 'arp':
        groove(s, a, b, 'full')
        for r in inseg('ramp', s):
            k, t = 0, r['t']
            while t < r['t'] + r['d']:
                root, ch = chord(s, t); p = S.name(S.midi(ch[k % 4]) + 24)
                add(chipbuf, pulse(hz(p), B / 4 * .8, .125, .13), t, 1, (.4 if k % 2 else -.4)); t += B / 4; k += 1
    elif m in ('night', 'why'):
        groove(s, a, b, 'full')
    elif m == 'resolve':
        mn = inseg('minimize', s); tm = mn[0]['t'] if mn else a + 4.75
        groove(s, a, tm, 'light')
        to = inseg('toast', s); tt0 = to[0]['t'] if to else tm + .8
        N(tt0, 'drum_kit', 'crash_right', 4, .55, .2); N(tt0, 'jazz_bass', 'F1', 5, .7)
        for j, p in enumerate(['F2', 'C3', 'A3', 'E4', 'G4', 'C5']): N(tt0 + j * .03, 'piano', p, 6, .42, -.15 + j * .06)
        for p in ['A3', 'C4', 'E4']: EVN.append(dict(t=tt0, inst='vibraphone_bowed', pitch=p, dur=5.5, vel=.3, pan=.1, attack=.5))
        for j, p in enumerate(['F5', 'A5', 'C6', 'E6', 'G6', 'A6']): N(tt0 + .15 + j * B / 4, 'glockenspiel', p, 1.5, .32, .35)
        dr = inseg('seal', s)
        motif((dr[0]['t'] + .7) if dr else tt0 + 4.5, unit=B * .75, vol=.16, glock=True)

# chapter seams: tom fill on the last beat + crash on the seam
for w in ev_('wipe'):
    for k, tm in enumerate(['tom_1', 'tom_2', 'tom_3', 'tom_4']): N(w['t'] - B + k * B / 4, 'drum_kit', tm, .3, .38 + .08 * k, (k - 1.5) * .3)
    N(w['t'], 'drum_kit', 'crash_left', 2.2, .42, -.2)
# freezes: a held pad over the current chord, one soft piano chord
for a, b in FREEZE:
    s = next(x for x in SEG if x['t'] <= a < x['t1']); root, ch = chord(s, a)
    for p in ch[:3]: EVN.append(dict(t=a, inst='vibraphone_bowed', pitch=S.name(S.midi(p) + 12) if S.midi(p) < 57 else p, dur=b - a, vel=.3, pan=0, attack=.25))
    [N(a + j * .02, 'piano', p, 2.6, .26, -.1) for j, p in enumerate(ch)]; N(a, 'jazz_bass', root, 2.4, .45)

band = S.render(EVN, dur=DUR + 2)[:NS]
band = np.pad(band, ((0, NS - len(band)), (0, 0))) + bandx
# night mode: from the dark switch to the end-card toast the band is low-passed
tn = np.arange(NS) / SR
def ramp(a, b): return np.clip((tn - a) / (b - a), 0, 1)
night = np.zeros(NS)
dk = ev_('darkon'); to = ev_('toast')
start = dk[0]['t'] if dk else (next((s['t'] for s in SEG if s['mood'] == 'resolve'), DUR))
night = ramp(start, start + .8) if dk else (tn >= start).astype(float)
if to: night = night * (1 - ramp(to[0]['t'], to[0]['t'] + .9))
dark = np.stack([lp(band[:, c], 950, 2) for c in (0, 1)], 1).astype(np.float32) * 1.2
band = band * (1 - night[:, None]) + dark * night[:, None]
music = S.room(band + chipbuf, size=.3, mix=.1)
# silences: true silence (music out) / near-silence before the drill freeze
mute = np.ones(NS)
for a, b in SIL:
    s = next(x for x in SEG if x['t'] <= a < x['t1']); g = 0. if s['mood'] == 'drop' else .08
    mute *= 1 - (1 - g) * np.clip(np.minimum((tn - a) / .12, (b - tn) / .03), 0, 1)
music *= mute[:, None]

# ═════════ foley
# keep effects off word onsets (a hit on a consonant masks the word): short cues that land within 60 ms before / 160 ms after
# a spoken word's start move past that window (repeated until clear); ~0.15 s is invisible against the picture
WORDS = json.load(open(os.path.join(HERE, 'voices', 'words.json'), encoding='utf-8'))
ONSETS = sorted(e['t'] + max(0, w[1]) for e in ev_('vo') for w in WORDS[e['id']])
SHIFT = {'stamp', 'alert', 'pop', 'chipop', 'tool', 'ok', 'tick', 'ding', 'seal', 'ping', 'dissolve', 'redpulse', 'lockpop', 'land', 'jump', 'click', 'enter', 'send', 'hit', 'read'}
for e in E:
    if e['type'] in SHIFT:
        for _ in range(4):
            hit_ = next((o for o in ONSETS if o - .06 <= e['t'] < o + .16), None)
            if hit_ is None: break
            e['t'] = hit_ + .16
fx = np.zeros((NS, 2), np.float32)
def key(v=.8, heavy=False):
    d = .09; t = tt(d); th = np.sin(2 * np.pi * (170 + rng.uniform(-20, 20)) * t) * np.exp(-t / .018) * .5
    ck = nz(d, 2500, 7000, .5, .006) + nz(d, 900, 2200, .3, .012)
    return ((th + ck[:len(th)]) * v * (1.5 if heavy else 1)).astype(np.float32)
def tick(v=.5, f=2600): t = tt(.05); return (np.sin(2 * np.pi * f * t) * np.exp(-t / .008) * v + nz(.05, 3000, 8000, .15 * v, .004)[:len(t)]).astype(np.float32)
def pop(v=.6, f0=520, f1=980): t = tt(.12); f = f0 * (f1 / f0) ** np.minimum(1, t / .05); return (np.sin(2 * np.pi * np.cumsum(f) / SR) * np.exp(-t / .035) * v).astype(np.float32)
def swish(d=.35, v=.5, lo=400, hi=4000):
    x = rng.standard_normal(int(d * SR)); t = tt(d)[:len(x)]; e = np.sin(np.pi * t / d) ** 2
    return (bp(x, lo, hi) * e * v).astype(np.float32)
def boom(v=1., f0=90, d=.9): v *= .45; t = tt(d); f = f0 * np.exp(-t * 2.2) + 32; return (np.sin(2 * np.pi * np.cumsum(f) / SR) * np.exp(-t / .3) * v).astype(np.float32)
for e in E:
    t0, tp = e['t'], e['type']
    if tp == 'key': add(fx, key(e.get('v', .7) * .55, e.get('sp')), t0, .5, -.1 + rng.uniform(-.1, .1))
    elif tp == 'akey': add(fx, key(e.get('v', .7) * .3), t0, .4, .2)
    elif tp == 'enter': add(fx, key(1, True), t0, .38, 0)
    elif tp == 'send': add(fx, swish(.3, .22, 800, 6000), t0, 1, 0); add(fx, pop(.22, 600, 1100), t0 + .25, 1, 0)
    elif tp == 'click': add(fx, sclick(1.1, .8), t0, .45, .1)
    elif tp in ('pop', 'chipop'): add(fx, pop(.3, 520 + 60 * e.get('i', 0), 980 + 60 * e.get('i', 0)), t0, 1, 0)
    elif tp == 'tick': add(fx, tick(.25), t0, 1, .2)
    elif tp == 'tool': add(fx, tick(.28, 3200), t0, 1, -.2); add(fx, tick(.18, 4200), t0 + .05, 1, -.2)
    elif tp == 'ok': add(fx, tick(.2, 5200), t0, 1, .1)
    elif tp == 'read': add(fx, pulse(hz(['C6', 'D6', 'E6', 'G6', 'A6', 'C7', 'D7', 'E7'][e['i'] % 8]), .05, .125, .14), t0, 1, .3)
    elif tp in ('pane', 'whoosh'): add(fx, swish(.38 if tp == 'pane' else .5, .26 if tp == 'pane' else .32, 300, 3500), t0 - .1, 1, (e.get('d', .5) or 0) * .4)
    elif tp == 'jump': d = min(.16, e.get('d', .3) * .4); add(fx, pulse(330, d, .25, .16, slide=2.4), t0, 1, .1)
    elif tp == 'land': add(fx, pulse(110, .06, .5, .2 * e.get('v', .6)), t0, 1, 0); add(fx, crush(nz(.05, 200, 2000, .22 * e.get('v', .6), .015)), t0, 1, 0)
    elif tp == 'step': add(fx, crush(nz(.02, 1500, 6000, .06, .005), 4), t0, 1, .1)
    elif tp == 'morph':
        for k in range(26): add(fx, pulse(rng.uniform(900, 2600), .03, .125, .06), t0 + rng.uniform(0, .7), 1, rng.uniform(-.6, .6))
    elif tp == 'redpulse': add(fx, pulse(hz(['A4', 'A4', 'A4'][e['i']]), .09, .5, .13), t0, 1, .3); add(fx, boom(.25, 60, .35), t0, 1, 0)
    elif tp == 'hit': add(fx, boom(.5, 100, .6), t0, 1, 0)
    elif tp == 'lockpop': add(fx, sclick(.8, .9), t0, .5, .2); add(fx, pulse(hz('E6'), .05, .125, .14), t0 + .04, 1, .2); add(fx, pulse(hz('B6'), .07, .125, .12), t0 + .1, 1, .2)
    elif tp == 'alert': add(fx, pulse(hz('E6'), .06, .25, .16), t0, 1, .2); add(fx, pulse(hz('E6'), .09, .25, .16), t0 + .1, 1, .2)
    elif tp == 'stamp': add(fx, boom(.7, 150, .35), t0, 1, .1); add(fx, sclick(.6, 1.), t0, .6, .1); add(fx, pulse(hz('C5'), .14, .5, .2, slide=.5), t0, 1, .1)
    elif tp == 'whirr': d = 1.2; x = nz(d, 200, 1400, .18) * np.sin(np.pi * tt(d)[:int(d * SR)] / d) ** 2; add(fx, x.astype(np.float32), t0, 1, -.1)
    elif tp == 'block':
        add(fx, boom(1.2, 70, 1.1), t0, 1, 0); add(fx, pulse(110, .22, .5, .25), t0, 1, 0); add(fx, crush(nz(.3, 100, 3000, .3, .08)), t0, 1, 0)
    elif tp == 'drag':
        d = e['d']; x = nz(d, 700, 3200, .14) * (.6 + .4 * np.abs(np.sin(2 * np.pi * 7 * tt(d)[:int(d * SR)]))); add(fx, x.astype(np.float32), t0, 1, .3)
    elif tp == 'ding':
        for k, p in enumerate(['C6', 'G6']): add(fx, S.note('glockenspiel', p, .8, .45), t0 + k * .07, .5, .2)
    elif tp == 'seal':
        add(fx, boom(.6, 90, .4), t0, 1, .1); add(fx, sclick(.7, 1.), t0 + .02, .7, .1)
        for k in range(6): add(fx, tick(.16, 3000 + 300 * k), t0 + .08 + k * .07, 1, .1)
    elif tp == 'ping': add(fx, pulse(hz(['E6', 'G6', 'B6'][e['i']]), .1, .125, .14), t0, 1, .5); add(fx, S.note('glockenspiel', ['E6', 'G6', 'B6'][e['i']], .5, .3), t0, .35, .5)
    elif tp == 'dissolve':
        for k in range(22): add(fx, pulse(rng.uniform(800, 2800) * (1 - k / 40), .03, .125, .06), t0 + k * .04, 1, rng.uniform(-.5, .5))
        add(fx, swish(.9, .2, 1500, 9000), t0, 1, .3)
    elif tp == 'restart': add(fx, swish(.7, .3, 200, 2500), t0, 1, 0); d = 1.6; x = np.sin(2 * np.pi * 110 * tt(d)) * np.sin(np.pi * tt(d) / d) * .05; add(fx, x.astype(np.float32), t0 + .3, 1, 0)
    elif tp == 'stomp': add(fx, pulse(hz('C3'), .14, .5, .32, slide=.5), t0, 1, .3); add(fx, boom(.6, 120, .6), t0, 1, .2)
    elif tp == 'darkon': d = 1.1; x = lp(noise(d), 500) * np.exp(-tt(d) / .5) * .22; add(fx, x.astype(np.float32), t0, 1, 0); add(fx, boom(.6, 70, 1.3), t0, 1, 0)
    elif tp == 'minimize': add(fx, swish(.45, .28, 600, 5000), t0, 1, 0)
    elif tp == 'toast':
        for k, p in enumerate(['E5', 'B5']): add(fx, S.note('vibraphone', p, 1.2, .5), t0 + .1 + k * .12, .55, .5)
        add(fx, swish(.4, .16, 1500, 6000), t0, 1, .6)
    elif tp == 'snore':
        for r in range(2):
            for k, p in enumerate(['A4', 'F4']): add(fx, pulse(hz(p), .35, .5, .07, att=.08, rel=.15), t0 + r * 1.6 + k * .4, 1, .2)
# room tone under everything (the silences drop to this, never to digital zero)
room = lp(noise(NS / SR), 900, 2) * .012 + lp(noise(NS / SR), 160, 2) * .02
fx += np.stack([room[:NS], np.roll(room[:NS], 997)], 1).astype(np.float32)

# ═════════ voice, ducking, balance
vo = np.zeros((NS, 2), np.float32)
for e in ev_('vo'):
    y, sr = sf.read(os.path.join(HERE, 'voices', e['id'] + '.wav'), dtype='float32')
    if y.ndim > 1: y = y.mean(1)
    y = soxr.resample(y, sr, SR).astype(np.float32); y = compress(y, .3, 3.0); add(vo, y, e['t'], 1.0, 0)
env = np.abs(vo[:, 0]); k = int(.12 * SR); env = np.convolve(env, np.ones(k) / k, 'same'); env = np.clip(env / (env.max() * .25), 0, 1)
music *= (1 - .62 * env)[:, None]
fx *= (1 - .32 * env)[:, None]
music = music / (np.abs(music).max() + 1e-9) * .5
fx = fx / (np.abs(fx).max() + 1e-9) * .42
vo = vo / (np.abs(vo).max() + 1e-9) * .9
G_MUS, G_FX = db(float(os.environ.get('GM', -1))), db(float(os.environ.get('GF', 2)))
mix = music * G_MUS + fx * G_FX + vo
fade = np.ones(NS); fo = int(1.0 * SR); end = int(DUR * SR); fade[end - fo:end] = np.linspace(1, 0, fo); fade[end:] = 0
mix = limit(mix * fade[:, None], .95)
os.makedirs(os.path.join(HERE, 'out'), exist_ok=True)
sf.write(os.path.join(HERE, 'out', f'mix_{CUT}.wav'), mix[:int((DUR + .05) * SR)], SR)
if os.environ.get('STEMS'):
    for nm, y in (('music', music * G_MUS), ('fx', fx * G_FX), ('vo', vo)): sf.write(os.path.join(HERE, 'out', f'{nm}_{CUT}.wav'), y[:int((DUR + .05) * SR)], SR)
print(f'mix_{CUT}.wav', round(DUR, 2), 's; notes', len(EVN))
