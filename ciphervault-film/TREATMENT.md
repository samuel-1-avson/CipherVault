# CipherVault — "Sealed" · treatment

Style: **Living Screencast** (Lemo-Opuscar). Two cuts from one source:
**full film ≤ 3:00** (target ≈ 2:43) and a **hackathon cut < 90 s** (target ≈ 87.5 s).
1920×1080, 30 fps (STYLE.md §5), English VO (Kokoro `am_michael`, calm US male),
burned caption pills + `.srt`, −14 LUFS.

## 1. Three candidate structures

1. **A day of one agent.** Morning to night in one Hermes session on a small
   repo; each feature turns up as a natural task, the theme dims with the hour.
   Warm, but the stakes never rise: features just queue up.
2. **Before / after race.** Two Hermes windows side by side, plain vs. sealed,
   same prompts; the left leaks, the right redacts. Clear, but it puts a leak
   of fake values on screen for half the film, and the split halves the
   readable size of every UI line.
3. **Five doors (chosen).** One continuous session in which the pressure on
   the secrets keeps rising: run → a prompt injection → a dirty commit → a
   lost disk. Each chapter is a door the secret could leave by, and each door
   has a different lock. The turn is the injection: the agent itself is
   tricked, and the vault still holds.

Why 3: it gives one subject (the `.env`, embodied by the vault sprite), one
goal (keep values out of the model), rising stakes and a real turn, and it
maps 1:1 onto real plugin surfaces, so every frame is verifiable output.

## 2. Logline and arc

*A coding agent that can read every file in a repo is tricked into leaking
its secrets, and a small pixel vault living in the Hermes window stops it at
every door, then proves the secrets survive even a lost disk.*

- **Setup:** the repo's secret files glow; the vault sprite climbs out of the
  `cv • vault` status chip and moves in on the `.env` row.
- **Turn:** an issue the agent reads carries a hidden instruction. The agent
  obeys and tries `cat .env`. Silence. The `pre_tool_call` guard refuses.
- **Ending:** a recovery drill restores and deletes its own plaintext; Hermes
  itself boots from the vault; the window minimises to the Windows taskbar and
  the end card arrives as a system toast the sprite rides in on.

## 3. Benchmark

- **Linear / Raycast launch walkthroughs** — learn: one feature per sentence,
  cursor choreography that always has a destination, zoom that follows intent,
  chapter pacing that alternates fast and held. Don't take: their UI, type,
  music, colour, any shot.
- **Screen-recorder product films (auto-zoom grammar)** — learn: push-ins to
  the caret, smoothing, click pushes. Don't take: any footage or branding.

## 4. Cast and world

- **The user = the cursor.** Never a hand.
- **The software = the vault sprite**: an original 16×16 square-pixel safe in
  amber-gold `#f5a524` (no UI element uses it; Hermes accent is blue), dark
  outline, a round dial as its belly that turns in 45° pixel steps when it
  "thinks", 2×2 eyes above the dial, stub legs. Props on the same grid: a
  `REDACTED` stamp, a pixel padlock, `!`, sparkles, dust, `z`.
- **The world = Hermes Desktop, light theme, redrawn in HTML/CSS** from the
  real app: sidebar (New session · Skills & Tools · Messaging · Artifacts ·
  Search sessions… · PINNED · SESSIONS), transcript + composer ("What's on your
  mind?"), right pane stack (Files | ciphervault), status bar (Gateway ready ·
  Agents · Cron … `cv • vault` chip). The CipherVault pane uses the plugin's
  exact labels (`plugins/ciphervault/desktop/plugin.js`). Windows title-bar
  controls (the plugin's binaries are Windows-first). No Hermes wordmark.
- **Demo repo `shop-api`**: `src/`, `package.json`, `.env` (tracked),
  `deploy/id_rsa` (sprawl), `config/credentials.json` (git-ignored).
  Fake values only: `API_KEY=test_value_123456`.

## 5. Segments (one timeline, two playlists)

Tempo **96 BPM, 4/4 → 1 bar = 2.5 s**. Every segment is a whole number of
bars, so either playlist keeps the music on the grid. Cuts happen only under
chapter-pill pixel wipes (STYLE.md §6).

| Seg | Chapter pill | Bars | Dur | Full | 90 s cut |
|---|---|---:|---:|:-:|:-:|
| S0 Hook | – | 4 | 10.0 | ✓ | ✓ |
| S1 Install | Install | 7 | 17.5 | ✓ | |
| S2 See | See | 8 | 20.0 | ✓ | |
| S3 Run | Run | 8 | 20.0 | ✓ | ✓ |
| S4 Guard | Guard | 9 | 22.5 | ✓ | ✓ |
| S5 Commit | Commit | 8 | 20.0 | ✓ | |
| S6 Recover | Recover | 9 | 22.5 | ✓ | ✓ |
| S7 Boot sealed | Boot sealed | 7 | 17.5 | ✓ | |
| S8 Close | – | 5 | 12.5 | ✓ | ✓ |
| **Total** | | | | **162.5 s** | **87.5 s** |

(Final bar counts are set from the measured VO; both totals stay under their caps.)

## 6. Shot list

| Seg | Framing / move | Why |
|---|---|---|
| S0 | Medium on the Files pane, **slow push** to `.env` as the three secret rows pulse red; **whip-pan** down to the status bar chip, the sprite climbs out of its amber dot (*match-cut origin*), hops back up the pane rows and lands on `.env` | hook in 3 s; the threat, then the guardian |
| S1 | **Push-in to the caret**: `hermes ciphervault bootstrap` typed in the terminal pane, key HUD; checksum line resolves; **pull back** to full window as the vault pane docks and the chip dot turns emerald | trust first: a verified install |
| S2 | Composer push-in ("Show my CipherVault status"); **rack focus** to the status card; scan result list — **follow the sprite** along the violation rows; the `deploy/id_rsa` row flips to *ignored* | the sprite reads what the scan reads |
| S3 | Prompt typed; `ciphervault_run` row expands into a process card; one stdout line **rides out** of the process (moving floor) toward the chat, the sprite jumps and stamps it mid-air → `[REDACTED:API_KEY]`; **push-in + vignette freeze** on `"redactions": 1` | **signature shot**: exact-value scrub made physical |
| S4 | `web_extract` result opens; **rack focus** + slow push to a hidden HTML comment in the issue; the agent's `terminal` call types `cat .env`; **room-tone silence**; the guard's block card drops in; the sprite plants itself in front with a padlock; **freeze** on "Paths are fine; contents are not." | the turn |
| S5 | **Whip-pan** chat → Files/git staging; `.env` sits in *Staged*; the block card; `ciphervault_scan` → `STAGED_TRACKED_SECRET .env`; the sprite **drags** the row out of Staged; clean commit ✓ | same answer, different lock |
| S6 | `ciphervault_push` log types out; pane Head / Operators rows pulse ×3; **time-lapse tag ▶▶ 4×** on the drill; a `cv-drill-…/.env` row appears in Files and **dissolves into pixels** the sprite sweeps away; **freeze** on `"drill_dir_deleted": true` | rehearsed, and no residue |
| S7 | `config.yaml` in the preview pane: `secrets: ciphervault: enabled: true`; save → restart; **the film changes state**: a theme-reveal circle from the sprite turns Hermes dark ("sealed"); agent answers with key *names* only | the agent itself is sealed |
| S8 | **Pull back** to the full window; the agent's summary shows three proof chips `[REDACTED]` · `BLOCKED` · `REHEARSED ✓` (sprite hops chip to chip on the words: *karaoke ball*); window **minimises to the taskbar**; a Windows toast carries the end card; the sprite rides it in, closes its door and sleeps | ending echoes the opening chip |

Camera moves used: push-in, pull-back, whip-pan, rack focus, follow, freeze
(+ vignette), time-lapse tag: **seven**, zoom ≥ 1 throughout.

## 7. Beat sheet (full film, planned)

| t | Beat |
|---:|---|
| 0.0 | Files pane; `.env`, `deploy/id_rsa`, `config/credentials.json` pulse red. VO L01 |
| 4.4 | whip to status bar; sprite pops out of the `cv • vault` dot; VO L02; lands on `.env` (downbeat 10.0) |
| 10.0 | wipe → **01 Install** — typing `hermes ciphervault bootstrap` |
| 27.5 | wipe → **02 See** — status card (no values), deep scan, `id_rsa` ignored |
| 47.5 | wipe → **03 Run** — RAM-only run, stamp, freeze on `redactions: 1` |
| 67.5 | wipe → **04 Guard** — hidden instruction, silence, BLOCK, freeze |
| 90.0 | wipe → **05 Commit** — staged `.env`, block, scan, unstage, clean commit |
| 110.0 | wipe → **06 Recover** — push 3/3 replicas, drill ▶▶ 4×, plaintext dissolves |
| 132.5 | wipe → **07 Boot sealed** — config, restart, film turns dark |
| 150.0 | close — proof chips, minimise, toast end card, sprite sleeps |
| 162.5 | end |

## 8. Cue map (96 BPM, 2.5 s bars)

| Section | Music | Hits |
|---|---|---|
| S0 | felt piano pulse + low pad; chip voice enters on the sprite's birth | sprite landing = downbeat bar 4 |
| S1–S2 | band in: piano, upright bass, brushed kit; glockenspiel on UI pops | tom fill + soft crash under each wipe |
| S3 | full band; chip voice duets with piano as the line rides out | stamp = beat 1; freeze → held pad, drums out 1 bar |
| S4 | drums drop (tension), bass pedal; **1.5 s room tone** before the block | block thud = first hit after silence, on a downbeat |
| S5 | band back, tighter kit | commit ✓ = glock ding |
| S6 | band + arpeggiated chip during ▶▶ 4×; **near-silence** before `drill_dir_deleted` | freeze on the downbeat |
| S7 | low-passed "night" band (dark theme) | theme circle on beat 1 |
| S8 | full band resolves; chip melody plays the motif once, slower; final chord under the toast | sprite's last step = final downbeat |

## 9. Sound design

| Seg | Ambience | Foley | Music state |
|---|---|---|---|
| S0 | room tone | red pulses (soft ticks), pop out of chip, 8-bit hops, landing + dust | pulse + pad |
| S1 | room tone | keyboard (thock + click, jittered), terminal lines, pane swish, chip ding | band enters |
| S2 | room tone | typing, card pop, sprite steps along rows, toggle click | band |
| S3 | room tone | typing, process whirr, whoosh of the riding line, **stamp** | band → held pad |
| S4 | room tone | page swish, typing `cat .env`, **silence**, block thud, padlock clack | drums out |
| S5 | room tone | whip swish, block thud, drag, commit ding | band |
| S6 | room tone | log ticks, three replica pings, ▶▶ tick, pixel dissolve sweep | band + arp |
| S7 | room tone (darker) | save click, restart whoosh, theme reveal | night band |
| S8 | room tone | chip pops ×3, minimise swish, toast chime, door clunk, soft snore | resolve |

## 9b. Revision 2 — "explain what it is and why it is better"

Feedback after the first cut: the film told the agent-safety story well but did not say what CipherVault *is* or why a
developer should choose it. Changes (all from `cipherv.online`, `README.md`, `docs/WHAT_IS_CIPHERVAULT.md`,
`docs/CURRENT_SECURITY_GUARANTEES.md`):

- **Hook line 2** is now the project's own tagline: "CipherVault protects everything that Git leaves behind."
- **New chapter 08 "Why CipherVault"** (9 bars, 22.5 s, full film only): the landing page's four failure modes plus the
  agent as a fifth, as five rows that flip from risk to shield, then four quality chips. It is the film's *summary
  turn*: every row points back at a chapter already shown, so the claim is demonstrated before it is stated.
- **Chapter 07 shortened** to 5 bars (the Q&A beat was dropped) to pay for it: full film 2:37.5 → 2:55.
- **Honesty rule**: only claims backed by the guarantees doc; no benchmark multipliers, no named-competitor table
  (see `report/HACKATHON_VIDEO_SCRIPT.md`, "Claims we make, and claims we deliberately do not").
- The 90 s cut is unchanged apart from the new hook line: the hackathon rule (< 90 s) leaves no room for a sixth
  chapter, so it keeps the agent-safety story and the full film carries the product case.

## 9c. Revision 3 — the approval gate

Plugin commit `3964115` made every `ciphervault_run` pass Hermes's human-approval gate and restricted the recovery
drill to a tool-owned temp dir. Chapter 03 Run now shows it: after the tool row, Hermes Desktop's approval card
(redrawn from `apps/desktop/.../tool/approval.tsx` and its i18n strings) asks the user to approve, the **cursor clicks
Run** (the cursor is the user: the approval is the one place the human acts), then the RAM-only run proceeds. A new
narration line (L08, plus L08b) explains why, and the 20 s chapter length is unchanged, so both cuts keep their
runtimes (175 s and 87.5 s). Chapter 06's drill result shows the new note text.

## 10. Subtitles and titles

- Caption pill: frosted glass, bottom-centre, Inter 34 px, never over the
  element discussed or under the sprite; hold ≥ max(1.8 s, line + 0.6 s).
- Chapter pill top-left: `01 Install` … numbered per playlist.
- Key HUD bottom-right for typed commands and shortcuts.
- Titles are diegetic only: the toast ("CipherVault — Zero-knowledge secrets
  for AI agents", repo, catalog PR #151642).
