# Console component conventions (binding)

Read `shared/protocol.ts`, `src/lib/store.ts`, `src/lib/theme.ts`, `src/lib/format.ts`,
`src/index.css` and `src/components/EventStream.tsx` before writing anything.
`EventStream.tsx` is the exemplar: copy its panel shell, header and row markup.

## Hard design constraints (project mandate — a violation fails the work)

- **Monochrome only.** Permitted classes: `bg-void` `bg-panel` `bg-panel2` `border-line`
  `border-line2` `text-fg` `text-dim` `text-dimmer`. The three state colours
  `text-clean` `text-pending` `text-flagged` may appear **only** where they encode a
  verdict or a refusal class — never for decoration, focus, hover, selection or branding.
- **Forbidden:** gradients, `backdrop-blur`/glassmorphism, `box-shadow`/glow, rounded
  corners, any icon library (lucide, heroicons…) or emoji, framer-motion or any
  animation library, keyframe animations, transitions on layout properties, images,
  and vague marketing copy. Allowed symbols: `->` `[!]` `[x]` `+` `~` `!` `·` `█` `░`.
- **Copy is dense and technical.** State the measurement and what it proves. Never
  address the reader, never sell, never use a slogan.
- `strict`, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes` and
  `verbatimModuleSyntax` are on. No `any`. No `!` non-null assertions. Handle
  `undefined` from every array index. Explicit return type on every function.
- Never edit a file another worker owns. Never add a dependency. Never create files
  beyond the ones you are assigned.

## Component contract

- Every panel is `export default function Name(): JSX.Element`, **no props** — each panel
  reads the store itself. `import type { JSX } from "react";`
- Store: `import { useConsole, telemetry } from "@/lib/store";` then `const state = useConsole();`

  | field | meaning |
  |---|---|
  | `link` | `"IDLE" \| "CONNECTING" \| "LIVE" \| "RESET" \| "DOWN"` |
  | `reason` | human-readable link note |
  | `counters` | `PublicCounters \| null` |
  | `corpus` | allowlist corpus size |
  | `tuning` | `PublicTuning \| null` |
  | `gates` | `GateStageView[]` |
  | `ledger` | `LedgerView[]` (oldest → newest, up to 48) |
  | `chain` | `ChainView \| null` |
  | `agents` | provisioned agent principals |
  | `uptimeMs` | arbiter uptime |
  | `paused` / `rate` / `scenario` | operator pause state, fleet target evt/s, armed adversary profile |
  | `subjects` | `PublicSubject[]`, server-sorted by score desc (≤120) |
  | `events` | `EventRing` — use `at(i)`, `size`, `dropped`, `received`, `capacity` |
  | `eventSeq` / `frames` / `snapshots` / `resets` / `lastFrameAt` | stream health |
  | `selected` / `notice` | selected subject tag, transient operator message |

  Actions: `telemetry.select(tagOrNull)`, `telemetry.notify(text)`.
- Formatting, from `@/lib/format`: `pad` `padZero` `compact` `pct` `score` `clock`
  `duration` `uptime` `bar` `group12`. **Use these for every number** so no readout
  changes width when a value changes.
- Labels, from `@/lib/theme`: `VERDICT_TEXT` `VERDICT_GLYPH` `VERDICT_LABEL` `STEP_LABEL`
  `STEP_TEXT` `STEP_ORDER` `ROLE_RING_LABEL` `ROLE_LONG` `REJECTION_CLASSES`
  `ringsFor(mask)` `ringCount(mask)` `maskCells(mask)` `GATE_ORDER` `GATE_DESCRIPTION`
  `DISPOSITION_TEXT`.
- Key protocol shapes:
  - `PublicCounters` = `{ rx, drop, rej, rl, spf, sig, rpy, conv, subj, evicted, tps, p95, ring: Record<Role, number>, boot: string }`
  - `PublicSubject` = `{ su, vd, rm, sc, dw, st, ct, n, last }`
  - `LedgerView` = `{ seq, ts, kind, su, dt, h }`
  - `ChainView` = `{ head, length, sealed, broken }`
  - `GateStageView` = `{ gate, label, seen }`
  - `PublicTuning` = `{ windowMs, sampleCap, subjectCap, convictScore, pendingScore, dwellMs, decayMs, vetoScore, ratePerSec, rateBurst, maxSkewMs }`

## Panel shell (copy this shape exactly)

```tsx
<section className="flex min-h-0 flex-col border-b border-line bg-panel">
  <header className="flex h-[22px] shrink-0 items-center justify-between border-b border-line px-2 text-[10px] uppercase tracking-[0.18em]">
    <span className="text-fg">TITLE</span>
    <span className="text-dimmer">right-side meta</span>
  </header>
  <div className="min-h-0 flex-1 overflow-y-scroll p-2">…</div>
</section>
```

Use `overflow-y-scroll` (never `auto`) so a panel gaining content cannot shift the
layout. Keep row heights fixed. Column labels use
`text-[10px] uppercase tracking-[0.12em] text-dimmer`; numeric cells carry the `num`
class. A commit happens at most once per display frame, so re-rendering is cheap —
but never map over more than ~200 rows without windowing.
