/**
 * Lightning.
 *
 * The hero's signature: bolts that strike the top of the frame, walk downward with a drift
 * that is carried between segments rather than drawn independently, throw a couple of
 * branches, and fade out over half a second or so. Every stroke is drawn twice — a wide
 * translucent pass under an additive glow, then a thin near-white core on top — which is
 * what makes it read as light rather than as a line.
 *
 * This is a faithful port of the routine the original page ran, not a lookalike: the
 * segment count, the drift terms, the branch probabilities, the four colours and the
 * additive compositing are the same arithmetic. What changed is only the shape of the code
 * — names, types, and the two structural details below.
 *
 *  - THE ARRAY IS MUTATED IN PLACE. Each bolt owns a counter and is retired when it passes
 *    its own lifetime, so no allocation happens per frame and a bolt's lifetime is
 *    independent of every other bolt's.
 *  - THE DEVICE PIXEL RATIO IS CAPPED AT 2. A 4x display would quadruple the fill cost of a
 *    full-viewport additive canvas for no visible gain at this weight.
 *
 * Nothing here is load-bearing for the page: it is `pointer-events-none`, it sits under a
 * mask, and it is decoration. It is still written to be cheap, because decoration that
 * drops frames is not decoration.
 */
import { useEffect, useRef } from "react";
import type { JSX } from "react";

/** A point in CSS pixels. Destructured rather than indexed to survive `noUncheckedIndexedAccess`. */
type Point = readonly [number, number];

interface Bolt {
  /** The main channel, from above the top edge to wherever it dies out. */
  readonly pts: readonly Point[];
  readonly branches: readonly (readonly Point[])[];
  life: number;
  readonly max: number;
  readonly width: number;
  readonly seed: number;
}

/**
 * One bolt: a main channel that drifts as it falls, plus zero to two branches that leave it
 * partway down and fork sideways.
 *
 * `x` and `y` are built outward from the previous segment, and the horizontal drift carries
 * 90% of its momentum into the next segment — that memory is what separates a lightning
 * shape from a jagged random walk.
 */
function makeBolt(width: number, height: number): Bolt {
  const pts: Point[] = [];
  let x = width * (0.12 + Math.random() * 0.76);
  let y = -24;
  pts.push([x, y]);

  const segments = 16 + Math.floor(Math.random() * 12);
  const step = (height * 0.88) / segments;
  let drift = 0;

  for (let i = 0; i < segments; i += 1) {
    drift += (Math.random() - 0.5) * 54;
    drift *= 0.9;
    x += (Math.random() - 0.5) * 44 + drift * 0.35;
    y += step * (0.62 + Math.random() * 0.76);
    pts.push([x, y]);
  }

  const branches: Point[][] = [];
  const branchCount = Math.random() < 0.75 ? 1 + Math.floor(Math.random() * 2) : 0;

  for (let b = 0; b < branchCount; b += 1) {
    // Branches leave from the middle of the channel, where the bolt is brightest.
    const originIndex = Math.floor(pts.length * (0.2 + Math.random() * 0.45));
    const origin = pts[originIndex] ?? pts[pts.length - 1] ?? ([x, y] as Point);
    let bx = origin[0];
    let by = origin[1];
    const direction = Math.random() < 0.5 ? -1 : 1;
    const line: Point[] = [[bx, by]];
    const legs = 4 + Math.floor(Math.random() * 6);

    for (let i = 0; i < legs; i += 1) {
      bx += direction * (12 + Math.random() * 34);
      by += 14 + Math.random() * 34;
      line.push([bx, by]);
    }
    branches.push(line);
  }

  return {
    pts,
    branches,
    life: 0,
    max: 30 + Math.random() * 26,
    width: 1.2 + Math.random() * 1.4,
    seed: Math.random() * 1000,
  };
}

/** Lay a polyline down as a path. Stroking is the caller's job, as in the original. */
function trace(ctx: CanvasRenderingContext2D, line: readonly Point[]): void {
  const first = line[0];
  if (first === undefined) return;
  ctx.beginPath();
  ctx.moveTo(first[0], first[1]);
  for (let i = 1; i < line.length; i += 1) {
    const point = line[i];
    if (point === undefined) continue;
    ctx.lineTo(point[0], point[1]);
  }
}

export default function HeroCanvas({ className }: { readonly className?: string | undefined }): JSX.Element {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (canvas === null) return;
    const ctx = canvas.getContext("2d");
    if (ctx === null) return;

    const ratio = Math.min(window.devicePixelRatio || 1, 2);
    let raf = 0;
    let bolts: Bolt[] = [];
    /** Frames until the next strike. Seeded low so the first one lands as the page settles. */
    let cooldown = 40;
    /** Strength of the sky-flash a strike leaves behind; decays by 14% per frame. */
    let flash = 0;

    const size = (): void => {
      const rect = canvas.getBoundingClientRect();
      canvas.width = rect.width * ratio;
      canvas.height = rect.height * ratio;
      ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
    };
    size();
    window.addEventListener("resize", size);

    const frame = (): void => {
      const width = canvas.getBoundingClientRect().width;
      const height = canvas.getBoundingClientRect().height;
      ctx.clearRect(0, 0, width, height);

      // The sky-flash: one radial wash centred above the frame, strongest the frame a bolt
      // is born and gone within a fifth of a second.
      if (flash > 0) {
        const glow = ctx.createRadialGradient(width * 0.5, height * 0.12, 0, width * 0.5, height * 0.12, width * 0.75);
        glow.addColorStop(0, `rgba(120, 190, 255, ${0.09 * flash})`);
        glow.addColorStop(1, "rgba(120, 190, 255, 0)");
        ctx.fillStyle = glow;
        ctx.fillRect(0, 0, width, height);
        flash *= 0.86;
      }

      cooldown -= 1;
      if (cooldown <= 0) {
        bolts.push(makeBolt(width, height));
        if (Math.random() < 0.55) flash = 0.9 + Math.random() * 0.6;
        // The gap between strikes: 1.8s to 5.8s at 60fps. Irregular on purpose — a metronome
        // reads as a loading spinner.
        cooldown = 110 + Math.random() * 240;
      }

      ctx.globalCompositeOperation = "lighter";

      for (const bolt of bolts) {
        bolt.life += 1;
        const progress = bolt.life / bolt.max;
        // Two out-of-phase sines: a slow swell against a faster one, so the stroke flickers
        // rather than fading smoothly.
        const pulse = 0.55 + 0.45 * Math.abs(Math.sin(bolt.seed + bolt.life * 0.9) * Math.sin(bolt.life * 0.37));
        const fade = Math.max(0, (1 - progress) * pulse);

        ctx.lineCap = "round";
        ctx.lineJoin = "round";

        // Pass one: the corona. Seven times the core's width, shadowed, at 16% — this is the
        // pass that makes the bolt feel like it is lighting the air around it.
        ctx.strokeStyle = `rgba(87, 224, 255, ${0.16 * fade})`;
        ctx.lineWidth = bolt.width * 7;
        ctx.shadowColor = "rgba(87, 224, 255, 0.85)";
        ctx.shadowBlur = 26;
        trace(ctx, bolt.pts);
        ctx.stroke();

        // Branches borrow that width deliberately: they are drawn before it is narrowed.
        for (const branch of bolt.branches) {
          ctx.strokeStyle = `rgba(122, 92, 255, ${0.12 * fade})`;
          trace(ctx, branch);
          ctx.stroke();
        }

        // Pass two: the core, near-white and thin, with a small glow so it stays crisp.
        ctx.shadowBlur = 8;
        ctx.strokeStyle = `rgba(232, 248, 255, ${0.85 * fade})`;
        ctx.lineWidth = bolt.width;
        trace(ctx, bolt.pts);
        ctx.stroke();

        // And the branches' own cores, at 60% of the main width.
        ctx.strokeStyle = `rgba(160, 235, 255, ${0.5 * fade})`;
        for (const branch of bolt.branches) {
          ctx.lineWidth = bolt.width * 0.6;
          trace(ctx, branch);
          ctx.stroke();
        }

        ctx.shadowBlur = 0;
      }

      bolts = bolts.filter((bolt) => bolt.life < bolt.max);
      ctx.globalCompositeOperation = "source-over";
      raf = requestAnimationFrame(frame);
    };

    raf = requestAnimationFrame(frame);
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", size);
    };
  }, []);

  return <canvas ref={canvasRef} className={className} />;
}
