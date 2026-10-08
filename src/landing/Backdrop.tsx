/**
 * The page's ground.
 *
 * Five stacked layers, all of them inert, from the original build: a drifting storm plate,
 * a masked blueprint grid, two radial washes (volt from above, violet from below) and a
 * linear fade into the abyss at the foot of the viewport.
 *
 * It is fixed and behind everything (`-z-10`) so the page scrolls over it rather than with
 * it, and it is `aria-hidden`: none of this carries meaning, and a screen reader should
 * never be made to walk through it.
 */
import type { JSX } from "react";

export default function Backdrop(): JSX.Element {
  return (
    <div aria-hidden="true" className="pointer-events-none fixed inset-0 -z-10 overflow-hidden bg-abyss">
      <div
        className="absolute inset-x-0 top-0 h-[120vh] animate-drift bg-cover bg-center opacity-45 [mask-image:linear-gradient(to_bottom,black_0%,black_45%,transparent_92%)]"
        style={{ backgroundImage: "url(/images/storm.jpg)" }}
      />
      <div className="grid-lines absolute inset-0" />
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_65%_50%_at_50%_-5%,rgba(87,224,255,0.07),transparent_60%)]" />
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_80%_60%_at_50%_115%,rgba(122,92,255,0.05),transparent_60%)]" />
      <div className="absolute inset-0 bg-[linear-gradient(to_bottom,transparent_55%,rgba(4,6,12,0.9)_100%)]" />
    </div>
  );
}
