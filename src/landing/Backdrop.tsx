import type { JSX } from "react";
export default function Backdrop(): JSX.Element {
  return <div aria-hidden="true" className="pointer-events-none fixed inset-0 -z-10 overflow-hidden bg-abyss">
    <div className="grid-lines absolute inset-0 opacity-50" />
    <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_85%_15%,rgba(239,121,94,0.09),transparent_60%)]" />
  </div>;
}
