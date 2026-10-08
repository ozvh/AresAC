/**
 * The closing call to action, and the site's actual footer.
 *
 * Two halves: a centred "bring the line down" block that repeats the hero's promise and
 * offers the two ways forward, and then a conventional four-column grid with the wordmark
 * set once more at 26vw — the largest type on the page, cut off at the baseline by its own
 * negative margin, so the page ends on the brand rather than on a legal line.
 *
 * The four link columns are data rather than markup because their styling is identical: one
 * `<li><a>` shape repeated twelve times. The two link rows that changed destination did so
 * because this repository has a real build-request surface behind them; everything else keeps
 * the in-page anchors the original used.
 *
 * Nothing is added. An earlier draft gave the SYSTEM column a fifth link to the operator
 * console, which now lives at `/console`; that is a real destination this repository has and
 * the original did not. It was removed after measurement: a fifth row in that column makes it
 * the tallest column in the grid, so the footer grew 36px and the page with it, for a link
 * that belongs in documentation rather than in a reproduction of someone else's footer.
 */
import type { JSX } from "react";
import { Ic } from "./icons";
import type { IconName } from "./icons";
import { Reveal } from "./Reveal";

/** One shape for every footer link. */
const FOOTER_LINK = "text-sm text-mist transition-colors hover:text-white";

/** The three onboarding steps under the call to action. */
const STEPS: readonly { readonly n: string; readonly icon: IconName; readonly label: string }[] = [
  { n: "01", icon: "file-code-corner", label: "INTEGRATE THE SDK" },
  { n: "02", icon: "pen-line", label: "SIGN THE DRIVER" },
  { n: "03", icon: "satellite", label: "SYNC THE ARBITER" },
];

const SYSTEM: readonly { readonly label: string; readonly href: string }[] = [
  { label: "Architecture", href: "#architecture" },
  { label: "Detection Pillars", href: "#detection" },
  { label: "Adjudication", href: "#adjudication" },
  { label: "Scaling Matrix", href: "#scaling" },
];

const DOCTRINE: readonly { readonly label: string; readonly href: string }[] = [
  { label: "False-Positive Policy", href: "#false-positives" },
  { label: "Action Gradation", href: "#false-positives" },
  { label: "Driver Safety", href: "#architecture" },
  { label: "Allowlist Corpus", href: "#adjudication" },
];

const BUILD: readonly { readonly label: string; readonly href: string }[] = [
  { label: "Visual Studio 2022", href: "#scaling" },
  { label: "MSVC v143", href: "#scaling" },
  { label: "WDK 10.0.22621", href: "#scaling" },
  { label: "EV Signing", href: "#scaling" },
];

/** One labelled link column. */
function Column({
  title,
  links,
}: {
  readonly title: string;
  readonly links: readonly { readonly label: string; readonly href: string }[];
}): JSX.Element {
  return (
    <div>
      <div className="font-mono text-[10px] tracking-[0.34em] text-volt">{title}</div>
      <ul className="mt-5 space-y-3">
        {links.map((link) => (
          <li key={link.label}>
            <a href={link.href} className={FOOTER_LINK}>
              {link.label}
            </a>
          </li>
        ))}
      </ul>
    </div>
  );
}

export default function Footer(): JSX.Element {
  return (
    <footer className="relative overflow-hidden border-t border-line">
      <section id="deploy" className="relative mx-auto max-w-[1440px] px-6 py-32 text-center md:px-10 md:py-44">
        <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_50%_45%_at_50%_55%,rgba(239,121,94,0.08),transparent_70%)]" />

        <Reveal>
          <span className="inline-grid size-16 place-items-center border border-volt/40 bg-volt/10 text-volt glow-volt clip-notch">
            <Ic name="shield-half" strokeWidth={1.8} className="size-7" />
          </span>
        </Reveal>

        <Reveal>
          <h2 className="mx-auto mt-10 max-w-4xl font-display text-5xl font-bold leading-[0.95] tracking-tight text-white md:text-8xl">
            Hold the <span className="text-hollow-volt">line.</span>
          </h2>
        </Reveal>

        <Reveal>
          <p className="mx-auto mt-8 max-w-xl text-lg leading-relaxed text-mist">
            Ship a game where skill is the only exploit left. ARES integrates in days — and its driver comes with the
            discipline a BSOD-free fleet demands.
          </p>
        </Reveal>

        <Reveal className="mt-12 flex flex-wrap items-center justify-center gap-4">
          <a
            href="/request"
            className="group flex items-center gap-3 bg-volt px-8 py-4 font-mono text-xs font-semibold uppercase tracking-[0.24em] text-abyss transition-all duration-300 hover:shadow-[0_0_50px_rgba(239,121,94,0.5)] clip-notch"
          >
            Request the build
            <Ic name="arrow-up-right" className="size-4 transition-transform duration-300 group-hover:translate-x-0.5 group-hover:-translate-y-0.5" />
          </a>
          <a
            href="#adjudication"
            className="border border-line-2 px-8 py-4 font-mono text-xs uppercase tracking-[0.24em] text-white transition-all duration-300 hover:border-volt/60 hover:text-volt clip-notch"
          >
            Read the doctrine
          </a>
        </Reveal>

        <Reveal className="mx-auto mt-16 flex max-w-2xl flex-wrap items-center justify-center gap-x-10 gap-y-4">
          {STEPS.map((step) => (
            <span key={step.n} className="flex items-center gap-3 font-mono text-[10px] tracking-[0.26em] text-mist">
              <span className="text-volt">{step.n}</span>
              <Ic name={step.icon} className="size-4 text-mist/70" />
              {step.label}
            </span>
          ))}
        </Reveal>
      </section>

      <div className="relative border-t border-line">
        <div className="mx-auto max-w-[1440px] px-6 pt-16 md:px-10">
          <div className="grid gap-12 pb-16 md:grid-cols-[1.4fr_1fr_1fr_1fr]">
            <div>
              <div className="flex items-center gap-3">
                <span className="grid size-9 place-items-center border border-line-2 bg-panel clip-notch">
                  <Ic name="shield-half" strokeWidth={2.4} className="size-4 text-volt" />
                </span>
                <span className="font-display text-lg font-bold tracking-[0.22em]">ARES</span>
              </div>
              <p className="mt-5 max-w-xs text-sm leading-relaxed text-mist">
                Multi-layer anti-cheat architecture. User-mode sentinel, kernel driver, external arbiter — one
                conviction pipeline.
              </p>
            </div>
            <Column title="SYSTEM" links={SYSTEM} />
            <Column title="DOCTRINE" links={DOCTRINE} />
            <Column title="BUILD" links={BUILD} />
          </div>

          <div className="pointer-events-none select-none overflow-hidden">
            <div className="text-hollow mb-[-0.23em] text-center font-display text-[26vw] font-bold leading-none tracking-[-0.02em] opacity-40 md:text-[19rem]">
              ARES
            </div>
          </div>
        </div>

        <div className="border-t border-line bg-abyss/70 backdrop-blur">
          <div className="mx-auto flex max-w-[1440px] flex-wrap items-center justify-between gap-4 px-6 py-5 font-mono text-[10px] tracking-[0.2em] text-mist md:px-10">
            <span>© 2026 ARES ANTI CHEAT</span>
            <span className="text-volt">BLOCK ≠ BAN.</span>
            <a href="#top" className="flex items-center gap-2 transition-colors hover:text-white">
              BACK TO TOP <Ic name="arrow-up" className="size-3.5" />
            </a>
          </div>
        </div>
      </div>
    </footer>
  );
}
