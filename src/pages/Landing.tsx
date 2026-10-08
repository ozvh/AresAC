/**
 * The landing surface — the front of the site.
 *
 * This is the marketing page: what a stranger, a publisher or a recruiter sees before they
 * have any reason to trust this system. It says what the architecture is and what it refuses
 * to do, and it is deliberately the only surface a visitor without a session is given.
 *
 * It is a second visual world from the console behind `/console`: dark blue rather than
 * black, coloured rather than monochrome, and in motion. The two are kept apart in
 * `src/index.css` with cascade layers and scoped tokens rather than by forking the
 * stylesheet, so the console's posture is not weakened by this page's.
 *
 * The composition is thin on purpose — nine section components and one backdrop, in the
 * original's order. Everything below is markup, so the only decision this file makes is the
 * order, and the order is the original's.
 */
import type { JSX } from "react";
import Backdrop from "../landing/Backdrop";
import Header from "../landing/Header";
import Hero from "../landing/Hero";
import Ticker from "../landing/Ticker";
import Architecture from "../landing/Architecture";
import Detection from "../landing/Detection";
import Adjudication from "../landing/Adjudication";
import CollateralZero from "../landing/CollateralZero";
import Scaling from "../landing/Scaling";
import Footer from "../landing/Footer";

export default function Landing(): JSX.Element {
  return (
    /*
     * `landing` is the hook `src/index.css` scopes this surface's cascade layers to: the
     * tokens this page redefines (its panel blue, its hairline, its two typefaces) and the
     * declarations it hands back to the utilities layer are all keyed on this class, so the
     * console keeps the values it shipped with. Without it the page silently inherits the
     * console's 12px monospace body and its black-and-grey palette.
     *
     * `grain` is not decoration either: its ::after is the fixed noise overlay, so the class
     * has to sit on an element that spans the page. `relative` gives the absolutely positioned
     * hollow ARES marks at the foot something to resolve against.
     */
    <div className="landing grain relative min-h-screen bg-abyss font-display text-white antialiased">
      <Backdrop />
      <Header />
      <main>
        <Hero />
        <Ticker />
        <Architecture />
        <Detection />
        <Adjudication />
        <CollateralZero />
        <Scaling />
      </main>
      <Footer />
    </div>
  );
}
