/**
 * Scroll-triggered reveal.
 *
 * The original page animated each block in from `opacity: 0` with a 34px rise, and used a
 * blur-to-sharp variant on the two largest marks. That came from a motion library; this is
 * the same effect in about thirty lines and no dependency, because the repository's
 * dependency surface is deliberate and a keyframe library would be the largest thing in it.
 *
 * Two details are load-bearing:
 *
 *  - THE OBSERVER IS DISCONNECTED ON THE FIRST INTERSECTION. The reveal is one-way, so a
 *    block that has already been seen costs nothing to scroll past on the way back up.
 *  - REDUCED MOTION WINS. A visitor who has asked their system not to animate gets the
 *    content immediately, with no transition, rather than a page that fades in around them.
 *    The repository's console doctrine has no animation at all, so honouring that
 *    preference is the same posture, applied where motion is decorative.
 *
 * The wrapper renders the element the original markup put these classes on, so the layout
 * is unchanged by the animation: `className` is the original's, verbatim.
 */
import { useEffect, useRef, useState } from "react";
import type { CSSProperties, JSX, ReactNode } from "react";

/** The easing the original motion used: fast out of the gate, long settle. */
const EASE = "cubic-bezier(0.22, 1, 0.36, 1)";

/** How far a revealed block travels, in pixels. From the original's `translateY(34px)`. */
const RISE = 34;

/** How long the reveal itself runs. Used to know when the inline transition can be dropped. */
const DURATION = 800;

/** Only elements the original actually used a reveal wrapper for are permitted here. */
type RevealTag = "div" | "h1" | "h2" | "p" | "span" | "section";

export function Reveal({
  as = "div",
  variant = "rise",
  delay = 0,
  className,
  children,
}: {
  readonly as?: RevealTag | undefined;
  /**
   * `rise` fades and lifts. `blur` also focuses from a heavy blur — used on the hero's ARES
   * mark and on the kernel detail panel, the two places the original spent it.
   */
  readonly variant?: "rise" | "blur" | undefined;
  /** Stagger, in milliseconds. */
  readonly delay?: number | undefined;
  readonly className?: string | undefined;
  readonly children?: ReactNode;
}): JSX.Element {
  // Cast through a single intrinsic tag so JSX accepts the element. Every tag in RevealTag
  // takes the same three props, so the cast cannot smuggle an invalid attribute past the
  // compiler — it only collapses the union to something the JSX checker can resolve.
  const Tag = as as "div";

  const node = useRef<HTMLElement | null>(null);
  const [shown, setShown] = useState(false);
  const [settled, setSettled] = useState(false);

  useEffect(() => {
    const element = node.current;
    if (element === null) return;

    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduced || typeof IntersectionObserver === "undefined") {
      setShown(true);
      return;
    }

    const observer = new IntersectionObserver(
      (entries) => {
        if (entries.some((entry) => entry.isIntersecting)) {
          setShown(true);
          observer.disconnect();
        }
      },
      { threshold: 0.06, rootMargin: "0px 0px -64px 0px" },
    );
    observer.observe(element);
    return () => observer.disconnect();
  }, []);

  /*
   * THE TRANSITION IS TEMPORARY, AND THAT IS THE POINT.
   *
   * It has to be inline while the block animates in, because that is what drives the reveal.
   * But an inline `transition` shorthand outranks the element's own transition utility, so
   * leaving it in place would flatten every hover effect on a revealed element — the card that
   * eases its border over 500ms would snap instead. The original never had this problem: its
   * motion library wrote opacity and transform inline and left `transition` to the class. So
   * once the reveal has finished, the inline transition is removed and the element's own
   * transition utility takes over, exactly as it did there.
   *
   * The residual inline opacity/transform/filter stay, which also matches the original's
   * captured markup.
   */
  useEffect(() => {
    if (!shown) return;
    const timer = setTimeout(() => setSettled(true), DURATION + delay + 60);
    return () => clearTimeout(timer);
  }, [shown, delay]);

  const resting: CSSProperties =
    variant === "blur" ? { opacity: 1, filter: "blur(0px)", transform: "none" } : { opacity: 1, transform: "none" };
  const waiting: CSSProperties =
    variant === "blur" ? { opacity: 0, filter: "blur(14px)", transform: `translateY(${RISE}px)` } : { opacity: 0, transform: `translateY(${RISE}px)` };

  const style: CSSProperties = {
    ...(shown ? resting : waiting),
    ...(settled
      ? {}
      : {
          transition:
            `opacity ${DURATION}ms ${EASE} ${delay}ms, ` +
            `transform ${DURATION}ms ${EASE} ${delay}ms, ` +
            `filter ${DURATION}ms ${EASE} ${delay}ms`,
        }),
  };

  return (
    <Tag
      ref={(instance: HTMLElement | null) => {
        node.current = instance;
      }}
      className={className}
      style={style}
    >
      {children}
    </Tag>
  );
}
