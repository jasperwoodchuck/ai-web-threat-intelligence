import type { ReactNode } from "react";
import type { Tone } from "../../types/investigation";

export function Badge({ children, tone = "neutral" }: { children: ReactNode; tone?: Tone }) {
  return <span className={`pill pill-${tone}`}>{children}</span>;
}
