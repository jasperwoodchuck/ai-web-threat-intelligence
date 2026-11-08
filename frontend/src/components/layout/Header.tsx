import type { Theme } from "../../types/investigation";
import { StatusIndicator } from "../ui/StatusIndicator";

interface HeaderProps { theme: Theme; onThemeChange: (theme: Theme) => void; }

export function Header({ theme, onThemeChange }: HeaderProps) {
  return (
    <header className="topbar">
      <a className="brand" href="#top" aria-label="Web Threat Intelligence home">
        <span className="brand-mark" aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none"><path d="M12 2.8 20 6v5.7c0 4.6-3.2 7.8-8 9.5-4.8-1.7-8-4.9-8-9.5V6l8-3.2Z" /><path d="m8.5 12.1 2.2 2.2 4.9-5" /></svg>
        </span>
        <span>Web Threat Intelligence</span>
      </a>
      <div className="topbar-actions">
        <StatusIndicator label="Threat intelligence online" detail="Passive analysis engine ready" />
        <div className="theme-toggle" role="group" aria-label="Color theme">
          {(["light", "dark"] as Theme[]).map((option) => (
            <button key={option} type="button" aria-pressed={theme === option} onClick={() => onThemeChange(option)}>
              <span aria-hidden="true">{option === "light" ? "☼" : "◐"}</span>{option[0].toUpperCase() + option.slice(1)}
            </button>
          ))}
        </div>
      </div>
    </header>
  );
}
