import type { Theme } from "../../types/investigation";

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
        <div className="theme-toggle" role="group" aria-label="Color theme">
          {(["light", "dark"] as Theme[]).map((option) => (
            <button key={option} type="button" aria-label={`Switch to ${option} mode`} aria-pressed={theme === option} onClick={() => onThemeChange(option)}>
              {option === "light" ? <svg className="theme-icon theme-sun" viewBox="0 0 24 24" fill="none" aria-hidden="true"><circle cx="12" cy="12" r="4" /><path d="M12 2v2m0 16v2M4.93 4.93l1.42 1.42m11.3 11.3 1.42 1.42M2 12h2m16 0h2M4.93 19.07l1.42-1.42m11.3-11.3 1.42-1.42" /></svg> : <svg className="theme-icon theme-moon" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M20.2 15.1A8.5 8.5 0 0 1 8.9 3.8 8.6 8.6 0 1 0 20.2 15.1Z" /></svg>}
            </button>
          ))}
        </div>
      </div>
    </header>
  );
}
