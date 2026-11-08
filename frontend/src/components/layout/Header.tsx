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
        <a className="github-link" href="https://github.com/jasperwoodchuck/ai-web-threat-intelligence" target="_blank" rel="noreferrer" aria-label="View Web Threat Intelligence on GitHub" title="View on GitHub">
          <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 .9a11.1 11.1 0 0 0-3.51 21.63c.56.1.76-.24.76-.54v-2.08c-3.1.67-3.76-1.32-3.76-1.32-.5-1.29-1.24-1.63-1.24-1.63-1.01-.69.08-.68.08-.68 1.12.08 1.7 1.15 1.7 1.15.99 1.7 2.6 1.21 3.23.93.1-.72.39-1.21.7-1.49-2.47-.28-5.07-1.24-5.07-5.5 0-1.22.44-2.21 1.15-2.99-.12-.28-.5-1.42.11-2.95 0 0 .94-.3 3.05 1.14a10.6 10.6 0 0 1 5.55 0c2.12-1.44 3.05-1.14 3.05-1.14.61 1.53.23 2.67.12 2.95.71.78 1.14 1.77 1.14 2.99 0 4.27-2.6 5.21-5.08 5.49.4.34.75 1.02.75 2.06v3.06c0 .3.2.65.77.54A11.1 11.1 0 0 0 12 .9Z" /></svg>
        </a>
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
