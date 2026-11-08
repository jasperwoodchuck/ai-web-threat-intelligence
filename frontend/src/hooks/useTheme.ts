import { useEffect, useState } from "react";
import { THEME_STORAGE_KEY } from "../constants/investigation";
import type { Theme } from "../types/investigation";

function getInitialTheme(): Theme {
  let storedTheme: string | null = null;
  try {
    storedTheme = typeof window === "undefined" ? null : window.localStorage.getItem(THEME_STORAGE_KEY);
  } catch {
    // Theme selection still works for the current session.
  }
  if (storedTheme === "light" || storedTheme === "dark") return storedTheme;
  return typeof window !== "undefined" && window.matchMedia?.("(prefers-color-scheme: dark)").matches
    ? "dark"
    : "light";
}

export function useTheme() {
  const [theme, setTheme] = useState<Theme>(getInitialTheme);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    document.documentElement.style.colorScheme = theme;
  }, [theme]);

  function selectTheme(nextTheme: Theme) {
    setTheme(nextTheme);
    try {
      window.localStorage.setItem(THEME_STORAGE_KEY, nextTheme);
    } catch {
      // Keep the selected theme for the current session.
    }
  }

  return { theme, selectTheme };
}
