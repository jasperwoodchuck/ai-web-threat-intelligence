import type { AnalysisMode } from "../types/investigation";

export const THEME_STORAGE_KEY = "web-threat-intelligence-theme";

export interface InvestigationModeConfig {
  id: AnalysisMode;
  label: string;
  description: string;
  inputLabel: string;
  placeholder: string;
  supportingText: string;
  capabilities: string;
  icon: "url" | "message";
  maxLength?: number;
}

export const INVESTIGATION_MODES: Record<AnalysisMode, InvestigationModeConfig> = {
  url: {
    id: "url",
    label: "URL",
    description: "Website or domain",
    inputLabel: "URL to analyze",
    placeholder: "https://example.com",
    supportingText: "HTTP and HTTPS URLs supported",
    capabilities: "Checks domain · DNS · TLS · reputation · redirects",
    icon: "url",
  },
  message: {
    id: "message",
    label: "Text Message",
    description: "Email, notification, or chat",
    inputLabel: "Suspicious message",
    placeholder: "Paste the suspicious message, email, or notification here...",
    supportingText: "Up to 20,000 characters",
    capabilities: "Checks links · urgency · impersonation · language signals",
    icon: "message",
    maxLength: 20000,
  },
};

export const INVESTIGATION_MODE_ORDER: AnalysisMode[] = ["url", "message"];
