export type Tone = "neutral" | "good" | "warning" | "danger" | "info";
export type Theme = "light" | "dark";
export type AnalysisMode = "url" | "message" | "file";
export type WebsiteStatus = "reachable" | "not_found" | "unreachable" | "error";
export interface WebsiteAvailability {
  status: WebsiteStatus;
  message: string;
  details: string;
  domain: string;
  http_status: number | null;
}
export interface UrlAvailabilityResponse {
  availability: WebsiteAvailability;
}
export type FileContentType =
  | "email"
  | "text_message"
  | "chat_message"
  | "notification"
  | "website_screenshot"
  | "login_security_page"
  | "document"
  | "image_with_text"
  | "unknown";
export interface FileAnalysisResponse {
  filename: string;
  media_type: string;
  size_bytes: number;
  sha256: string;
  extracted_text: string;
  content_type: FileContentType;
  classification_confidence: number;
  classification_reasoning: string;
  summary: string;
  key_findings: string[];
  recommended_action: string;
  indicators: string[];
  limitations: string[];
  extracted_urls: string[];
  deterministic_indicators: MessageIndicator[];
  url_threat_intelligence: MessageAnalysisResponse["url_threat_intelligence"];
  risk_assessment: RiskAssessment;
  ai_explanation: MessageAnalysisResponse["ai_explanation"];
}

export interface UrlAnalysis {
  original_url: string;
  normalized_url: string | null;
  scheme: string | null;
  hostname: string | null;
  port: number | null;
  path: string | null;
  has_query: boolean;
  has_fragment: boolean;
  has_username: boolean;
  has_password: boolean;
  registered_domain: string | null;
  subdomain: string | null;
  public_suffix: string | null;
  is_ip_address: boolean;
  is_valid: boolean;
  validation_error: string | null;
}

export interface DnsError {
  record_type: string;
  error_type: string;
  message: string;
}
export interface DnsAnalysis {
  hostname: string;
  status: string;
  resolution_succeeded: boolean;
  ipv4_addresses: string[];
  ipv6_addresses: string[];
  cname_target: string | null;
  mail_servers: { preference: number; exchange: string }[];
  nameservers: string[];
  txt_records: string[];
  errors: DnsError[];
  reason: string | null;
}
export interface PhishingIndicator {
  type: string;
  severity: string;
  description: string;
  evidence: string;
  score_contribution: number;
}
export interface FraudUrlSignal {
  status: string;
  result: Record<string, unknown> | null;
  score_contribution: number;
  error: string | null;
}
export interface PhishingAnalysis {
  is_suspicious: boolean;
  score: number;
  indicators: PhishingIndicator[];
  fraudurl: FraudUrlSignal;
}
export interface TyposquattingAnalysis {
  detected: boolean;
  submitted_domain: string | null;
  possible_intended_site: string | null;
  similarity: number | null;
  edit_distance: number | null;
}
export interface RiskEvidence {
  source: string;
  indicator: string;
  severity: string;
  weight: number;
  description: string;
  evidence: string;
}
export interface RiskAssessment {
  classification: string;
  score: number;
  confidence: number;
  contributing_indicators: RiskEvidence[];
  recommended_precautions: string[];
  limitations: string[];
}
export interface TlsCertificate {
  subject: string | null;
  issuer: string | null;
  serial_number: string | null;
  not_before: string | null;
  not_after: string | null;
  is_expired: boolean | null;
  san_names: string[];
  hostname_matches: boolean | null;
  public_key_algorithm: string | null;
  public_key_size: number | null;
  signature_algorithm: string | null;
}
export interface TlsFinding {
  type: string;
  severity: string;
  description: string;
  evidence: string;
}
export interface TlsAnalysis {
  status: string;
  supported: boolean;
  connection_successful: boolean;
  hostname: string | null;
  port: number | null;
  protocol_version: string | null;
  certificate_verified: boolean | null;
  certificate: TlsCertificate | null;
  certificate_chain: { subject: string; issuer: string; serial_number: string }[];
  certificate_transparency: { status: string; reason: string };
  certificate_revocation: { status: string; reason: string };
  findings: TlsFinding[];
  trust_note: string;
}
export interface HttpFinding {
  type: string;
  severity: string;
  description: string;
  evidence: string;
  score_contribution: number;
}
export interface HttpAnalysis {
  status: string;
  supported: boolean;
  request_successful: boolean;
  scheme: string | null;
  hostname: string | null;
  port: number | null;
  request_method: string;
  status_code: number | null;
  security_headers: Record<string, string | null>;
  headers_size_bytes: number | null;
  redirect_detected: boolean;
  redirect_status_code: number | null;
  redirect_location: string | null;
  final_behavior: string;
  error: string | null;
  findings: HttpFinding[];
  trust_note: string;
}
export interface ThreatIntelligenceResult {
  status: "matched" | "no_match" | "unavailable";
  matched: boolean | null;
  source: string;
  indicator: string;
  match_scope: string | null;
  threat_type: string | null;
  confidence: number | null;
  evidence: Record<string, unknown>;
  reference: string | null;
  checked_at: string;
  error: string | null;
}
export interface UrlAnalysisResponse {
  availability: WebsiteAvailability;
  url_analysis: UrlAnalysis;
  dns_analysis: DnsAnalysis;
  phishing_analysis: PhishingAnalysis;
  typosquatting: TyposquattingAnalysis;
  risk_assessment: RiskAssessment;
  tls_analysis: TlsAnalysis;
  http_analysis: HttpAnalysis;
  threat_intelligence: ThreatIntelligenceResult;
}
export interface MessageIndicator {
  category: string;
  severity: string;
  description: string;
  evidence: string;
}
export interface MessageAnalysisResponse {
  extracted_urls: string[];
  extracted_email_addresses: string[];
  extracted_phone_numbers: string[];
  deterministic_indicators: MessageIndicator[];
  url_threat_intelligence: {
    status: string;
    source: string;
    indicator: string;
    match_scope: string | null;
    threat_type: string | null;
  }[];
  risk_assessment: RiskAssessment;
  ai_explanation: {
    status: string;
    summary: string | null;
    suspicious_indicators: string[];
    evidence: string[];
    recommended_actions: string[];
    limitations: string[];
    confidence: number | null;
    advisory_note: string;
  };
  limitations: string[];
}
export interface KeyValue {
  label: string;
  value: unknown;
  mono?: boolean;
}
export interface SummaryFinding {
  title: string;
  detail: string;
  tone: Tone;
}
export interface NormalizedSecurityCheck {
  title: string;
  state: string;
  detail: string;
  tone: Tone;
}
export interface NormalizedAnalysisResult {
  source: string;
  target: string;
  contentType?: string;
  risk: RiskAssessment;
  findings: SummaryFinding[];
  recommendation: string;
  checks: NormalizedSecurityCheck[];
}
