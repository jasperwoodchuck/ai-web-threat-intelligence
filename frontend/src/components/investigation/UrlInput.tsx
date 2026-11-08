export function UrlInput({ value, placeholder, onChange }: { value: string; placeholder: string; onChange: (value: string) => void }) {
  return <div className="url-field-wrap"><svg className="url-icon" viewBox="0 0 24 24" fill="none" aria-hidden="true"><circle cx="12" cy="12" r="9" /><path d="M3.5 12h17M12 3c2.2 2.4 3.3 5.4 3.3 9s-1.1 6.6-3.3 9c-2.2-2.4-3.3-5.4-3.3-9S9.8 5.4 12 3Z" /></svg><input id="url-input" type="url" value={value} onChange={(event) => onChange(event.target.value)} placeholder={placeholder} /><span className="field-shortcut">⌘ ↵</span></div>;
}
