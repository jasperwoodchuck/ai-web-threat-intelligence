export function MessageInput({ value, maxLength, placeholder, onChange }: { value: string; maxLength: number; placeholder: string; onChange: (value: string) => void }) {
  return <textarea id="message-input" maxLength={maxLength} value={value} onChange={(event) => onChange(event.target.value)} rows={6} placeholder={placeholder} />;
}
