export function AnimatedSecurityBackground() {
  return <div className="security-background" aria-hidden="true">
    <span className="security-glow security-glow-cyan" />
    <span className="security-glow security-glow-blue" />
    <span className="security-glow security-glow-teal" />
    <svg className="security-network" viewBox="0 0 1440 900" preserveAspectRatio="xMidYMid slice" fill="none">
      <path d="m80 180 150 90 135-60 140 110m790-170-120 100-125-35-90 120M110 740l170-100 125 60 115-130m820 130-155-90-115 45-105-100" />
      <circle cx="230" cy="270" r="3" /><circle cx="365" cy="210" r="3" /><circle cx="505" cy="320" r="3" />
      <circle cx="1175" cy="250" r="3" /><circle cx="1060" cy="370" r="3" /><circle cx="280" cy="640" r="3" />
      <circle cx="405" cy="700" r="3" /><circle cx="1160" cy="650" r="3" />
    </svg>
  </div>;
}
