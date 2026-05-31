# Email Threat Scanner

> A high-performance, local security triage engine for forensic analysis of raw email MIME payloads — with zero external API dependencies.

---

## Core Features

### Deep MIME Decomposition
Recursively unpacks multi-part email structures to isolate and individually analyze headers, plain-text bodies, and embedded HTML scripts across every MIME layer — no matter how deeply nested the payload.

### Crash-Resilient Parsing
Employs hardened decoding cycles with error mapping set to `replace`, ensuring the engine remains stable when processing malformed or adversarially crafted character encodings — a common evasion technique used by attackers to break naive parsers.

### Multi-Phase Heuristic Telemetry
Risk is evaluated across four independent tactical vectors, each targeting a distinct class of threat behavior. Results are aggregated into a composite risk score spanning four phases of analysis.

### Zero External Dependencies
No API keys. No cloud lookups. No data leaves the host. Suitable for deployment in air-gapped networks, classified environments, and regulated industries with strict data residency requirements.

---

## Threat Detection Pipeline

### Phase 1 — Envelope Diagnostics
Targets identity-layer deception at the mail envelope level.

- `From` vs `Reply-To` mismatch detection
- SPF authentication failure or absence
- DKIM signature failure or absence
- DMARC policy failure or absence

### Phase 2 — Lexical Threat Matrix
Scans body content for language patterns associated with social engineering attacks.

- Credential-harvesting trigger phrases (e.g. "verify your account", "confirm your password")
- Artificial urgency markers (e.g. "immediate action required", "your account will be suspended")
- Cryptocurrency wallet address patterns used in extortion campaigns

### Phase 3 — Mathematical Entropy Analysis
Calculates base-2 Shannon Entropy across decoded body content.

- Entropy scores above **5.5 bits** flag potential base64-encoded payloads, obfuscated scripts, or hidden data exfiltration strings
- Provides a quantitative signal independent of keyword matching, catching threats that evade lexical detection entirely

### Phase 4 — Structural Evasion Detection
Inspects HTML structure for rendering manipulation and link-masking techniques.

- Invisible text injection (zero-width characters, `display:none`, `font-size:0`)
- Hyperlink domain masking — detects mismatches between the visible anchor text domain and the actual `href` destination
- Catches evasion tactics designed to deceive human readers while bypassing naive URL scanners

---

## Technical Implementation

The project follows a decoupled architecture across three files, separating routing, analysis logic, and presentation into independent layers.

**`app.py`** — Central web routing coordinator and policy-driven MIME parser. Handles request validation, recursive MIME unpacking, and response assembly.

**`analyzer.py`** — Core mathematical and heuristic engine. Houses the Shannon entropy calculation and the full four-phase ruleset built on pre-compiled regular expressions for deterministic, low-latency execution.

**`index.html`** — Dark-themed forensic dashboard. Maps analysis output into interactive radar charts and a tabbed triage workspace for structured incident review.

---

## Primary Use Cases

**Air-Gapped SOC Environments**
Deploy on isolated networks to perform immediate offline forensic triage without any data leaving the perimeter. No API keys to rotate, no rate limits, no cloud vendor risk surface.

**Incident Response Pipeline**
Integrate as a Tier 1 automation stage in IR workflows. Analysts dump suspect `.eml` files directly into the scanner for rapid initial classification before escalating to deeper forensic review.

**Threat Vector Research**
Use as a sandboxed lab environment to study adversarial techniques — HTML layout evasion, structural entropy manipulation, and crafted encoding attacks — in a controlled, observable setting.

---

## Security & Privacy

- No telemetry. No usage data is collected or transmitted.
- No external lookups. Sender IPs, domains, and message content never leave the host machine.
- Local processing only. The engine operates entirely on the raw MIME payload in memory.
- Hardened parsing. Malformed inputs are handled gracefully without crashing on adversarial payloads.

This tool is intended for use by security professionals on systems and email samples they are authorized to analyze.

---

## License

MIT License — see [LICENSE](LICENSE) for details.