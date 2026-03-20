# Formal Threat Model

## Methodology

This threat model uses:
- STRIDE for security threats
- Privacy impact considerations (LINDDUN-aligned)

Threats are evaluated assuming breach.

---

## STRIDE Analysis

### Spoofing
- Mitigation: phishing-resistant auth, device keys, WebAuthn
- Residual risk: low

### Tampering
- Mitigation: signed intents, append-only evidence
- Residual risk: low

### Repudiation
- Mitigation: mandatory evidence, immutable logs
- Residual risk: minimal

### Information Disclosure
- Mitigation: scoped investigation, least privilege
- Residual risk: bounded

### Denial of Service
- Mitigation: rate limiting, backpressure, fail-closed
- Residual risk: acceptable (availability traded for safety)

### Elevation of Privilege
- Mitigation: JIT grants, containment, no standing admin
- Residual risk: very low

---

## Insider Threats

- Malicious admin: contained automatically
- Malicious investigator: scope-enforced, contained
- Evidence tampering: triggers containment

---

## Privacy Considerations

- Minimal PII exposure
- Evidence uses stable identifiers
- SIEM/SOAR exports exclude secrets
