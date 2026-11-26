# What GameArena taught me about cybersecurity

GameArena started as a tournament website. It became my cybersecurity lab, because every feature
created a new way to be attacked: chat → scams and floods, tournaments → cheating, uploads → disguised
files, notifications → SSRF, admin → account takeover.

## The rules I set before any code was written

1. Row Level Security on every table, with policies in versioned migrations.
2. Validate every input on the server with a schema; never trust the browser.
3. Never put secrets in code; server-only keys never become public variables.
4. Never trust payment confirmation from the client: verify the provider's callback hash **and** poll
   the provider before anything counts as paid. Test mode only until licensed.
5. File uploads: images only (magic bytes, not extensions), size limits, random names, private storage,
   signed links.
6. Players' phone numbers are private: only confirmed teammates see them, enforced in the database.
7. Log decisions that settle disputes (who, what, when).
8. Every new control gets a line in the security log, and every database rule gets attack tests.

## Skills demonstrated

| Area | Evidence in this repo |
| --- | --- |
| Threat modelling (STRIDE) | [threat-model.md](threat-model.md) |
| Access control design (RLS, least privilege, column grants) | [migrations/](https://github.com/Ghostzw1/gamearena-security-case-study/tree/main/migrations), [controls.md](controls.md) |
| Authentication and MFA | `mfa` tests, admin `aal2` design |
| Secure file handling | `media` tests, [magic-bytes.ts](https://github.com/Ghostzw1/gamearena-security-case-study/blob/main/snippets/magic-bytes.ts) |
| SSRF prevention | `push` tests, [ssrf-allowlist.ts](https://github.com/Ghostzw1/gamearena-security-case-study/blob/main/snippets/ssrf-allowlist.ts) |
| Applied cryptography (HMAC, SHA-256, ES256/JWT, constant-time compare) | [snippets/](https://github.com/Ghostzw1/gamearena-security-case-study/tree/main/snippets) |
| Web security headers and CSP | [security-headers.ts](https://github.com/Ghostzw1/gamearena-security-case-study/blob/main/snippets/security-headers.ts) |
| Security testing and automation (DevSecOps) | 548 attack tests, CI workflow |
| Incident response and honest reporting | [incidents-and-lessons.md](incidents-and-lessons.md) |
| Privacy by design | Empty push payloads, offline help bot, hashed IPs |
| Standards | [owasp-mapping.md](owasp-mapping.md), PCI DSS scope reduction |

## How this maps to roles and certifications

- **Application security / AppSec analyst**: access control design, OWASP Top 10, secure code review,
  security testing.
- **Cloud security**: least privilege in a managed database, secrets management, CI permissions.
- **CompTIA Security+ (SY0-701)** domains: security architecture, threats and mitigations,
  identity and access management, security operations (incident response).

## Interview stories (STAR)

- **Situation:** a public API key meant anyone could query the database. **Task:** keep 27 tables of
  player data private. **Action:** RLS on every table, column grants, ownership defaults, and 548
  attack tests. **Result:** every known attack path blocked and re-tested on every push.
- **Situation:** an admin password could be phished. **Action:** made admin rights depend on a second
  factor at the database level (`aal2`), not just in the UI. **Result:** a stolen password gives no
  admin powers.
- **Situation:** a secret was partially exposed. **Action:** rotated it immediately and changed the
  process so secrets are never displayed. **Result:** no window of exposure.

## Next steps in my learning

- [ ] Run an OWASP ZAP baseline scan and a manual Burp Suite test against a staging copy, and write a
      bug-bounty-style report on my own app.
- [ ] Add SAST (Semgrep) and dependency scanning (Dependabot / `npm audit`) to CI.
- [ ] Add secret scanning (gitleaks) as a pre-commit hook.
- [ ] Implement the payment flow in test mode and test the callback verification with forged requests.
- [ ] Study for CompTIA Security+ and practise on TryHackMe / Hack The Box.
