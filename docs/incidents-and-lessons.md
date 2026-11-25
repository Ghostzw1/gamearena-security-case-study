# Incidents, lessons and known limitations

Real security issues found while building GameArena, how they were handled, and what they taught me.

## Incidents

### 1. Invisible characters slipped into source code (Trojan Source risk)
**What happened:** a code-generation tool decoded `\u200B`-style escapes inside regular expressions into the
real invisible characters. The code still looked identical on screen, the classic setup for a
"Trojan Source" attack, where what you read differs from what runs.
**Response:** found during review; every affected file was rewritten to use escapes, all database tests
re-run, and a scanner now checks every file for zero-width and bidi characters before each commit.
**Lesson:** generated code needs the same scrutiny as third-party code. Scan for invisible characters.

### 2. Part of a secret appeared in tool output
**What happened:** during setup a few characters of a server secret were printed in a terminal.
**Response:** treated as compromised and **rotated immediately**; from then on, secrets are generated
straight into `.env.local` and only their presence (never the value) is ever shown.
**Lesson:** exposure, not exploitation, triggers rotation. Never print secrets, not even partially.

### 3. A database default gave visitors more than intended
**What happened:** Supabase grants `EXECUTE` on new functions to the `anon` role by default. A
signed-in-only function was callable by visitors.
**Response:** caught by the attack tests; every signed-in-only function now has an explicit
`revoke ... from anon`, and the tests check it.
**Lesson:** "secure by default" isn't always the default. Test what visitors can do, not what you meant.

### 4. The admin panel revealed that it existed
**What happened:** with partial prerendering, the page's static shell (heading and title) was served
before the admin check, so anyone could see an "Admin panel" page existed.
**Response:** all admin content moved behind the check; everyone else gets a normal 404 and a neutral
title.
**Lesson:** information disclosure can come from rendering strategy, not just from data.

### 5. Least privilege versus convenient APIs
**What happened:** an "upsert" call needed `UPDATE` rights on columns that were deliberately not
granted (e.g. the owner id).
**Response:** replaced with update-then-insert, keeping the grants tight instead of loosening them.
**Lesson:** when a tool fights least privilege, change the code, not the permissions.

### 6. A card number was shared to "receive payments"
**What happened:** a full card number and expiry date were offered to wire up payouts.
**Response:** refused to store or use it. Payment providers pay out to a bank account configured in
their own dashboard; the app never handles card numbers (PCI DSS scope reduction). The owner was advised
to monitor and, if worried, replace the card.
**Lesson:** the safest sensitive data is the data you never hold.

### 7. Configuration drift from a CLI
**What happened:** a deployment CLI silently added `.env*` to `.gitignore`, which also hid
`.env.example` (the safe template).
**Response:** reverted; secrets stay ignored, the template stays tracked.
**Lesson:** review every file a tool changes.

### 8. Pasted secrets with hidden newlines
**What happened:** values pasted into a hosting dashboard can carry a trailing newline, which would break
a hash comparison.
**Response:** the job trims secrets and the Authorization header before comparing (still in constant
time).
**Lesson:** robustness is part of security: a broken check tends to get "temporarily" disabled.

## Known limitations and roadmap

| Limitation | Why it's accepted now | Plan |
| --- | --- | --- |
| Email confirmation off | Free email sending is limited to a few per hour | Enable with custom SMTP on a domain |
| Leaked-password (HaveIBeenPwned) check off | Paid Supabase feature | Enable when upgrading |
| CSP allows inline scripts | Static pages need small inline scripts; nonces force per-request rendering | Nonce-based CSP once content is mostly dynamic |
| Magic-byte check could be skipped by calling the API directly | The file is still private, own-folder, size- and MIME-limited | Move the final "post" step behind a server-only key or a storage webhook |
| Auth rate limits are per IP, and server-side calls share hosting IPs | Fine at launch scale | Add a CAPTCHA (e.g. Turnstile) if abuse appears |
| No central alerting | Small team | Log drain + alerts on spikes in 401/403/429 |
| Two-step login only for admins | Lower friction for players | Optional MFA for hosts and players |
| Payments not live | Waiting for a gaming licence and a merchant account | Integrate in test mode with callback hash verification + status polling |
