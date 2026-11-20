# Threat model

A security tool is a target too. This is what ThreatLens protects, who might attack it, what is done about it, and what is **not** done yet.

**Assets:** the alerts and logs (they reveal a network's weak points), analyst accounts and tokens, the audit trail, and the integrity of alert statuses.

| # | Threat | Mitigation in this repo | Still open |
| --- | --- | --- | --- |
| 1 | Guessing analyst passwords | Login limited to 10 attempts a minute; passwords need 10+ characters and must pass common-password checks; Django's password hashing | No account lockout or 2FA |
| 2 | Stolen or leaked token | Tokens expire after 12 hours; signing in replaces the old token; logout revokes it; the browser keeps it in `sessionStorage`, so closing the tab drops it | A script injected into the page could read it. A CSP header limits that, but cookies marked `HttpOnly` would be stronger |
| 3 | A viewer changing things | Write access is checked on the server for every request, not just hidden in the UI; viewers get 403 on upload and status change; tested | none known |
| 4 | Tampering with alerts or hiding actions | Alerts are read-only except `status`; no delete endpoint; every upload and status change is audited (admin-readable) | Audit entries can be removed by someone with direct database access |
| 5 | Oversized or malformed uploads | 2 MB size limit, 20,000-record limit, strict CSV validation with clear errors, uploads rate limited | A very large log split across many uploads can still use CPU |
| 6 | Hostile log content (for example script tags in a username) | React escapes everything it renders; the API stores values as plain text | none known |
| 7 | Running with insecure settings | The app refuses to start in production without `DJANGO_SECRET_KEY`; secure cookies, `nosniff` and no-framing by default; Compose requires the secrets and publishes only localhost | |
| 8 | Eavesdropping | None in this repo | **No HTTPS in the Compose file.** Put it behind a TLS proxy before any real use |
| 9 | Model file replaced by a malicious one | The model is loaded from a path the server owner controls and is committed with its metrics | The model is a pickle file, which can run code when loaded. Never load a model from an untrusted source |
| 10 | Trusting the ML output too much | The Model page shows the weak spots (R2L 10.6%, U2R 19.4%, 40.6% on unseen attacks); the model never raises critical alerts | |

**Not in scope:** protecting the machine it runs on, and anything that depends on the data being genuine (a forged log produces forged alerts).
