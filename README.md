# Device Code Phishing — Training Simulator

> **Defensive security training tool.** No live endpoints. No real tokens. No credentials captured.

An interactive, browser-based simulation of **OAuth 2.0 Device Authorization Grant abuse** (RFC 8628), commonly called *Device Code Phishing*. Built for SOC analysts, blue teamers, and security awareness training.

🔗 **Live demo:** `https://YOUR-USERNAME.github.io/devicecode-phishing-sim/`

![License](https://img.shields.io/badge/license-MIT-green) ![Purpose](https://img.shields.io/badge/purpose-defensive%20training-blue) ![No Server](https://img.shields.io/badge/server-none%20required-lightgrey)

---

## What it demonstrates

| Phase | What happens |
|-------|-------------|
| 0 | Attacker requests a `user_code` + `device_code` from Microsoft's real `/oauth2/v2.0/devicecode` endpoint |
| 1 | Phishing email delivered with the code embedded — linking to the **real** `microsoft.com/devicelogin` |
| 2 | Victim navigates to the legitimate Microsoft page and enters the code |
| 3 | Victim authenticates with real credentials + MFA, consents to OAuth scopes |
| 4 | Attacker's polling script receives access + refresh tokens |
| 5 | Post-compromise: Graph API exfil, detection opportunities, mitigations |

---

## Why this attack is dangerous

- The victim authenticates on a **real Microsoft domain** — no MITM, no fake page
- Passes SPF/DKIM email checks if sent via a compromised tenant relay
- Bypasses traditional MFA because the user authenticates willingly
- `offline_access` scope grants a refresh token valid for **~90 days**
- Activity logs show the **victim's IP** as the sign-in location

---

## Usage

```bash
# Just open the file — no server, no dependencies
open index.html
```

Or deploy to GitHub Pages (see below).

Controls:
- `▶ Next phase` button or `→` / `Space` to advance
- Click any timeline step to jump to it
- `Auto-play` advances every 4.5 seconds
- `R` to reset

---

## Deploy to GitHub Pages

1. Push this repo to GitHub
2. Go to **Settings → Pages**
3. Source: `Deploy from a branch` → `main` → `/ (root)`
4. Save — live in ~60 seconds at `https://YOUR-USERNAME.github.io/devicecode-phishing-sim/`

The included GitHub Actions workflow (`.github/workflows/pages.yml`) automates this on every push.

---

## Detection (Microsoft Sentinel / Entra ID)

```kql
// Hunt for device code sign-ins
SigninLogs
| where AuthenticationProtocol == "deviceCode"
| where TimeGenerated > ago(7d)
| project TimeGenerated, UserPrincipalName, AppDisplayName,
          IPAddress, ResultType, ConditionalAccessStatus
| order by TimeGenerated desc

// Correlate: token used from different IP than sign-in
SigninLogs
| where AuthenticationProtocol == "deviceCode" and ResultType == 0
| join kind=inner (
    AADNonInteractiveUserSignInLogs
    | where TimeGenerated > ago(7d)
) on CorrelationId
| where IPAddress != IPAddress1
| project TimeGenerated, UserPrincipalName, SignInIP=IPAddress, TokenUseIP=IPAddress1
```

See `hunt.kql` for the full hunting query pack.

---

## Mitigations

- **Conditional Access:** Block `authenticationFlows` where `deviceCodeFlow` is enabled, scoped to users who don't need it
- **Require compliant/Hybrid AAD joined device**
- **Token lifetime policies:** Reduce refresh token lifetime from default 90 days
- **User training:** Never enter a device code you didn't generate yourself
- **Alert on:** New OAuth app consents with `offline_access` + Mail/Files scopes

---

## References

- [RFC 8628 §6 — Security Considerations](https://www.rfc-editor.org/rfc/rfc8628#section-6)
- [MITRE ATT&CK T1528 — Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)
- [Microsoft: Token theft playbook](https://learn.microsoft.com/en-us/security/operations/token-theft-playbook)
- [Microsoft: Protect against device code flow phishing](https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-device-code-flow)

---

## Legal / Ethical use

This tool is for **defensive education only**. It makes no real network requests, captures no credentials, and generates no actual OAuth tokens. All codes, tokens, and API responses are randomly generated client-side.

Do not use knowledge from this simulation to attack systems you do not own or have explicit written permission to test.

---

## License

MIT — see `LICENSE`
