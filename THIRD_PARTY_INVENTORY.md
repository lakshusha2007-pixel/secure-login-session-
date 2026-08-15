# Third-Party Resource Inventory & Security Policy

This document provides a comprehensive inventory of all third-party JavaScript, CSS, Fonts, and CDN assets utilized across the SecureAuth system, documenting their provider, purpose, SRI integrity status, and Content-Security-Policy (CSP) directive compliance.

---

## 1. Third-Party Resource Matrix

| Asset Name | Provider | Domain / URL | Purpose | Receives PII? | SRI Hash Available? | CSP Directive |
|---|---|---|---|---|---|---|
| **Google Fonts Stylesheet** | Google LLC | `https://fonts.googleapis.com` | Renders typography (Outfit & Plus Jakarta Sans) | No | Yes (`crossorigin="anonymous"`) | `style-src 'self' https://fonts.googleapis.com` |
| **Google Fonts Font Files** | Google LLC | `https://fonts.gstatic.com` | WOFF2 font binary assets | No | Yes (`crossorigin="anonymous"`) | `font-src 'self' https://fonts.gstatic.com data:` |
| **Vanilla JS App Libraries** | Self-Hosted | `/assets/js/` | Local interactive UI & WebAuthn logic | No | Self-Hosted | `script-src 'self'` |
| **Local Stylesheet** | Self-Hosted | `/assets/css/style.css` | Application UI styling | No | Self-Hosted | `style-src 'self'` |

---

## 2. Security Assessment & Policy

1. **CDNs & Remote Scripts**:
   - No untrusted or dynamic third-party JavaScript libraries (e.g. unpkg, cdnjs, raw git CDNs) are loaded directly into execution contexts.
   - WebAuthn and passkey scripts are self-hosted within `/assets/js/` to eliminate dependency supply-chain risks.

2. **Subresource Integrity (SRI)**:
   - All external `<link>` declarations for font stylesheets enforce CORS preconnect attributes (`crossorigin="anonymous"`).

3. **Data Privacy & PII Boundary**:
   - None of the external third-party assets receive user credentials, session cookies, or PII.

4. **CSP Whitelisting**:
   - CSP header explicitly restricts font loading to `https://fonts.gstatic.com` and font stylesheets to `https://fonts.googleapis.com`.
   - All script execution is strictly locked down to `'self'` with dynamic per-request nonces (`script-src 'self' 'nonce-...'`).
