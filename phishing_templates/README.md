# Phishing templates — authorized engagements

This directory contains **6 parameterizable email templates plus 1 landing page** with operational-grade visual quality, for Red Team campaigns backed by written contractual authorization.

## Usage contract

These templates are **starter templates**, not turnkey kits:

- No pixel-perfect registered trademarks (they are not byte-for-byte clones of Microsoft/Google/PayPal/etc.). Generic modern SaaS look-and-feel.
- No external assets: inline CSS, no `<img src="https://brand-cdn/...">` and no `@font-face` loaded from a proprietary CDN. The only external image is the `{{PIXEL_URL}}` tracking pixel that points at your own infrastructure.
- With runtime-replaceable placeholders that the `secemail.tracking.Tracker.tokenize_html()` module substitutes on send.

To use any of them in an engagement, the operator must:

1. Validate scope, dates, nominal target list, and written authorization.
2. Register a lookalike domain, publish your own SPF/DKIM/DMARC, warm up the domain.
3. Bring up the capture server (`secemail capture --port 8443 --bind 127.0.0.1 --templates-dir phishing_templates/`) behind valid TLS.
4. Customize the template for the client: `{{COMPANY_NAME}}`, tone, visual palette if applicable.
5. Launch the campaign with `secemail --targets-file targets.csv --html phishing_templates/<template>.html --authorize-domain client.com --track --capture-url https://lure.youroperator.tld`.

## Included templates

| File | Pretext | Primary vector | Expected CTR 2026 |
|--------|----------|-----------------|-------------------|
| `mfa_authenticator_approval.html` | "Approve this sign-in" with matching number | AiTM + session cookie theft | High |
| `documento_compartido.html` | "{{SENDER_NAME}} shared a document with you" | SSO credential phish | Very high |
| `solicitud_firma_digital.html` | "1 document awaiting your signature" | Credential phish + lateral | High |
| `buzon_de_voz.html` | "New voice message of {{VOICEMAIL_DURATION}}" | Credential phish or attachment | Medium |
| `revision_compensacion_rrhh.html` | "Your annual compensation review is available" | Internal portal credential phish | Very high |

The expected CTRs are indicative: they depend on the maturity of the client's defenses, the quality of the lookalike, and the level of per-target personalization.

## Available placeholders

All placeholders follow the `{{NAME}}` format. The ones reserved by the tracking module (`secemail.tracking`) are substituted automatically when `--track` is used; the rest are provided by the operator in the targets CSV or on the command line:

### Tracking (automatic with `--track`)

| Placeholder | Substituted by |
|-------------|----------------|
| `{{LURE_URL}}` | `<capture_url>/click/<token>?url=<base_lure>` |
| `{{PIXEL_URL}}` | `<capture_url>/pixel/<token>.png` |
| `{{CLICK_URL}}` | Same as `{{LURE_URL}}` (alias) |
| `{{TARGET_EMAIL}}` | Recipient's email |
| `{{TOKEN}}` | Session UUID, for correlation |

### Per-target personalization (CSV or flags)

| Placeholder | Example |
|-------------|---------|
| `{{TARGET_NAME}}` | "Ana García" |
| `{{TARGET_FIRST_NAME}}` | "Ana" |
| `{{COMPANY_NAME}}` | "ACME Corp" |
| `{{SENDER_NAME}}` | "Carlos Méndez" |
| `{{SENDER_EMAIL}}` | "carlos.mendez@acme-corp.example" |
| `{{SENDER_INITIALS}}` | "CM" |
| `{{SENDER_TITLE}}` | "Legal Counsel" |
| `{{DOCUMENT_NAME}}` | "Anexo_Q2_2026.pdf" |
| `{{DOCUMENT_TYPE}}` | "XLSX", "PDF", "DOCX" |
| `{{DOCUMENT_SIZE}}` | "184 KB" |
| `{{DOCUMENT_PAGES}}` | "4" |
| `{{ENVELOPE_ID}}` | UUID/8-4-4-4-12 |
| `{{MATCH_NUMBER}}` | "37" |
| `{{DEVICE_NAME}}` | "MacBook" |
| `{{DEVICE_LOCATION}}` | "Madrid, Spain" |
| `{{REQUEST_TIME}}` | "Today 13:42" |
| `{{SHARE_DATE}}`, `{{RECEIVED_AT}}` | Human-readable date |
| `{{EXPIRES_DATE}}`, `{{REVIEW_DEADLINE}}` | Human-readable date |
| `{{CALLER_NAME}}`, `{{CALLER_NUMBER}}` | "+34 91 *** ****" |
| `{{VOICEMAIL_DURATION}}`, `{{VOICEMAIL_SIZE}}` | "00:42", "324 KB" |
| `{{TRANSCRIPT_EXCERPT}}` | Quoted excerpt |
| `{{HRBP_NAME}}`, `{{HRBP_EMAIL}}` | "Lucía Pérez", "..." |
| `{{YEAR}}` | "2026" |
| `{{REFERENCE_CODE}}` | "HR-COMP-2026-A7F3" |
| `{{SUPPORT_URL}}` | Fake helpdesk URL |
| `{{UNSUBSCRIBE_URL}}` | Placeholder URL (non-functional in an honest kit) |

Placeholders that are not substituted stay as `{{NAME}}` in the final HTML — that's a sign of incomplete configuration and should be caught in pre-launch.

## Per-engagement adaptation

Recommended before the first send:

1. **Visually render** the template with real values and check it in Gmail web, Outlook desktop, and iPhone Mail. Some clients (Outlook 2019/Win) render some tables inconsistently; adjust if you spot it.
2. **Tune the tone** to the client's culture: very formal company vs. startup with informal address, etc. The HR template uses Georgia/serif by default — change it if the client uses sans.
3. **Replace `{{COMPANY_NAME}}`** with the client's real name or a recognized internal name (department, system).
4. **Verify** that no placeholder is left unsubstituted: `grep -E '\{\{[A-Z_]+\}\}' rendered_email.html` should be empty.
5. **Log changes** for reproducibility and client deliverable.

## Quishing (QR phishing)

If you need a QR variant (a growing vector in 2026 because it bypasses URL filters), generate the QR pointing at `{{LURE_URL}}` with an external generator and embed it as a base64 `<img>`. We do not include a specific template because the visual decision (where to place the QR, what pretext) depends on context.

## License

These templates are distributed under the root LICENSE of the repository (`/LICENSE`): use is restricted to authorized engagements, defensive awareness, and CTF in isolated environments. Any other use falls outside the permitted scope and is the sole responsibility of the operator.
