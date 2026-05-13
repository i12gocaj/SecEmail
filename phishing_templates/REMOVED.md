# Templates removed in May 2026

The following templates were removed from the repository because they (a) used pixel-perfect registered trademarks (DMCA / trademark risk), (b) loaded webfonts from the vendor's CDN (identifiable forensic fingerprint), or (c) were legitimate emails cloned with links to the real domains (no capture, no parameterization, no operational value).

| File | Reason |
|---------|--------|
| `alerta_seguridad_critica.html` | Duplicate of `inicio_sesion_google.html`. Same HTML, different copy. |
| `inicio_sesion_google.html` | Pixel-perfect clone of a Google alert email. Logos and assets loaded from `gstatic.com` and `lh3.googleusercontent.com`. Links point at the legitimate `accounts.google.com`. No capture. |
| `cambio_password_paypal.html` | Pixel-perfect clone of a PayPal email. Webfonts `@font-face url(https://www.paypalobjects.com/...)` = identifiable forensic fingerprint. Links point at `paypal.com` with the real email's original `utm_unptid`. No capture. |
| `cambio_suscripcion_prime.html` | Amazon Prime clone with Amazon-compiled MJML CSS (`rio-button-cta-primary`, `m.media-amazon.com`). No capture. |

Replaced by **reference-only** templates in this directory: no registered trademarks, no functional pixel, no runtime-replaceable placeholders. See `README.md` for defensive use (awareness) and offensive use (authorized engagement).
