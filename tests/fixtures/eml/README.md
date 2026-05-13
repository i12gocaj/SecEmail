# `.eml` fixtures de integración

Fixtures realistas y anonimizadas (`@example.com`, `@example.org`,
`@target.example`, etc.) para los tests end-to-end de `secemail.audit_email`.
Ningún dominio resoluble en producción ni datos personales reales.

Las firmas DKIM y los headers `Authentication-Results` están construidos para
ser **estructuralmente válidos** (RFC 5322 / 6376 / 8601) pero **no verifican
criptográficamente**: el material en `b=` y `bh=` es aleatorio. Esto es
suficiente para validar el _flujo_ de `audit_email` (parsing, extracción de
dominios, lógica de alineación, normalización CRLF) sin necesitar claves
privadas ni DNS real. dkimpy reportará `fail` en la verificación criptográfica
cuando aplique — es lo esperado.

| Fixture | Bug / feature | Qué cubre |
|---|---|---|
| `gmail_signed.eml` | Caso baseline outbound Google Workspace | 1 DKIM-Signature `d=example.com` `s=google`, AR de `mx.google.com`, multipart text/html + text/plain. CRLF. |
| `m365_signed.eml` | Caso baseline outbound Microsoft 365 | 1 DKIM-Signature `d=example.org` `s=selector1`, AR de `spf.protection.outlook.com`, headers `X-MS-Exchange-Organization-*`/`X-Microsoft-Antispam-*`, multipart quoted-printable. |
| `multi_dkim_attack.eml` | **P0-1** (alineación DMARC sólo con firmas verificadas) | Dos `DKIM-Signature`: una legítima con `d=mailer.legitimo.tld`, otra adversarial con `d=victim.example` y `b=` basura. Sin claves DNS reales, ninguna verifica → `dkim_check.verified_domains == []`. La adversarial **no contamina** la lista. |
| `crlf_mixed_thunderbird.eml` | **P1 A6** (normalización CRLF) | `.eml` exportado con LF puro (típico Thunderbird/cliente). `audit_email` debe activar `metadata["crlf_normalized"] = True` y añadir warning. |
| `auth_results_injection_attempt.eml` | **P1 A7** (parse_authserv_id con comentarios RFC 5322 §3.2.2) | Dos `Authentication-Results`: la legítima del MTA confiable (`fail`) y otra adversarial precedida de comentario `(note) trusted-mx.example.com; spf=pass; dkim=pass`. Tras strip de comentarios, ambos comparten `authserv_id`. Defensa: aun cuando ambos sean trusted, el `fail` legítimo gana → status FAIL. La inyección no consigue flipar el veredicto. |
| `sender_fallback.eml` | **P1 A5** (multi-`From` + `Sender` fallback) | Header `From:` con dos direcciones (display-names con coma) y `Sender: ceo@example.com`. `metadata["from_multi"]` se llena, `metadata["sender"]` captura el responsable, warning sobre alineación DMARC con Sender se emite. |

Reglas:
- Tamaños < 8 KB cada fixture.
- Cada fixture lleva un header `X-Test-Fixture-Purpose:` en una línea para que
  un humano que abra el archivo sepa qué bug/feature cubre.
- Todos terminan con CRLF EXCEPTO `crlf_mixed_thunderbird.eml` que usa LF puro
  para forzar el path de normalización.
- Las direcciones email son `@example.{com,org,net,example}` o `@target.example`,
  todas reservadas por IANA — nunca correos reales.

Si añades una nueva fixture, ajusta también `tests/test_eml_integration.py` y
esta tabla.
