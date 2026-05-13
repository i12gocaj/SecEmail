"""Helper para generar QRs como data: URIs embeddables en plantillas HTML.

Uso:
    from phishing_templates.qr_helper import qr_data_uri
    uri = qr_data_uri("https://lure.example.com/track/abc123")
    html = template.replace("{{QR_DATA_URI}}", uri)

Requiere: `pip install qrcode[pil]` (no es dep obligatoria del paquete).
Si no está instalado, devuelve un placeholder SVG inline mínimo para no
romper el render del HTML.
"""

from __future__ import annotations

import base64
import io
from typing import Optional


def qr_data_uri(url: str, box_size: int = 8, border: int = 2) -> str:
    """Devuelve un data: URI base64 con el QR PNG del `url` dado.

    Args:
        url: URL completa a codificar en el QR.
        box_size: tamaño de cada módulo del QR en pixels (8 = QR de ~200px).
        border: módulos de margen blanco alrededor.

    Si la dependencia `qrcode` no está instalada, devuelve un SVG placeholder
    para que el HTML siga renderizando.
    """
    try:
        import qrcode  # type: ignore
    except ImportError:
        return _placeholder_svg(url)

    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=box_size,
        border=border,
    )
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#000000", back_color="#ffffff")

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{b64}"


def _placeholder_svg(url: str) -> str:
    """Placeholder SVG cuando `qrcode` no está instalado. NO es un QR real."""
    safe_url = url[:40] + "…" if len(url) > 40 else url
    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200" viewBox="0 0 200 200">'
        f'<rect width="200" height="200" fill="#ffffff"/>'
        f'<rect x="10" y="10" width="180" height="180" fill="none" stroke="#000000" stroke-width="2"/>'
        f'<text x="100" y="95" font-family="monospace" font-size="9" text-anchor="middle" fill="#000000">'
        f'QR PLACEHOLDER</text>'
        f'<text x="100" y="115" font-family="monospace" font-size="7" text-anchor="middle" fill="#666666">'
        f'pip install qrcode[pil]</text>'
        f'<text x="100" y="135" font-family="monospace" font-size="6" text-anchor="middle" fill="#aaaaaa">'
        f'url: {safe_url}</text>'
        f'</svg>'
    )
    b64 = base64.b64encode(svg.encode("utf-8")).decode("ascii")
    return f"data:image/svg+xml;base64,{b64}"


if __name__ == "__main__":  # CLI mínimo para probar
    import sys
    if len(sys.argv) < 2:
        print("Uso: python3 qr_helper.py <url>", file=sys.stderr)
        sys.exit(2)
    print(qr_data_uri(sys.argv[1]))
